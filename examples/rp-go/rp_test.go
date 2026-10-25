package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	bridgeproviders "github.com/tpt-solutions/tpt-identity/internal/bridge/providers"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const (
	testUser     = "rp-user@example.com"
	testPassword = "correct-horse-battery"
	testClientID = "rp-example-client"
	testRedirect = "https://rp.example/callback"
	testKID      = "rp-1"
)

// fixture runs the platform on a real HTTP listener, with a password account and this RP registered
// the way POST /oidc/register would register it.
type fixture struct {
	platform *httptest.Server
	rp       *RP
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	st := storetest.New(t)

	pw := bridgeproviders.NewPasswordBridge(st)
	if err := pw.SetPassword(ctx, testUser, testPassword); err != nil {
		t.Fatal(err)
	}
	bm := bridge.NewManager()
	bm.Register(pw)

	_, platformKey, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	// The issuer is the listener's own URL, so the platform's iss and aud match what the RP expects.
	ts := httptest.NewUnstartedServer(nil)
	srv := api.NewServer(api.Config{
		APIKey:     "rp-example-api-key-0123456789",
		Issuer:     "http://" + ts.Listener.Addr().String(),
		SigningKey: platformKey,
		Store:      st,
		OIDC:       oidc.NewProvider("http://"+ts.Listener.Addr().String(), platformKey, "platform-1", st),
		Resolver:   resolver.New(time.Minute),
		Bridges:    bm,
	})
	ts.Config.Handler = srv
	ts.Start()
	t.Cleanup(ts.Close)

	clientPub, clientKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "kid": testKID,
		"x": base64.RawURLEncoding.EncodeToString(clientPub),
	}}})
	if err := st.SaveClient(ctx, &store.OIDCClient{
		ClientID:                testClientID,
		ClientName:              "rp-go",
		RedirectURIs:            []string{testRedirect},
		TokenEndpointAuthMethod: "private_key_jwt",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		JWKS:                    string(jwks),
		CreatedAt:               time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	return &fixture{
		platform: ts,
		rp: &RP{
			Issuer:      ts.URL,
			ClientID:    testClientID,
			RedirectURI: testRedirect,
			Key:         clientKey,
			KeyID:       testKID,
			HTTP:        ts.Client(),
		},
	}
}

// The whole flow works against a live platform: sign in, exchange, verify, read userinfo.
func TestSignInEndToEnd(t *testing.T) {
	f := newFixture(t)
	res, err := f.rp.Run(context.Background(), testUser, testPassword)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	if !strings.HasPrefix(res.Subject, "did:") {
		t.Errorf("subject is not a DID: %q", res.Subject)
	}
	if res.IDClaims.Sub != res.Subject || res.IDClaims.DID != res.Subject {
		t.Errorf("id token subject and did disagree: %+v", res.IDClaims)
	}
	if res.UserInfo["sub"] != res.Subject {
		t.Errorf("userinfo sub: want %s, got %v", res.Subject, res.UserInfo["sub"])
	}
}

// A wrong password gets no code, so there is nothing to exchange.
func TestWrongPasswordIsRefused(t *testing.T) {
	f := newFixture(t)
	if _, err := f.rp.Run(context.Background(), testUser, "not-the-password-at-all"); err == nil {
		t.Fatal("wrong password signed in")
	}
}

// A redirect that carries another sign-in's state is refused, and its code is never exchanged. The stub
// platform answers with a code and a state the RP did not send.
func TestStateMismatchIsRefused(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", testRedirect+"?code=someones-code&state=another-signin-state")
		w.WriteHeader(http.StatusFound)
	}))
	defer stub.Close()
	rp := &RP{Issuer: stub.URL, ClientID: testClientID, RedirectURI: testRedirect, HTTP: stub.Client()}
	flow, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.Login(context.Background(), flow, testUser, testPassword); err == nil || !strings.Contains(err.Error(), "state") {
		t.Errorf("state mismatch: want refusal, got %v", err)
	}
}

// PKCE binds the code to the verifier: a different verifier cannot redeem it.
func TestWrongPKCEVerifierCannotRedeemCode(t *testing.T) {
	f := newFixture(t)
	flow, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.rp.Login(context.Background(), flow, testUser, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.rp.Exchange(context.Background(), code, other.Verifier); err == nil {
		t.Error("code redeemed with the wrong PKCE verifier")
	}
}

// The client must authenticate with its registered key. A different key is refused at /token.
func TestExchangeNeedsRegisteredClientKey(t *testing.T) {
	f := newFixture(t)
	flow, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.rp.Login(context.Background(), flow, testUser, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, impostor, _ := ed25519.GenerateKey(nil)
	bad := *f.rp
	bad.Key = impostor
	if _, err := bad.Exchange(context.Background(), code, flow.Verifier); err == nil {
		t.Error("exchange authenticated with an unregistered key")
	}
}

// An ID token with a changed nonce is refused, so a token minted for another request cannot be replayed here.
func TestIDTokenNonceIsChecked(t *testing.T) {
	f := newFixture(t)
	flow, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.rp.Login(context.Background(), flow, testUser, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := f.rp.Exchange(context.Background(), code, flow.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.rp.VerifyIDToken(context.Background(), tokens.IDToken, "some-other-nonce"); err == nil {
		t.Error("id token accepted with the wrong nonce")
	}
	if _, err := f.rp.VerifyIDToken(context.Background(), tokens.IDToken, flow.Nonce); err != nil {
		t.Errorf("id token with the right nonce: %v", err)
	}
}

// A tampered ID token fails the signature check.
func TestTamperedIDTokenIsRefused(t *testing.T) {
	f := newFixture(t)
	flow, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.rp.Login(context.Background(), flow, testUser, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := f.rp.Exchange(context.Background(), code, flow.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tokens.IDToken, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	claims["sub"] = "did:peer:someone-else"
	forged, _ := json.Marshal(claims)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]

	if _, err := f.rp.VerifyIDToken(context.Background(), tampered, flow.Nonce); err == nil {
		t.Error("tampered id token accepted")
	}
}

// The sign-in page renders the form, and a failed sign-in shows the error without the password.
func TestSignInPageDoesNotEchoPassword(t *testing.T) {
	f := newFixture(t)
	page := &signInPage{rp: f.rp}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", page.form)
	mux.HandleFunc("POST /login", page.login)
	ui := httptest.NewServer(mux)
	defer ui.Close()

	const secret = "a-password-that-must-not-appear"
	resp, err := ui.Client().PostForm(ui.URL+"/login", map[string][]string{
		"identifier": {testUser},
		"password":   {secret},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), secret) {
		t.Error("the sign-in page echoed the password")
	}
	if !strings.Contains(string(body), "Sign-in failed") {
		t.Errorf("failed sign-in not shown: %s", body)
	}
}

// The generated key round-trips through its PEM file, and the registration body carries its public key.
func TestKeyAndRegistrationRoundTrip(t *testing.T) {
	path := t.TempDir() + "/rp-key.pem"
	if err := writeKey(path); err != nil {
		t.Fatal(err)
	}
	if err := writeKey(path); err == nil {
		t.Error("existing key file overwritten")
	}
	key, err := readKey(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := registrationBody(key, testKID, "rp", testRedirect)
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
		JWKS                    struct {
			Keys []struct {
				X   string `json:"x"`
				KID string `json:"kid"`
			} `json:"keys"`
		} `json:"jwks"`
	}
	if err := json.Unmarshal([]byte(body), &reg); err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	if reg.TokenEndpointAuthMethod != "private_key_jwt" || len(reg.JWKS.Keys) != 1 ||
		reg.JWKS.Keys[0].X != base64.RawURLEncoding.EncodeToString(pub) || reg.JWKS.Keys[0].KID != testKID {
		t.Errorf("registration body does not carry the key: %s", body)
	}
}

// The body that -print-registration prints is accepted by the platform's POST /oidc/register, which is the
// route an operator uses. The client then gets a client_id and no client secret.
func TestRegistrationBodyIsAcceptedByPlatform(t *testing.T) {
	st := storetest.New(t)
	_, platformKey, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	const apiKey = "rp-registration-api-key-0123456789"
	ts := httptest.NewUnstartedServer(nil)
	issuer := "http://" + ts.Listener.Addr().String()
	srv := api.NewServer(api.Config{
		APIKey:     apiKey,
		Issuer:     issuer,
		SigningKey: platformKey,
		Store:      st,
		OIDC:       oidc.NewProvider(issuer, platformKey, "platform-1", st),
		Resolver:   resolver.New(time.Minute),
	})
	ts.Config.Handler = srv
	ts.Start()
	defer ts.Close()

	path := t.TempDir() + "/rp-key.pem"
	if err := writeKey(path); err != nil {
		t.Fatal(err)
	}
	key, err := readKey(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := registrationBody(key, testKID, "rp-go", testRedirect)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oidc/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated || out.ClientID == "" {
		t.Fatalf("registration: want 201 with a client_id, got %d %+v", resp.StatusCode, out)
	}
	if out.ClientSecret != "" {
		t.Error("a private_key_jwt client was issued a secret")
	}
}
