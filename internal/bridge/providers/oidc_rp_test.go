package providers_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/bridge/providers"
)

const (
	rpClientID = "tpt-client"
	rpKID      = "upstream-1"
	rpState    = "signed-state-token"
)

func rpNonce(state string) string {
	sum := sha256.Sum256([]byte("tpt-identity-nonce:" + state))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// fakeIDP is an in-process upstream provider: discovery, JWKS and a token endpoint that returns
// the id_token it was given.
type fakeIDP struct {
	srv     *httptest.Server
	priv    ed25519.PrivateKey
	idToken string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{priv: priv}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
			"jwks_uri":               f.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "kid": rpKID,
			"x": base64.RawURLEncoding.EncodeToString(pub),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": f.idToken})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// mintIDToken signs an upstream id_token with the fake IdP's key.
func (f *fakeIDP) mintIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": rpKID})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(f.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// goodClaims are the claims a correct upstream id_token carries for the test login.
func (f *fakeIDP) goodClaims() map[string]any {
	return map[string]any{
		"iss":            f.srv.URL,
		"aud":            rpClientID,
		"sub":            "upstream-user-42",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"nonce":          rpNonce(rpState),
		"email":          "pat@example.com",
		"email_verified": true,
	}
}

func newRP(f *fakeIDP) *providers.OIDCRPBridge {
	return providers.NewOIDCRP(providers.OIDCRPConfig{
		Name:            "idp",
		Issuer:          f.srv.URL,
		ClientID:        rpClientID,
		ClientSecret:    "secret",
		RedirectBaseURL: "https://identity.example",
	})
}

func TestOIDCRPAcceptsValidIDToken(t *testing.T) {
	f := newFakeIDP(t)
	f.idToken = f.mintIDToken(t, f.goodClaims())

	ext, err := newRP(f).ExchangeCode(context.Background(), "code", rpState)
	if err != nil {
		t.Fatalf("valid id_token rejected: %v", err)
	}
	if ext.ExternalID != "upstream-user-42" {
		t.Errorf("ExternalID = %q", ext.ExternalID)
	}
	if ext.Claims["email_verified"] != "true" {
		t.Errorf("email_verified = %q, want true", ext.Claims["email_verified"])
	}
}

func TestOIDCRPReportsUnverifiedEmail(t *testing.T) {
	f := newFakeIDP(t)
	claims := f.goodClaims()
	claims["email_verified"] = false
	f.idToken = f.mintIDToken(t, claims)

	ext, err := newRP(f).ExchangeCode(context.Background(), "code", rpState)
	if err != nil {
		t.Fatalf("id_token rejected: %v", err)
	}
	if ext.Claims["email_verified"] != "false" {
		t.Errorf("email_verified = %q, want false", ext.Claims["email_verified"])
	}
}

func TestOIDCRPRejectsBadClaims(t *testing.T) {
	cases := map[string]func(c map[string]any){
		"wrong issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
		"wrong audience": func(c map[string]any) { c["aud"] = "some-other-client" },
		"wrong nonce":    func(c map[string]any) { c["nonce"] = "replayed-from-another-login" },
		"no nonce":       func(c map[string]any) { delete(c, "nonce") },
		"expired":        func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"no subject":     func(c map[string]any) { delete(c, "sub") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeIDP(t)
			claims := f.goodClaims()
			mutate(claims)
			f.idToken = f.mintIDToken(t, claims)
			if _, err := newRP(f).ExchangeCode(context.Background(), "code", rpState); err == nil {
				t.Fatal("id_token with a bad claim was accepted")
			}
		})
	}
}

func TestOIDCRPAcceptsAudienceArray(t *testing.T) {
	f := newFakeIDP(t)
	claims := f.goodClaims()
	claims["aud"] = []string{"other-client", rpClientID}
	f.idToken = f.mintIDToken(t, claims)
	if _, err := newRP(f).ExchangeCode(context.Background(), "code", rpState); err != nil {
		t.Fatalf("aud array containing the client was rejected: %v", err)
	}
}

func TestOIDCRPAuthorizationURLCarriesNonce(t *testing.T) {
	f := newFakeIDP(t)
	authURL, err := newRP(f).AuthorizationURL(context.Background(), rpState)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(authURL, "nonce="+rpNonce(rpState)) {
		t.Errorf("authorization URL lacks the state-bound nonce: %s", authURL)
	}
}
