package oidc_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const (
	pkjClientID  = "pkj-client"
	pkjKID       = "ck-1"
	pkjIssuer    = "https://issuer.example.com"
	pkjTokenURL  = pkjIssuer + "/token"
	pkjAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// pkjFixture is a provider with one private_key_jwt client, whose key is returned.
func pkjFixture(t *testing.T) (*oidc.Provider, ed25519.PrivateKey) {
	t.Helper()
	st := storetest.New(t)
	_, platformPriv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(pkjIssuer, platformPriv, "key-1", st)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	jwks := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"` + pkjKID + `","x":"` +
		base64.RawURLEncoding.EncodeToString(pub) + `"}]}`
	if err := st.SaveClient(t.Context(), &store.OIDCClient{
		ClientID: pkjClientID, ClientName: "pkj", TokenEndpointAuthMethod: "private_key_jwt",
		GrantTypes: []string{"client_credentials"}, JWKS: jwks, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return p, priv
}

// signAssertion returns a compact JWS with the given claims, signed by key under kid.
func signAssertion(t *testing.T, key ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signing)))
}

func goodClaims(jti string) map[string]any {
	return map[string]any{
		"iss": pkjClientID, "sub": pkjClientID, "aud": pkjTokenURL,
		"exp": time.Now().Add(time.Minute).Unix(), "jti": jti,
	}
}

// callToken posts a client_credentials request authenticated with the given assertion.
func callToken(t *testing.T, p *oidc.Provider, assertion string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {pkjClientID},
		"client_assertion_type": {pkjAssertion},
		"client_assertion":      {assertion},
	}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler(w, r)
	return w
}

// A client that signs with its registered key is authenticated, and the assertion works once only.
func TestPrivateKeyJWTAuthenticatesOnce(t *testing.T) {
	p, priv := pkjFixture(t)
	assertion := signAssertion(t, priv, pkjKID, goodClaims("jti-once"))

	if w := callToken(t, p, assertion); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "access_token") {
		t.Fatalf("valid assertion: want token, got %d: %s", w.Code, w.Body.String())
	}
	w := callToken(t, p, assertion)
	if w.Code == http.StatusOK {
		t.Fatalf("replayed assertion accepted: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "already been used") {
		t.Errorf("replayed assertion: want 'already been used', got %d %s", w.Code, w.Body.String())
	}
}

// The issuer is an accepted audience as well as the token endpoint URL.
func TestPrivateKeyJWTAcceptsIssuerAudience(t *testing.T) {
	p, priv := pkjFixture(t)
	claims := goodClaims("jti-aud")
	claims["aud"] = pkjIssuer
	if w := callToken(t, p, signAssertion(t, priv, pkjKID, claims)); w.Code != http.StatusOK {
		t.Errorf("issuer audience: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// Each claim and key check is enforced: a failure in any one refuses the client.
func TestPrivateKeyJWTRefusesBadAssertions(t *testing.T) {
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	cases := map[string]func(c map[string]any) (kid string, key ed25519.PrivateKey){
		"wrong key":   func(c map[string]any) (string, ed25519.PrivateKey) { return pkjKID, otherPriv },
		"unknown kid": func(c map[string]any) (string, ed25519.PrivateKey) { return "nope", nil },
		"wrong audience": func(c map[string]any) (string, ed25519.PrivateKey) {
			c["aud"] = "https://evil.example"
			return pkjKID, nil
		},
		"iss not client": func(c map[string]any) (string, ed25519.PrivateKey) { c["iss"] = "someone-else"; return pkjKID, nil },
		"sub not client": func(c map[string]any) (string, ed25519.PrivateKey) { c["sub"] = "someone-else"; return pkjKID, nil },
		"expired": func(c map[string]any) (string, ed25519.PrivateKey) {
			c["exp"] = time.Now().Add(-time.Minute).Unix()
			return pkjKID, nil
		},
		"lives too long": func(c map[string]any) (string, ed25519.PrivateKey) {
			c["exp"] = time.Now().Add(time.Hour).Unix()
			return pkjKID, nil
		},
		"no exp": func(c map[string]any) (string, ed25519.PrivateKey) { delete(c, "exp"); return pkjKID, nil },
		"no jti": func(c map[string]any) (string, ed25519.PrivateKey) { delete(c, "jti"); return pkjKID, nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, priv := pkjFixture(t)
			claims := goodClaims("jti-" + strings.ReplaceAll(name, " ", "-"))
			kid, key := mutate(claims)
			if key == nil {
				key = priv
			}
			if w := callToken(t, p, signAssertion(t, key, kid, claims)); w.Code == http.StatusOK {
				t.Errorf("want refusal, got 200: %s", w.Body.String())
			}
		})
	}
}

// A request with an assertion but no assertion type is refused.
func TestPrivateKeyJWTNeedsAssertionType(t *testing.T) {
	p, priv := pkjFixture(t)
	form := url.Values{
		"grant_type":       {"client_credentials"},
		"client_id":        {pkjClientID},
		"client_assertion": {signAssertion(t, priv, pkjKID, goodClaims("jti-type"))},
	}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler(w, r)
	if w.Code == http.StatusOK {
		t.Errorf("assertion without assertion type accepted: %s", w.Body.String())
	}
}

// Registration: private_key_jwt needs a valid Ed25519 key set, and issues no client secret.
func TestRegisterPrivateKeyJWTClient(t *testing.T) {
	st := storetest.New(t)
	_, platformPriv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(pkjIssuer, platformPriv, "key-1", st)

	pub, _, _ := ed25519.GenerateKey(nil)
	x := base64.RawURLEncoding.EncodeToString(pub)
	register := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/oidc/register", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		p.RegisterClientHandler(w, r)
		return w
	}

	bad := map[string]string{
		"no jwks":                      `{"client_name":"c","redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"private_key_jwt","grant_types":["client_credentials"]}`,
		"rsa key":                      `{"client_name":"c","redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"private_key_jwt","grant_types":["client_credentials"],"jwks":{"keys":[{"kty":"RSA","n":"x","e":"AQAB"}]}}`,
		"short x":                      `{"client_name":"c","redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"private_key_jwt","grant_types":["client_credentials"],"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}]}}`,
		"jwks without private_key_jwt": `{"client_name":"c","redirect_uris":["https://c.example/cb"],"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}]}}`,
	}
	for name, body := range bad {
		if w := register(body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, w.Code, w.Body.String())
		}
	}

	good := `{"client_name":"c","redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"private_key_jwt","grant_types":["client_credentials"],"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"a"}]}}`
	w := register(good)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid private_key_jwt registration: want 201, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "client_secret") {
		t.Errorf("private_key_jwt client was issued a secret: %s", w.Body.String())
	}
}
