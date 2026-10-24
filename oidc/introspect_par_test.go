package oidc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const (
	introIssuer = "https://issuer.example.com"
	introRP     = "rp-confidential"
	introSecret = "rp-secret-value"
	parRedirect = "https://rp.example.com/cb"
)

// introSetup stores a confidential client (rp-confidential), a public client (public-rp) and a
// second public client (other-rp), then returns a provider and its signing key.
func introSetup(t *testing.T) (*oidc.Provider, ed25519.PrivateKey, store.Store) {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	secretHash := sha256.Sum256([]byte(introSecret))
	clients := []*store.OIDCClient{
		{ClientID: introRP, ClientName: "confidential", ClientSecretHash: hex.EncodeToString(secretHash[:]),
			TokenEndpointAuthMethod: "client_secret_basic", RedirectURIs: []string{parRedirect},
			GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, CreatedAt: time.Now()},
		{ClientID: "public-rp", ClientName: "public", TokenEndpointAuthMethod: "none",
			RedirectURIs: []string{parRedirect}, GrantTypes: []string{"authorization_code"},
			ResponseTypes: []string{"code"}, CreatedAt: time.Now()},
		{ClientID: "other-rp", ClientName: "other", TokenEndpointAuthMethod: "none",
			RedirectURIs: []string{parRedirect}, GrantTypes: []string{"authorization_code"},
			ResponseTypes: []string{"code"}, CreatedAt: time.Now()},
	}
	for _, c := range clients {
		if err := st.SaveClient(context.Background(), c); err != nil {
			t.Fatalf("save client %s: %v", c.ClientID, err)
		}
	}
	_, priv, _ := crypto.GenerateSigningKey()
	return oidc.NewProvider(introIssuer, priv, "key-1", st), priv, st
}

func introspect(t *testing.T, p *oidc.Provider, form url.Values, basicUser, basicPass string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		r.SetBasicAuth(basicUser, basicPass)
	}
	w := httptest.NewRecorder()
	p.IntrospectHandler(w, r)
	return w
}

// Introspection without client authentication is refused, even for a valid token.
func TestIntrospectRequiresClientAuth(t *testing.T) {
	p, priv, _ := introSetup(t)
	token, err := oidc.IssueAccessToken(introIssuer, "did:peer:user", "public-rp", time.Hour, priv, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	w := introspect(t, p, url.Values{"token": {token}}, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no client auth: want 401, got %d: %s", w.Code, w.Body.String())
	}
}

// A public client has no secret, so it cannot introspect.
func TestIntrospectRefusesPublicClient(t *testing.T) {
	p, priv, _ := introSetup(t)
	token, _ := oidc.IssueAccessToken(introIssuer, "did:peer:user", "public-rp", time.Hour, priv, "key-1")
	w := introspect(t, p, url.Values{"token": {token}, "client_id": {"public-rp"}}, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("public client: want 401, got %d: %s", w.Code, w.Body.String())
	}
}

// A confidential client with the right secret gets token metadata; a wrong secret does not.
func TestIntrospectWithConfidentialClient(t *testing.T) {
	p, priv, _ := introSetup(t)
	token, _ := oidc.IssueAccessToken(introIssuer, "did:peer:user", "public-rp", time.Hour, priv, "key-1")

	w := introspect(t, p, url.Values{"token": {token}}, introRP, introSecret)
	if w.Code != http.StatusOK {
		t.Fatalf("valid client: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Active bool   `json:"active"`
		Sub    string `json:"sub"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Active || resp.Sub != "did:peer:user" {
		t.Errorf("want active token for did:peer:user, got %+v", resp)
	}

	if w := introspect(t, p, url.Values{"token": {token}}, introRP, "wrong"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong secret: want 401, got %d", w.Code)
	}
}

// A request pushed by one client cannot be redeemed by another client.
func TestPARRequestBoundToPushingClient(t *testing.T) {
	p, _, _ := introSetup(t)

	push := url.Values{
		"client_id":             {"public-rp"},
		"redirect_uri":          {parRedirect},
		"response_type":         {"code"},
		"state":                 {"s1"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	r := httptest.NewRequest(http.MethodPost, "/oidc/par", strings.NewReader(push.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.PARHandler(w, r)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("PAR push: %d %s", w.Code, w.Body.String())
	}
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pushed); err != nil || pushed.RequestURI == "" {
		t.Fatalf("no request_uri in %s", w.Body.String())
	}

	// Another client presents the same request_uri.
	authz := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id=other-rp&request_uri="+url.QueryEscape(pushed.RequestURI), nil)
	aw := httptest.NewRecorder()
	p.AuthorizeHandler(aw, authz)
	if aw.Code == http.StatusFound || !strings.Contains(aw.Body.String(), "client_id does not match") {
		t.Fatalf("other client redeemed the PAR request: %d %s", aw.Code, aw.Body.String())
	}
}
