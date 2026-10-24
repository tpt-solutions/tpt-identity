package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	crIssuer   = "https://issuer.example.com"
	crClient   = "rp-public"
	crRedirect = "https://rp.example/cb"
	crVerifier = "verifier-0123456789-abcdefghijklmnopqrstuvwxyzABCDEF"
	crSubject  = "did:peer:subject"
)

// newCodeProvider returns a provider with one registered public client.
func newCodeProvider(t *testing.T) *oidc.Provider {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SaveClient(context.Background(), &store.OIDCClient{
		ClientID:                crClient,
		ClientName:              "test rp",
		RedirectURIs:            []string{crRedirect},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		CreatedAt:               time.Now(),
	}); err != nil {
		t.Fatalf("save client: %v", err)
	}
	_, priv, _ := crypto.GenerateSigningKey()
	return oidc.NewProvider(crIssuer, priv, "key-1", st)
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func tokenPost(t *testing.T, p *oidc.Provider, form url.Values) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler(w, r)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

// issueCode performs the server side of /authorize and returns an authorization code.
func issueCode(t *testing.T, p *oidc.Provider) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	code, err := p.IssueSessionForDIDCtx(req, crSubject, crClient, crRedirect, "openid", "n-1",
		pkceChallenge(crVerifier), "S256", []string{"pwd"})
	if err != nil {
		t.Fatalf("issue code: %v", err)
	}
	return code
}

// An authorization code redeems once; the second redemption fails.
func TestAuthorizationCodeSingleUse(t *testing.T) {
	p := newCodeProvider(t)
	code := issueCode(t, p)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {crClient},
		"redirect_uri": {crRedirect}, "code_verifier": {crVerifier},
	}
	if status, _ := tokenPost(t, p, form); status != http.StatusOK {
		t.Fatalf("first redemption: want 200, got %d", status)
	}
	if status, _ := tokenPost(t, p, form); status == http.StatusOK {
		t.Error("authorization code redeemed twice")
	}
}

// Replaying a rotated refresh token must also end the newer token in its family.
func TestRefreshReplayRevokesFamily(t *testing.T) {
	p := newCodeProvider(t)
	_, first := tokenPost(t, p, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueCode(t, p)}, "client_id": {crClient},
		"redirect_uri": {crRedirect}, "code_verifier": {crVerifier},
	})
	rt1, _ := first["refresh_token"].(string)
	if rt1 == "" {
		t.Fatalf("no refresh token in code response: %v", first)
	}

	status, second := tokenPost(t, p, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}, "client_id": {crClient}})
	rt2, _ := second["refresh_token"].(string)
	if status != http.StatusOK || rt2 == "" {
		t.Fatalf("first refresh: want 200 with token, got %d", status)
	}

	// Replay the consumed token: refused, and the live successor must die with it.
	if status, _ := tokenPost(t, p, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}, "client_id": {crClient}}); status == http.StatusOK {
		t.Fatal("replayed refresh token accepted")
	}
	if status, _ := tokenPost(t, p, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt2}, "client_id": {crClient}}); status == http.StatusOK {
		t.Error("family not revoked: successor refresh token still accepted after replay")
	}
}
