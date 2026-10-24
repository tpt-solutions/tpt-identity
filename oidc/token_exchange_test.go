package oidc_test

import (
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

const teIssuer = "https://issuer.example.com"

func postTokenExchange(t *testing.T, p *oidc.Provider, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler(w, r)
	return w
}

func exchangeForm(subject string) url.Values {
	return url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
}

// Token exchange with no client authentication must be refused, even with a valid token.
func TestTokenExchangeRequiresClientAuth(t *testing.T) {
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, priv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(teIssuer, priv, "key-1", st)
	tok, _ := oidc.IssueAccessToken(teIssuer, "did:peer:sub", "client-1", time.Hour, priv, "key-1")

	w := postTokenExchange(t, p, exchangeForm(tok))
	if w.Code == http.StatusOK {
		t.Fatalf("anonymous token exchange succeeded: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_client") {
		t.Errorf("want invalid_client, got %d: %s", w.Code, w.Body.String())
	}
}

// An ID token must not be accepted as the subject token of an exchange.
func TestTokenExchangeRejectsIDTokenSubject(t *testing.T) {
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, priv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(teIssuer, priv, "key-1", st)
	idTok, _ := oidc.IssueIDToken(teIssuer, "did:peer:sub", "client-1", "n", time.Hour, priv, nil, "key-1")

	form := exchangeForm(idTok)
	form.Set("client_id", "client-1")
	w := postTokenExchange(t, p, form)
	if w.Code == http.StatusOK {
		t.Fatalf("ID token accepted as subject_token: %s", w.Body.String())
	}
}
