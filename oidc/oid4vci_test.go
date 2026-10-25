package oidc_test

import (
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

// An ordinary user access token (no credential scope) must not mint credentials.
func TestCredentialEndpointRejectsUserToken(t *testing.T) {
	st := storetest.New(t)

	_, priv, _ := crypto.GenerateSigningKey()
	saveTestIdentity(t, st, "did:peer:user")
	p := oidc.NewProvider("https://issuer.example.com", priv, "key-1", st)
	token, err := oidc.IssueAccessToken("https://issuer.example.com", "did:peer:user", "client-1", time.Hour, priv, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	h := p.CredentialHandler(priv, "key-1", st)
	r := httptest.NewRequest(http.MethodPost, "/oid4vci/credential",
		strings.NewReader(`{"vct":"identity.legal-name"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code == http.StatusOK {
		t.Fatalf("user token minted a credential: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "insufficient_scope") {
		t.Errorf("want insufficient_scope, got %d: %s", w.Code, w.Body.String())
	}
}
