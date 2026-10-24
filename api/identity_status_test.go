package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/PhillipC05/tpt-identity/api"
	"github.com/PhillipC05/tpt-identity/internal/resolver"
	"github.com/PhillipC05/tpt-identity/internal/store"
	"github.com/PhillipC05/tpt-identity/oidc"
	"github.com/PhillipC05/tpt-identity/pkg/crypto"
)

// Suspending an identity must stop its unexpired tokens from working at once.
func TestSuspendedIdentityLosesAccess(t *testing.T) {
	const did = "did:peer:suspend-me"
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now()
	if err := st.SaveIdentity(context.Background(), &store.Identity{
		DID: did, Method: "peer", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		APIKey:     testAPIKey,
		Issuer:     testIssuer,
		SigningKey: priv,
		Store:      st,
		OIDC:       oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:   resolver.New(time.Minute),
	})
	tok, err := oidc.IssueAccessToken(testIssuer, did, "client-1", time.Hour, priv, "test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	bearer := map[string]string{"Authorization": "Bearer " + tok}

	if w := do(t, srv, http.MethodGet, "/api/v1/me/sessions", "", bearer); w.Code != http.StatusOK {
		t.Fatalf("before suspension: want 200, got %d", w.Code)
	}
	if w := authed(t, srv, http.MethodPost, "/admin/v1/identities/"+did+"/suspend", ""); w.Code != http.StatusOK {
		t.Fatalf("suspend: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/me/sessions", "", bearer); w.Code != http.StatusUnauthorized {
		t.Errorf("after suspension: want 401, got %d", w.Code)
	}
}
