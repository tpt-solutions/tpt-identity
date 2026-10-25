package api_test

import (
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"net/http"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const (
	testAdminKey   = "test-admin-key-5678"
	testWebhookKey = "test-webhook-key-9012"
)

// newScopedTestServer builds a server with a separate admin key and one webhook-only scoped key.
func newScopedTestServer(t *testing.T) *api.Server {
	t.Helper()
	st := storetest.New(t)

	_, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return api.NewServer(api.Config{
		APIKey:       testAPIKey,
		AdminAPIKey:  testAdminKey,
		ScopedKeys:   []api.ScopedKey{{Name: "hooks", Key: testWebhookKey, Scopes: []string{"webhooks"}}},
		Issuer:       testIssuer,
		SigningKey:   priv,
		SigningKeyID: testPlatformDID + "#signing-key-1", // the issuing key must belong to the platform DID
		Store:        st,
		Resolver:     resolver.New(5 * time.Minute),
		OIDC:         oidc.NewProvider(testIssuer, priv, "test-key-1", st),
	})
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// A dedicated admin key replaces the master key on admin endpoints.
func TestAdminKeyRequiredForAdminRoutes(t *testing.T) {
	srv := newScopedTestServer(t)

	if w := do(t, srv, http.MethodGet, "/admin/v1/stats", "", bearer(testAPIKey)); w.Code != http.StatusUnauthorized {
		t.Errorf("master key on admin route: want 401, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/admin/v1/stats", "", bearer(testAdminKey)); w.Code == http.StatusUnauthorized {
		t.Errorf("admin key on admin route: want authorised, got 401")
	}
}

// The master key keeps working on non-admin routes, and scoped keys reach only their scopes.
func TestScopedKeys(t *testing.T) {
	srv := newScopedTestServer(t)

	if w := do(t, srv, http.MethodGet, "/api/v1/webhooks", "", bearer(testWebhookKey)); w.Code == http.StatusUnauthorized {
		t.Errorf("webhook key on webhook route: want authorised, got 401")
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/credentials", "", bearer(testWebhookKey)); w.Code != http.StatusUnauthorized {
		t.Errorf("webhook key on credentials route: want 401, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/credentials", "", bearer(testAPIKey)); w.Code == http.StatusUnauthorized {
		t.Errorf("master key on credentials route: want authorised, got 401")
	}
}

// Scoped keys never reach admin, and unknown or empty tokens are rejected.
func TestScopedKeysCannotReachAdminOrUnknownTokens(t *testing.T) {
	srv := newScopedTestServer(t)

	if w := do(t, srv, http.MethodGet, "/admin/v1/stats", "", bearer(testWebhookKey)); w.Code != http.StatusUnauthorized {
		t.Errorf("scoped key on admin route: want 401, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/webhooks", "", bearer("guess")); w.Code != http.StatusUnauthorized {
		t.Errorf("unknown token: want 401, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/webhooks", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: want 401, got %d", w.Code)
	}
}

// A scoped key with an empty key string must never match an empty bearer.
func TestEmptyScopedKeyDoesNotMatchEmptyBearer(t *testing.T) {
	st := storetest.New(t)
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		ScopedKeys: []api.ScopedKey{{Name: "blank", Key: "", Scopes: []string{"*"}}},
		Issuer:     testIssuer,
		SigningKey: priv,
		Store:      st,
		Resolver:   resolver.New(5 * time.Minute),
		OIDC:       oidc.NewProvider(testIssuer, priv, "test-key-1", st),
	})
	if w := do(t, srv, http.MethodGet, "/api/v1/webhooks", "", bearer("")); w.Code != http.StatusUnauthorized {
		t.Errorf("empty bearer with blank scoped key: want 401, got %d", w.Code)
	}
}
