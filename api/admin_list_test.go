package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

// The admin role filter must apply before pagination: a page of matches must not come back short,
// and X-Total-Count must count matches, not the whole table.
func TestAdminRoleFilterAppliesBeforePagination(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now()
	// Interleave roles so the matches are not all on the first page of the raw table.
	for i := 0; i < 12; i++ {
		role := "user"
		if i%3 == 0 {
			role = "suspended"
		}
		if err := st.SaveIdentity(ctx, &store.Identity{
			DID: fmt.Sprintf("did:peer:id-%02d", i), Method: "peer", Role: role,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("save identity %d: %v", i, err)
		}
	}

	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		APIKey:      testAPIKey,
		AdminAPIKey: testAdminKey,
		Issuer:      testIssuer,
		SigningKey:  priv,
		Store:       st,
		Resolver:    resolver.New(time.Minute),
		OIDC:        oidc.NewProvider(testIssuer, priv, "test-key-1", st),
	})

	// 4 suspended identities (ids 0, 3, 6, 9). Page 2 of size 3 must hold the 4th one.
	w := do(t, srv, http.MethodGet, "/admin/v1/identities?role=suspended&limit=3&offset=3", "", bearer(testAdminKey))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Total-Count"); got != "4" {
		t.Errorf("X-Total-Count = %q, want 4 matches", got)
	}
	var page []store.Identity
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page) != 1 || page[0].Role != "suspended" {
		t.Errorf("want one suspended identity on page 2, got %+v", page)
	}
}
