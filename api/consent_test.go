package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
)

// consentServer returns a server and bearer tokens for two subjects.
func consentServer(t *testing.T) (*api.Server, string, string) {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now()
	for _, did := range []string{"did:peer:alice", "did:peer:bob"} {
		if err := st.SaveIdentity(context.Background(), &store.Identity{DID: did, Method: "peer", Role: "user", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("save identity: %v", err)
		}
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
	alice, _ := oidc.IssueAccessToken(testIssuer, "did:peer:alice", "client-1", time.Hour, priv, "test-key-1")
	bob, _ := oidc.IssueAccessToken(testIssuer, "did:peer:bob", "client-1", time.Hour, priv, "test-key-1")
	return srv, alice, bob
}

func grantBody(scope string, confirmed bool) string {
	b, _ := json.Marshal(map[string]any{
		"relyingDid": "did:web:rp.example", "level": "schema", "scopeId": scope, "explicitlyConfirmed": confirmed,
	})
	return string(b)
}

// Extra-sensitive schemas need an explicit confirmation; unknown scopes are refused outright.
func TestGrantRefusesUnsafeScopes(t *testing.T) {
	srv, alice, _ := consentServer(t)
	hdr := map[string]string{"Authorization": "Bearer " + alice, "Content-Type": "application/json"}
	if w := do(t, srv, http.MethodPost, "/api/v1/consents/grants", grantBody("healthcare.mental-health", false), hdr); w.Code != http.StatusBadRequest {
		t.Errorf("extra-sensitive without confirmation: want 400, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodPost, "/api/v1/consents/grants", grantBody("no.such-schema", true), hdr); w.Code != http.StatusBadRequest {
		t.Errorf("unknown scope: want 400, got %d", w.Code)
	}
}

// A grant takes its subject from the token, and only its owner can revoke it. Revocation
// keeps the row, marked revoked.
func TestGrantOwnershipAndSoftRevoke(t *testing.T) {
	srv, alice, bob := consentServer(t)
	hdr := map[string]string{"Authorization": "Bearer " + alice, "Content-Type": "application/json"}
	w := do(t, srv, http.MethodPost, "/api/v1/consents/grants", grantBody("identity.legal-name", false), hdr)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var g struct {
		ID         string `json:"id"`
		SubjectDID string `json:"subjectDid"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &g)
	if g.SubjectDID != "did:peer:alice" || !strings.HasPrefix(g.ID, "grant_") {
		t.Fatalf("grant subject/id not server-assigned: %+v", g)
	}

	bobHdr := map[string]string{"Authorization": "Bearer " + bob}
	if w := do(t, srv, http.MethodDelete, "/api/v1/consents/grants/"+g.ID, "", bobHdr); w.Code != http.StatusNotFound {
		t.Errorf("another subject revoking the grant: want 404, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodDelete, "/api/v1/consents/grants/"+g.ID, "", hdr); w.Code != http.StatusNoContent {
		t.Fatalf("owner revoke: want 204, got %d", w.Code)
	}
	list := do(t, srv, http.MethodGet, "/api/v1/consents/grants", "", hdr)
	if !strings.Contains(list.Body.String(), `"revokedAt"`) {
		t.Errorf("revoked grant not kept with revokedAt: %s", list.Body.String())
	}
}
