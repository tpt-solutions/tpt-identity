package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"net/http"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

// Suspending an identity must stop its unexpired tokens from working at once.
func TestSuspendedIdentityLosesAccess(t *testing.T) {
	const did = "did:peer:suspend-me"
	st := storetest.New(t)
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

// Creating an identity returns its private keys once and stores the identity with its document.
func TestCreateIdentityReturnsKeysAndStores(t *testing.T) {
	srv := newTestServer(t)
	w := authed(t, srv, http.MethodPost, "/api/v1/identities", `{"method":"peer"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		DID  string `json:"did"`
		Keys struct {
			Ed25519Seed   string `json:"ed25519_seed"`
			X25519Private string `json:"x25519_private"`
		} `json:"private_keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for name, v := range map[string]string{"ed25519": out.Keys.Ed25519Seed, "x25519": out.Keys.X25519Private} {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(b) != 32 {
			t.Errorf("%s key: want 32 bytes, got %d (%v)", name, len(b), err)
		}
	}
	if w := authed(t, srv, http.MethodGet, "/api/v1/identities/"+out.DID, ""); w.Code != http.StatusOK {
		t.Errorf("created identity not resolvable: %d", w.Code)
	}
}
