package oidc_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const rotIssuer = "https://issuer.example.com"

// rotationFixture stores an active subject and returns the store, the old and new keys, and a
// provider that has rotated from the old key to the new one.
func rotationFixture(t *testing.T) (st store.Store, oldPub ed25519.PublicKey, oldPriv ed25519.PrivateKey, newPriv ed25519.PrivateKey) {
	t.Helper()
	st2, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	saveTestIdentity(t, st2, "did:peer:user")
	oldPub, oldPriv, _ = crypto.GenerateSigningKey()
	_, newPriv, _ = crypto.GenerateSigningKey()
	return st2, oldPub, oldPriv, newPriv
}

// A token signed before a rotation keeps verifying while the old key is configured as retired, and
// stops verifying once it is removed.
func TestRetiredKeyVerifiesOldTokens(t *testing.T) {
	st, oldPub, oldPriv, newPriv := rotationFixture(t)
	oldToken, err := oidc.IssueAccessToken(rotIssuer, "did:peer:user", "rp", time.Hour, oldPriv, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	rotated := oidc.NewProvider(rotIssuer, newPriv, "key-2", st)
	if err := rotated.AddPreviousKey("key-1", oldPub); err != nil {
		t.Fatalf("add retired key: %v", err)
	}
	if _, err := rotated.VerifyAccessToken(context.Background(), oldToken); err != nil {
		t.Fatalf("token from the retired key rejected: %v", err)
	}

	withoutRetired := oidc.NewProvider(rotIssuer, newPriv, "key-2", st)
	if _, err := withoutRetired.VerifyAccessToken(context.Background(), oldToken); err == nil {
		t.Error("token from a key no longer configured was accepted")
	}
}

// Tokens from the new key verify, and a token that names the retired kid but is signed by another key
// is refused: the kid selects which key to check, and never replaces the signature check.
func TestKidSelectsKeyAndCannotBeSpoofed(t *testing.T) {
	st, oldPub, oldPriv, newPriv := rotationFixture(t)
	rotated := oidc.NewProvider(rotIssuer, newPriv, "key-2", st)
	if err := rotated.AddPreviousKey("key-1", oldPub); err != nil {
		t.Fatal(err)
	}

	newToken, _ := oidc.IssueAccessToken(rotIssuer, "did:peer:user", "rp", time.Hour, newPriv, "key-2")
	if _, err := rotated.VerifyAccessToken(context.Background(), newToken); err != nil {
		t.Errorf("token from the current key rejected: %v", err)
	}

	// Signed by the old key, but its header claims the new key's kid.
	spoofed, _ := oidc.IssueAccessToken(rotIssuer, "did:peer:user", "rp", time.Hour, oldPriv, "key-2")
	if _, err := rotated.VerifyAccessToken(context.Background(), spoofed); err == nil {
		t.Error("token with a spoofed kid was accepted")
	}

	unknown, _ := oidc.IssueAccessToken(rotIssuer, "did:peer:user", "rp", time.Hour, oldPriv, "key-9")
	if _, err := rotated.VerifyAccessToken(context.Background(), unknown); err == nil {
		t.Error("token with an unknown kid was accepted")
	}
}

// The JWKS publishes the current key and the retired key.
func TestJWKSPublishesRetiredKey(t *testing.T) {
	st, oldPub, _, newPriv := rotationFixture(t)
	p := oidc.NewProvider(rotIssuer, newPriv, "key-2", st)
	if err := p.AddPreviousKey("key-1", oldPub); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	p.JWKSHandler(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	kids := map[string]bool{}
	for _, k := range set.Keys {
		kids[k.Kid] = true
	}
	if !kids["key-2"] || !kids["key-1"] || len(set.Keys) != 2 {
		t.Errorf("JWKS kids = %v, want key-2 and key-1", kids)
	}
}

// A retired key needs its own kid, a 32-byte key, and a kid different from the current key's.
func TestAddPreviousKeyValidates(t *testing.T) {
	st, oldPub, _, newPriv := rotationFixture(t)
	p := oidc.NewProvider(rotIssuer, newPriv, "key-2", st)
	if err := p.AddPreviousKey("", oldPub); err == nil {
		t.Error("retired key without a kid accepted")
	}
	if err := p.AddPreviousKey("key-1", oldPub[:10]); err == nil {
		t.Error("short retired key accepted")
	}
	if err := p.AddPreviousKey("key-2", oldPub); err == nil {
		t.Error("retired key with the current kid accepted")
	}
	if err := p.AddPreviousKey("key-1", oldPub); err != nil {
		t.Errorf("valid retired key refused: %v", err)
	}
}
