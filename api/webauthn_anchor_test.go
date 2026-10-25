package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// anchorTestServer is a server whose store holds one did:key identity, as the bridge or the
// identity API would create it.
func anchorTestServer(t *testing.T) (*Server, store.Store, string) {
	t.Helper()
	st := storetest.New(t)
	_, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{
		APIKey:       "anchor-test-api-key-0123456789",
		Issuer:       "https://anchor.example",
		SigningKey:   priv,
		SigningKeyID: "did:web:anchor.example#signing-key-1",
		Store:        st,
		Resolver:     resolver.New(time.Minute),
		OIDC:         oidc.NewProvider("https://anchor.example", priv, "k1", st),
	})

	// A did:key subject with a stored document, as the identity API stores one.
	_, doc, err := did.Create("key", did.CreateOptions{SigningPub: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	id := doc.ID
	now := time.Now()
	if err := st.CreateIdentityWithDocument(context.Background(), &store.Identity{DID: id, Method: "key", CreatedAt: now, UpdatedAt: now}, doc); err != nil {
		t.Fatal(err)
	}
	return srv, st, id
}

func getDoc(t *testing.T, srv *Server, id string) did.Document {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/identities/"+id, nil)
	r.Header.Set("Authorization", "Bearer anchor-test-api-key-0123456789")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("resolve %s: %d %s", id, w.Code, w.Body.String())
	}
	var doc did.Document
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func hasVM(doc did.Document, vmID string) bool {
	for _, vm := range doc.VerificationMethod {
		if vm.ID == vmID {
			return true
		}
	}
	return false
}

// A passkey anchored after the identity was created appears in the identity's resolved document.
func TestAnchoredPasskeyVisibleInResolution(t *testing.T) {
	srv, st, id := anchorTestServer(t)
	credID := "abcdefghijklmnop"
	vmID := webAuthnVMID(id, credID)

	anchorWebAuthnKey(context.Background(), st, id, credID, []byte{1, 2, 3})

	doc := getDoc(t, srv, id)
	if !hasVM(doc, vmID) {
		t.Fatalf("anchored passkey %s not in resolved document", vmID)
	}
	found := false
	for _, ref := range doc.Authentication {
		if ref == vmID {
			found = true
		}
	}
	if !found {
		t.Error("anchored passkey not listed for authentication")
	}
}

// Deleting the passkey removes its key from the document; the other keys stay.
func TestUnanchorRemovesOnlyThatPasskey(t *testing.T) {
	srv, st, id := anchorTestServer(t)
	ctx := context.Background()
	credA, credB := "aaaaaaaa-one", "bbbbbbbb-two"
	anchorWebAuthnKey(ctx, st, id, credA, []byte{1})
	anchorWebAuthnKey(ctx, st, id, credB, []byte{2})
	before := len(getDoc(t, srv, id).VerificationMethod)

	unanchorWebAuthnKey(ctx, st, id, credA)

	doc := getDoc(t, srv, id)
	if hasVM(doc, webAuthnVMID(id, credA)) {
		t.Error("deleted passkey still published")
	}
	if !hasVM(doc, webAuthnVMID(id, credB)) {
		t.Error("other passkey was removed")
	}
	if len(doc.VerificationMethod) != before-1 {
		t.Errorf("want %d methods after unanchor, got %d", before-1, len(doc.VerificationMethod))
	}
	for _, ref := range doc.Authentication {
		if strings.HasSuffix(ref, "#webauthn-"+credA[:8]) {
			t.Error("deleted passkey still listed for authentication")
		}
	}
}

// Anchoring the same passkey twice publishes it once.
func TestAnchorIsIdempotent(t *testing.T) {
	srv, st, id := anchorTestServer(t)
	ctx := context.Background()
	anchorWebAuthnKey(ctx, st, id, "cccccccc-x", []byte{3})
	anchorWebAuthnKey(ctx, st, id, "cccccccc-x", []byte{3})

	count := 0
	for _, vm := range getDoc(t, srv, id).VerificationMethod {
		if vm.ID == webAuthnVMID(id, "cccccccc-x") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("passkey published %d times", count)
	}
}
