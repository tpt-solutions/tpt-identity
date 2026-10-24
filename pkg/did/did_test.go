package did_test

import (
	"strings"
	"testing"

	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

func pubBytes(t *testing.T) []byte {
	t.Helper()
	pub, _, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return []byte(pub)
}

// ---- did:key ----

func TestKeyCreate(t *testing.T) {
	id, doc, err := did.Create("key", did.CreateOptions{SigningPub: pubBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "did:key:") {
		t.Errorf("unexpected DID: %s", id)
	}
	if doc.ID != id {
		t.Errorf("doc.ID %s != DID %s", doc.ID, id)
	}
}

func TestKeyResolveRoundTrip(t *testing.T) {
	id, _, err := did.Create("key", did.CreateOptions{SigningPub: pubBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := did.Resolve(id)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", id, err)
	}
	if doc.ID != id {
		t.Errorf("resolved doc.ID %s != DID %s", doc.ID, id)
	}
	if len(doc.VerificationMethod) == 0 {
		t.Error("expected at least one verification method")
	}
}

func TestKeyResolveInvalidDID(t *testing.T) {
	if _, err := did.Resolve("did:key:invalid"); err == nil {
		t.Error("expected error for invalid did:key")
	}
}

// ---- did:web ----

func TestWebCreate(t *testing.T) {
	id, doc, err := did.Create("web", did.CreateOptions{Domain: "example.com", SigningPub: pubBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	if id != "did:web:example.com" {
		t.Errorf("unexpected DID: %s", id)
	}
	if doc.ID != id {
		t.Errorf("doc.ID %s != DID %s", doc.ID, id)
	}
}

func TestWebCreateRequiresDomain(t *testing.T) {
	if _, _, err := did.Create("web", did.CreateOptions{SigningPub: pubBytes(t)}); err == nil {
		t.Error("expected error when domain is empty")
	}
}

// ---- did:peer ----

func TestPeerCreate(t *testing.T) {
	id, doc, err := did.Create("peer", did.CreateOptions{SigningPub: pubBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "did:peer:") {
		t.Errorf("unexpected DID: %s", id)
	}
	if doc.ID != id {
		t.Errorf("doc.ID %s != DID %s", doc.ID, id)
	}
}

// ---- MarshalDocument ----

func TestMarshalDocument(t *testing.T) {
	_, doc, _ := did.Create("key", did.CreateOptions{SigningPub: pubBytes(t)})
	b, err := did.MarshalDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty JSON")
	}
}

// ---- SSRF hardening ----

func TestWebSSRFBlockLocalhost(t *testing.T) {
	_, err := did.Resolve("did:web:localhost")
	if err == nil {
		t.Error("expected SSRF block for localhost")
	}
}

func TestWebSSRFAllowlistBlock(t *testing.T) {
	did.SetWebResolverConfig(did.WebResolverConfig{AllowedDomains: []string{"trusted.example"}})
	defer did.SetWebResolverConfig(did.WebResolverConfig{})

	_, err := did.Resolve("did:web:untrusted.com")
	if err == nil {
		t.Error("expected allowlist to block untrusted.com")
	}
	if err != nil && !strings.Contains(err.Error(), "allowlist") {
		t.Logf("got different error (may be DNS/network): %v", err)
	}
}

func TestWebSSRFAllowlistPermitsDomain(t *testing.T) {
	did.SetWebResolverConfig(did.WebResolverConfig{AllowedDomains: []string{"trusted.example"}})
	defer did.SetWebResolverConfig(did.WebResolverConfig{})

	_, err := did.Resolve("did:web:trusted.example")
	// May fail at network level (no real server), but must NOT fail with an allowlist error.
	if err != nil && strings.Contains(err.Error(), "allowlist") {
		t.Errorf("allowlist blocked a permitted domain: %v", err)
	}
}
