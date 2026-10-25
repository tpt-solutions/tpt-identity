package did_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

func newKeyPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// A rotated document keeps the retired key resolvable, but only the current key is an assertion method.
func TestWebDocumentKeepsRetiredKeyNonAsserting(t *testing.T) {
	current, old := newKeyPub(t), newKeyPub(t)
	const domain = "id.example"
	const currentID = "did:web:id.example#signing-key-2"
	const oldID = "did:web:id.example#signing-key-1"

	_, doc, err := did.Create("web", did.CreateOptions{
		Domain:       domain,
		SigningPub:   current,
		SigningKeyID: currentID,
		RetiredKeys:  []did.RetiredKey{{ID: oldID, Pub: old}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	ids := map[string]bool{}
	for _, vm := range doc.VerificationMethod {
		ids[vm.ID] = true
	}
	if !ids[currentID] || !ids[oldID] {
		t.Fatalf("verification methods: want both keys, got %v", ids)
	}
	if len(doc.AssertionMethod) != 1 || doc.AssertionMethod[0] != currentID {
		t.Errorf("assertionMethod: want only %s, got %v", currentID, doc.AssertionMethod)
	}
	if len(doc.Authentication) != 1 || doc.Authentication[0] != currentID {
		t.Errorf("authentication: want only %s, got %v", currentID, doc.Authentication)
	}
}

func TestWebDocumentDefaultKeyIDUnchanged(t *testing.T) {
	_, doc, err := did.Create("web", did.CreateOptions{Domain: "id.example", SigningPub: newKeyPub(t)})
	if err != nil {
		t.Fatal(err)
	}
	if doc.AssertionMethod[0] != "did:web:id.example#signing-key-1" {
		t.Errorf("default key ID: got %s", doc.AssertionMethod[0])
	}
}

func TestWebDocumentRejectsBadRetiredKeys(t *testing.T) {
	current := newKeyPub(t)
	cases := map[string][]did.RetiredKey{
		"same id as current": {{ID: "did:web:id.example#signing-key-1", Pub: newKeyPub(t)}},
		"no id":              {{Pub: newKeyPub(t)}},
		"short key":          {{ID: "did:web:id.example#old", Pub: ed25519.PublicKey{1, 2, 3}}},
	}
	for name, retired := range cases {
		_, _, err := did.Create("web", did.CreateOptions{
			Domain: "id.example", SigningPub: current, RetiredKeys: retired,
		})
		if err == nil || !strings.Contains(err.Error(), "retired key") {
			t.Errorf("%s: want retired-key error, got %v", name, err)
		}
	}
}
