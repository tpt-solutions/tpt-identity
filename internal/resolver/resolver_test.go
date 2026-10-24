package resolver_test

import (
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// A pinned document resolves with no network and survives both expiry and Purge.
func TestPinnedDocumentNeverExpires(t *testing.T) {
	r := resolver.New(time.Millisecond)
	doc := &did.Document{ID: "did:web:pinned.example.invalid"}
	r.Pin(doc.ID, doc)

	time.Sleep(5 * time.Millisecond)
	r.Purge()

	got, err := r.Resolve(doc.ID)
	if err != nil {
		t.Fatalf("pinned document not served: %v", err)
	}
	if got != doc {
		t.Error("resolver returned a different document than the pinned one")
	}
}
