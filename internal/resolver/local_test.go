package resolver

import (
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// A hosted DID answers from the local lookup, and the answer is not cached: a change to the hosted
// document shows on the next resolution.
func TestLocalLookupIsNotCached(t *testing.T) {
	r := New(time.Hour)
	const id = "did:example:hosted"
	version := "v1"
	r.SetLocal(func(got string) (*did.Document, bool) {
		if got != id {
			return nil, false
		}
		return &did.Document{ID: id, Controller: version}, true
	})

	first, err := r.Resolve(id)
	if err != nil || first.Controller != "v1" {
		t.Fatalf("first resolve: %v %+v", err, first)
	}
	version = "v2"
	second, err := r.Resolve(id)
	if err != nil || second.Controller != "v2" {
		t.Errorf("hosted document served stale: %+v (%v)", second, err)
	}
}

// Pinned documents take precedence over the local lookup.
func TestPinnedBeatsLocalLookup(t *testing.T) {
	r := New(time.Hour)
	const id = "did:example:pinned"
	r.Pin(id, &did.Document{ID: id, Controller: "pinned"})
	r.SetLocal(func(string) (*did.Document, bool) { return &did.Document{ID: id, Controller: "local"}, true })

	doc, err := r.Resolve(id)
	if err != nil || doc.Controller != "pinned" {
		t.Errorf("pinned document overridden: %+v (%v)", doc, err)
	}
}
