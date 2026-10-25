package resolver

import (
	"fmt"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

func TestEvictLockedKeepsCacheBounded(t *testing.T) {
	r := New(time.Hour)
	r.Pin("did:web:pinned.example", &did.Document{ID: "did:web:pinned.example"})
	for i := 0; i < maxEntries-1; i++ {
		r.cache[fmt.Sprintf("did:web:h%d.example", i)] = entry{doc: &did.Document{}, expires: time.Now().Add(time.Hour)}
	}
	if len(r.cache) != maxEntries {
		t.Fatalf("setup: cache has %d entries, want %d", len(r.cache), maxEntries)
	}

	r.mu.Lock()
	r.evictLocked()
	r.mu.Unlock()

	if len(r.cache) != maxEntries-1 {
		t.Fatalf("after evict: %d entries, want %d", len(r.cache), maxEntries-1)
	}
	if e, ok := r.cache["did:web:pinned.example"]; !ok || !e.pinned {
		t.Fatal("pinned entry was evicted")
	}
}

func TestEvictLockedDropsExpiredFirst(t *testing.T) {
	r := New(time.Hour)
	for i := 0; i < maxEntries; i++ {
		r.cache[fmt.Sprintf("did:web:h%d.example", i)] = entry{doc: &did.Document{}, expires: time.Now().Add(time.Hour)}
	}
	r.cache["did:web:stale.example"] = entry{doc: &did.Document{}, expires: time.Now().Add(-time.Second)}

	r.mu.Lock()
	r.evictLocked()
	r.mu.Unlock()

	if _, ok := r.cache["did:web:stale.example"]; ok {
		t.Fatal("expired entry survived eviction")
	}
	// The stale entry is dropped, then one live entry makes room for the insert that follows.
	if len(r.cache) != maxEntries-1 {
		t.Fatalf("after evict: %d entries, want %d", len(r.cache), maxEntries-1)
	}
}
