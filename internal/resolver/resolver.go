package resolver

import (
	"fmt"
	"sync"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

const defaultTTL = 5 * time.Minute

type entry struct {
	doc     *did.Document
	expires time.Time
	// pinned entries are documents this server owns. They never expire and are never purged.
	pinned bool
}

// Resolver caches DID document lookups with a configurable TTL.
type Resolver struct {
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[string]entry
}

// New returns a Resolver with the given cache TTL.
func New(ttl time.Duration) *Resolver {
	if ttl == 0 {
		ttl = defaultTTL
	}
	return &Resolver{ttl: ttl, cache: map[string]entry{}}
}

// Resolve returns the DID Document for id, using a cached result if still valid.
func (r *Resolver) Resolve(id string) (*did.Document, error) {
	r.mu.RLock()
	e, ok := r.cache[id]
	r.mu.RUnlock()
	if ok && (e.pinned || time.Now().Before(e.expires)) {
		return e.doc, nil
	}

	doc, err := did.Resolve(id)
	if err != nil {
		return nil, fmt.Errorf("resolver: %w", err)
	}

	r.mu.Lock()
	r.cache[id] = entry{doc: doc, expires: time.Now().Add(r.ttl)}
	r.mu.Unlock()
	return doc, nil
}

// Invalidate removes a DID from the cache, forcing a fresh fetch on next access.
func (r *Resolver) Invalidate(id string) {
	r.mu.Lock()
	delete(r.cache, id)
	r.mu.Unlock()
}

// Purge removes all expired entries from the cache.
func (r *Resolver) Purge() {
	now := time.Now()
	r.mu.Lock()
	for k, e := range r.cache {
		if !e.pinned && now.After(e.expires) {
			delete(r.cache, k)
		}
	}
	r.mu.Unlock()
}

// Pin stores a document this server is the authority for, such as its own platform DID document.
// A pinned document is never fetched over the network, never expires, and survives Purge. Use it
// only for documents the caller controls.
func (r *Resolver) Pin(id string, doc *did.Document) {
	r.mu.Lock()
	r.cache[id] = entry{doc: doc, pinned: true}
	r.mu.Unlock()
}
