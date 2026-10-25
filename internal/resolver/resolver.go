package resolver

import (
	"fmt"
	"sync"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

const (
	defaultTTL = 5 * time.Minute
	// maxEntries bounds the cache. Resolve is reachable with attacker-chosen DIDs, so an unbounded
	// map is a memory-exhaustion path.
	maxEntries = 10000
)

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
	// local, when set, answers for DIDs this server hosts. Its answer is not cached, so an update to a
	// hosted document (for example a newly registered passkey) is visible at once.
	local func(id string) (*did.Document, bool)
}

// SetLocal sets the lookup for DIDs this server hosts. Resolve asks it before the network, and a
// found document is returned without caching. Pinned documents still take precedence.
func (r *Resolver) SetLocal(lookup func(id string) (*did.Document, bool)) {
	r.mu.Lock()
	r.local = lookup
	r.mu.Unlock()
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
	local := r.local
	r.mu.RUnlock()
	if ok && e.pinned {
		return e.doc, nil
	}
	if local != nil {
		if doc, found := local(id); found {
			return doc, nil
		}
	}
	if ok && time.Now().Before(e.expires) {
		return e.doc, nil
	}

	doc, err := did.Resolve(id)
	if err != nil {
		return nil, fmt.Errorf("resolver: %w", err)
	}

	r.mu.Lock()
	if _, exists := r.cache[id]; !exists && len(r.cache) >= maxEntries {
		r.evictLocked()
	}
	r.cache[id] = entry{doc: doc, expires: time.Now().Add(r.ttl)}
	r.mu.Unlock()
	return doc, nil
}

// evictLocked makes room for one entry. It drops expired entries first and, if the cache is still
// full, an arbitrary unpinned one. The caller must hold r.mu.
func (r *Resolver) evictLocked() {
	now := time.Now()
	for k, e := range r.cache {
		if !e.pinned && now.After(e.expires) {
			delete(r.cache, k)
		}
	}
	if len(r.cache) < maxEntries {
		return
	}
	for k, e := range r.cache {
		if !e.pinned {
			delete(r.cache, k)
			return
		}
	}
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
