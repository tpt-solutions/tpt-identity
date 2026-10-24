package bridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// BootstrapFunc is called after a new platform identity is created from an
// external provider. It may auto-issue VCs from bridge claims.
// Errors are logged but do not fail the login flow.
type BootstrapFunc func(ctx context.Context, subjectDID string, ext *ExternalIdentity)

// Mapper resolves or creates platform DIDs from external identities.
type Mapper struct {
	store     store.Store
	bootstrap BootstrapFunc // optional; called on new identity creation
	// externalLocks serialises first-login creation per external identity, so two concurrent
	// callbacks for the same account cannot both create a platform DID. It covers one process;
	// replicas need a unique constraint on the external link.
	externalLocks sync.Map // externalKey → *sync.Mutex
}

// externalKey identifies an external account for locking.
type externalKey struct {
	provider   string
	externalID string
}

// lockExternal takes the per-account lock and returns its release function.
func (m *Mapper) lockExternal(provider, externalID string) func() {
	v, _ := m.externalLocks.LoadOrStore(externalKey{provider, externalID}, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// NewMapper creates a Mapper backed by the given store.
func NewMapper(st store.Store) *Mapper {
	return &Mapper{store: st}
}

// SetBootstrap registers a function to call when a new identity is first created.
func (m *Mapper) SetBootstrap(fn BootstrapFunc) {
	m.bootstrap = fn
}

// FindOrCreate looks up the platform DID linked to the external identity.
// If none exists, a new did:key identity is created and persisted.
// Returns the subjectDID and whether the identity was newly created.
func (m *Mapper) FindOrCreate(ctx context.Context, ext *ExternalIdentity) (subjectDID string, isNew bool, err error) {
	unlock := m.lockExternal(ext.Provider, ext.ExternalID)
	defer unlock()

	link, err := m.store.GetExternalLink(ctx, ext.Provider, ext.ExternalID)
	if err == nil {
		// Found — update last used and return.
		link.LastUsedAt = time.Now()
		_ = m.store.SaveExternalLink(ctx, link)
		return link.SubjectDID, false, nil
	}
	if !isNotFound(err) {
		return "", false, fmt.Errorf("bridge: lookup external link: %w", err)
	}

	// Create a new did:key identity.
	subjectDID, err = m.createIdentity(ctx)
	if err != nil {
		return "", false, err
	}

	now := time.Now()
	if err := m.store.SaveExternalLink(ctx, &store.ExternalProviderLink{
		SubjectDID: subjectDID,
		Provider:   ext.Provider,
		ExternalID: ext.ExternalID,
		LinkedAt:   now,
		LastUsedAt: now,
	}); err != nil {
		return "", false, fmt.Errorf("bridge: save external link: %w", err)
	}
	if m.bootstrap != nil {
		m.bootstrap(ctx, subjectDID, ext)
	}
	return subjectDID, true, nil
}

// LinkIdentity associates an additional external provider with an existing platform DID.
// Returns an error if the external ID is already linked to a different DID.
func (m *Mapper) LinkIdentity(ctx context.Context, subjectDID string, ext *ExternalIdentity) error {
	existing, err := m.store.GetExternalLink(ctx, ext.Provider, ext.ExternalID)
	if err == nil {
		if existing.SubjectDID != subjectDID {
			return errors.New("bridge: external identity already linked to a different DID")
		}
		return nil // already linked to this DID
	}
	if !isNotFound(err) {
		return fmt.Errorf("bridge: check existing link: %w", err)
	}

	now := time.Now()
	return m.store.SaveExternalLink(ctx, &store.ExternalProviderLink{
		SubjectDID: subjectDID,
		Provider:   ext.Provider,
		ExternalID: ext.ExternalID,
		LinkedAt:   now,
		LastUsedAt: now,
	})
}

// UnlinkIdentity removes an external provider link from a DID.
// Returns an error if this is the last auth method (prevents account lockout).
func (m *Mapper) UnlinkIdentity(ctx context.Context, subjectDID, provider, externalID string) error {
	links, err := m.store.ListExternalLinks(ctx, subjectDID)
	if err != nil {
		return fmt.Errorf("bridge: list links: %w", err)
	}
	// The link must belong to subjectDID. Without this check, a caller could remove
	// another account's link by naming its provider and external ID.
	owned := false
	for _, l := range links {
		if l.Provider == provider && l.ExternalID == externalID {
			owned = true
			break
		}
	}
	if !owned {
		return errors.New("bridge: link not found for this identity")
	}
	if len(links) <= 1 {
		return errors.New("bridge: cannot unlink last auth method")
	}
	return m.store.DeleteExternalLink(ctx, provider, externalID)
}

// createIdentity generates a new Ed25519 keypair, derives a did:key, and persists it.
// The private key is NOT stored — bridge identities authenticate via their external provider.
// The DID itself encodes the public key and serves as the stable identifier.
func (m *Mapper) createIdentity(ctx context.Context) (string, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("bridge: generate key: %w", err)
	}

	didStr, doc, err := did.Create("key", did.CreateOptions{SigningPub: pub})
	if err != nil {
		return "", fmt.Errorf("bridge: create did:key: %w", err)
	}

	now := time.Now()
	identity := &store.Identity{
		DID:       didStr,
		Method:    "key",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := m.store.SaveIdentity(ctx, identity); err != nil {
		return "", fmt.Errorf("bridge: save identity: %w", err)
	}
	if err := m.store.SaveDocument(ctx, doc); err != nil {
		return "", fmt.Errorf("bridge: save did document: %w", err)
	}
	return didStr, nil
}

// isNotFound reports whether a store lookup found nothing. Stores return store.ErrNotFound for that;
// matching error text would turn an unrelated failure that mentions "not found" into a create.
func isNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound)
}
