// Package bridge provides the identity bridge layer — a registry of authentication
// providers that map external identities to platform DIDs.
package bridge

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

// ExternalIdentity is the normalized result of authenticating via an external provider.
type ExternalIdentity struct {
	Provider   string            // "google", "github", "saml:acme", "ldap", "magiclink-email", "password"
	ExternalID string            // stable identifier from the provider (sub, NameID, DN, normalised email)
	Claims     map[string]string // additional claims: email, given_name, family_name, groups, etc.
	// Duress is true when the user authenticated with their duress passphrase, indicating
	// possible coercion. The session is allowed to proceed normally but a session.duress
	// event is fired so security staff can respond.
	Duress bool
}

// Bridge authenticates a request via an external provider and returns the external identity.
type Bridge interface {
	Name() string
	Authenticate(ctx context.Context, r *http.Request) (*ExternalIdentity, error)
}

// RedirectBridge is implemented by providers that use a browser redirect-callback flow
// (OIDC authorization code, plain OAuth2). handleBridgeStart calls AuthorizationURL to
// initiate and handleBridgeCallback calls ExchangeCode to complete authentication.
type RedirectBridge interface {
	Bridge
	AuthorizationURL(ctx context.Context, state string) (string, error)
	ExchangeCode(ctx context.Context, code, state string) (*ExternalIdentity, error)
}

// SAMLBridgeHandler is implemented by SAML 2.0 bridge providers.
// Keeping crewjam/saml types out of the api layer allows the API to compile without
// the saml build tag.
type SAMLBridgeHandler interface {
	Bridge
	// MetadataHandler serves this SP's SAML metadata XML at GET /auth/{provider}/metadata.
	MetadataHandler(w http.ResponseWriter, r *http.Request)
	// PrepareAuth generates a SAML AuthnRequest and returns the IdP redirect URL (without
	// RelayState appended) and the AuthnRequest ID for anti-replay tracking.
	PrepareAuth(ctx context.Context) (idpRedirectURL string, requestID string, err error)
	// ProcessACS validates the SAMLResponse POST from the IdP.
	// requestIDs should contain the pending AuthnRequest ID returned by PrepareAuth.
	ProcessACS(r *http.Request, requestIDs []string) (*ExternalIdentity, error)
}

// Manager holds the registered bridge providers.
type Manager struct {
	mu      sync.RWMutex
	bridges map[string]Bridge
}

// NewManager creates an empty bridge manager.
func NewManager() *Manager {
	return &Manager{bridges: make(map[string]Bridge)}
}

// Register adds a bridge provider. Panics on duplicate name.
func (m *Manager) Register(b Bridge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.bridges[b.Name()]; exists {
		panic(fmt.Sprintf("bridge: duplicate provider %q", b.Name()))
	}
	m.bridges[b.Name()] = b
}

// Get returns a bridge by name.
func (m *Manager) Get(name string) (Bridge, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.bridges[name]
	return b, ok
}

// Names returns all registered provider names.
func (m *Manager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.bridges))
	for n := range m.bridges {
		names = append(names, n)
	}
	return names
}
