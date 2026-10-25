package did

import (
	"fmt"
	"strings"
	"sync"
)

// CreateOptions carries parameters for DID creation.
type CreateOptions struct {
	// Domain is used by did:web.
	Domain string
	// SigningPub is the raw Ed25519 public key bytes.
	SigningPub []byte
	// EncPub is the raw X25519 public key bytes (optional).
	EncPub []byte
	// SigningKeyID is the verification method ID of the signing key. did:web uses it. It defaults to
	// "<did>#signing-key-1".
	SigningKeyID string
	// RetiredKeys are earlier signing keys (did:web only). They stay in the document as verification
	// methods, so proofs they made still verify. They are not listed as authentication or assertion
	// methods, so they cannot sign anything new.
	RetiredKeys []RetiredKey
}

// RetiredKey is an earlier signing key kept in a DID document after rotation.
type RetiredKey struct {
	ID  string
	Pub []byte // raw Ed25519 public key bytes
}

// Method is the interface every DID method must implement.
// External packages implement this and call RegisterMethod to extend the resolver.
type Method interface {
	// Prefix returns the method name, e.g. "web", "key", "peer".
	Prefix() string
	// Create generates a new DID and its Document from the given options.
	Create(opts CreateOptions) (did string, doc *Document, err error)
	// Resolve fetches and returns the DID Document for the given DID string.
	Resolve(did string) (*Document, error)
}

var (
	mu      sync.RWMutex
	methods = map[string]Method{}
)

// RegisterMethod adds a DID method to the global registry.
// Built-in methods (web, key, peer, ion) are registered automatically at init time.
// Panics if a method with the same prefix is already registered.
func RegisterMethod(m Method) {
	mu.Lock()
	defer mu.Unlock()
	p := m.Prefix()
	if _, ok := methods[p]; ok {
		panic(fmt.Sprintf("did: method %q already registered", p))
	}
	methods[p] = m
}

// Resolve dispatches DID resolution to the registered method.
func Resolve(did string) (*Document, error) {
	prefix, err := prefix(did)
	if err != nil {
		return nil, err
	}
	mu.RLock()
	m, ok := methods[prefix]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("did: unsupported method %q", prefix)
	}
	return m.Resolve(did)
}

// Create generates a new DID using the named method.
func Create(methodName string, opts CreateOptions) (string, *Document, error) {
	mu.RLock()
	m, ok := methods[methodName]
	mu.RUnlock()
	if !ok {
		return "", nil, fmt.Errorf("did: unsupported method %q", methodName)
	}
	return m.Create(opts)
}

// prefix extracts the method name from a DID string ("did:web:example.com" → "web").
func prefix(did string) (string, error) {
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 || parts[0] != "did" {
		return "", fmt.Errorf("did: malformed DID %q", did)
	}
	return parts[1], nil
}
