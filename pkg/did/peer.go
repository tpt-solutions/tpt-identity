package did

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// did:peer implements Peer DID Method Spec v2.0 (numalgo 0 — inception key only).
// Peer DIDs are not publicly resolvable; both parties store the document locally.
// See: https://identity.foundation/peer-did-method-spec/

func init() {
	RegisterMethod(&peerMethod{docs: map[string]*Document{}})
}

type peerMethod struct {
	// docs holds locally stored peer DID documents (in-process store; production
	// code should persist these via the SQLite store and inject a lookup func).
	docs map[string]*Document
}

func (p *peerMethod) Prefix() string { return "peer" }

// Create generates a did:peer numalgo-0 DID from the Ed25519 public key.
// The DID encodes the SHA-256 of the inception key — offline, no network needed.
func (p *peerMethod) Create(opts CreateOptions) (string, *Document, error) {
	if len(opts.SigningPub) != ed25519.PublicKeySize {
		return "", nil, errors.New("did:peer requires a 32-byte Ed25519 public key")
	}
	// Numalgo 0: did:peer:0z<multibase(multicodec(key))>
	prefix := []byte{0xed, 0x01}
	raw := append(prefix, opts.SigningPub...)
	mb := "u" + base64RawURL(raw) // multibase base64url (prefix 'u') to match the actual encoding
	did := "did:peer:0" + mb

	sigKeyID := did + "#key-1"
	sigPubStr := mb
	doc := &Document{
		Context: DefaultContext(),
		ID:      did,
		VerificationMethod: []VerificationMethod{{
			ID:                 sigKeyID,
			Type:               "Ed25519VerificationKey2020",
			Controller:         did,
			PublicKeyMultibase: &sigPubStr,
		}},
		Authentication:  []string{sigKeyID},
		AssertionMethod: []string{sigKeyID},
	}

	if len(opts.EncPub) == 32 {
		encKeyID := did + "#key-2"
		encRaw := append([]byte{0xec, 0x01}, opts.EncPub...)
		encMB := "z" + base64RawURL(encRaw)
		doc.VerificationMethod = append(doc.VerificationMethod, VerificationMethod{
			ID:                 encKeyID,
			Type:               "X25519KeyAgreementKey2020",
			Controller:         did,
			PublicKeyMultibase: &encMB,
		})
		doc.KeyAgreement = []string{encKeyID}
	}

	// Store locally so the same process can resolve it.
	p.docs[did] = doc
	return did, doc, nil
}

// Resolve returns a locally stored peer DID document.
// Peer DIDs cannot be resolved from the network by design; the document must have
// been stored locally (via StoreDocument) or created in this process.
func (p *peerMethod) Resolve(did string) (*Document, error) {
	if !strings.HasPrefix(did, "did:peer:") {
		return nil, fmt.Errorf("did:peer: invalid DID %q", did)
	}
	doc, ok := p.docs[did]
	if !ok {
		return nil, fmt.Errorf("did:peer: document not found locally for %q — must be stored via StoreDocument", did)
	}
	return doc, nil
}

// StoreDocument stores a received peer DID document locally for future resolution.
// Call this when a counterparty shares their peer DID document out-of-band.
func (p *peerMethod) StoreDocument(doc *Document) error {
	if doc.ID == "" {
		return errors.New("did:peer: document has no ID")
	}
	p.docs[doc.ID] = doc
	return nil
}

func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
