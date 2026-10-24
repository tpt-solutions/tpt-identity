package api

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PhillipC05/tpt-identity/pkg/crypto"
	"github.com/PhillipC05/tpt-identity/pkg/did"
)

// PlatformDID returns the did:web identifier for the server at issuer, for example
// https://id.example.com -> did:web:id.example.com. A port is written as %3A, as the
// did:web method requires. Verifiers resolve the platform DID at /.well-known/did.json.
func PlatformDID(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("issuer %q is not an absolute URL", issuer)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("issuer %q has no host", issuer)
	}
	domain := host
	if port := u.Port(); port != "" {
		domain = host + "%3A" + port
	}
	return "did:web:" + domain, nil
}

// buildPlatformDIDDocument produces the JSON DID document for the platform identity. It
// carries the signing key (and the encryption key when one is configured).
func buildPlatformDIDDocument(issuer string, signingPub ed25519.PublicKey, encPriv [crypto.KeySize]byte) (string, []byte, error) {
	if len(signingPub) != ed25519.PublicKeySize {
		return "", nil, errors.New("platform signing key missing")
	}
	platformDID, err := PlatformDID(issuer)
	if err != nil {
		return "", nil, err
	}
	opts := did.CreateOptions{Domain: strings.TrimPrefix(platformDID, "did:web:"), SigningPub: signingPub}
	if encPriv != ([crypto.KeySize]byte{}) {
		encPub, err := crypto.X25519PublicKey(encPriv)
		if err != nil {
			return "", nil, err
		}
		opts.EncPub = encPub[:]
	}
	id, doc, err := did.Create("web", opts)
	if err != nil {
		return "", nil, err
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return "", nil, err
	}
	return id, body, nil
}

// handleDIDDocument serves the platform DID document at /.well-known/did.json.
func (s *Server) handleDIDDocument(w http.ResponseWriter, r *http.Request) {
	if s.platformDIDDoc == nil {
		http.Error(w, "platform DID not configured", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	w.Header().Set("Cache-Control", "max-age=300")
	_, _ = w.Write(s.platformDIDDoc)
}

// issuerForRequest returns the issuer DID for a credential request. The platform signs
// every credential with its own key, so it can only issue as its own DID. A caller may
// omit issuer_did or name exactly that DID; any other value would attribute the
// credential to a DID that did not sign it.
func (s *Server) issuerForRequest(requested string) (string, error) {
	if s.platformDID == "" {
		return "", errors.New("platform DID not configured")
	}
	if requested != "" && requested != s.platformDID {
		return "", fmt.Errorf("issuer_did must be the platform DID %s", s.platformDID)
	}
	return s.platformDID, nil
}
