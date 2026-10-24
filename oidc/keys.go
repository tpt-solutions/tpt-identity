package oidc

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// verificationKey is a retired signing key that still verifies tokens issued before a rotation.
type verificationKey struct {
	kid string
	pub ed25519.PublicKey
}

// AddPreviousKey keeps a retired signing key for verification. Its tokens keep verifying, and the
// key stays in the JWKS, until it is removed from configuration. Remove it once every token it signed
// has expired (the access-token lifetime is the bound).
func (p *Provider) AddPreviousKey(kid string, pub ed25519.PublicKey) error {
	if kid == "" {
		return errors.New("previous signing key needs a kid")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("previous signing key %q: want a %d-byte Ed25519 public key", kid, ed25519.PublicKeySize)
	}
	if kid == p.keyID {
		return fmt.Errorf("previous signing key %q has the same kid as the current key", kid)
	}
	p.previousKeys = append(p.previousKeys, verificationKey{kid: kid, pub: append(ed25519.PublicKey(nil), pub...)})
	return nil
}

// verifyJWT checks a token's signature with the key its kid names: the current key, or a retired key
// added with AddPreviousKey. A token with an unknown kid is refused.
func (p *Provider) verifyJWT(token string) (*Claims, error) {
	header, err := ParseHeader(token)
	if err != nil {
		return nil, err
	}
	kid := header["kid"]
	if kid == "" || kid == p.keyID {
		return Verify(token, p.signingPub)
	}
	for _, k := range p.previousKeys {
		if k.kid == kid {
			return Verify(token, k.pub)
		}
	}
	return nil, fmt.Errorf("jwt: unknown signing key %q", kid)
}
