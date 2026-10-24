package vc

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	tptcrypto "github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/google/uuid"
)

// PresentOptions configures Verifiable Presentation creation.
type PresentOptions struct {
	HolderDID            string
	HolderKey            ed25519.PrivateKey
	VerificationMethodID string
	Credentials          []VerifiableCredential
	// Challenge is a nonce provided by the verifier to prevent replay attacks.
	// Required for any presentation sent to a relying party.
	Challenge string
	// Domain restricts this presentation to the intended verifier audience.
	Domain string
}

// Present creates a signed Verifiable Presentation wrapping the given credentials.
// The holder proves they possess each credential by signing the presentation.
func Present(opts PresentOptions) (*VerifiablePresentation, error) {
	if len(opts.Credentials) == 0 {
		return nil, fmt.Errorf("present: at least one credential required")
	}
	now := time.Now().UTC()
	pres := Presentation{
		Context:              DefaultContext(),
		ID:                   "urn:uuid:" + uuid.NewString(),
		Type:                 []string{TypeVP},
		Holder:               opts.HolderDID,
		VerifiableCredential: opts.Credentials,
		Challenge:            opts.Challenge,
		Domain:               opts.Domain,
	}
	sig, err := tptcrypto.SignJSON(opts.HolderKey, pres)
	if err != nil {
		return nil, fmt.Errorf("present sign: %w", err)
	}
	return &VerifiablePresentation{
		Presentation: pres,
		Proof: &Proof{
			Type:               "Ed25519Signature2020",
			Created:            now.Format(time.RFC3339),
			VerificationMethod: opts.VerificationMethodID,
			ProofPurpose:       "authentication",
			ProofValue:         base64.RawURLEncoding.EncodeToString(sig),
		},
	}, nil
}
