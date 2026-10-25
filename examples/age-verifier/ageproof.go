// Package ageproof is an example of an age-over-N check built on tpt-identity's SD-JWT credentials.
//
// Three roles take part:
//
//   - the issuer checks the holder's date of birth and attests "at least N years old". The credential carries the
//     threshold and the result. It does not carry the date of birth.
//   - the holder presents the credential to a verifier, with a key-binding JWT tied to the verifier's nonce and
//     audience. The holder discloses only the two proof claims.
//   - the verifier checks the presentation: the issuer is one it trusts, the proof meets its own threshold, the
//     result is true, and the presentation is fresh and addressed to it.
//
// The date of birth never leaves the issuer. The example is for reading and adapting, not for production use as is.
package ageproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"

	// The credential type is registered by the core schema package.
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
)

// SchemaID is the credential type this example issues and checks.
const SchemaID = "identity.age-over-proof"

// credentialLifetime bounds how long an issued proof stays valid.
const credentialLifetime = 365 * 24 * time.Hour

var (
	// ErrTooYoung is returned when the holder is younger than the threshold, so no proof is issued.
	ErrTooYoung = errors.New("ageproof: holder is younger than the threshold")
	// ErrUntrustedIssuer is returned when a proof comes from an issuer the verifier does not trust.
	ErrUntrustedIssuer = errors.New("ageproof: issuer is not trusted by this verifier")
	// ErrNotOverThreshold is returned when a proof attests a lower age than the verifier requires.
	ErrNotOverThreshold = errors.New("ageproof: proof is for a lower age than this verifier requires")
	// ErrNotAdult is returned when the proof's result claim is not true.
	ErrNotAdult = errors.New("ageproof: proof does not attest the threshold")
	// ErrWrongCredential is returned when the presentation is not an age proof.
	ErrWrongCredential = errors.New("ageproof: presentation is not an age proof")
)

// Issuer is the platform (or any tpt-identity deployment) that signs age proofs.
type Issuer struct {
	DID   string
	KeyID string
	Key   ed25519.PrivateKey
}

// Issue checks the date of birth against the threshold and, if the holder is old enough, returns a proof bound to
// the holder's key. The proof names the threshold and the result, never the date of birth.
func (is Issuer) Issue(holderDID string, holderKey ed25519.PublicKey, dob time.Time, threshold int, now time.Time) (*vc.SDJWTToken, error) {
	if !AtLeast(dob, threshold, now) {
		return nil, ErrTooYoung
	}
	return vc.IssueSDJWT(vc.SDJWTIssueOptions{
		IssuerDID:            is.DID,
		IssuerKey:            is.Key,
		VerificationMethodID: is.KeyID,
		SubjectDID:           holderDID,
		SchemaID:             SchemaID,
		SelectiveClaims: map[string]any{
			"age_over": threshold,
			"result":   true,
		},
		// The holder's key is bound into the credential, so a presentation needs a key-binding JWT signed by it.
		AlwaysVisibleClaims: map[string]any{
			"cnf": map[string]any{"jwk": map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(holderKey),
			}},
		},
		ValidFor: credentialLifetime,
	})
}

// AtLeast reports whether someone born on dob is at least years old on day now. Birthdays count: a person turns N
// on the anniversary of their birth, not before.
func AtLeast(dob time.Time, years int, now time.Time) bool {
	// Compare on UTC dates so the answer does not depend on the machine's time zone.
	dob = dob.UTC()
	now = now.UTC()
	threshold := dob.AddDate(years, 0, 0)
	return !now.Before(threshold)
}

// Holder presents a proof to one verifier. It discloses only the two proof claims, and it signs a key-binding JWT
// over the verifier's nonce and audience so the presentation cannot be replayed to another verifier.
type Holder struct {
	KeyID string
	Key   ed25519.PrivateKey
}

// Present returns the presentation for one verifier.
func (h Holder) Present(token *vc.SDJWTToken, nonce, audience string) (string, error) {
	return token.PresentWithKeyBinding([]string{"age_over", "result"}, h.Key, h.KeyID, nonce, audience)
}

// Verifier decides whether a presentation proves the holder is at least Threshold years old.
type Verifier struct {
	Threshold int
	// Trusted lists the issuer DIDs this verifier accepts. Any other issuer is refused.
	Trusted map[string]bool
	v       *vc.SDJWTVerifier
}

// NewVerifier builds a verifier that accepts proofs from the given issuers for the given threshold.
func NewVerifier(threshold int, trustedIssuers ...string) *Verifier {
	trusted := make(map[string]bool, len(trustedIssuers))
	for _, did := range trustedIssuers {
		trusted[did] = true
	}
	return &Verifier{
		Threshold: threshold,
		Trusted:   trusted,
		v:         vc.NewSDJWTVerifier(resolver.New(time.Minute)),
	}
}

// Check verifies a presentation. nonce and audience must be the values the verifier issued for this request.
// It returns nil only when the proof is genuine, fresh, addressed to this verifier, from a trusted issuer, and
// attests an age at or above the verifier's threshold with result true.
func (v *Verifier) Check(presentation, nonce, audience string) error {
	res, err := v.v.Verify(presentation, nonce, audience)
	if err != nil {
		return err
	}
	if !v.Trusted[res.IssuerDID] {
		return ErrUntrustedIssuer
	}
	if !isAgeProof(res.SchemaID) {
		return ErrWrongCredential
	}
	over, ok := res.DisclosedClaims["age_over"].(float64)
	if !ok {
		return fmt.Errorf("%w: age_over is missing", ErrNotOverThreshold)
	}
	if over < float64(v.Threshold) {
		return ErrNotOverThreshold
	}
	if result, _ := res.DisclosedClaims["result"].(bool); !result {
		return ErrNotAdult
	}
	return nil
}

// isAgeProof accepts the base schema ID and its versioned form ("identity.age-over-proof-v1").
func isAgeProof(schemaID string) bool {
	return schemaID == SchemaID || strings.HasPrefix(schemaID, SchemaID+"-v")
}
