package vc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	tptcrypto "github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/multiformats/go-multibase"
)

// StatusChecker is an optional callback for checking credentialStatus (revocation).
// Return a non-nil error if the credential is revoked.
type StatusChecker func(status *CredentialStatus) error

// Verifier resolves issuer DIDs and verifies credential signatures.
type Verifier struct {
	resolver      *resolver.Resolver
	statusChecker StatusChecker
}

// NewVerifier creates a Verifier backed by the given resolver.
func NewVerifier(r *resolver.Resolver) *Verifier {
	return &Verifier{resolver: r}
}

// WithStatusChecker attaches a credentialStatus checker (revocation) to the verifier.
func (v *Verifier) WithStatusChecker(fn StatusChecker) *Verifier {
	v.statusChecker = fn
	return v
}

// Verify checks the signature, expiry, structure, and revocation status of a VerifiableCredential.
func (v *Verifier) Verify(vc *VerifiableCredential) error {
	if vc.Proof == nil {
		return errors.New("verify: no proof")
	}
	if time.Now().Before(vc.ValidFrom) {
		return errors.New("verify: credential is not yet valid")
	}
	if vc.ValidUntil != nil && time.Now().After(*vc.ValidUntil) {
		return errors.New("verify: credential has expired")
	}

	doc, err := v.resolver.Resolve(vc.Issuer)
	if err != nil {
		return fmt.Errorf("verify: resolve issuer DID: %w", err)
	}

	pub, err := extractEd25519Key(doc, vc.Proof.VerificationMethod)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	switch {
	case vc.Proof.Type == "DataIntegrityProof" && vc.Proof.Cryptosuite == "eddsa-jcs-2022":
		if err := verifyDataIntegrity(pub, &vc.Credential, vc.Proof); err != nil {
			return fmt.Errorf("verify: %w", err)
		}
	case vc.Proof.Type == "Ed25519Signature2020":
		// Legacy: verify the direct JSON signature.
		sig, err := base64.RawURLEncoding.DecodeString(vc.Proof.ProofValue)
		if err != nil {
			return fmt.Errorf("verify: decode proof value: %w", err)
		}
		if err := tptcrypto.VerifyJSON(pub, vc.Credential, sig); err != nil {
			return fmt.Errorf("verify: signature invalid: %w", err)
		}
	default:
		return fmt.Errorf("verify: unsupported proof type %q / cryptosuite %q", vc.Proof.Type, vc.Proof.Cryptosuite)
	}

	// Check revocation status if present and a checker is configured.
	if vc.CredentialStatus != nil && v.statusChecker != nil {
		if err := v.statusChecker(vc.CredentialStatus); err != nil {
			return fmt.Errorf("verify: credential revoked: %w", err)
		}
	}

	return nil
}

// verifyDataIntegrity verifies an eddsa-jcs-2022 DataIntegrityProof.
func verifyDataIntegrity(pub ed25519.PublicKey, cred *Credential, proof *Proof) error {
	sig, err := base64.RawURLEncoding.DecodeString(proof.ProofValue)
	if err != nil {
		return fmt.Errorf("decode proof value: %w", err)
	}

	proofOptions := map[string]string{
		"type":               proof.Type,
		"cryptosuite":        proof.Cryptosuite,
		"created":            proof.Created,
		"verificationMethod": proof.VerificationMethod,
		"proofPurpose":       proof.ProofPurpose,
	}
	proofOptionsBytes, err := tptcrypto.JCS(proofOptions)
	if err != nil {
		return fmt.Errorf("jcs proof options: %w", err)
	}
	documentBytes, err := tptcrypto.JCS(*cred)
	if err != nil {
		return fmt.Errorf("jcs document: %w", err)
	}
	proofHash := sha256.Sum256(proofOptionsBytes)
	docHash := sha256.Sum256(documentBytes)
	hashData := append(proofHash[:], docHash[:]...)

	if !ed25519.Verify(pub, hashData, sig) {
		return errors.New("signature invalid")
	}
	return nil
}

// VerifyPresentationOptions configures anti-replay validation for presentations.
type VerifyPresentationOptions struct {
	// ExpectedChallenge, when non-empty, must match the challenge in the presentation.
	ExpectedChallenge string
	// ExpectedDomain, when non-empty, must match the domain in the presentation.
	ExpectedDomain string
}

// VerifyPresentation verifies a VerifiablePresentation and all enclosed credentials.
// Pass opts to enforce challenge/domain for anti-replay protection.
func (v *Verifier) VerifyPresentation(vp *VerifiablePresentation, opts VerifyPresentationOptions) error {
	if vp.Proof == nil {
		return errors.New("verify presentation: no proof")
	}
	if opts.ExpectedChallenge != "" && vp.Challenge != opts.ExpectedChallenge {
		return fmt.Errorf("verify presentation: challenge mismatch (replay attack?)")
	}
	if opts.ExpectedDomain != "" && vp.Domain != opts.ExpectedDomain {
		return fmt.Errorf("verify presentation: domain mismatch")
	}
	doc, err := v.resolver.Resolve(vp.Holder)
	if err != nil {
		return fmt.Errorf("verify presentation: resolve holder DID: %w", err)
	}
	pub, err := extractEd25519Key(doc, vp.Proof.VerificationMethod)
	if err != nil {
		return fmt.Errorf("verify presentation: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(vp.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("verify presentation: decode proof: %w", err)
	}
	if err := tptcrypto.VerifyJSON(pub, vp.Presentation, sig); err != nil {
		return fmt.Errorf("verify presentation: signature invalid: %w", err)
	}
	for i, vc := range vp.VerifiableCredential {
		if err := v.Verify(&vc); err != nil {
			return fmt.Errorf("verify presentation: credential[%d]: %w", i, err)
		}
	}
	return nil
}

// extractEd25519Key finds and decodes the Ed25519 public key identified by vmID in doc.
func extractEd25519Key(doc *did.Document, vmID string) (ed25519.PublicKey, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.ID != vmID {
			continue
		}
		if vm.Revoked {
			return nil, fmt.Errorf("key %q is revoked", vmID)
		}
		if vm.Type != "Ed25519VerificationKey2020" {
			return nil, fmt.Errorf("key %q has type %q, expected Ed25519VerificationKey2020", vmID, vm.Type)
		}
		if vm.PublicKeyMultibase == nil {
			return nil, fmt.Errorf("key %q has no publicKeyMultibase", vmID)
		}
		return decodeMultibaseEd25519(*vm.PublicKeyMultibase)
	}
	return nil, fmt.Errorf("verification method %q not found in DID document", vmID)
}

// decodeMultibaseEd25519 decodes a multibase-encoded Ed25519 public key.
func decodeMultibaseEd25519(mb string) (ed25519.PublicKey, error) {
	_, raw, err := multibase.Decode(mb)
	if err != nil {
		// Fallback: base64url (used by did:peer and fallback encoding)
		if strings.HasPrefix(mb, "u") {
			raw, err = base64.RawURLEncoding.DecodeString(mb[1:])
			if err != nil {
				return nil, fmt.Errorf("decode key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("decode key multibase: %w", err)
		}
	}
	// Strip 2-byte multicodec prefix (0xed 0x01 for ed25519-pub)
	if len(raw) < 2 {
		return nil, errors.New("key too short")
	}
	// Consume varint prefix
	_, n := decodeUvarint(raw)
	key := raw[n:]
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected 32-byte Ed25519 key, got %d bytes", len(key))
	}
	return ed25519.PublicKey(key), nil
}

func decodeUvarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, c := range b {
		if c < 0x80 {
			return x | uint64(c)<<s, i + 1
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
	return 0, 0
}
