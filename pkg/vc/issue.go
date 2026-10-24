package vc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	tptcrypto "github.com/PhillipC05/tpt-identity/pkg/crypto"
	"github.com/PhillipC05/tpt-identity/pkg/schema"
	"github.com/google/uuid"
)

// ErrEphemeralIssuer is returned when a did:key is used as an issuer DID.
// did:key DIDs are self-certifying and cannot rotate keys; they must not be used
// as issuers for persistent credentials.
// ErrIssuerNotDID is returned when the issuer is not a DID. Credentials carry the issuer as a DID so verifiers can resolve its keys.
var ErrIssuerNotDID = errors.New("issuer must be a DID (did:web, did:peer or did:ion)")

var ErrEphemeralIssuer = errors.New("did:key is ephemeral and cannot be used as issuer for persistent credentials; use did:web or did:peer")

// IssueOptions configures credential issuance.
type IssueOptions struct {
	// IssuerDID is the DID of the credential issuer.
	IssuerDID string
	// IssuerKey is the Ed25519 private key used to sign.
	IssuerKey ed25519.PrivateKey
	// VerificationMethodID is the key ID within the issuer's DID document.
	VerificationMethodID string
	// SubjectDID is the DID of the credential subject (the person).
	SubjectDID string
	// SchemaID is the tpt-identity schema (e.g. "healthcare.gp-records").
	SchemaID string
	// Claims are the credential payload, validated against the schema.
	Claims map[string]string
	// ValidFor is how long the credential is valid. Zero means no expiry.
	ValidFor time.Duration
	// StatusListCredential is the URL of the BitstringStatusList VC, if revocation is enabled.
	StatusListCredential string
	// StatusListIndex is this credential's bit index in the status list.
	StatusListIndex int
}

// Issue creates and signs a Verifiable Credential using the DataIntegrityProof
// with the eddsa-jcs-2022 cryptosuite (W3C Data Integrity).
func Issue(opts IssueOptions) (*VerifiableCredential, error) {
	if !strings.HasPrefix(opts.IssuerDID, "did:") {
		return nil, ErrIssuerNotDID
	}
	if strings.HasPrefix(opts.IssuerDID, "did:key:") {
		return nil, ErrEphemeralIssuer
	}
	if err := schema.Validate(opts.SchemaID, opts.Claims); err != nil {
		return nil, fmt.Errorf("issue: %w", err)
	}

	// Resolve the schema to get its canonical versioned ID.
	s, err := schema.GetSchema(opts.SchemaID)
	if err != nil {
		return nil, fmt.Errorf("issue: %w", err)
	}
	versionedSchemaID := s.VersionedID()

	now := time.Now().UTC()
	cred := Credential{
		Context: DefaultContext(),
		ID:      "urn:uuid:" + uuid.NewString(),
		Type:    []string{TypeVC, versionedSchemaID},
		Issuer:  opts.IssuerDID,
		ValidFrom: now,
		CredentialSubject: CredentialSubject{
			ID:     opts.SubjectDID,
			Claims: opts.Claims,
		},
		CredentialSchema: &CredentialSchema{
			ID:   versionedSchemaID,
			Type: "TptCredentialSchema",
		},
	}
	if opts.ValidFor != 0 {
		t := now.Add(opts.ValidFor)
		cred.ValidUntil = &t
	}
	if opts.StatusListCredential != "" {
		cred.CredentialStatus = &CredentialStatus{
			ID:                   opts.StatusListCredential + "#" + fmt.Sprint(opts.StatusListIndex),
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        "revocation",
			StatusListIndex:      opts.StatusListIndex,
			StatusListCredential: opts.StatusListCredential,
		}
	}

	// eddsa-jcs-2022: sign SHA-256(proofOptions) || SHA-256(document).
	proofOptions := map[string]string{
		"type":               "DataIntegrityProof",
		"cryptosuite":        "eddsa-jcs-2022",
		"created":            now.Format(time.RFC3339),
		"verificationMethod": opts.VerificationMethodID,
		"proofPurpose":       "assertionMethod",
	}
	proofOptionsBytes, err := tptcrypto.JCS(proofOptions)
	if err != nil {
		return nil, fmt.Errorf("issue: jcs proof options: %w", err)
	}
	documentBytes, err := tptcrypto.JCS(cred)
	if err != nil {
		return nil, fmt.Errorf("issue: jcs document: %w", err)
	}
	proofHash := sha256.Sum256(proofOptionsBytes)
	docHash := sha256.Sum256(documentBytes)
	hashData := append(proofHash[:], docHash[:]...)
	sig := ed25519.Sign(opts.IssuerKey, hashData)

	return &VerifiableCredential{
		Credential: cred,
		Proof: &Proof{
			Type:               "DataIntegrityProof",
			Cryptosuite:        "eddsa-jcs-2022",
			Created:            now.Format(time.RFC3339),
			VerificationMethod: opts.VerificationMethodID,
			ProofPurpose:       "assertionMethod",
			ProofValue:         base64.RawURLEncoding.EncodeToString(sig),
		},
	}, nil
}
