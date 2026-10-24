package vc

import "time"

// W3C Verifiable Credentials Data Model 2.0 context.
const (
	ContextVC  = "https://www.w3.org/ns/credentials/v2"
	ContextTpt = "https://tpt-identity.org/ns/v1"
	TypeVC     = "VerifiableCredential"
	TypeVP     = "VerifiablePresentation"
)

// CredentialStatus points to a BitstringStatusList entry for revocation checks.
type CredentialStatus struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"` // "BitstringStatusListEntry"
	StatusPurpose        string `json:"statusPurpose"`
	StatusListIndex      int    `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}

// Credential is a W3C Verifiable Credential (unsigned).
type Credential struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id,omitempty"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	ValidFrom         time.Time         `json:"validFrom"`
	ValidUntil        *time.Time        `json:"validUntil,omitempty"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	// CredentialSchema links to the tpt-identity schema definition.
	CredentialSchema *CredentialSchema `json:"credentialSchema,omitempty"`
	// CredentialStatus points to a BitstringStatusList for revocation.
	CredentialStatus *CredentialStatus `json:"credentialStatus,omitempty"`
}

// CredentialSubject holds the subject DID and the claim payload.
type CredentialSubject struct {
	ID     string            `json:"id"`
	Claims map[string]string `json:"claims,omitempty"`
}

// CredentialSchema links to the tpt-identity schema definition.
type CredentialSchema struct {
	ID   string `json:"id"`   // e.g. "healthcare.gp-records"
	Type string `json:"type"` // "TptCredentialSchema"
}

// VerifiableCredential is a signed Credential (Credential + proof).
type VerifiableCredential struct {
	Credential
	Proof *Proof `json:"proof,omitempty"`
}

// Proof is a cryptographic proof block. Supports DataIntegrityProof (eddsa-jcs-2022)
// and the legacy Ed25519Signature2020 type.
type Proof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite,omitempty"` // e.g. "eddsa-jcs-2022"
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"` // multibase-encoded signature (base64url for eddsa-jcs-2022)
}

// Presentation is a W3C Verifiable Presentation (unsigned).
type Presentation struct {
	Context              []string               `json:"@context"`
	ID                   string                 `json:"id,omitempty"`
	Type                 []string               `json:"type"`
	Holder               string                 `json:"holder,omitempty"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential,omitempty"`
	// Challenge is a nonce provided by the verifier to prevent replay attacks.
	Challenge string `json:"challenge,omitempty"`
	// Domain restricts this presentation to a specific verifier audience.
	Domain string `json:"domain,omitempty"`
}

// VerifiablePresentation is a signed Presentation.
type VerifiablePresentation struct {
	Presentation
	Proof *Proof `json:"proof,omitempty"`
}

// DefaultContext returns the standard @context for tpt-identity credentials.
func DefaultContext() []string {
	return []string{ContextVC, ContextTpt}
}
