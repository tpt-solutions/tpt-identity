package did

import "time"

// W3C DID Core context URLs.
const (
	ContextDIDCore = "https://www.w3.org/ns/did/v1"
	ContextED25519 = "https://w3id.org/security/suites/ed25519-2020/v1"
	ContextX25519  = "https://w3id.org/security/suites/x25519-2020/v1"
)

// Document is a W3C DID Document.
type Document struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	Controller         string               `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []string             `json:"authentication,omitempty"`
	KeyAgreement       []string             `json:"keyAgreement,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	Service            []Service            `json:"service,omitempty"`
	Created            *time.Time           `json:"created,omitempty"`
	Updated            *time.Time           `json:"updated,omitempty"`
	// Deactivated is set on the document of a deactivated DID. Such a document carries no keys, and
	// the DID can never be reactivated (the DID Core deactivation metadata, carried inline here).
	Deactivated bool `json:"deactivated,omitempty"`
}

// VerificationMethod describes a cryptographic key in a DID Document.
type VerificationMethod struct {
	ID                 string  `json:"id"`
	Type               string  `json:"type"`
	Controller         string  `json:"controller"`
	PublicKeyMultibase *string `json:"publicKeyMultibase,omitempty"`
	Revoked            bool    `json:"revoked,omitempty"`
	NotBefore          *string `json:"notBefore,omitempty"`
}

// Service describes a service endpoint in a DID Document.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// DefaultContext returns the standard @context slice for tpt-identity documents.
func DefaultContext() []string {
	return []string{ContextDIDCore, ContextED25519, ContextX25519}
}
