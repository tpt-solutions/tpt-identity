package consent

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	tptcrypto "github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/google/uuid"
)

// LegalBasis describes the legal ground for processing under NZ Privacy Act 2020.
type LegalBasis string

const (
	LegalBasisConsent     LegalBasis = "consent"
	LegalBasisVitalInterest LegalBasis = "vital-interest"
	LegalBasisLegalObligation LegalBasis = "legal-obligation"
	LegalBasisPublicTask  LegalBasis = "public-task"
)

// Receipt is a cryptographically signed record of a data access event.
// The subject (or their agent) can audit who accessed what and when.
type Receipt struct {
	ID         string     `json:"id"`
	SubjectDID string     `json:"subjectDid"`
	RelyingDID string     `json:"relyingDid"`
	SchemaID   string     `json:"schemaId"`
	AccessedAt time.Time  `json:"accessedAt"`
	LegalBasis LegalBasis `json:"legalBasis"`
	Purpose    string     `json:"purpose,omitempty"`
	// ExpiresAt is when the access authorisation underlying this receipt expires.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// RevokedAt is set when the subject withdraws consent after the fact.
	// The receipt itself is never deleted — it is the audit trail.
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	// Signature is the base64url Ed25519 signature over the receipt fields (excluding Signature/RevokedAt).
	Signature string `json:"signature,omitempty"`
	// SignedBy is the DID key ID that produced the signature.
	SignedBy string `json:"signedBy,omitempty"`
}

// IssueOptions configures receipt issuance.
type IssueOptions struct {
	SubjectDID  string
	RelyingDID  string
	SchemaID    string
	Purpose     string
	LegalBasis  LegalBasis
	ExpiresAt   *time.Time
	SignerKey    ed25519.PrivateKey
	SignerKeyID  string
}

// Issue creates and signs a new consent receipt.
// The receipt is typically signed by the relying party at the time of access.
func Issue(opts IssueOptions) (*Receipt, error) {
	r := &Receipt{
		ID:         "urn:uuid:" + uuid.NewString(),
		SubjectDID: opts.SubjectDID,
		RelyingDID: opts.RelyingDID,
		SchemaID:   opts.SchemaID,
		AccessedAt: time.Now().UTC(),
		LegalBasis: opts.LegalBasis,
		Purpose:    opts.Purpose,
		ExpiresAt:  opts.ExpiresAt,
		SignedBy:   opts.SignerKeyID,
	}
	sig, err := tptcrypto.SignJSON(opts.SignerKey, receiptPayload(r))
	if err != nil {
		return nil, fmt.Errorf("receipt sign: %w", err)
	}
	r.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return r, nil
}

// Withdraw marks a receipt as revoked (consent withdrawn). The receipt is never deleted.
func Withdraw(r *Receipt) {
	now := time.Now().UTC()
	r.RevokedAt = &now
}

// receiptPayload returns the signable fields (everything except Signature and RevokedAt,
// which are post-issuance).
func receiptPayload(r *Receipt) map[string]string {
	p := map[string]string{
		"id":         r.ID,
		"subjectDid": r.SubjectDID,
		"relyingDid": r.RelyingDID,
		"schemaId":   r.SchemaID,
		"accessedAt": r.AccessedAt.Format(time.RFC3339),
		"legalBasis": string(r.LegalBasis),
		"purpose":    r.Purpose,
		"signedBy":   r.SignedBy,
	}
	if r.ExpiresAt != nil {
		p["expiresAt"] = r.ExpiresAt.Format(time.RFC3339)
	}
	return p
}
