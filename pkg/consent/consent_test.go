package consent_test

import (
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/consent"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
)

const (
	subject = "did:peer:subject"
	relying = "did:peer:relying-party"
)

func newGrant(id, scopeID string, level consent.GrantLevel) consent.Grant {
	return consent.Grant{
		ID:                  id,
		SubjectDID:          subject,
		RelyingDID:          relying,
		Level:               level,
		ScopeID:             scopeID,
		GrantedAt:           time.Now(),
		ExplicitlyConfirmed: level == consent.GrantCategory,
	}
}

// ---- CanAccess ----

func TestCanAccessGrantedSchema(t *testing.T) {
	g := newGrant("g1", "identity.legal-name", consent.GrantSchema)
	p := consent.NewPolicy([]consent.Grant{g})
	if err := p.CanAccess(subject, relying, "identity.legal-name"); err != nil {
		t.Errorf("expected access; got: %v", err)
	}
}

func TestCanAccessDeniedWithoutGrant(t *testing.T) {
	p := consent.NewPolicy(nil)
	if err := p.CanAccess(subject, relying, "identity.legal-name"); err == nil {
		t.Error("expected deny without grant")
	}
}

func TestCanAccessExpiredGrant(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	g := newGrant("g1", "identity.legal-name", consent.GrantSchema)
	g.ExpiresAt = &past
	p := consent.NewPolicy([]consent.Grant{g})
	if err := p.CanAccess(subject, relying, "identity.legal-name"); err == nil {
		t.Error("expected deny for expired grant")
	}
}

func TestCanAccessRevokedGrant(t *testing.T) {
	g := newGrant("g1", "identity.legal-name", consent.GrantSchema)
	p := consent.NewPolicy([]consent.Grant{g})
	if err := p.RevokeGrant("g1"); err != nil {
		t.Fatal(err)
	}
	if err := p.CanAccess(subject, relying, "identity.legal-name"); err == nil {
		t.Error("expected deny after revoke")
	}
}

func TestRevokeGrantPreservesRecord(t *testing.T) {
	g := newGrant("g1", "identity.legal-name", consent.GrantSchema)
	p := consent.NewPolicy([]consent.Grant{g})
	p.RevokeGrant("g1")
	// Revoking again should indicate already revoked, not "not found".
	if err := p.RevokeGrant("g1"); err == nil {
		t.Error("expected error on double-revoke")
	}
}

func TestCanAccessCategoryGrant(t *testing.T) {
	g := consent.Grant{
		ID:                  "g2",
		SubjectDID:          subject,
		RelyingDID:          relying,
		Level:               consent.GrantCategory,
		ScopeID:             "identity",
		GrantedAt:           time.Now(),
		ExplicitlyConfirmed: true,
	}
	p := consent.NewPolicy([]consent.Grant{g})
	if err := p.CanAccess(subject, relying, "identity.legal-name"); err != nil {
		t.Errorf("category grant should allow non-sensitive schema: %v", err)
	}
}

func TestCanAccessExtraSensitiveRequiresExplicit(t *testing.T) {
	// healthcare.mental-health is extra-sensitive.
	g := consent.Grant{
		ID:                  "g3",
		SubjectDID:          subject,
		RelyingDID:          relying,
		Level:               consent.GrantCategory,
		ScopeID:             "healthcare",
		GrantedAt:           time.Now(),
		ExplicitlyConfirmed: true,
	}
	p := consent.NewPolicy([]consent.Grant{g})
	// Category grant must NOT cover extra-sensitive schemas.
	if err := p.CanAccess(subject, relying, "healthcare.mental-health"); err == nil {
		t.Error("expected deny: category grant must not cover extra-sensitive schema")
	}
}

// ---- Receipts ----

func TestIssueReceipt(t *testing.T) {
	_, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	r, err := consent.Issue(consent.IssueOptions{
		SubjectDID: subject,
		RelyingDID: relying,
		SchemaID:   "identity.legal-name",
		Purpose:    "identity verification",
		LegalBasis: consent.LegalBasisConsent,
		SignerKey:  priv,
		SignerKeyID: "did:peer:rp#key-1",
	})
	if err != nil {
		t.Fatalf("Issue receipt: %v", err)
	}
	if r.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if r.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestReceiptWithdraw(t *testing.T) {
	_, priv, _ := crypto.GenerateSigningKey()
	r, _ := consent.Issue(consent.IssueOptions{
		SubjectDID: subject,
		RelyingDID: relying,
		SchemaID:   "identity.legal-name",
		LegalBasis: consent.LegalBasisConsent,
		SignerKey:  priv,
		SignerKeyID: "did:peer:rp#key-1",
	})
	if r.RevokedAt != nil {
		t.Error("expected RevokedAt to be nil before Withdraw")
	}
	consent.Withdraw(r)
	if r.RevokedAt == nil {
		t.Error("expected RevokedAt to be set after Withdraw")
	}
}

func TestReceiptExpiresAt(t *testing.T) {
	_, priv, _ := crypto.GenerateSigningKey()
	expiry := time.Now().Add(24 * time.Hour)
	r, _ := consent.Issue(consent.IssueOptions{
		SubjectDID: subject,
		RelyingDID: relying,
		SchemaID:   "identity.legal-name",
		LegalBasis: consent.LegalBasisConsent,
		ExpiresAt:  &expiry,
		SignerKey:  priv,
		SignerKeyID: "did:peer:rp#key-1",
	})
	if r.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}
}
