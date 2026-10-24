package vc_test

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core" // register core schemas
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// testIssuer creates a did:peer with a fresh keypair.
func testIssuer(t *testing.T) (issuerDID, vmID string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := did.Create("peer", did.CreateOptions{SigningPub: []byte(pub)})
	if err != nil {
		t.Fatal(err)
	}
	return id, id + "#key-1", priv
}

func issueTestCred(t *testing.T, issuerDID, vmID string, priv ed25519.PrivateKey) *vc.VerifiableCredential {
	t.Helper()
	cred, err := vc.Issue(vc.IssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            priv,
		VerificationMethodID: vmID,
		SubjectDID:           issuerDID,
		SchemaID:             "identity.legal-name",
		Claims:               map[string]string{"givenNames": "Alice", "familyName": "Smith"},
		ValidFor:             time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return cred
}

func newVerifier(t *testing.T) *vc.Verifier {
	t.Helper()
	return vc.NewVerifier(resolver.New(5 * time.Minute))
}

// ---- Issue + Verify ----

func TestIssueVerifyRoundTrip(t *testing.T) {
	issuerDID, vmID, priv := testIssuer(t)
	cred := issueTestCred(t, issuerDID, vmID, priv)
	if err := newVerifier(t).Verify(cred); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestIssueProofTypeIsDataIntegrity(t *testing.T) {
	issuerDID, vmID, priv := testIssuer(t)
	cred := issueTestCred(t, issuerDID, vmID, priv)
	if cred.Proof == nil {
		t.Fatal("expected proof")
	}
	if cred.Proof.Type != "DataIntegrityProof" {
		t.Errorf("expected DataIntegrityProof, got %s", cred.Proof.Type)
	}
	if cred.Proof.Cryptosuite != "eddsa-jcs-2022" {
		t.Errorf("expected eddsa-jcs-2022, got %s", cred.Proof.Cryptosuite)
	}
}

func TestIssueRejectsDIDKeyIssuer(t *testing.T) {
	pub, priv, _ := crypto.GenerateSigningKey()
	id, _, _ := did.Create("key", did.CreateOptions{SigningPub: []byte(pub)})
	_, err := vc.Issue(vc.IssueOptions{
		IssuerDID:  id,
		IssuerKey:  priv,
		SubjectDID: "did:peer:abc",
		SchemaID:   "identity.legal-name",
		Claims:     map[string]string{"givenNames": "Alice", "familyName": "Smith"},
	})
	if err == nil {
		t.Error("expected ErrEphemeralIssuer")
	}
}

func TestIssueRejectsMissingRequiredClaim(t *testing.T) {
	issuerDID, vmID, priv := testIssuer(t)
	_, err := vc.Issue(vc.IssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            priv,
		VerificationMethodID: vmID,
		SubjectDID:           issuerDID,
		SchemaID:             "identity.legal-name",
		Claims:               map[string]string{"givenNames": "Alice"}, // missing familyName
	})
	if err == nil {
		t.Error("expected error for missing required claim")
	}
}

func TestIssueUsesVersionedSchemaID(t *testing.T) {
	issuerDID, vmID, priv := testIssuer(t)
	cred := issueTestCred(t, issuerDID, vmID, priv)
	if cred.CredentialSchema == nil {
		t.Fatal("expected CredentialSchema")
	}
	if !strings.Contains(cred.CredentialSchema.ID, "-v") {
		t.Errorf("expected versioned schema ID, got %q", cred.CredentialSchema.ID)
	}
}

// ---- Expiry ----

func TestVerifyRejectsExpiredCredential(t *testing.T) {
	issuerDID, vmID, priv := testIssuer(t)
	cred, err := vc.Issue(vc.IssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            priv,
		VerificationMethodID: vmID,
		SubjectDID:           issuerDID,
		SchemaID:             "identity.legal-name",
		Claims:               map[string]string{"givenNames": "Alice", "familyName": "Smith"},
		ValidFor:             -time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := newVerifier(t).Verify(cred); err == nil {
		t.Error("expected verify to fail on expired credential")
	}
}

// ---- Tampered proof ----

func TestVerifyRejectsTamperedProof(t *testing.T) {
	issuerDID, vmID, priv := testIssuer(t)
	cred := issueTestCred(t, issuerDID, vmID, priv)
	cred.Proof.ProofValue = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := newVerifier(t).Verify(cred); err == nil {
		t.Error("expected verify to fail on tampered proof")
	}
}

// ---- Presentation anti-replay ----

func TestPresentVerifyChallengeDomain(t *testing.T) {
	issuerDID, vmID, priv := testIssuer(t)
	cred := issueTestCred(t, issuerDID, vmID, priv)

	vp, err := vc.Present(vc.PresentOptions{
		HolderDID:            issuerDID,
		HolderKey:            priv,
		VerificationMethodID: vmID,
		Credentials:          []vc.VerifiableCredential{*cred},
		Challenge:            "nonce-abc-123",
		Domain:               "https://rp.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := newVerifier(t)

	if err := v.VerifyPresentation(vp, vc.VerifyPresentationOptions{
		ExpectedChallenge: "nonce-abc-123",
		ExpectedDomain:    "https://rp.example.com",
	}); err != nil {
		t.Errorf("expected valid presentation: %v", err)
	}
	if err := v.VerifyPresentation(vp, vc.VerifyPresentationOptions{
		ExpectedChallenge: "wrong-nonce",
	}); err == nil {
		t.Error("expected challenge mismatch to fail")
	}
	if err := v.VerifyPresentation(vp, vc.VerifyPresentationOptions{
		ExpectedDomain: "https://attacker.com",
	}); err == nil {
		t.Error("expected domain mismatch to fail")
	}
}

// ---- BitstringStatusList ----

func TestStatusListRevokeUnrevoke(t *testing.T) {
	sl := vc.NewStatusList("https://example.com/api/v1/status/test", 0)
	if ok, _ := sl.IsRevoked(5); ok {
		t.Error("expected not revoked initially")
	}
	if err := sl.Revoke(5); err != nil {
		t.Fatal(err)
	}

	if ok, _ := sl.IsRevoked(5); !ok {
		t.Error("expected revoked after Revoke")
	}
	if err := sl.Unrevoke(5); err != nil {
		t.Fatal(err)
	}

	if ok, _ := sl.IsRevoked(5); ok {
		t.Error("expected not revoked after Unrevoke")
	}
}

func TestStatusListEncodeDecode(t *testing.T) {
	sl := vc.NewStatusList("https://example.com/api/v1/status/test", 0)
	if err := sl.Revoke(0); err != nil {
		t.Fatal(err)
	}

	if err := sl.Revoke(100); err != nil {
		t.Fatal(err)
	}

	encoded, err := sl.EncodedList()
	if err != nil {
		t.Fatal(err)
	}
	bits, err := vc.ParseEncodedList(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := vc.CheckStatus(bits, &vc.CredentialStatus{StatusListIndex: 100}); err == nil {
		t.Error("expected revoked for index 100")
	}
	if err := vc.CheckStatus(bits, &vc.CredentialStatus{StatusListIndex: 50}); err != nil {
		t.Errorf("unexpected revoked for index 50: %v", err)
	}
}
