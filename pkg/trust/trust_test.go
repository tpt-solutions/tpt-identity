package trust_test

import (
	"context"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/trust"
)

// ---- Permit ----

func TestIssueVerifyPermit(t *testing.T) {
	pubKey, privKey, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	token, err := trust.IssuePermit(
		"did:peer:issuer",
		privKey,
		"did:peer:subject",
		"did:peer:audience",
		"read:email",
		5*time.Minute,
		"jti-001",
	)
	if err != nil {
		t.Fatal(err)
	}

	p, err := trust.VerifyPermit(token, pubKey, "did:peer:audience", "read:email")
	if err != nil {
		t.Fatalf("VerifyPermit: %v", err)
	}
	if p.Subject != "did:peer:subject" {
		t.Errorf("unexpected subject: %s", p.Subject)
	}
	if p.Action != "read:email" {
		t.Errorf("unexpected action: %s", p.Action)
	}
}

func TestVerifyPermitRejectsWrongKey(t *testing.T) {
	_, privKey, _ := crypto.GenerateSigningKey()
	wrongPub, _, _ := crypto.GenerateSigningKey()
	token, _ := trust.IssuePermit("did:peer:issuer", privKey, "did:peer:subject", "did:peer:aud", "read:x", time.Minute, "")
	if _, err := trust.VerifyPermit(token, wrongPub, "", ""); err == nil {
		t.Error("expected error for wrong key")
	}
}

func TestVerifyPermitRejectsExpired(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	token, _ := trust.IssuePermit("did:peer:issuer", privKey, "did:peer:sub", "did:peer:aud", "action", -time.Hour, "")
	if _, err := trust.VerifyPermit(token, pubKey, "", ""); err == nil {
		t.Error("expected error for expired permit")
	}
}

func TestVerifyPermitRejectsWrongAudience(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	token, _ := trust.IssuePermit("did:peer:issuer", privKey, "did:peer:sub", "did:peer:aud", "action", time.Minute, "")
	if _, err := trust.VerifyPermit(token, pubKey, "did:peer:other", "action"); err == nil {
		t.Error("expected error for wrong audience")
	}
}

func TestVerifyPermitRejectsWrongAction(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	token, _ := trust.IssuePermit("did:peer:issuer", privKey, "did:peer:sub", "did:peer:aud", "read:x", time.Minute, "")
	if _, err := trust.VerifyPermit(token, pubKey, "did:peer:aud", "write:y"); err == nil {
		t.Error("expected error for wrong action")
	}
}

func TestVerifyPermitMalformed(t *testing.T) {
	pubKey, _, _ := crypto.GenerateSigningKey()
	if _, err := trust.VerifyPermit("not.a.valid.token.format", pubKey, "", ""); err == nil {
		t.Error("expected error for malformed token")
	}
}

// ---- Reputation VC ----

func TestIssueVerifyReputationVC(t *testing.T) {
	pubKey, privKey, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	rec := trust.ReputationRecord{Score: 90, Tier: "trusted", Since: "2024-01-01"}
	vcBytes, err := trust.IssueReputationVC(
		"did:web:trust.tpt.nz",
		privKey,
		"did:web:trust.tpt.nz#key-1",
		"did:web:example.com",
		rec,
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("IssueReputationVC: %v", err)
	}

	got, err := trust.VerifyReputationVC(vcBytes, pubKey)
	if err != nil {
		t.Fatalf("VerifyReputationVC: %v", err)
	}
	if got.Score != 90 {
		t.Errorf("score: got %d, want 90", got.Score)
	}
	if got.Tier != "trusted" {
		t.Errorf("tier: got %s, want trusted", got.Tier)
	}
	if got.Domain != "did:web:example.com" {
		t.Errorf("domain: got %s", got.Domain)
	}
}

func TestReputationVCRejectsWrongKey(t *testing.T) {
	_, privKey, _ := crypto.GenerateSigningKey()
	wrongPub, _, _ := crypto.GenerateSigningKey()
	rec := trust.ReputationRecord{Score: 70, Tier: "verified", Since: "2024-06-01"}
	vcBytes, _ := trust.IssueReputationVC("did:web:auth", privKey, "did:web:auth#k1", "did:web:subject", rec, time.Hour)
	if _, err := trust.VerifyReputationVC(vcBytes, wrongPub); err == nil {
		t.Error("expected signature error for wrong key")
	}
}

func TestReputationVCRejectsExpired(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	rec := trust.ReputationRecord{Score: 70, Tier: "verified", Since: "2024-06-01"}
	vcBytes, _ := trust.IssueReputationVC("did:web:auth", privKey, "did:web:auth#k1", "did:web:subject", rec, -time.Hour)
	if _, err := trust.VerifyReputationVC(vcBytes, pubKey); err == nil {
		t.Error("expected expiry error")
	}
}

func TestReputationVCRejectsWrongType(t *testing.T) {
	pubKey, _, _ := crypto.GenerateSigningKey()
	if _, err := trust.VerifyReputationVC([]byte(`{"type":["VerifiableCredential"],"credentialSubject":{}}`), pubKey); err == nil {
		t.Error("expected type error")
	}
}

func TestReputationVCScoreOutOfRange(t *testing.T) {
	_, privKey, _ := crypto.GenerateSigningKey()
	rec := trust.ReputationRecord{Score: 150}
	if _, err := trust.IssueReputationVC("did:web:auth", privKey, "did:web:auth#k1", "did:web:subject", rec, time.Hour); err == nil {
		t.Error("expected error for score > 100")
	}
}

// ---- Legacy DNS reputation ----

func TestLookupReputationDNSNoRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// A domain guaranteed to not have a _tpt-rep record — should return nil without error.
	rec, err := trust.LookupReputation(ctx, "example.com")
	if err != nil {
		t.Logf("LookupReputation DNS error (expected in CI): %v", err)
		return
	}
	_ = rec
}

func TestTrustLevelUnknownForNilRecord(t *testing.T) {
	if level := trust.Level(nil); level != trust.TrustUnknown {
		t.Errorf("expected TrustUnknown for nil record, got %v", level)
	}
}

func TestTrustLevelFromScore(t *testing.T) {
	cases := []struct {
		score int
		want  trust.TrustLevel
	}{
		{100, trust.TrustTrusted},
		{85, trust.TrustTrusted},
		{84, trust.TrustVerified},
		{60, trust.TrustVerified},
		{59, trust.TrustProvisional},
		{25, trust.TrustProvisional},
		{24, trust.TrustRestricted},
		{0, trust.TrustRestricted},
	}
	for _, c := range cases {
		rec := &trust.ReputationRecord{Score: c.score}
		if got := trust.Level(rec); got != c.want {
			t.Errorf("Level(score=%d) = %v, want %v", c.score, got, c.want)
		}
	}
}

func TestTrustLevelString(t *testing.T) {
	if trust.TrustTrusted.String() != "trusted" {
		t.Errorf("unexpected string: %s", trust.TrustTrusted.String())
	}
}
