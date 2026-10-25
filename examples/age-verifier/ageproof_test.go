package ageproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

const (
	testAudience = "https://shop.example"
	testNonce    = "nonce-from-the-verifier"
)

// fixture is one issuer, one holder and the verifier that trusts the issuer.
type fixture struct {
	issuer    Issuer
	holder    Holder
	holderDID string
	holderPub ed25519.PublicKey
	verifier  *Verifier
}

func newFixture(t *testing.T, threshold int) fixture {
	t.Helper()
	issuerPub, issuerPriv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerDID, _, err := did.Create("peer", did.CreateOptions{SigningPub: []byte(issuerPub)})
	if err != nil {
		t.Fatal(err)
	}
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderDID, _, err := did.Create("peer", did.CreateOptions{SigningPub: holderPub})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		issuer:    Issuer{DID: issuerDID, KeyID: issuerDID + "#key-1", Key: issuerPriv},
		holder:    Holder{KeyID: holderDID + "#signing-key-1", Key: holderPriv},
		holderDID: holderDID,
		holderPub: holderPub,
		verifier:  NewVerifier(threshold, issuerDID),
	}
}

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

// bornYearsAgo returns a date of birth that makes someone exactly years old on now, with a birthday today.
func bornYearsAgo(years int) time.Time {
	return now.AddDate(-years, 0, 0)
}

func TestAdultPresentationIsAccepted(t *testing.T) {
	f := newFixture(t, 18)
	token, err := f.issuer.Issue(f.holderDID, f.holderPub, bornYearsAgo(30), 18, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	presented, err := f.holder.Present(token, testNonce, testAudience)
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	if err := f.verifier.Check(presented, testNonce, testAudience); err != nil {
		t.Fatalf("adult refused: %v", err)
	}
}

func TestIssuerRefusesAMinor(t *testing.T) {
	f := newFixture(t, 18)
	if _, err := f.issuer.Issue(f.holderDID, f.holderPub, bornYearsAgo(17), 18, now); !errors.Is(err, ErrTooYoung) {
		t.Fatalf("minor: got %v, want ErrTooYoung", err)
	}
}

// A person turns 18 on the anniversary, not the day before.
func TestBirthdayCountsOnTheAnniversary(t *testing.T) {
	dob := time.Date(2008, 10, 26, 0, 0, 0, 0, time.UTC)
	if AtLeast(dob, 18, time.Date(2026, 10, 25, 23, 59, 0, 0, time.UTC)) {
		t.Error("eligible the day before the 18th birthday")
	}
	if !AtLeast(dob, 18, time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)) {
		t.Error("not eligible on the 18th birthday")
	}
}

func TestPresentationDisclosesOnlyTheProofClaims(t *testing.T) {
	f := newFixture(t, 18)
	dob := bornYearsAgo(30)
	token, err := f.issuer.Issue(f.holderDID, f.holderPub, dob, 18, now)
	if err != nil {
		t.Fatal(err)
	}
	presented, err := f.holder.Present(token, testNonce, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.verifier.v.Verify(presented, testNonce, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range res.DisclosedClaims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "age_over,result" {
		t.Errorf("disclosed %v, want only age_over and result", keys)
	}
	if strings.Contains(presented, dob.Format("2006-01-02")) {
		t.Error("the date of birth appears in the presentation")
	}
}

func TestVerifierRefusesProofForLowerAge(t *testing.T) {
	// A proof issued at 16 must not satisfy a verifier that needs 18.
	issuance := newFixture(t, 16)
	token, err := issuance.issuer.Issue(issuance.holderDID, issuance.holderPub, bornYearsAgo(16), 16, now)
	if err != nil {
		t.Fatal(err)
	}
	presented, err := issuance.holder.Present(token, testNonce, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	strict := NewVerifier(18, issuance.issuer.DID)
	if err := strict.Check(presented, testNonce, testAudience); !errors.Is(err, ErrNotOverThreshold) {
		t.Fatalf("over-16 proof at an 18 verifier: got %v, want ErrNotOverThreshold", err)
	}
}

func TestVerifierRefusesUntrustedIssuer(t *testing.T) {
	f := newFixture(t, 18)
	other := newFixture(t, 18)
	token, err := other.issuer.Issue(other.holderDID, other.holderPub, bornYearsAgo(30), 18, now)
	if err != nil {
		t.Fatal(err)
	}
	presented, err := other.holder.Present(token, testNonce, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.verifier.Check(presented, testNonce, testAudience); err == nil {
		t.Fatal("proof from an untrusted issuer accepted")
	}
}

func TestPresentationIsBoundToNonceAndAudience(t *testing.T) {
	f := newFixture(t, 18)
	token, err := f.issuer.Issue(f.holderDID, f.holderPub, bornYearsAgo(30), 18, now)
	if err != nil {
		t.Fatal(err)
	}
	presented, err := f.holder.Present(token, testNonce, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.verifier.Check(presented, "a-different-nonce", testAudience); err == nil {
		t.Error("presentation replayed under another nonce was accepted")
	}
	if err := f.verifier.Check(presented, testNonce, "https://other-shop.example"); err == nil {
		t.Error("presentation addressed to another audience was accepted")
	}
}

// The proof is holder-bound, so a bare presentation with no key-binding JWT is refused.
func TestBarePresentationIsRefused(t *testing.T) {
	f := newFixture(t, 18)
	token, err := f.issuer.Issue(f.holderDID, f.holderPub, bornYearsAgo(30), 18, now)
	if err != nil {
		t.Fatal(err)
	}
	bare := token.Present([]string{"age_over", "result"})
	if err := f.verifier.Check(bare, testNonce, testAudience); err == nil {
		t.Fatal("bare presentation of a holder-bound proof was accepted")
	}
}
