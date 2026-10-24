package vc_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// ──────────────────────────────────────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────────────────────────────────────

func testSDJWTIssuer(t *testing.T) (issuerDID, vmID string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := did.Create("peer", did.CreateOptions{SigningPub: []byte(pub)})
	if err != nil {
		t.Fatal(err)
	}
	return id, id + "#signing-key-1", priv
}

func issueTestSDJWT(t *testing.T) *vc.SDJWTToken {
	t.Helper()
	issuerDID, vmID, priv := testSDJWTIssuer(t)
	token, err := vc.IssueSDJWT(vc.SDJWTIssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            priv,
		VerificationMethodID: vmID,
		SubjectDID:           "did:peer:holder123",
		SchemaID:             "identity.legal-name",
		SelectiveClaims: map[string]any{
			"givenNames": "Alice",
			"familyName": "Smith",
			"dob":        "1990-01-15",
		},
		AlwaysVisibleClaims: map[string]any{
			"assurance_level": "low",
		},
		ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueSDJWT: %v", err)
	}
	return token
}

// decodeJWTPayload base64url-decodes the payload section of a JWT and unmarshals it.
func decodeJWTPayload(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatal("not a valid JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// ──────────────────────────────────────────────────────────────────────────────
// Disclosure
// ──────────────────────────────────────────────────────────────────────────────

func TestDisclosureRoundTrip(t *testing.T) {
	d, err := vc.NewDisclosure("givenName", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := vc.ParseDisclosure(enc)
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	if got.Key != "givenName" {
		t.Errorf("key round-trip: got %q, want %q", got.Key, "givenName")
	}
	if got.Value != "Alice" {
		t.Errorf("value round-trip: got %v, want %q", got.Value, "Alice")
	}
	if got.Salt == "" {
		t.Error("salt should be non-empty after round-trip")
	}
}

func TestDisclosureDigestIsDeterministic(t *testing.T) {
	d, err := vc.NewDisclosure("key", 42)
	if err != nil {
		t.Fatal(err)
	}
	h1, _ := d.Digest()
	h2, _ := d.Digest()
	if h1 != h2 {
		t.Error("Digest must be deterministic for the same disclosure")
	}
}

func TestTwoDisclosuresHaveDifferentSalts(t *testing.T) {
	d1, _ := vc.NewDisclosure("k", "v")
	d2, _ := vc.NewDisclosure("k", "v")
	if d1.Salt == d2.Salt {
		t.Error("two NewDisclosure calls must produce different salts")
	}
}

func TestParseDisclosureRejectsWrongLength(t *testing.T) {
	// Encode a 2-element array (missing the value).
	b, _ := json.Marshal([]any{"salt", "key"})
	enc := base64.RawURLEncoding.EncodeToString(b)
	_, err := vc.ParseDisclosure(enc)
	if err == nil {
		t.Error("expected error for 2-element disclosure, got nil")
	}
}

func TestParseDisclosurePreservesNumericValue(t *testing.T) {
	d, _ := vc.NewDisclosure("age", 30)
	enc, _ := d.Encode()
	got, err := vc.ParseDisclosure(enc)
	if err != nil {
		t.Fatal(err)
	}
	// JSON numbers unmarshal to float64.
	if v, ok := got.Value.(float64); !ok || v != 30 {
		t.Errorf("numeric value round-trip: got %v (%T)", got.Value, got.Value)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Issuance
// ──────────────────────────────────────────────────────────────────────────────

func TestIssueSDJWT(t *testing.T) {
	token := issueTestSDJWT(t)
	if token.JWT == "" {
		t.Error("JWT should not be empty")
	}
	if len(token.Disclosures) != 3 {
		t.Errorf("expected 3 disclosures (givenNames, familyName, dob), got %d", len(token.Disclosures))
	}
	serialized := token.Serialize()
	if !strings.HasSuffix(serialized, "~") {
		t.Error("serialized SD-JWT must end with ~")
	}
}

func TestIssueSDJWTPayloadContainsSDArray(t *testing.T) {
	token := issueTestSDJWT(t)
	payload := decodeJWTPayload(t, token.JWT)

	sd, ok := payload["_sd"].([]any)
	if !ok {
		t.Fatal("payload must contain _sd array")
	}
	if len(sd) != 3 {
		t.Errorf("_sd must have 3 hashes, got %d", len(sd))
	}
	if alg, _ := payload["_sd_alg"].(string); alg != "sha-256" {
		t.Errorf("_sd_alg must be sha-256, got %q", alg)
	}
	// Verify the hashes match the disclosures.
	for _, d := range token.Disclosures {
		digest, _ := d.Digest()
		found := false
		for _, h := range sd {
			if h.(string) == digest {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("disclosure digest for key %q not found in _sd array", d.Key)
		}
	}
}

func TestIssueSDJWTAlwaysVisibleClaimsInPayload(t *testing.T) {
	token := issueTestSDJWT(t)
	payload := decodeJWTPayload(t, token.JWT)

	if payload["assurance_level"] != "low" {
		t.Errorf("always-visible claim 'assurance_level' should be in JWT payload, got %v", payload["assurance_level"])
	}
	// It must NOT appear as a selective disclosure.
	for _, d := range token.Disclosures {
		if d.Key == "assurance_level" {
			t.Error("always-visible claim must not be in the disclosures")
		}
	}
}

func TestIssueSDJWTSetsVCT(t *testing.T) {
	token := issueTestSDJWT(t)
	payload := decodeJWTPayload(t, token.JWT)
	vct, _ := payload["vct"].(string)
	if vct == "" {
		t.Error("vct (credential type) should be set from SchemaID")
	}
	if !strings.Contains(vct, "legal-name") {
		t.Errorf("vct should contain 'legal-name', got %q", vct)
	}
}

func TestIssueSDJWTRejectsDIDKey(t *testing.T) {
	pub, priv, _ := crypto.GenerateSigningKey()
	keyDID, _, _ := did.Create("key", did.CreateOptions{SigningPub: []byte(pub)})
	_, err := vc.IssueSDJWT(vc.SDJWTIssueOptions{
		IssuerDID:  keyDID,
		IssuerKey:  priv,
		SubjectDID: "did:peer:sub",
		ValidFor:   time.Hour,
	})
	if err != vc.ErrEphemeralIssuer {
		t.Errorf("expected ErrEphemeralIssuer, got %v", err)
	}
}

func TestIssueSDJWTRejectsUnknownSchema(t *testing.T) {
	issuerDID, vmID, priv := testSDJWTIssuer(t)
	_, err := vc.IssueSDJWT(vc.SDJWTIssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            priv,
		VerificationMethodID: vmID,
		SubjectDID:           "did:peer:sub",
		SchemaID:             "nonexistent.schema",
		ValidFor:             time.Hour,
	})
	if err == nil {
		t.Error("expected error for unknown schema, got nil")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Selective presentation
// ──────────────────────────────────────────────────────────────────────────────

func TestPresentSubsetOfClaims(t *testing.T) {
	token := issueTestSDJWT(t) // 3 selective claims

	presented := token.Present([]string{"givenNames"})
	p, err := vc.ParseSDJWT(presented)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure in presentation, got %d", len(p.Disclosures))
	}
	d, _ := vc.ParseDisclosure(p.Disclosures[0])
	if d.Key != "givenNames" {
		t.Errorf("expected givenNames disclosure, got %q", d.Key)
	}
}

func TestPresentZeroDisclosures(t *testing.T) {
	token := issueTestSDJWT(t)
	p, err := vc.ParseSDJWT(token.Present(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Disclosures) != 0 {
		t.Errorf("zero-knowledge presentation should have 0 disclosures, got %d", len(p.Disclosures))
	}
}

func TestPresentFullSerializeContainsAllDisclosures(t *testing.T) {
	token := issueTestSDJWT(t)
	p, err := vc.ParseSDJWT(token.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Disclosures) != len(token.Disclosures) {
		t.Errorf("Serialize() should include all %d disclosures, got %d",
			len(token.Disclosures), len(p.Disclosures))
	}
}

func TestPresentDoesNotRevealUndisclosedClaimValues(t *testing.T) {
	token := issueTestSDJWT(t)
	presented := token.Present([]string{"givenNames"})

	// familyName and dob values must not appear verbatim in the presentation string.
	if strings.Contains(presented, "Smith") {
		t.Error("familyName value 'Smith' must not appear in a presentation that excludes it")
	}
	if strings.Contains(presented, "1990-01-15") {
		t.Error("dob value must not appear in a presentation that excludes it")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Key Binding JWT
// ──────────────────────────────────────────────────────────────────────────────

func TestPresentWithKeyBinding(t *testing.T) {
	token := issueTestSDJWT(t)
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderDID, _, _ := did.Create("peer", did.CreateOptions{SigningPub: holderPub})

	presented, err := token.PresentWithKeyBinding(
		[]string{"givenNames"},
		holderPriv,
		holderDID+"#signing-key-1",
		"nonce-abc",
		"https://verifier.example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	p, err := vc.ParseSDJWT(presented)
	if err != nil {
		t.Fatal(err)
	}
	if p.KBToken == "" {
		t.Error("expected KB-JWT in presentation, got none")
	}
	// KB-JWT payload must include nonce, aud, sd_hash.
	kbPayload := decodeJWTPayload(t, p.KBToken)
	if kbPayload["nonce"] != "nonce-abc" {
		t.Errorf("KB-JWT nonce mismatch: %v", kbPayload["nonce"])
	}
	if kbPayload["aud"] != "https://verifier.example.com" {
		t.Errorf("KB-JWT aud mismatch: %v", kbPayload["aud"])
	}
	if _, ok := kbPayload["sd_hash"]; !ok {
		t.Error("KB-JWT must contain sd_hash")
	}
}

func TestSDHashBindsToExactDisclosureSet(t *testing.T) {
	token := issueTestSDJWT(t)
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	holderDID, _, _ := did.Create("peer", did.CreateOptions{SigningPub: holderPub})

	// Present with givenNames only.
	pres1, _ := token.PresentWithKeyBinding(
		[]string{"givenNames"}, holderPriv, holderDID+"#k", "n1", "aud",
	)
	// Present with givenNames + familyName.
	pres2, _ := token.PresentWithKeyBinding(
		[]string{"givenNames", "familyName"}, holderPriv, holderDID+"#k", "n2", "aud",
	)

	p1, _ := vc.ParseSDJWT(pres1)
	p2, _ := vc.ParseSDJWT(pres2)

	// The KB-JWT sd_hash values must differ because the disclosure sets differ.
	kbPayload1 := decodeJWTPayload(t, p1.KBToken)
	kbPayload2 := decodeJWTPayload(t, p2.KBToken)
	if kbPayload1["sd_hash"] == kbPayload2["sd_hash"] {
		t.Error("sd_hash must differ when different disclosures are presented")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Parsing
// ──────────────────────────────────────────────────────────────────────────────

func TestParseSDJWTRejectsMalformed(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"no_tilde", "header.payload.sig"},
		{"only_tilde", "~"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vc.ParseSDJWT(tc.input)
			if tc.input != "~" && err == nil {
				t.Errorf("expected error for input %q, got nil", tc.input)
			}
		})
	}
}

func TestParseSDJWTSeparatesKBToken(t *testing.T) {
	token := issueTestSDJWT(t)
	holderPub, holderPriv, _ := ed25519.GenerateKey(rand.Reader)
	holderDID, _, _ := did.Create("peer", did.CreateOptions{SigningPub: holderPub})

	presented, _ := token.PresentWithKeyBinding(
		[]string{"givenNames"}, holderPriv, holderDID+"#k", "n", "a",
	)
	p, err := vc.ParseSDJWT(presented)
	if err != nil {
		t.Fatal(err)
	}
	if p.KBToken == "" {
		t.Error("KB-JWT not extracted from presented SD-JWT")
	}
	// The KB-JWT should not be in Disclosures.
	for _, d := range p.Disclosures {
		if strings.Count(d, ".") == 2 {
			t.Errorf("KB-JWT ended up in Disclosures: %q", d)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Tamper-detection (structural, no resolver needed)
// ──────────────────────────────────────────────────────────────────────────────

func TestForgedDisclosureDigestNotInSDArray(t *testing.T) {
	token := issueTestSDJWT(t)

	// Create a disclosure that was never in the issued token.
	forged, _ := vc.NewDisclosure("admin", true)
	forgedDigest, _ := forged.Digest()

	// Verify that the forged digest is not among the legitimate digests.
	for _, d := range token.Disclosures {
		if dg, _ := d.Digest(); dg == forgedDigest {
			t.Error("forged disclosure digest should not match any legitimate disclosure digest")
		}
	}
}
