package vc

// Zero-knowledge age proof for tpt-identity.
//
// Implements a practical "age-over-N" proof using a derived credential pattern
// (not full ZK-SNARKs). The approach:
//
//  1. The user holds a VC containing their date_of_birth (DOB).
//  2. The prover requests an "age-over-N" assertion from the issuer.
//  3. The issuer verifies the DOB VC, computes whether age >= N, and signs
//     a NEW credential containing only: { "age_over": N, "result": true/false }.
//  4. The verifier trusts the issuer's signature on the derived credential.
//
// The DOB is never transmitted to the verifier — only the binary claim.

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AgeProofRequest is a request to derive an age-over credential from a DOB VC.
type AgeProofRequest struct {
	DOBCredentialID string `json:"dob_credential_id"`
	AgeThreshold    int    `json:"age_threshold"`
	SubjectDID      string `json:"subject_did"`
	VerifierDID     string `json:"verifier_did"`
}

// AgeProofResult is a derived VC asserting only that the subject is (or is not)
// at least AgeThreshold years old. The actual DOB is never included.
type AgeProofResult struct {
	Credential *VerifiableCredential `json:"credential"`
	AgeOver    int                   `json:"age_over"`
	Result     bool                  `json:"result"`
}

// IssueAgeProof derives an "age-over-N" VC from a verified DOB credential.
// The DOB is accessed server-side and never transmitted in the result.
func IssueAgeProof(
	dobVC *VerifiableCredential,
	threshold int,
	issuerDID string,
	issuerKey ed25519.PrivateKey,
	keyID string,
	verifierDID string,
) (*AgeProofResult, error) {
	// Extract DOB from the credential claims.
	claims := dobVC.CredentialSubject.Claims
	dobStr := ""
	for _, name := range []string{"date_of_birth", "dob", "dateOfBirth", "birthDate"} {
		if v, ok := claims[name]; ok && v != "" {
			dobStr = v
			break
		}
	}
	if dobStr == "" {
		return nil, fmt.Errorf("age proof: DOB credential does not contain date_of_birth")
	}

	dob, err := parseDOB(dobStr)
	if err != nil {
		return nil, fmt.Errorf("age proof: parse DOB: %w", err)
	}

	age := ageFromDOB(dob)
	result := age >= threshold

	subjectDID := dobVC.CredentialSubject.ID

	// Issue the derived "age-over-N" credential. DOB is NEVER included.
	// Use the standard Issue pipeline (handles signing and schema validation).
	if strings.HasPrefix(issuerDID, "did:key:") {
		return nil, ErrEphemeralIssuer
	}

	derivedClaims := map[string]string{
		"age_over":   strconv.Itoa(threshold),
		"result":     strconv.FormatBool(result),
		"proof_type": "derived",
		"method":     "issuer-computed",
	}
	if verifierDID != "" {
		derivedClaims["verifier"] = verifierDID
	}

	opts := IssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            issuerKey,
		VerificationMethodID: keyID,
		SubjectDID:           subjectDID,
		SchemaID:             "identity.age-over-proof",
		Claims:               derivedClaims,
		ValidFor:             time.Hour, // age proofs are short-lived
	}

	signed, err := Issue(opts)
	if err != nil {
		return nil, fmt.Errorf("age proof: sign: %w", err)
	}

	return &AgeProofResult{
		Credential: signed,
		AgeOver:    threshold,
		Result:     result,
	}, nil
}

// parseDOB parses a date of birth string.
func parseDOB(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("02/01/2006", s); err == nil {
		return t, nil
	}
	if len(s) == 4 {
		if year, err := strconv.Atoi(s); err == nil {
			return time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse DOB %q; expected YYYY-MM-DD", s)
}

// ageFromDOB computes the current age in whole years from a date of birth.
func ageFromDOB(dob time.Time) int {
	now := time.Now()
	years := now.Year() - dob.Year()
	if now.Month() < dob.Month() ||
		(now.Month() == dob.Month() && now.Day() < dob.Day()) {
		years--
	}
	if years < 0 {
		return 0
	}
	return years
}
