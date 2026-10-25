package pe_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/tpt-solutions/tpt-identity/pkg/pe"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// legalNameVP returns a presentation holding one credential whose subject carries givenNames.
func legalNameVP(claims map[string]string) *vc.VerifiablePresentation {
	cred := vc.VerifiableCredential{Credential: vc.Credential{
		CredentialSubject: vc.CredentialSubject{ID: "did:peer:holder", Claims: claims},
	}}
	return &vc.VerifiablePresentation{Presentation: vc.Presentation{
		Holder:               "did:peer:holder",
		VerifiableCredential: []vc.VerifiableCredential{cred},
	}}
}

func givenNameDefinition() *pe.PresentationDefinition {
	return &pe.PresentationDefinition{
		ID: "def-1",
		InputDescriptors: []pe.InputDescriptor{{
			ID: "legal-name",
			Constraints: &pe.Constraints{Fields: []pe.Field{{
				Path: []string{"$.credentialSubject.claims.givenNames"},
			}}},
		}},
	}
}

func submissionFor(defID string) *pe.PresentationSubmission {
	return &pe.PresentationSubmission{
		ID:           "sub-1",
		DefinitionID: defID,
		DescriptorMap: []pe.Descriptor{{
			ID:     "legal-name",
			Format: "ldp_vc",
			Path:   "$.verifiableCredential[0]",
		}},
	}
}

func TestEvaluateSatisfied(t *testing.T) {
	vp := legalNameVP(map[string]string{"givenNames": "Alice"})
	res, err := pe.Evaluate(givenNameDefinition(), submissionFor("def-1"), vp, acceptAll{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !res.Satisfied {
		t.Fatalf("want satisfied, errors: %v", res.Errors)
	}
	if res.MatchedCredentials["legal-name"] == nil {
		t.Error("matched credential not reported for the descriptor")
	}
}

// A submission for another definition is an error, not a silent pass.
func TestEvaluateRejectsDefinitionMismatch(t *testing.T) {
	vp := legalNameVP(map[string]string{"givenNames": "Alice"})
	if _, err := pe.Evaluate(givenNameDefinition(), submissionFor("other-def"), vp, acceptAll{}); err == nil {
		t.Fatal("submission for another definition was evaluated")
	}
}

// An input descriptor with no descriptor_map entry leaves the request unsatisfied.
func TestEvaluateMissingDescriptorUnsatisfied(t *testing.T) {
	vp := legalNameVP(map[string]string{"givenNames": "Alice"})
	sub := submissionFor("def-1")
	sub.DescriptorMap = nil
	res, err := pe.Evaluate(givenNameDefinition(), sub, vp, acceptAll{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Satisfied || len(res.Errors) == 0 {
		t.Fatalf("want unsatisfied with an error, got satisfied=%v errors=%v", res.Satisfied, res.Errors)
	}
}

// A required claim the credential does not carry leaves the request unsatisfied.
func TestEvaluateMissingClaimUnsatisfied(t *testing.T) {
	vp := legalNameVP(map[string]string{"familyName": "Smith"})
	res, err := pe.Evaluate(givenNameDefinition(), submissionFor("def-1"), vp, acceptAll{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Satisfied {
		t.Fatal("credential without givenNames satisfied the request")
	}
}

// acceptAll stands in for a verifier that finds every credential valid.
type acceptAll struct{}

func (acceptAll) Verify(*vc.VerifiableCredential) error { return nil }

// rejectAll stands in for a verifier that finds every credential invalid.
type rejectAll struct{}

func (rejectAll) Verify(*vc.VerifiableCredential) error { return errors.New("bad signature") }

// Claims from a credential that fails verification never satisfy a definition, even when they match.
func TestEvaluateUnverifiedCredentialDoesNotMatch(t *testing.T) {
	vp := legalNameVP(map[string]string{"givenNames": "Mallory"})
	res, err := pe.Evaluate(givenNameDefinition(), submissionFor("def-1"), vp, rejectAll{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Satisfied {
		t.Fatal("forged credential satisfied the definition")
	}
	if res.MatchedCredentials["legal-name"] != nil {
		t.Error("unverified credential reported as matched")
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "failed verification") {
		t.Errorf("want a verification error, got %v", res.Errors)
	}
}

// A verifier is required: evaluating without one is an error, not a claims-only pass.
func TestEvaluateRequiresVerifier(t *testing.T) {
	vp := legalNameVP(map[string]string{"givenNames": "Alice"})
	if _, err := pe.Evaluate(givenNameDefinition(), submissionFor("def-1"), vp, nil); err == nil {
		t.Error("evaluation without a verifier was accepted")
	}
}

// Each presented credential is verified once, even when several descriptors select it.
type countingVerifier struct{ calls int }

func (c *countingVerifier) Verify(*vc.VerifiableCredential) error { c.calls++; return nil }

func TestEvaluateVerifiesEachCredentialOnce(t *testing.T) {
	def := &pe.PresentationDefinition{ID: "def-2", InputDescriptors: []pe.InputDescriptor{{ID: "a"}, {ID: "b"}}}
	sub := &pe.PresentationSubmission{
		DefinitionID: "def-2",
		DescriptorMap: []pe.Descriptor{
			{ID: "a", Path: "$.verifiableCredential[0]"},
			{ID: "b", Path: "$.verifiableCredential[0]"},
		},
	}
	cv := &countingVerifier{}
	if _, err := pe.Evaluate(def, sub, legalNameVP(map[string]string{}), cv); err != nil {
		t.Fatal(err)
	}
	if cv.calls != 1 {
		t.Errorf("credential verified %d times, want 1", cv.calls)
	}
}
