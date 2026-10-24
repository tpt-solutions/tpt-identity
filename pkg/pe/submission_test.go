package pe_test

import (
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
	res, err := pe.Evaluate(givenNameDefinition(), submissionFor("def-1"), vp)
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
	if _, err := pe.Evaluate(givenNameDefinition(), submissionFor("other-def"), vp); err == nil {
		t.Fatal("submission for another definition was evaluated")
	}
}

// An input descriptor with no descriptor_map entry leaves the request unsatisfied.
func TestEvaluateMissingDescriptorUnsatisfied(t *testing.T) {
	vp := legalNameVP(map[string]string{"givenNames": "Alice"})
	sub := submissionFor("def-1")
	sub.DescriptorMap = nil
	res, err := pe.Evaluate(givenNameDefinition(), sub, vp)
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
	res, err := pe.Evaluate(givenNameDefinition(), submissionFor("def-1"), vp)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Satisfied {
		t.Fatal("credential without givenNames satisfied the request")
	}
}
