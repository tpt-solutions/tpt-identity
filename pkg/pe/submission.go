package pe

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// PresentationSubmission maps a presented VP to a PresentationDefinition.
type PresentationSubmission struct {
	ID           string        `json:"id"`
	DefinitionID string        `json:"definition_id"`
	DescriptorMap []Descriptor `json:"descriptor_map"`
}

// Descriptor maps an InputDescriptor to a credential path within the VP.
type Descriptor struct {
	ID     string `json:"id"`   // matches InputDescriptor.ID
	Format string `json:"format"` // "ldp_vc", "jwt_vc", etc.
	Path   string `json:"path"`   // JSON path into the VP, e.g. "$.verifiableCredential[0]"
}

// EvaluationResult is the outcome of evaluating a submission against a definition.
type EvaluationResult struct {
	Satisfied bool
	Errors    []string
	// MatchedCredentials maps descriptor ID → matched credential.
	MatchedCredentials map[string]*vc.VerifiableCredential
}

// Evaluate checks whether the given VP and submission satisfy the definition.
func Evaluate(def *PresentationDefinition, submission *PresentationSubmission, vp *vc.VerifiablePresentation) (*EvaluationResult, error) {
	if submission.DefinitionID != def.ID {
		return nil, fmt.Errorf("pe: submission.definition_id %q does not match definition.id %q", submission.DefinitionID, def.ID)
	}

	result := &EvaluationResult{
		MatchedCredentials: make(map[string]*vc.VerifiableCredential),
	}

	// Build a map from descriptor ID → descriptor path.
	descMap := make(map[string]string)
	for _, d := range submission.DescriptorMap {
		descMap[d.ID] = d.Path
	}

	// Index VP credentials by position.
	creds := vp.VerifiableCredential

	for _, inputDesc := range def.InputDescriptors {
		path, ok := descMap[inputDesc.ID]
		if !ok {
			result.Errors = append(result.Errors, fmt.Sprintf("missing descriptor_map entry for input_descriptor %q", inputDesc.ID))
			continue
		}

		cred, err := resolveCredential(creds, path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("descriptor %q: %s", inputDesc.ID, err))
			continue
		}

		// Check field constraints.
		if inputDesc.Constraints != nil {
			if err := checkConstraints(inputDesc.Constraints, cred); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("descriptor %q constraint: %s", inputDesc.ID, err))
				continue
			}
		}

		result.MatchedCredentials[inputDesc.ID] = cred
	}

	result.Satisfied = len(result.Errors) == 0 && len(result.MatchedCredentials) == len(def.InputDescriptors)
	return result, nil
}

// resolveCredential extracts the credential at the given JSON path from the VP credentials slice.
// Supports simple paths like "$.verifiableCredential[0]" and "$.verifiableCredential[2]".
func resolveCredential(creds []vc.VerifiableCredential, path string) (*vc.VerifiableCredential, error) {
	idx := extractArrayIndex(path)
	if idx < 0 || idx >= len(creds) {
		return nil, fmt.Errorf("path %q: credential index %d out of range (have %d)", path, idx, len(creds))
	}
	return &creds[idx], nil
}

// extractArrayIndex parses the index from a path like "$.verifiableCredential[2]".
func extractArrayIndex(path string) int {
	// Find the last "[N]" in the path.
	lb := strings.LastIndex(path, "[")
	rb := strings.LastIndex(path, "]")
	if lb < 0 || rb < 0 || rb <= lb {
		return 0 // default to first credential
	}
	var idx int
	fmt.Sscanf(path[lb+1:rb], "%d", &idx)
	return idx
}

// checkConstraints validates a credential against the constraint fields.
func checkConstraints(c *Constraints, cred *vc.VerifiableCredential) error {
	// Marshal the credential subject to a map for JSON-path-style access.
	subjectBytes, err := json.Marshal(cred.CredentialSubject)
	if err != nil {
		return fmt.Errorf("marshal subject: %w", err)
	}
	var subjectMap map[string]any
	if err := json.Unmarshal(subjectBytes, &subjectMap); err != nil {
		return fmt.Errorf("unmarshal subject: %w", err)
	}

	for _, field := range c.Fields {
		if field.Optional {
			continue
		}
		found := false
		for _, jsonPath := range field.Path {
			val := resolveJSONPath(subjectMap, jsonPath)
			if val != nil {
				if field.Filter != nil {
					if err := applyFilter(field.Filter, val); err != nil {
						continue
					}
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("required field %v not found or filter not satisfied", field.Path)
		}
	}
	return nil
}

// resolveJSONPath resolves a simple JSON path (e.g. "$.credentialSubject.given_name") against a map.
func resolveJSONPath(m map[string]any, path string) any {
	// Strip leading "$." or "$"
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, "$")

	parts := strings.Split(path, ".")
	var current any = m
	for _, part := range parts {
		if part == "" {
			continue
		}
		mm, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = mm[part]
	}
	return current
}

// applyFilter checks a value against a JSON Schema filter fragment.
func applyFilter(f *Filter, val any) error {
	if f.Const != nil {
		if !jsonEqual(val, f.Const) {
			return errors.New("value does not match const")
		}
	}
	if len(f.Enum) > 0 {
		for _, e := range f.Enum {
			if jsonEqual(val, e) {
				return nil
			}
		}
		return errors.New("value not in enum")
	}
	if f.Pattern != "" {
		s, ok := val.(string)
		if !ok {
			return errors.New("pattern filter requires string value")
		}
		if !matchesPattern(f.Pattern, s) {
			return fmt.Errorf("value does not match pattern %q", f.Pattern)
		}
	}
	return nil
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

// matchesPattern does a simple prefix/suffix/contains match (not full regex).
// For production, replace with regexp.MatchString.
func matchesPattern(pattern, s string) bool {
	if strings.HasPrefix(pattern, "^") && strings.HasSuffix(pattern, "$") {
		return s == pattern[1:len(pattern)-1]
	}
	return strings.Contains(s, strings.Trim(pattern, "^$.*"))
}
