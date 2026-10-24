// Package pe implements the DIF Presentation Exchange v2 protocol.
// https://identity.foundation/presentation-exchange/
package pe

// PresentationDefinition describes what credentials and claims a verifier requires.
type PresentationDefinition struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	Purpose          string            `json:"purpose,omitempty"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
	Format           *Format           `json:"format,omitempty"`
}

// InputDescriptor specifies a single credential requirement.
type InputDescriptor struct {
	ID          string       `json:"id"`
	Name        string       `json:"name,omitempty"`
	Purpose     string       `json:"purpose,omitempty"`
	Constraints *Constraints `json:"constraints,omitempty"`
	Format      *Format      `json:"format,omitempty"`
}

// Constraints defines the required fields and optionality.
type Constraints struct {
	Fields          []Field `json:"fields,omitempty"`
	LimitDisclosure string  `json:"limit_disclosure,omitempty"` // "required" | "preferred"
	SubjectIsIssuer string  `json:"subject_is_issuer,omitempty"`
}

// Field specifies a required or preferred claim path.
type Field struct {
	Path      []string `json:"path"` // JSON paths in order of preference, e.g. ["$.credentialSubject.claims.given_name"]
	ID        string   `json:"id,omitempty"`
	Purpose   string   `json:"purpose,omitempty"`
	Filter    *Filter  `json:"filter,omitempty"`
	Optional  bool     `json:"optional,omitempty"`
	Predicate string   `json:"predicate,omitempty"` // "required" | "preferred"
}

// Filter is a JSON Schema fragment applied to the resolved path value.
type Filter struct {
	Type    string `json:"type,omitempty"`
	Format  string `json:"format,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Const   any    `json:"const,omitempty"`
	Enum    []any  `json:"enum,omitempty"`
	Minimum any    `json:"minimum,omitempty"`
	Maximum any    `json:"maximum,omitempty"`
}

// Format specifies acceptable credential and proof formats.
type Format struct {
	LDPvc *FormatDetail `json:"ldp_vc,omitempty"`
	LDPvp *FormatDetail `json:"ldp_vp,omitempty"`
	JWTVC *FormatDetail `json:"jwt_vc,omitempty"`
	JWTVP *FormatDetail `json:"jwt_vp,omitempty"`
}

// FormatDetail lists acceptable algorithms for a format.
type FormatDetail struct {
	Alg       []string `json:"alg,omitempty"`
	ProofType []string `json:"proof_type,omitempty"`
}

// PresentationRequest wraps a definition with a nonce for replay protection.
type PresentationRequest struct {
	ID         string                 `json:"id"`
	Definition PresentationDefinition `json:"presentation_definition"`
	Nonce      string                 `json:"nonce"`
	Domain     string                 `json:"domain,omitempty"`
}
