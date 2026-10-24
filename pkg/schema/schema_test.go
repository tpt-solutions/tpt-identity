package schema_test

import (
	"testing"

	"github.com/tpt-solutions/tpt-identity/pkg/schema"
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
)

// ---- Registry ----

func TestGetSchemaByBaseID(t *testing.T) {
	s, err := schema.GetSchema("identity.legal-name")
	if err != nil {
		t.Fatalf("GetSchema: %v", err)
	}
	if s.ID != "identity.legal-name" {
		t.Errorf("unexpected ID: %s", s.ID)
	}
}

func TestGetSchemaByVersionedID(t *testing.T) {
	// GetSchema must resolve versioned IDs like "identity.legal-name-v1".
	base, err := schema.GetSchema("identity.legal-name")
	if err != nil {
		t.Fatal(err)
	}
	versioned := base.VersionedID()
	s, err := schema.GetSchema(versioned)
	if err != nil {
		t.Fatalf("GetSchema(%s): %v", versioned, err)
	}
	if s.ID != "identity.legal-name" {
		t.Errorf("expected base ID, got %s", s.ID)
	}
}

func TestGetSchemaNotFound(t *testing.T) {
	if _, err := schema.GetSchema("nonexistent.schema"); err == nil {
		t.Error("expected error for unknown schema")
	}
}

func TestVersionedID(t *testing.T) {
	s := schema.Schema{ID: "healthcare.gp-records", Version: 2}
	if got := s.VersionedID(); got != "healthcare.gp-records-v2" {
		t.Errorf("VersionedID: got %q, want %q", got, "healthcare.gp-records-v2")
	}
}

func TestVersionedIDDefaultsToV1(t *testing.T) {
	s := schema.Schema{ID: "test.foo"}
	if got := s.VersionedID(); got != "test.foo-v1" {
		t.Errorf("VersionedID default: got %q", got)
	}
}

func TestBaseID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"healthcare.gp-records-v1", "healthcare.gp-records"},
		{"healthcare.gp-records-v42", "healthcare.gp-records"},
		{"healthcare.gp-records", "healthcare.gp-records"},
		{"identity.nhi-v1", "identity.nhi"},
	}
	for _, c := range cases {
		got := schema.BaseID(c.in)
		if got != c.want {
			t.Errorf("BaseID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGetCategoryNotFound(t *testing.T) {
	if _, err := schema.GetCategory("nonexistent"); err == nil {
		t.Error("expected error for unknown category")
	}
}

func TestAllCategoriesNotEmpty(t *testing.T) {
	cats := schema.AllCategories()
	if len(cats) == 0 {
		t.Error("expected at least one category")
	}
}

func TestSchemasForCategory(t *testing.T) {
	schemas := schema.SchemasForCategory("identity")
	if len(schemas) == 0 {
		t.Error("expected identity schemas")
	}
	for _, s := range schemas {
		if s.CategoryID != "identity" {
			t.Errorf("unexpected category %s in identity schemas", s.CategoryID)
		}
	}
}

func TestIsExtraSensitive(t *testing.T) {
	if !schema.IsExtraSensitive("healthcare.mental-health") {
		t.Error("mental-health should be extra-sensitive")
	}
	if schema.IsExtraSensitive("identity.legal-name") {
		t.Error("legal-name should not be extra-sensitive")
	}
}

// ---- Validate ----

func TestValidateRequiredFields(t *testing.T) {
	err := schema.Validate("identity.legal-name", map[string]string{
		"givenNames": "Alice",
		"familyName": "Smith",
	})
	if err != nil {
		t.Errorf("expected valid: %v", err)
	}
}

func TestValidateMissingRequired(t *testing.T) {
	err := schema.Validate("identity.legal-name", map[string]string{
		"givenNames": "Alice",
		// familyName missing
	})
	if err == nil {
		t.Error("expected error for missing familyName")
	}
}

func TestValidateWrongType(t *testing.T) {
	err := schema.Validate("identity.dob", map[string]string{
		"dateOfBirth": "not-a-date",
	})
	if err == nil {
		t.Error("expected error for wrong date format")
	}
}

func TestValidateCorrectDate(t *testing.T) {
	err := schema.Validate("identity.dob", map[string]string{
		"dateOfBirth": "1990-06-15",
	})
	if err != nil {
		t.Errorf("expected valid date: %v", err)
	}
}

func TestValidateVersionedSchemaID(t *testing.T) {
	// Validate must accept versioned IDs.
	err := schema.Validate("identity.legal-name-v1", map[string]string{
		"givenNames": "Alice",
		"familyName": "Smith",
	})
	if err != nil {
		t.Errorf("expected valid for versioned ID: %v", err)
	}
}

func TestAllCoreSchemasCovered(t *testing.T) {
	expected := []string{
		"identity", "healthcare", "finance", "professional",
		"education", "legal", "property", "civic", "social", "travel", "insurance",
	}
	for _, cat := range expected {
		schemas := schema.SchemasForCategory(cat)
		if len(schemas) == 0 {
			t.Errorf("no schemas registered for category %q", cat)
		}
	}
}

func TestExtraSensitiveSchemas(t *testing.T) {
	sensitive := []string{
		"healthcare.mental-health",
		"healthcare.sexual-health",
		"healthcare.addiction",
		"legal.criminal-record",
	}
	for _, id := range sensitive {
		if !schema.IsExtraSensitive(id) {
			t.Errorf("expected %s to be extra-sensitive", id)
		}
	}
}
