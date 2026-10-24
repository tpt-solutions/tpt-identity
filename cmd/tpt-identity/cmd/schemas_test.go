package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func runSchemas(t *testing.T, args ...string) (string, error) {
	t.Helper()
	c := schemasCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), err
}

func TestSchemasListFiltersByCategory(t *testing.T) {
	out, err := runSchemas(t, "list", "--category", "healthcare")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "healthcare.mental-health") || strings.Contains(out, "identity.legal-name") {
		t.Errorf("category filter wrong:\n%s", out)
	}
}

func TestSchemasShowPrintsClaims(t *testing.T) {
	out, err := runSchemas(t, "show", "identity.legal-name")
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if !strings.Contains(out, `"givenNames"`) {
		t.Errorf("claim definitions missing from show output:\n%s", out)
	}
}

func TestSchemasShowUnknownIsError(t *testing.T) {
	if _, err := runSchemas(t, "show", "no.such-schema"); err == nil {
		t.Error("unknown schema was not an error")
	}
}
