package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func hasProblem(problems []configProblem, level, fragment string) bool {
	for _, p := range problems {
		if p.level == level && strings.Contains(p.msg, fragment) {
			return true
		}
	}
	return false
}

// A config with a missing secret, an http issuer and a scoped key with no scopes reports each.
func TestValidateConfigReportsErrors(t *testing.T) {
	path := writeConfig(t, `
issuer: "http://identity.example.com"
identity:
  signing_key: "does-not-exist.pem"
scoped_api_keys:
  - name: "hooks"
    key: "0123456789abcdef0123"
    scopes: []
`)
	problems := validateConfig(path)
	for _, want := range []string{"api_key is not set", "must be an https URL", "grants no scopes", "does-not-exist.pem"} {
		if !hasProblem(problems, "error", want) {
			t.Errorf("want error containing %q; got %+v", want, problems)
		}
	}
}

// A complete config has no errors; missing optional settings are warnings only.
func TestValidateConfigAcceptsCompleteConfig(t *testing.T) {
	key := filepath.Join(t.TempDir(), "ed25519.pem")
	if err := os.WriteFile(key, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, `
api_key: "0123456789abcdef0123456789abcdef"
admin_api_key: "fedcba9876543210fedcba9876543210"
bridge_secret: "bridge-secret-0123456789abcdef"
issuer: "https://identity.example.com"
identity:
  signing_key: "`+filepath.ToSlash(key)+`"
oidc:
  code_ttl: "5m"
`)
	for _, p := range validateConfig(path) {
		if p.level == "error" {
			t.Errorf("unexpected error: %s", p.msg)
		}
	}
}

// A bad duration is an error, not silently ignored.
func TestValidateConfigRejectsBadDuration(t *testing.T) {
	path := writeConfig(t, `
api_key: "0123456789abcdef0123456789abcdef"
issuer: "https://identity.example.com"
oidc:
  code_ttl: "soon"
`)
	if !hasProblem(validateConfig(path), "error", "oidc.code_ttl") {
		t.Error("bad oidc.code_ttl was not reported")
	}
}

// A misspelt key is reported as a warning, because the server would silently ignore it. A retired
// did_web block is reported too.
func TestValidateConfigReportsUnknownKeys(t *testing.T) {
	path := writeConfig(t, `
api_key: "0123456789abcdef0123456789abcdef"
issuer: "https://identity.example.com"
api_keyy: "typo"
did_web:
  enabled: true
`)
	problems := validateConfig(path)
	if !hasProblem(problems, "warning", `unknown key "api_keyy"`) {
		t.Errorf("misspelt key not reported: %+v", problems)
	}
	if !hasProblem(problems, "warning", "did_web is no longer read") {
		t.Errorf("retired did_web block not reported: %+v", problems)
	}
}
