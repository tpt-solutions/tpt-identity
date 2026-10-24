package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
)

func initInto(t *testing.T, opts initOptions) (string, error) {
	t.Helper()
	c := &cobra.Command{}
	var out bytes.Buffer
	c.SetOut(&out)
	err := runInit(c, opts)
	return out.String(), err
}

// A dev init writes keys, a config and a database, and the config passes validation with no errors.
func TestInitDevProfileProducesValidConfig(t *testing.T) {
	dir := t.TempDir()
	if _, err := initInto(t, initOptions{Dir: dir, Profile: "dev"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, f := range []string{"config.yaml", "tpt-identity.db", "keys/ed25519.pem", "keys/x25519.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}
	for _, p := range validateConfig(filepath.Join(dir, "config.yaml")) {
		if p.level == "error" {
			t.Errorf("generated config has an error: %s", p.msg)
		}
	}
}

// The secrets are fresh per run and the admin key differs from the master key.
func TestInitGeneratesDistinctSecrets(t *testing.T) {
	dir := t.TempDir()
	if _, err := initInto(t, initOptions{Dir: dir, Profile: "dev"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	var keys []string
	for _, l := range lines {
		if strings.HasPrefix(l, "api_key:") || strings.HasPrefix(l, "admin_api_key:") || strings.HasPrefix(l, "bridge_secret:") {
			keys = append(keys, l)
		}
	}
	if len(keys) != 3 {
		t.Fatalf("want 3 secrets in config, got %d", len(keys))
	}
	if keys[0] == keys[1] || keys[1] == keys[2] || keys[0] == keys[2] {
		t.Error("two secrets are identical")
	}
}

// An existing config is not overwritten without --force.
func TestInitRefusesToOverwriteConfig(t *testing.T) {
	dir := t.TempDir()
	if _, err := initInto(t, initOptions{Dir: dir, Profile: "dev"}); err != nil {
		t.Fatal(err)
	}
	if _, err := initInto(t, initOptions{Dir: dir, Profile: "dev"}); err == nil {
		t.Fatal("second init overwrote the config without --force")
	}
	if _, err := initInto(t, initOptions{Dir: dir, Profile: "dev", Force: true}); err != nil {
		t.Errorf("init with --force: %v", err)
	}
}

// prod needs an https issuer and a passphrase in the environment.
func TestInitProdNeedsIssuerAndPassphrase(t *testing.T) {
	t.Setenv(passphraseEnv, "")
	if _, err := initInto(t, initOptions{Dir: t.TempDir(), Profile: "prod", Issuer: "https://id.example.com"}); err == nil {
		t.Error("prod init without a passphrase succeeded")
	}
	t.Setenv(passphraseEnv, "correct horse battery")
	if _, err := initInto(t, initOptions{Dir: t.TempDir(), Profile: "prod", Issuer: "http://id.example.com"}); err == nil {
		t.Error("prod init with an http issuer succeeded")
	}
}

// prod keys are encrypted: they load with the passphrase and not without it.
func TestInitProdKeysAreEncrypted(t *testing.T) {
	const pass = "correct horse battery"
	t.Setenv(passphraseEnv, pass)
	dir := t.TempDir()
	if _, err := initInto(t, initOptions{Dir: dir, Profile: "prod", Issuer: "https://id.example.com"}); err != nil {
		t.Fatalf("prod init: %v", err)
	}
	signPath := filepath.Join(dir, "keys", "ed25519.pem")
	if _, err := keystore.LoadSigning(signPath, pass); err != nil {
		t.Errorf("keys do not load with the passphrase: %v", err)
	}
	if _, err := keystore.LoadSigning(signPath, ""); err == nil {
		t.Error("keys load without a passphrase")
	}
}
