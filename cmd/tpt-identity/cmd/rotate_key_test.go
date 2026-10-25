package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
)

func TestNextSigningKeyID(t *testing.T) {
	cases := map[string]string{
		"did:web:id.example#signing-key-1": "did:web:id.example#signing-key-2",
		"did:web:id.example#signing-key-9": "did:web:id.example#signing-key-10",
		"did:web:id.example#custom":        "did:web:id.example#custom-2",
	}
	for in, want := range cases {
		if got := nextSigningKeyID(in); got != want {
			t.Errorf("nextSigningKeyID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckRotationTarget(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current.pem")
	if err := os.WriteFile(current, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(dir, "next.pem")
	prev := []previousKeyEntry{{Kid: "did:web:id.example#signing-key-1", PublicKey: "AA"}}
	const cur = "did:web:id.example#signing-key-2"

	if err := checkRotationTarget("did:web:id.example#signing-key-3", cur, fresh, current, prev); err != nil {
		t.Errorf("fresh target rejected: %v", err)
	}
	if err := checkRotationTarget(cur, cur, fresh, current, prev); err == nil {
		t.Error("reusing the current key ID was accepted")
	}
	if err := checkRotationTarget("did:web:id.example#signing-key-1", cur, fresh, current, prev); err == nil {
		t.Error("reusing a retired key ID was accepted")
	}
	if err := checkRotationTarget("did:web:id.example#signing-key-3", cur, current, current, prev); err == nil {
		t.Error("overwriting the current key file was accepted")
	}
	if err := checkRotationTarget("did:web:id.example#signing-key-3", cur, current+"", current, prev); err == nil {
		t.Error("existing file was accepted as a target")
	}
}

func TestRotationSnippetListsOutgoingKeyFirst(t *testing.T) {
	prev := []previousKeyEntry{{Kid: "old-1", PublicKey: "PREV"}}
	out := rotationSnippet("keys/new.pem", "new-3", "cur-2", "CURPUB", prev)
	for _, want := range []string{`signing_key: "keys/new.pem"`, `key_id: "new-3"`, `kid: "cur-2"`, `public_key: "CURPUB"`, `kid: "old-1"`} {
		if !strings.Contains(out, want) {
			t.Errorf("snippet missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "cur-2") > strings.Index(out, "old-1") {
		t.Error("outgoing key should come before the existing retired keys")
	}
}

// End to end: the command generates a key the config can load, leaves the current key alone, and
// prints a block that names the outgoing key's public key.
func TestRotateKeyCommandWritesNewKey(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(dir, "ed25519.pem")
	if err := keystore.SaveSigning(ks, currentPath, ""); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := "issuer: https://id.example\nidentity:\n  signing_key: " + currentPath + "\n  passphrase: \"\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(dir, "ed25519-2.pem")

	prev := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = prev })

	cmd := rotateKeyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--out-sign", newPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	next, err := keystore.LoadSigning(newPath, "")
	if err != nil {
		t.Fatalf("new key does not load: %v", err)
	}
	if bytes.Equal(next.SigningPub, ks.SigningPub) {
		t.Fatal("new key equals the old key")
	}
	if !strings.Contains(out.String(), `key_id: "did:web:id.example#signing-key-2"`) {
		t.Errorf("output lacks the next key ID:\n%s", out.String())
	}
	if !strings.Contains(out.String(), `kid: "did:web:id.example#signing-key-1"`) {
		t.Errorf("output does not retire the current key:\n%s", out.String())
	}
	if strings.Contains(out.String(), "PRIVATE") {
		t.Error("output contains private key material")
	}

	// The second run must refuse: the file now exists.
	cmd2 := rotateKeyCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out-sign", newPath})
	if err := cmd2.Execute(); err == nil {
		t.Error("second rotation overwrote an existing key file")
	}
}
