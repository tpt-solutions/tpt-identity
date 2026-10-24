package keystore_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
)

// Argon2id (64 MB, 3 iterations) runs on every save and load, so each test keeps to one
// round trip where it can.
func TestSigningKeyRoundTrip(t *testing.T) {
	ks, err := keystore.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ed25519.pem")
	if err := keystore.SaveSigning(ks, path, "correct horse"); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := keystore.LoadSigning(path, "correct horse")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !bytes.Equal(loaded.SigningPriv, ks.SigningPriv) || !bytes.Equal(loaded.SigningPub, ks.SigningPub) {
		t.Error("signing key changed across save and load")
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	ks, err := keystore.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ed25519.pem")
	if err := keystore.SaveSigning(ks, path, "right"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := keystore.LoadSigning(path, "wrong"); err == nil {
		t.Error("loaded with the wrong passphrase")
	}
}

func TestEncryptionKeyRoundTrip(t *testing.T) {
	ks, err := keystore.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "x25519.pem")
	if err := keystore.SaveEncryption(ks, path, ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	var loaded keystore.Keystore
	if err := keystore.LoadEncryption(&loaded, path, ""); err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.EncPriv != ks.EncPriv {
		t.Error("encryption key changed across save and load")
	}
}
