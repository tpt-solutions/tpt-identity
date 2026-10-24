package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestParsePreviousKeysAcceptsValidKey(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	enc := base64.RawURLEncoding.EncodeToString(pub)
	keys, err := parsePreviousKeys([]previousKeyEntry{{Kid: "key-1", PublicKey: enc}})
	if err != nil || len(keys) != 1 || keys[0].kid != "key-1" {
		t.Fatalf("valid key rejected: %v %v", keys, err)
	}
}

func TestParsePreviousKeysRejectsBadEntries(t *testing.T) {
	good := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	cases := map[string]previousKeyEntry{
		"no kid":     {PublicKey: good},
		"not base64": {Kid: "k", PublicKey: "***"},
		"short key":  {Kid: "k", PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 5))},
	}
	for name, e := range cases {
		if _, err := parsePreviousKeys([]previousKeyEntry{e}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
