package api

import (
	"encoding/base64"
	"testing"

	"github.com/multiformats/go-multibase"

	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

// Documents written before the did:peer fix carry base64url under a "z" prefix. For some keys base58 decodes
// that text to other bytes. The decoder must still return the key, which needs the codec check, not the prefix.
func TestX25519DecoderAcceptsLegacyZPrefixEvenWhenBase58Misreads(t *testing.T) {
	exercised := 0
	for i := 0; i < 20000 && exercised < 3; i++ {
		encPub, _, err := crypto.GenerateEncryptionKey()
		if err != nil {
			t.Fatal(err)
		}
		legacy := "z" + base64.RawURLEncoding.EncodeToString(append([]byte{0xEC, 0x01}, encPub[:]...))
		_, misread, err := multibase.Decode(legacy)
		if err != nil || (len(misread) >= 2 && misread[0] == 0xEC && misread[1] == 0x01) {
			continue // base58 reads this one correctly, or not at all; it does not exercise the bug
		}
		exercised++
		got, err := decodeX25519Multibase(legacy)
		if err != nil || got != encPub {
			t.Fatalf("legacy key %q not recovered: err=%v", legacy, err)
		}
	}
	if exercised < 3 {
		t.Fatalf("only %d keys exercised the base58 misread; widen the search", exercised)
	}
}
