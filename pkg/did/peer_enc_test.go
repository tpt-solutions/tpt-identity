package did_test

import (
	"bytes"
	"testing"

	"github.com/multiformats/go-multibase"

	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// Every did:peer X25519 key must decode, as multibase, to its multicodec prefix and its own bytes. Before the
// fix the key was written with a "z" (base58btc) prefix over base64url text, and about 2% of keys decoded to
// other bytes.
func TestPeerX25519KeyDecodesToItsOwnBytes(t *testing.T) {
	for i := 0; i < 500; i++ {
		signPub, _, err := crypto.GenerateSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		encPub, _, err := crypto.GenerateEncryptionKey()
		if err != nil {
			t.Fatal(err)
		}
		_, doc, err := did.Create("peer", did.CreateOptions{SigningPub: signPub, EncPub: encPub[:]})
		if err != nil {
			t.Fatal(err)
		}
		var mb string
		for _, vm := range doc.VerificationMethod {
			if vm.Type == "X25519KeyAgreementKey2020" && vm.PublicKeyMultibase != nil {
				mb = *vm.PublicKeyMultibase
			}
		}
		if mb == "" {
			t.Fatal("no X25519 key in the peer document")
		}
		_, raw, err := multibase.Decode(mb)
		if err != nil {
			t.Fatalf("iteration %d: %q does not decode as multibase: %v", i, mb, err)
		}
		want := append([]byte{0xEC, 0x01}, encPub[:]...)
		if !bytes.Equal(raw, want) {
			t.Fatalf("iteration %d: %q decodes to other bytes", i, mb)
		}
	}
}
