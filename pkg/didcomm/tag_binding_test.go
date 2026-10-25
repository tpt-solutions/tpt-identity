package didcomm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// The ECDH-1PU KEK depends on the content tag: a different tag gives a different key.
func TestConcatKDFBindsContentTagForAuthcrypt(t *testing.T) {
	z := bytes.Repeat([]byte{7}, 64)
	tagA := bytes.Repeat([]byte{1}, 16)
	tagB := bytes.Repeat([]byte{2}, 16)

	kA, err := concatKDF(z, algAuthcrypt, "", "apv", tagA)
	if err != nil {
		t.Fatal(err)
	}
	kB, err := concatKDF(z, algAuthcrypt, "", "apv", tagB)
	if err != nil {
		t.Fatal(err)
	}
	if kA == kB {
		t.Error("KEK does not depend on the content tag")
	}
}

// Anoncrypt has no content tag in its KDF, so nil SuppPrivInfo keeps the ECDH-ES derivation.
func TestConcatKDFNilSuppPrivIsUnchangedFromECDHES(t *testing.T) {
	z := bytes.Repeat([]byte{9}, 32)
	withNil, err := concatKDF(z, algAnoncrypt, "", "apv", nil)
	if err != nil {
		t.Fatal(err)
	}
	withEmpty, err := concatKDF(z, algAnoncrypt, "", "apv", []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if withNil != withEmpty {
		t.Error("nil and empty SuppPrivInfo derive different keys")
	}
	withTag, _ := concatKDF(z, algAnoncrypt, "", "apv", bytes.Repeat([]byte{1}, 16))
	if withNil == withTag {
		t.Error("SuppPrivInfo has no effect on the derived key")
	}
}

// An authcrypt envelope whose tag is replaced no longer unpacks, even though the sender and recipient
// keys are right: the tag is part of the key agreement, and the AEAD check also covers it.
func TestAuthcryptRejectsSwappedContentTag(t *testing.T) {
	recipPriv, recipPub, err := generateX25519()
	if err != nil {
		t.Fatal(err)
	}
	senderPriv, senderPub, err := generateX25519()
	if err != nil {
		t.Fatal(err)
	}
	packed, err := PackAuthcrypt([]byte(`{"id":"m1"}`), []Recipient{{KID: "did:example:bob#enc-1", PubKey: recipPub}}, "did:example:alice#enc-1", senderPriv)
	if err != nil {
		t.Fatal(err)
	}

	var env Envelope
	if err := json.Unmarshal(packed, &env); err != nil {
		t.Fatal(err)
	}
	env.Tag = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 16))
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	recipKey := func(kid string) ([32]byte, error) { return recipPriv, nil }
	senderKey := func(skid string) ([32]byte, error) { return senderPub, nil }
	if _, _, err := Unpack(tampered, recipKey, senderKey); err == nil {
		t.Error("envelope with a swapped content tag unpacked")
	}
	if _, _, err := Unpack(packed, recipKey, senderKey); err != nil {
		t.Errorf("original envelope: %v", err)
	}
}
