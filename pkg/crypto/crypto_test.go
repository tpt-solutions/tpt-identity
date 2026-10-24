package crypto_test

import (
	"testing"

	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello tpt-identity")
	sig, err := crypto.Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.Verify(pub, msg, sig); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestVerifyRejectsAlteredMessage(t *testing.T) {
	pub, priv, _ := crypto.GenerateSigningKey()
	sig, _ := crypto.Sign(priv, []byte("original"))
	if err := crypto.Verify(pub, []byte("tampered"), sig); err == nil {
		t.Error("expected verify to fail on tampered message")
	}
}

func TestSignJSON(t *testing.T) {
	_, priv, _ := crypto.GenerateSigningKey()
	type payload struct {
		Name string `json:"name"`
	}
	sig, err := crypto.SignJSON(priv, payload{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestJCS_DeterministicOutput(t *testing.T) {
	// Two structs with the same data should produce the same JCS bytes.
	type obj struct {
		Z string `json:"z"`
		A string `json:"a"`
		M string `json:"m"`
	}
	v := obj{Z: "z", A: "a", M: "m"}
	b1, err := crypto.JCS(v)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := crypto.JCS(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Errorf("JCS not deterministic: %s vs %s", b1, b2)
	}
	// Keys should be sorted alphabetically.
	s := string(b1)
	aIdx := indexOf(s, `"a"`)
	mIdx := indexOf(s, `"m"`)
	zIdx := indexOf(s, `"z"`)
	if !(aIdx < mIdx && mIdx < zIdx) {
		t.Errorf("JCS keys not sorted: %s", s)
	}
}

func TestJCS_MapKeySorted(t *testing.T) {
	m := map[string]string{"z": "1", "a": "2", "m": "3"}
	b, err := crypto.JCS(m)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	aIdx := indexOf(s, `"a"`)
	mIdx := indexOf(s, `"m"`)
	zIdx := indexOf(s, `"z"`)
	if !(aIdx < mIdx && mIdx < zIdx) {
		t.Errorf("JCS map keys not sorted: %s", s)
	}
}

func TestHashJSON(t *testing.T) {
	h, err := crypto.HashJSON(map[string]string{"key": "value"})
	if err != nil {
		t.Fatal(err)
	}
	if len(h) == 0 {
		t.Error("expected non-empty hash")
	}
	// Same input → same hash.
	h2, _ := crypto.HashJSON(map[string]string{"key": "value"})
	if h != h2 {
		t.Error("HashJSON not deterministic")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	_, priv, err := crypto.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	// Seal/Open with the same symmetric key derived from priv for simplicity.
	plain := []byte("secret message")
	ct, err := crypto.Seal(priv, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.Open(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Errorf("Open: got %q, want %q", got, plain)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	_, priv, _ := crypto.GenerateEncryptionKey()
	ct, _ := crypto.Seal(priv, []byte("secret"))
	ct[len(ct)-1] ^= 0xff
	if _, err := crypto.Open(priv, ct); err == nil {
		t.Error("expected Open to fail on tampered ciphertext")
	}
}

func TestECDH(t *testing.T) {
	alicePub, alicePriv, _ := crypto.GenerateEncryptionKey()
	bobPub, bobPriv, _ := crypto.GenerateEncryptionKey()
	shared1, err := crypto.ECDH(alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}
	shared2, err := crypto.ECDH(bobPriv, alicePub)
	if err != nil {
		t.Fatal(err)
	}
	if shared1 != shared2 {
		t.Error("ECDH shared secrets do not match")
	}
}

func indexOf(s, sub string) int {
	for i := range s {
		if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
