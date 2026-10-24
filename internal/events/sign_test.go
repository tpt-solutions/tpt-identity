package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Receivers hold the raw signing secret, so the signature must be keyed by it.
func TestSignatureUsesRawSecret(t *testing.T) {
	body := []byte(`{"id":"evt_1","type":"consent.granted"}`)
	const secret = "whsec_0123456789abcdef"

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if got := computeHMAC(body, secret); got != want {
		t.Errorf("signature not keyed by raw secret: got %s want %s", got, want)
	}
}
