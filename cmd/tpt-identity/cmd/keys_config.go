package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/spf13/viper"
)

// previousKeyEntry is one retired signing key in identity.previous_keys: its kid and its raw
// Ed25519 public key, base64url-encoded (the "x" value of its JWK).
type previousKeyEntry struct {
	Kid       string `mapstructure:"kid"`
	PublicKey string `mapstructure:"public_key"`
}

type retiredKey struct {
	kid string
	pub ed25519.PublicKey
}

// parsePreviousKeys decodes and checks the retired keys. Each key must have a kid and decode to 32
// bytes.
func parsePreviousKeys(entries []previousKeyEntry) ([]retiredKey, error) {
	out := make([]retiredKey, 0, len(entries))
	for i, e := range entries {
		if e.Kid == "" {
			return nil, fmt.Errorf("identity.previous_keys[%d] has no kid", i)
		}
		raw, err := base64.RawURLEncoding.DecodeString(e.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("identity.previous_keys %q: public_key is not base64url: %w", e.Kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("identity.previous_keys %q: public_key is %d bytes, want %d", e.Kid, len(raw), ed25519.PublicKeySize)
		}
		out = append(out, retiredKey{kid: e.Kid, pub: raw})
	}
	return out, nil
}

// loadPreviousKeys reads identity.previous_keys from the loaded configuration.
func loadPreviousKeys() ([]retiredKey, error) {
	var entries []previousKeyEntry
	if err := viper.UnmarshalKey("identity.previous_keys", &entries); err != nil {
		return nil, fmt.Errorf("identity.previous_keys: %w", err)
	}
	return parsePreviousKeys(entries)
}
