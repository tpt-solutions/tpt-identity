package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
)

var trailingNumber = regexp.MustCompile(`^(.*-)(\d+)$`)

// nextSigningKeyID returns the key ID after current: "did:web:x#signing-key-1" becomes
// "did:web:x#signing-key-2". An ID without a trailing number gets "-2" appended.
func nextSigningKeyID(current string) string {
	if m := trailingNumber.FindStringSubmatch(current); m != nil {
		n, err := strconv.Atoi(m[2])
		if err == nil {
			return m[1] + strconv.Itoa(n+1)
		}
	}
	return current + "-2"
}

// rotationNotes is the operator guidance printed after a rotation. It states the two timing rules
// that matter: verifiers cache the DID document, and the retired private key is no longer needed.
const rotationNotes = `Notes:
  - Restart the server to start signing with the new key. Until then it keeps signing with the old key.
  - Verifiers cache the platform DID document for up to 5 minutes, so credentials signed right after
    the restart may fail to verify for a short time. Rotate during a quiet period if that matters.
  - The retired key stays in identity.previous_keys for as long as credentials or tokens it signed are
    still valid. Its public key is what verifiers need, so keep the entry. The private key file is no
    longer used for signing and can be archived.`

// rotationSnippet renders the config change for a rotation. previous is the existing retired-key list;
// the outgoing key is added to it. The output has no private key material.
func rotationSnippet(newPath, newKeyID, oldKeyID, oldPubB64 string, previous []previousKeyEntry) string {
	var b strings.Builder
	b.WriteString("identity:\n")
	fmt.Fprintf(&b, "  signing_key: %q\n", newPath)
	fmt.Fprintf(&b, "  key_id: %q\n", newKeyID)
	b.WriteString("  previous_keys:\n")
	entries := append([]previousKeyEntry{{Kid: oldKeyID, PublicKey: oldPubB64}}, previous...)
	for _, e := range entries {
		fmt.Fprintf(&b, "    - kid: %q\n", e.Kid)
		fmt.Fprintf(&b, "      public_key: %q\n", e.PublicKey)
	}
	return b.String()
}

// checkRotationTarget refuses a rotation whose new key ID or file would collide with a key already in
// use, since either would replace a key that is still needed.
func checkRotationTarget(newKeyID, currentKeyID, newPath, currentPath string, previous []previousKeyEntry) error {
	if newKeyID == currentKeyID {
		return fmt.Errorf("new key ID %q is the current key ID", newKeyID)
	}
	for _, e := range previous {
		if e.Kid == newKeyID {
			return fmt.Errorf("new key ID %q is already a retired key", newKeyID)
		}
	}
	if filepath.Clean(newPath) == filepath.Clean(currentPath) {
		return fmt.Errorf("refusing to overwrite the current signing key %s", currentPath)
	}
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("%s already exists; choose a new file", newPath)
	}
	return nil
}

func rotateKeyCmd() *cobra.Command {
	var (
		outSign string
		keyID   string
	)
	c := &cobra.Command{
		Use:   "rotate-key",
		Short: "Generate a new platform signing key and print the config change",
		Long: `Generates a new Ed25519 signing key and writes it encrypted with identity.passphrase. The
current key becomes a retired key: it stays in the platform DID document and in identity.previous_keys,
so credentials and tokens it signed keep verifying.

The config file is not edited, because rewriting YAML would drop its comments. The command prints the
identity block to paste in, then the server must be restarted.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := readConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("read config: %w", err)
			}
			platformDID, err := api.PlatformDID(v.GetString("issuer"))
			if err != nil {
				return fmt.Errorf("issuer: %w", err)
			}
			currentPath := v.GetString("identity.signing_key")
			currentKeyID := v.GetString("identity.key_id")
			if currentKeyID == "" {
				currentKeyID = platformDID + "#signing-key-1"
			}
			var previous []previousKeyEntry
			if err := v.UnmarshalKey("identity.previous_keys", &previous); err != nil {
				return fmt.Errorf("identity.previous_keys: %w", err)
			}

			newKeyID := keyID
			if newKeyID == "" {
				newKeyID = nextSigningKeyID(currentKeyID)
			}
			if err := checkRotationTarget(newKeyID, currentKeyID, outSign, currentPath, previous); err != nil {
				return err
			}

			current, err := keystore.LoadSigning(currentPath, v.GetString("identity.passphrase"))
			if err != nil {
				return fmt.Errorf("load current signing key: %w", err)
			}
			next, err := keystore.Generate()
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}
			if err := keystore.SaveSigning(next, outSign, v.GetString("identity.passphrase")); err != nil {
				return fmt.Errorf("save new key: %w", err)
			}

			out := cmd.OutOrStdout()
			oldPub := base64.RawURLEncoding.EncodeToString(current.SigningPub)
			fmt.Fprintf(out, "Generated %s (key ID %s). Current key %s is retired.\n\n", outSign, newKeyID, currentKeyID)
			fmt.Fprintln(out, "Replace the identity block in your config with:")
			fmt.Fprintln(out)
			fmt.Fprint(out, rotationSnippet(outSign, newKeyID, currentKeyID, oldPub, previous))
			fmt.Fprintln(out)
			fmt.Fprintln(out, rotationNotes)
			return nil
		},
	}
	c.Flags().StringVar(&outSign, "out-sign", "", "file for the new Ed25519 signing key (must not exist)")
	c.Flags().StringVar(&keyID, "key-id", "", "key ID for the new key (default: the current key ID with its number incremented)")
	_ = c.MarkFlagRequired("out-sign")
	return c
}
