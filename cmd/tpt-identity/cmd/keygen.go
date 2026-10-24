package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
)

func keygenCmd() *cobra.Command {
	var (
		method     string
		domain     string
		outSign    string
		outEnc     string
		passphrase string
	)
	c := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a keypair and DID",
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := keystore.Generate()
			if err != nil {
				return fmt.Errorf("generate keys: %w", err)
			}
			if outSign != "" {
				if err := keystore.SaveSigning(ks, outSign, passphrase); err != nil {
					return fmt.Errorf("save signing key: %w", err)
				}
				fmt.Fprintln(os.Stderr, "Signing key saved to", outSign)
			}
			if outEnc != "" {
				if err := keystore.SaveEncryption(ks, outEnc, passphrase); err != nil {
					return fmt.Errorf("save encryption key: %w", err)
				}
				fmt.Fprintln(os.Stderr, "Encryption key saved to", outEnc)
			}
			id, doc, err := did.Create(method, did.CreateOptions{
				Domain:     domain,
				SigningPub: ks.SigningPub,
				EncPub:     ks.EncPub[:],
			})
			if err != nil {
				return fmt.Errorf("create DID: %w", err)
			}
			fmt.Println("DID:", id)
			b, _ := json.MarshalIndent(doc, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
	c.Flags().StringVar(&method, "method", "key", "DID method: web, key, peer")
	c.Flags().StringVar(&domain, "domain", "", "Domain for did:web (e.g. example.com)")
	c.Flags().StringVar(&outSign, "out-sign", "ed25519.pem", "Output path for Ed25519 private key")
	c.Flags().StringVar(&outEnc, "out-enc", "x25519.pem", "Output path for X25519 private key")
	c.Flags().StringVar(&passphrase, "passphrase", "", "Passphrase for key encryption (leave empty for plaintext)")
	return c
}
