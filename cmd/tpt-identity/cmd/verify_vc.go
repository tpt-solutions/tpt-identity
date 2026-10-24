package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
	"github.com/spf13/cobra"
)

func verifyVCCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-vc <credential.json>",
		Short: "Verify a Verifiable Credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
			var cred vc.VerifiableCredential
			if err := json.Unmarshal(data, &cred); err != nil {
				return fmt.Errorf("parse credential: %w", err)
			}
			r := resolver.New(5 * time.Minute)
			verifier := vc.NewVerifier(r)
			if err := verifier.Verify(&cred); err != nil {
				fmt.Fprintln(os.Stderr, "INVALID:", err)
				os.Exit(1)
			}
			fmt.Println("VALID")
			fmt.Println("  Issuer:  ", cred.Issuer)
			fmt.Println("  Subject: ", cred.CredentialSubject.ID)
			fmt.Println("  Schema:  ", cred.CredentialSchema.ID)
			fmt.Println("  ValidFrom:", cred.ValidFrom)
			return nil
		},
	}
}
