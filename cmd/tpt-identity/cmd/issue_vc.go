package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

func issueVCCmd() *cobra.Command {
	var (
		issuerDID  string
		keyFile    string
		passphrase string
		vmID       string
		subjectDID string
		schemaID   string
		claimsList []string
		validFor   time.Duration
	)
	c := &cobra.Command{
		Use:   "issue-vc",
		Short: "Issue a Verifiable Credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := keystore.LoadSigning(keyFile, passphrase)
			if err != nil {
				return fmt.Errorf("load signing key: %w", err)
			}
			if vmID == "" {
				vmID = issuerDID + "#signing-key-1"
			}
			claims := parseClaims(claimsList)
			cred, err := vc.Issue(vc.IssueOptions{
				IssuerDID:            issuerDID,
				IssuerKey:            ks.SigningPriv,
				VerificationMethodID: vmID,
				SubjectDID:           subjectDID,
				SchemaID:             schemaID,
				Claims:               claims,
				ValidFor:             validFor,
			})
			if err != nil {
				return fmt.Errorf("issue: %w", err)
			}
			b, _ := json.MarshalIndent(cred, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
	c.Flags().StringVar(&issuerDID, "issuer", "", "Issuer DID (required)")
	c.Flags().StringVar(&keyFile, "key", "ed25519.pem", "Path to Ed25519 private key PEM")
	c.Flags().StringVar(&passphrase, "passphrase", "", "Key passphrase")
	c.Flags().StringVar(&vmID, "vm", "", "Verification method ID (default: <issuer>#signing-key-1)")
	c.Flags().StringVar(&subjectDID, "subject", "", "Subject DID (required)")
	c.Flags().StringVar(&schemaID, "schema", "", "Schema ID e.g. healthcare.gp-records (required)")
	c.Flags().StringArrayVar(&claimsList, "claim", nil, "Claim key=value (repeatable)")
	c.Flags().DurationVar(&validFor, "valid-for", 8760*time.Hour, "Credential validity duration (0 = no expiry)")
	_ = c.MarkFlagRequired("issuer")
	_ = c.MarkFlagRequired("subject")
	_ = c.MarkFlagRequired("schema")
	return c
}

func parseClaims(pairs []string) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, _ := strings.Cut(p, "=")
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return m
}
