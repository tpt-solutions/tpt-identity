package cmd

import "github.com/spf13/cobra"

var cfgFile string

func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "tpt-identity",
		Short: "Sovereign identity platform for the TPT ecosystem",
		Long: `tpt-identity provides DID management, Verifiable Credentials, consent
receipts, and an OIDC identity provider built on open standards.`,
	}
	root.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "config file path")
	root.AddCommand(serveCmd())
	root.AddCommand(keygenCmd())
	root.AddCommand(rotateKeyCmd())
	root.AddCommand(resolveCmd())
	root.AddCommand(issueVCCmd())
	root.AddCommand(verifyVCCmd())
	root.AddCommand(migrateCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(configCmd())
	root.AddCommand(schemasCmd())
	root.AddCommand(initCmd())
	root.AddCommand(doctorCmd())
	return root
}
