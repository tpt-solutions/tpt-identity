package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
)

func resolveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resolve <did>",
		Short: "Resolve a DID and print its DID Document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := resolver.New(5 * time.Minute)
			doc, err := r.Resolve(args[0])
			if err != nil {
				return fmt.Errorf("resolve: %w", err)
			}
			b, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		},
	}
}
