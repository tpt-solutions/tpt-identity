package cmd

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/tpt-solutions/tpt-identity/pkg/schema"
	// Register the built-in schemas; the commands below read them from the registry.
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
)

func schemasCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "schemas",
		Short: "Browse the credential schema registry",
	}
	var category string
	list := &cobra.Command{
		Use:   "list",
		Short: "List credential schemas, optionally for one category",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			schemas := schema.AllSchemas()
			if category != "" {
				schemas = schema.SchemasForCategory(category)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tNAME\tEXTRA-SENSITIVE")
			for _, s := range schemas {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%t\n", s.ID, s.Name, s.ExtraSensitive)
			}
			return w.Flush()
		},
	}
	list.Flags().StringVar(&category, "category", "", "only schemas in this category, e.g. healthcare")
	c.AddCommand(list)
	c.AddCommand(&cobra.Command{
		Use:   "show <id>",
		Short: "Print one schema as JSON, including its claim definitions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := schema.GetSchema(args[0])
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return err
		},
	})
	return c
}
