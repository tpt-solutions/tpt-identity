package cmd

import (
	"database/sql"
	"fmt"

	"github.com/tpt-solutions/tpt-identity/internal/store/migrations"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	_ "modernc.org/sqlite"
)

func migrateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "migrate",
		Short: "Manage database schema migrations",
	}
	c.AddCommand(migrateUpCmd())
	c.AddCommand(migrateDownCmd())
	c.AddCommand(migrateVersionCmd())
	return c
}

func migrateUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Apply all unapplied migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openMigrationDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if err := migrations.Up(db); err != nil {
				return fmt.Errorf("migrate up: %w", err)
			}
			v, _ := migrations.Version(db)
			fmt.Printf("OK — schema at version %03d\n", v)
			return nil
		},
	}
}

func migrateDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Roll back the most recent migration (removes version record only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openMigrationDB()
			if err != nil {
				return err
			}
			defer db.Close()
			return migrations.Down(db)
		},
	}
}

func migrateVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the current schema version",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openMigrationDB()
			if err != nil {
				return err
			}
			defer db.Close()
			v, err := migrations.Version(db)
			if err != nil {
				return err
			}
			fmt.Printf("schema version: %03d\n", v)
			return nil
		},
	}
}

func openMigrationDB() (*sql.DB, error) {
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = "tpt-identity.db"
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
