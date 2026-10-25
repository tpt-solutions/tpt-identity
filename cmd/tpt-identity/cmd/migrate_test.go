package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/store/migrations"
)

// migrate opens the database the --config file names, in that file's directory, and never a database in
// the working directory.
func TestMigrateUsesConfigFileDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "from-config.db")
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("db_path: \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = prev })

	db, _, err := openMigrationDB()
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	if err := migrations.Up(db); err != nil {
		t.Fatalf("migrate through the connection: %v", err)
	}
	_ = db.Close()
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("database not created at the config's db_path: %v", err)
	}
}

// A config file that cannot be read is an error, not a database in the working directory.
func TestMigrateRefusesMissingConfig(t *testing.T) {
	prev := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "absent.yaml")
	t.Cleanup(func() { cfgFile = prev })
	if _, _, err := openMigrationDB(); err == nil {
		t.Error("missing config accepted")
	}
}
