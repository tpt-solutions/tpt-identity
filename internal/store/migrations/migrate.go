// Package migrations provides an embedded SQL migration runner.
// Migration files are numbered sequentially: 001_initial.sql, 002_add_foo.sql, etc.
// The runner tracks applied versions in a schema_migrations table and applies
// only unapplied migrations in order.
package migrations

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed *.sql
var files embed.FS

// Migration represents a single SQL migration file.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Load reads all embedded *.sql files and returns them sorted by version number.
func Load() ([]Migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("migrations: read dir: %w", err)
	}

	var migrations []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, name, err := parseName(e.Name())
		if err != nil {
			return nil, err
		}
		content, err := files.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("migrations: read %s: %w", e.Name(), err)
		}
		migrations = append(migrations, Migration{
			Version: version,
			Name:    name,
			SQL:     string(content),
		})
	}
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	return migrations, nil
}

// Up applies all unapplied migrations to db in order.
func Up(db *sql.DB) error {
	if err := ensureTable(db); err != nil {
		return err
	}
	applied, err := appliedVersions(db)
	if err != nil {
		return err
	}
	migrations, err := Load()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		if err := apply(db, m); err != nil {
			return fmt.Errorf("migrations: apply v%03d %s: %w", m.Version, m.Name, err)
		}
	}
	return nil
}

// Down rolls back the most recently applied migration.
// NOTE: SQL rollback is not generally reversible. This implementation only
// removes the version record; it does NOT execute a down-script. A full
// reversible migration system would require paired down files.
func Down(db *sql.DB) error {
	if err := ensureTable(db); err != nil {
		return err
	}
	row := db.QueryRow(`SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`)
	var v int
	if err := row.Scan(&v); err == sql.ErrNoRows {
		return fmt.Errorf("migrations: nothing to roll back")
	} else if err != nil {
		return fmt.Errorf("migrations: query latest version: %w", err)
	}
	_, err := db.Exec(`DELETE FROM schema_migrations WHERE version = ?`, v)
	if err != nil {
		return fmt.Errorf("migrations: remove version record %d: %w", v, err)
	}
	fmt.Printf("migrations: rolled back version %03d (schema_migrations record removed; manual DDL rollback required)\n", v)
	return nil
}

// Version returns the highest applied migration version, or 0 if none.
func Version(db *sql.DB) (int, error) {
	if err := ensureTable(db); err != nil {
		return 0, err
	}
	row := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	var v int
	return v, row.Scan(&v)
}

func ensureTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL
		)`)
	return err
}

func appliedVersions(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrations: query applied: %w", err)
	}
	defer rows.Close()
	m := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		m[v] = true
	}
	return m, rows.Err()
}

// hooks run Go code in the same transaction as a migration's SQL, for changes that SQL alone cannot
// express idempotently (SQLite has no ADD COLUMN IF NOT EXISTS).
var hooks = map[int]func(tx *sql.Tx) error{
	4: addMissingColumns,
	5: func(tx *sql.Tx) error { return addColumns(tx, firstPartyColumns) },
}

// columnAdd is one column an older table shape may lack.
type columnAdd struct {
	table, column, decl string
}

// reconcileColumns lists every column the server reads or writes that a table created by migrations
// 001-003 may lack. Each is added only when PRAGMA table_info shows it missing.
var reconcileColumns = []columnAdd{
	{"oidc_clients", "backchannel_logout_uri", "TEXT"},
	{"oidc_clients", "post_logout_redirect_uris", "JSON"},
	{"oidc_clients", "jwks", "TEXT NOT NULL DEFAULT ''"},
	{"recovery_requests", "commitment", "TEXT NOT NULL DEFAULT ''"},
	{"recovery_configs", "guardian_emails", "TEXT NOT NULL DEFAULT '{}'"},
	{"refresh_tokens", "family_id", "TEXT NOT NULL DEFAULT ''"},
	{"webhook_subscriptions", "signing_secret", "TEXT NOT NULL DEFAULT ''"},
	{"totp_credentials", "verified_at", "DATETIME"},
	{"totp_credentials", "last_step", "INTEGER NOT NULL DEFAULT 0"},
	{"consent_grants", "revoked_at", "DATETIME"},
	{"credential_offers", "tx_code_hash", "TEXT NOT NULL DEFAULT ''"},
	{"audit_log", "hash_version", "INTEGER NOT NULL DEFAULT 1"},
	{"audit_log", "recorded_at", "TEXT NOT NULL DEFAULT ''"},
	{"status_lists", "created_at", "DATETIME"},
}

// addMissingColumns adds each reconcileColumns entry that its table lacks. Existing columns are left alone.
// firstPartyColumns are the columns migration 005 adds.
var firstPartyColumns = []columnAdd{
	{"oidc_clients", "first_party", "INTEGER NOT NULL DEFAULT 0"},
}

// addMissingColumns applies the reconcileColumns list (version 4).
func addMissingColumns(tx *sql.Tx) error {
	return addColumns(tx, reconcileColumns)
}

// addColumns adds each listed column its table lacks.
func addColumns(tx *sql.Tx, list []columnAdd) error {
	for _, c := range list {
		has, err := hasColumn(tx, c.table, c.column)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", c.table, c.column, c.decl)); err != nil {
			return fmt.Errorf("add %s.%s: %w", c.table, c.column, err)
		}
	}
	return nil
}

// hasColumn reports whether table has a column named column. It reads PRAGMA table_info and closes the rows
// before returning, so the transaction can run other statements afterwards.
func hasColumn(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, rows.Err()
		}
	}
	return false, rows.Err()
}

func apply(db *sql.DB, m Migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(m.SQL); err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if hook, ok := hooks[m.Version]; ok {
		if err := hook(tx); err != nil {
			return fmt.Errorf("hook: %w", err)
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.Version, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("record version: %w", err)
	}
	return tx.Commit()
}

// parseName extracts the version number and description from a migration filename.
// Format: NNN_description.sql where NNN is a zero-padded integer.
func parseName(filename string) (version int, name string, err error) {
	base := strings.TrimSuffix(filename, ".sql")
	idx := strings.IndexByte(base, '_')
	if idx < 0 {
		return 0, "", fmt.Errorf("migrations: invalid filename %q (expected NNN_name.sql)", filename)
	}
	v, err := strconv.Atoi(base[:idx])
	if err != nil {
		return 0, "", fmt.Errorf("migrations: invalid version in %q: %w", filename, err)
	}
	return v, base[idx+1:], nil
}

// Latest returns the highest version of the embedded migrations, the schema this build expects.
func Latest() (int, error) {
	all, err := Load()
	if err != nil {
		return 0, err
	}
	if len(all) == 0 {
		return 0, nil
	}
	return all[len(all)-1].Version, nil
}
