// Package storetest gives tests a fresh store. It keeps the choice of database in one place, so
// the same test suite runs against SQLite and PostgreSQL.
package storetest

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// EnvDSN names the PostgreSQL database that tests run against. Unset, tests use in-memory SQLite.
//
//	TPT_TEST_POSTGRES_DSN=postgres://user:pass@localhost:5432/db go test ./...
const EnvDSN = "TPT_TEST_POSTGRES_DSN"

// New returns a fresh store for one test. SQLite is in memory. When EnvDSN is set, the store is a
// PostgreSQL schema of its own, dropped when the test ends, so tests never share state.
func New(t testing.TB) store.Store {
	t.Helper()
	dsn := os.Getenv(EnvDSN)
	if dsn == "" {
		st, err := store.OpenSQLite(":memory:")
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		return st
	}

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	schema := "t_" + hex.EncodeToString(buf)
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
	})

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	st, err := store.OpenPostgres(dsn + sep + "search_path=" + schema)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
