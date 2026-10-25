package store_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// openPostgresSchema gives a test its own PostgreSQL schema under the database named by TPT_TEST_POSTGRES_DSN,
// and returns a DSN whose search path is that schema. The schema is dropped when the test ends. The tests are
// skipped when the variable is unset, as the other PostgreSQL tests are.
func openPostgresSchema(t *testing.T) (admin *sql.DB, dsn string) {
	t.Helper()
	base := os.Getenv(pgTestEnv)
	if base == "" {
		t.Skipf("set %s to run the PostgreSQL migration tests", pgTestEnv)
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	schema := "mig_" + hex.EncodeToString(buf)
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return admin, base + sep + "search_path=" + schema
}

const pgTestEnv = "TPT_TEST_POSTGRES_DSN"

// A fresh PostgreSQL database is built by the versioned migrations and reports its version.
func TestPostgresFreshDatabaseIsVersioned(t *testing.T) {
	_, dsn := openPostgresSchema(t)
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	applied, latest, err := st.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if applied != latest || latest < 1 {
		t.Errorf("schema version: applied %d, latest %d", applied, latest)
	}
}

// A schema created before versioning existed, with no schema_migrations table, is recorded as migrated when the
// server next opens it, and its data is untouched.
func TestPostgresSchemaWithoutVersionRecordIsRecorded(t *testing.T) {
	admin, dsn := openPostgresSchema(t)
	ctx := context.Background()

	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveClient(ctx, &store.OIDCClient{
		ClientID: "pre-versioning", ClientName: "old", TokenEndpointAuthMethod: "none",
		RedirectURIs: []string{"https://old.example/cb"}, GrantTypes: []string{"authorization_code"},
		FirstParty: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	// Remove the version record, which is what a database from before versioning looks like.
	schema := searchPath(t, dsn)
	if _, err := admin.Exec(`DROP TABLE ` + schema + `.schema_migrations`); err != nil {
		t.Fatal(err)
	}

	st, err = store.OpenPostgres(dsn)
	if err != nil {
		t.Fatalf("reopen without a version record: %v", err)
	}
	defer st.Close()
	applied, latest, err := st.SchemaVersion(ctx)
	if err != nil || applied != latest {
		t.Errorf("after reopening: applied %d, latest %d (%v)", applied, latest, err)
	}
	got, err := st.GetClient(ctx, "pre-versioning")
	if err != nil {
		t.Fatalf("data lost on reopen: %v", err)
	}
	if !got.FirstParty || got.ClientName != "old" {
		t.Errorf("client changed on reopen: %+v", got)
	}
}

// searchPath returns the schema a DSN's search_path names.
func searchPath(t *testing.T, dsn string) string {
	t.Helper()
	i := strings.Index(dsn, "search_path=")
	if i < 0 {
		t.Fatal("no search_path in DSN")
	}
	rest := dsn[i+len("search_path="):]
	if j := strings.IndexAny(rest, "&"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
