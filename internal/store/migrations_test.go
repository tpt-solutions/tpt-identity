package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/migrations"
)

// columnsOf lists the column names of a table in a SQLite file.
func columnsOf(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		cols[name] = true
	}
	return cols
}

// requiredColumns are columns the server reads or writes, including ones older shapes lack.
var requiredColumns = map[string][]string{
	"webhook_subscriptions": {"signing_secret", "tenant_id"},
	"oidc_clients":          {"jwks", "backchannel_logout_uri", "post_logout_redirect_uris"},
	"audit_log":             {"hash_version", "recorded_at"},
	"recovery_configs":      {"guardian_emails"},
	"recovery_requests":     {"commitment"},
	"refresh_tokens":        {"family_id"},
	"totp_credentials":      {"verified_at", "last_step"},
	"consent_grants":        {"revoked_at"},
	"credential_offers":     {"tx_code_hash"},
	"status_lists":          {"created_at"},
}

// requiredTables are tables the server uses that migrations 001-003 do not create.
var requiredTables = []string{
	"passwords", "revoked_access_tokens", "status_lists", "oid4vp_requests", "oid4vp_responses",
	"didcomm_seen", "didcomm_inbox", "sdjwt_issued", "schema_migrations",
}

func assertCurrentSchema(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	version, err := migrations.Version(db)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := migrations.Load()
	if err != nil {
		t.Fatal(err)
	}
	if want := latest[len(latest)-1].Version; version != want {
		t.Errorf("schema version: want %d, got %d", want, version)
	}
	for _, table := range requiredTables {
		if len(columnsOf(t, db, table)) == 0 {
			t.Errorf("table %s missing", table)
		}
	}
	for table, cols := range requiredColumns {
		have := columnsOf(t, db, table)
		for _, c := range cols {
			if !have[c] {
				t.Errorf("%s.%s missing", table, c)
			}
		}
	}
}

// A new database is built to the current schema by the migrations alone.
func TestFreshDatabaseReachesCurrentSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	assertCurrentSchema(t, path)
}

// A database that only ever had migration files 001-003 applied (no server start, no version record) is
// brought up to date on the next start. Its webhook table lacks signing_secret, which the server needs.
func TestDatabaseFromMigrationFilesUpgrades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	all, err := migrations.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if m.Version > 3 {
			break
		}
		if _, err := db.Exec(m.SQL); err != nil {
			t.Fatalf("apply %03d: %v", m.Version, err)
		}
	}
	if cols := columnsOf(t, db, "webhook_subscriptions"); cols["signing_secret"] {
		t.Fatal("precondition: 001-003 should not create signing_secret")
	}
	_ = db.Close()

	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("open upgraded database: %v", err)
	}
	defer st.Close()
	assertCurrentSchema(t, path)

	// The upgraded store works: a webhook keeps its signing secret.
	ctx := context.Background()
	if err := st.SaveWebhookSubscription(ctx, &store.WebhookSubscription{
		ID: "wh_upgrade", URL: "https://example.com/hook", EventTypes: []string{"*"},
		SigningSecret: "whsec_upgrade", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("save webhook on upgraded database: %v", err)
	}
	got, err := st.GetWebhookSubscription(ctx, "wh_upgrade")
	if err != nil {
		t.Fatal(err)
	}
	if got.SigningSecret != "whsec_upgrade" {
		t.Errorf("signing secret: got %q", got.SigningSecret)
	}
}

// Opening a database again runs nothing new and keeps every row.
func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "again.db")
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendAuditEvent(context.Background(), "test.event", `{"n":1}`); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	st, err = store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer st.Close()
	events, total, err := st.ListAuditEvents(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(events) != 1 {
		t.Errorf("rows changed across reopen: total %d", total)
	}
	assertCurrentSchema(t, path)
}

// The `migrate up` command runs the migrations on a plain file database, without the store. Migration SQL
// must work there too, so this path has its own test.
func TestRunnerMigratesPlainFileDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrations.Up(db); err != nil {
		t.Fatalf("runner on a plain file database: %v", err)
	}
	if err := migrations.Up(db); err != nil {
		t.Fatalf("second run: %v", err)
	}
	_ = db.Close()
	assertCurrentSchema(t, path)
}
