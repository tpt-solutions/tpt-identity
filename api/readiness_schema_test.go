package api_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

type readyzBody struct {
	Status string `json:"status"`
	Checks map[string]struct {
		OK bool `json:"ok"`
	} `json:"checks"`
}

// The readiness probe reports degraded when the schema is behind the version this build expects, and ready
// when it is current. Removing the version record for the newest migration makes the schema look behind.
func TestReadinessChecksSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready.db")
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		APIKey:       testAPIKey,
		Issuer:       testIssuer,
		SigningKey:   priv,
		SigningKeyID: testPlatformDID + "#signing-key-1",
		Store:        st,
		Resolver:     resolver.New(time.Minute),
		OIDC:         oidc.NewProvider(testIssuer, priv, "test-key-1", st),
	})

	readyz := func() (int, readyzBody) {
		w := do(t, srv, http.MethodGet, "/readyz", "", nil)
		var body readyzBody
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("readyz body: %v: %s", err, w.Body.String())
		}
		return w.Code, body
	}

	if code, body := readyz(); code != http.StatusOK || !body.Checks["schema"].OK {
		t.Fatalf("current schema: want ready, got %d %+v", code, body)
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, latest, err := st.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM schema_migrations WHERE version = ?`, latest); err != nil {
		t.Fatal(err)
	}

	code, body := readyz()
	if code != http.StatusServiceUnavailable || body.Status != "degraded" || body.Checks["schema"].OK {
		t.Errorf("schema behind: want degraded, got %d %+v", code, body)
	}
}
