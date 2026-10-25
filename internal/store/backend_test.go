package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
)

// Concurrent redemptions of one authorization code: exactly one wins, the rest find nothing. The
// code is single-use, so a race that let two callers redeem it would issue two token sets.
func TestConcurrentCodeRedemptionHasOneWinner(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	if err := st.SaveSession(ctx, &store.OIDCSession{
		ID: "sess-1", SubjectDID: "did:key:z6MkTest", ClientID: "client-1",
		RedirectURI: "https://rp.example/cb", Code: "code-once",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	const racers = 20
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, err := st.TakeSessionByCode(ctx, "code-once")
			if err != nil {
				return // the losers see no session
			}
			if sess == nil || sess.ID != "sess-1" {
				t.Errorf("unexpected session %+v", sess)
				return
			}
			mu.Lock()
			wins++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("code redeemed %d times, want exactly 1", wins)
	}
}

// Replicas that start together share one schema: the concurrent first-start migrations must all
// succeed. Without the schema lock, PostgreSQL can fail one of them with a duplicate-type error.
func TestConcurrentPostgresStartupMigrates(t *testing.T) {
	dsn := os.Getenv(storetest.EnvDSN)
	if dsn == "" {
		t.Skipf("set %s to run PostgreSQL tests", storetest.EnvDSN)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := fmt.Sprintf("t_start_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	target := dsn + sep + "search_path=" + schema

	const replicas = 6
	var wg sync.WaitGroup
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := store.OpenPostgres(target)
			if err != nil {
				errs <- err
				return
			}
			errs <- st.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("replica failed to start: %v", err)
		}
	}
}
