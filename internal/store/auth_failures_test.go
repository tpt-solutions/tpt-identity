package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// Concurrent failures for one subject are all counted: the read and write share a transaction.
func TestConcurrentAuthFailuresAllCounted(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const failures = 30
	var wg sync.WaitGroup
	for i := 0; i < failures; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := st.RecordAuthFailure(ctx, "target@example.com"); err != nil {
				t.Errorf("RecordAuthFailure: %v", err)
			}
		}()
	}
	wg.Wait()

	count, lockedUntil, err := st.GetAuthFailures(ctx, "target@example.com")
	if err != nil {
		t.Fatalf("GetAuthFailures: %v", err)
	}
	if count != failures {
		t.Errorf("want %d failures counted, got %d", failures, count)
	}
	if lockedUntil == nil || !lockedUntil.After(time.Now()) {
		t.Errorf("account not locked after %d failures", failures)
	}
}

// Failures below the first threshold do not lock the account.
func TestFewFailuresDoNotLock(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	for i := 0; i < 4; i++ {
		if err := st.RecordAuthFailure(ctx, "typo@example.com"); err != nil {
			t.Fatalf("RecordAuthFailure: %v", err)
		}
	}
	if _, lockedUntil, _ := st.GetAuthFailures(ctx, "typo@example.com"); lockedUntil != nil {
		t.Errorf("locked after 4 failures: until %v", *lockedUntil)
	}
}
