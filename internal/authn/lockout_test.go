package authn_test

import (
	"context"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/authn"
)

func newLockoutManager(t *testing.T) *authn.LockoutManager {
	t.Helper()
	st := storetest.New(t)
	return authn.NewLockoutManager(st)
}

func TestUnknownSubjectIsNotLocked(t *testing.T) {
	m := newLockoutManager(t)
	if err := m.CheckLocked(context.Background(), "nobody@example.com"); err != nil {
		t.Errorf("unknown subject reported locked: %v", err)
	}
}

// Five failures lock the account; the lock is enforced by CheckLocked, not only recorded.
func TestFiveFailuresLockAccount(t *testing.T) {
	ctx := context.Background()
	m := newLockoutManager(t)
	for i := 0; i < 5; i++ {
		if err := m.RecordFailure(ctx, "alice@example.com"); err != nil {
			t.Fatalf("record failure %d: %v", i+1, err)
		}
	}
	if err := m.CheckLocked(ctx, "alice@example.com"); err == nil {
		t.Error("account not locked after 5 failures")
	}
}

func TestSuccessClearsFailures(t *testing.T) {
	ctx := context.Background()
	m := newLockoutManager(t)
	for i := 0; i < 4; i++ {
		_ = m.RecordFailure(ctx, "bob@example.com")
	}
	m.RecordSuccess(ctx, "bob@example.com")
	_ = m.RecordFailure(ctx, "bob@example.com")
	if err := m.CheckLocked(ctx, "bob@example.com"); err != nil {
		t.Errorf("success did not reset the failure count: %v", err)
	}
}

func TestAdminResetUnlocks(t *testing.T) {
	ctx := context.Background()
	m := newLockoutManager(t)
	for i := 0; i < 5; i++ {
		_ = m.RecordFailure(ctx, "carol@example.com")
	}
	if err := m.AdminReset(ctx, "carol@example.com"); err != nil {
		t.Fatalf("admin reset: %v", err)
	}
	if err := m.CheckLocked(ctx, "carol@example.com"); err != nil {
		t.Errorf("still locked after admin reset: %v", err)
	}
}
