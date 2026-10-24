package authn

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// LockoutManager enforces per-identity brute-force lockout.
type LockoutManager struct {
	st store.Store
}

// NewLockoutManager creates a LockoutManager.
func NewLockoutManager(st store.Store) *LockoutManager {
	return &LockoutManager{st: st}
}

// CheckLocked returns an error if the subject is currently locked out.
func (m *LockoutManager) CheckLocked(ctx context.Context, subjectOrEmail string) error {
	_, lockedUntil, err := m.st.GetAuthFailures(ctx, subjectOrEmail)
	if err != nil {
		return nil // no record = not locked
	}
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		remaining := time.Until(*lockedUntil).Round(time.Second)
		return fmt.Errorf("account locked for %s", remaining)
	}
	return nil
}

// RecordFailure increments the failure count and updates the lockout window.
func (m *LockoutManager) RecordFailure(ctx context.Context, subjectOrEmail string) error {
	return m.st.RecordAuthFailure(ctx, subjectOrEmail)
}

// RecordSuccess clears the failure count on a successful authentication.
func (m *LockoutManager) RecordSuccess(ctx context.Context, subjectOrEmail string) {
	_ = m.st.ClearAuthFailures(ctx, subjectOrEmail)
}

// AdminReset clears the lockout — for use by the admin API.
func (m *LockoutManager) AdminReset(ctx context.Context, subjectOrEmail string) error {
	if err := m.st.ClearAuthFailures(ctx, subjectOrEmail); err != nil {
		return fmt.Errorf("lockout: admin reset: %w", err)
	}
	return nil
}

// ErrLocked is returned when the account is locked.
var ErrLocked = errors.New("account locked")
