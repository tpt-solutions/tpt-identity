package bridge_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

func newMapperStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// A second login for the same external account reuses the platform DID.
func TestFindOrCreateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	m := bridge.NewMapper(newMapperStore(t))
	ext := &bridge.ExternalIdentity{Provider: "idp", ExternalID: "user-1"}

	first, isNew, err := m.FindOrCreate(ctx, ext)
	if err != nil || !isNew {
		t.Fatalf("first login: did=%q isNew=%v err=%v", first, isNew, err)
	}
	second, isNew, err := m.FindOrCreate(ctx, ext)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if isNew || second != first {
		t.Errorf("second login: want %q not new, got %q isNew=%v", first, second, isNew)
	}
}

// Concurrent first logins for one account create exactly one platform identity.
func TestConcurrentFirstLoginCreatesOneIdentity(t *testing.T) {
	ctx := context.Background()
	st := newMapperStore(t)
	m := bridge.NewMapper(st)
	ext := &bridge.ExternalIdentity{Provider: "idp", ExternalID: "user-race"}

	var wg sync.WaitGroup
	dids := make([]string, 16)
	for i := range dids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			did, _, err := m.FindOrCreate(ctx, ext)
			if err != nil {
				t.Errorf("FindOrCreate: %v", err)
				return
			}
			dids[i] = did
		}(i)
	}
	wg.Wait()

	for _, did := range dids {
		if did != dids[0] {
			t.Fatalf("concurrent logins returned different DIDs: %q and %q", dids[0], did)
		}
	}
	_, total, err := st.ListIdentities(ctx, 100, 0)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if total != 1 {
		t.Errorf("want 1 platform identity, got %d", total)
	}
}

// A lookup failure that is not "not found" must surface, not start a new identity.
func TestIsNotFoundIsExact(t *testing.T) {
	if !bridge.IsNotFoundForTest(store.ErrNotFound) {
		t.Error("ErrNotFound not recognised")
	}
	if bridge.IsNotFoundForTest(errors.New("disk on fire: resource not found in cache")) {
		t.Error("an unrelated error mentioning 'not found' was treated as not found")
	}
}
