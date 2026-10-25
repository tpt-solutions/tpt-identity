package store_test

import (
	"context"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"sync"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

func newStatusStore(t *testing.T) store.Store {
	t.Helper()
	st := storetest.New(t)
	return st
}

// Concurrent allocations never hand out the same index, and a full list refuses.
func TestAllocateStatusIndexUniqueUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	st := newStatusStore(t)
	if err := st.CreateStatusList(ctx, &store.StatusListRecord{
		ID: "https://id.example/api/v1/status/a", IssuerDID: "did:web:id.example", SizeBits: 64, Bits: make([]byte, 8),
	}); err != nil {
		t.Fatal(err)
	}

	const n = 40
	var mu sync.Mutex
	seen := map[int]bool{}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			idx, err := st.AllocateStatusIndex(ctx, "https://id.example/api/v1/status/a")
			if err != nil {
				t.Errorf("allocate: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[idx] {
				t.Errorf("index %d handed out twice", idx)
			}
			seen[idx] = true
		}()
	}
	wg.Wait()
	if len(seen) != n {
		t.Errorf("want %d distinct indices, got %d", n, len(seen))
	}
}

// Setting a bit persists, and the list reports as full once every index is assigned.
func TestSetStatusBitPersistsAndListFills(t *testing.T) {
	ctx := context.Background()
	st := newStatusStore(t)
	id := "https://id.example/api/v1/status/b"
	if err := st.CreateStatusList(ctx, &store.StatusListRecord{
		ID: id, IssuerDID: "did:web:id.example", SizeBits: 8, Bits: make([]byte, 1),
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := st.AllocateStatusIndex(ctx, id); err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
	}
	if _, err := st.AllocateStatusIndex(ctx, id); err != store.ErrStatusListFull {
		t.Errorf("full list: want ErrStatusListFull, got %v", err)
	}

	rec, err := st.SetStatusBit(ctx, id, 5)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Bits[0]&(1<<5) == 0 {
		t.Error("bit 5 not set in the returned record")
	}
	stored, err := st.GetStatusList(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Bits[0]&(1<<5) == 0 {
		t.Error("bit 5 not persisted")
	}
	if _, err := st.SetStatusBit(ctx, id, 8); err == nil {
		t.Error("index past the list end was accepted")
	}
}
