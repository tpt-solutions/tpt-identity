package store_test

import (
	"context"

	"fmt"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"sync"
	"testing"
)

// Concurrent appends form one chain: each event links to the event before it, and every hash
// recomputes from its fields. A forked head would show up as a broken link.
func TestConcurrentAuditAppendsFormOneChain(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)

	const appends = 40
	var wg sync.WaitGroup
	for i := 0; i < appends; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := st.AppendAuditEvent(ctx, "test.event", fmt.Sprintf(`{"n":%d}`, i)); err != nil {
				t.Errorf("append %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	events, total, err := st.ListAuditEvents(ctx, appends+10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != appends || len(events) != appends {
		t.Fatalf("want %d events, got total=%d listed=%d", appends, total, len(events))
	}

	if err := store.VerifyAuditChain(events); err != nil {
		t.Fatalf("chain does not verify: %v", err)
	}
	for _, e := range events {
		if e.HashVersion != store.AuditHashV2 || e.RecordedAt == "" {
			t.Fatalf("seq %d: new event is not v2 with a recorded time", e.Seq)
		}
	}
}
