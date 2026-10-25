package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	prev := ""
	for _, e := range events {
		if e.PrevHash != prev {
			t.Fatalf("seq %d links to %q, want %q (chain forked)", e.Seq, e.PrevHash, prev)
		}
		raw, _ := json.Marshal(map[string]string{"event_type": e.EventType, "payload": e.Payload, "prev_hash": e.PrevHash})
		sum := sha256.Sum256(append([]byte(e.PrevHash), raw...))
		if got := hex.EncodeToString(sum[:]); got != e.Hash {
			t.Fatalf("seq %d hash does not recompute", e.Seq)
		}
		prev = e.Hash
	}
}
