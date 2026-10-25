package auditlog_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/auditlog"
	"github.com/tpt-solutions/tpt-identity/internal/events"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

func TestPublishedEventsAreAppendedToChain(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := events.NewBus(st, logger)
	t.Cleanup(func() { _ = bus.Close(ctx) })
	auditlog.New(st, logger).Subscribe(bus)

	bus.Publish(ctx, "consent.granted", map[string]string{"grant_id": "g-1"})
	bus.Publish(ctx, "credential.issued", map[string]string{"credential_id": "c-1"})

	entries, total, err := st.ListAuditEvents(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(entries) != 2 {
		t.Fatalf("want 2 audit entries, got total=%d len=%d", total, len(entries))
	}

	// ListAuditEvents returns entries in sequence order.
	first, second := entries[0], entries[1]
	if first.EventType != "consent.granted" || second.EventType != "credential.issued" {
		t.Fatalf("event order: %q then %q", first.EventType, second.EventType)
	}
	if first.PrevHash != "" {
		t.Errorf("first entry prev_hash = %q, want empty", first.PrevHash)
	}
	if second.PrevHash != first.Hash {
		t.Error("second entry does not link to the first entry's hash")
	}
	if !strings.Contains(first.Payload, "g-1") {
		t.Errorf("payload not recorded: %s", first.Payload)
	}
}
