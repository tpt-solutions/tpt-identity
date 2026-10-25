package store

import (
	"context"
	"testing"
	"time"
)

func openAuditStore(t *testing.T) *SQLStore {
	t.Helper()
	st, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// A row written before versioning (v1, no recorded time) and rows written after it form one chain that
// verifies end to end.
func TestChainMixesLegacyV1AndV2Rows(t *testing.T) {
	ctx := context.Background()
	st := openAuditStore(t)

	legacyHash, err := AuditHashOf(AuditHashV1, "", "", "identity.created", `{"did":"did:peer:old"}`)
	if err != nil {
		t.Fatal(err)
	}
	// The pre-versioning schema defaults hash_version to 1 and recorded_at to empty, so omit both.
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO audit_log (event_type, payload, hash, prev_hash) VALUES (?,?,?,?)`,
		"identity.created", `{"did":"did:peer:old"}`, legacyHash, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendAuditEvent(ctx, "consent.granted", `{"grant":"g-1"}`); err != nil {
		t.Fatal(err)
	}

	events, _, err := st.ListAuditEvents(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	if events[0].HashVersion != AuditHashV1 || events[1].HashVersion != AuditHashV2 {
		t.Errorf("versions: got %d then %d", events[0].HashVersion, events[1].HashVersion)
	}
	if err := VerifyAuditChain(events); err != nil {
		t.Fatalf("mixed chain does not verify: %v", err)
	}
}

// The recorded time is covered by the v2 hash: changing it breaks verification. v1 did not cover time,
// which is the gap this version closes.
func TestV2HashCoversRecordedTime(t *testing.T) {
	ctx := context.Background()
	st := openAuditStore(t)
	if _, err := st.AppendAuditEvent(ctx, "credential.issued", `{"id":"c-1"}`); err != nil {
		t.Fatal(err)
	}
	events, _, err := st.ListAuditEvents(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuditChain(events); err != nil {
		t.Fatalf("untouched chain: %v", err)
	}

	moved := *events[0]
	moved.RecordedAt = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if err := VerifyAuditChain([]*AuditEvent{&moved}); err == nil {
		t.Error("changed recorded time still verifies")
	}
}

// A broken link in the middle of a run is reported at the event where it breaks.
func TestVerifyAuditChainDetectsBrokenLink(t *testing.T) {
	ctx := context.Background()
	st := openAuditStore(t)
	for _, p := range []string{`{"n":1}`, `{"n":2}`, `{"n":3}`} {
		if _, err := st.AppendAuditEvent(ctx, "test.event", p); err != nil {
			t.Fatal(err)
		}
	}
	events, _, _ := st.ListAuditEvents(ctx, 10, 0)

	// Drop the middle event: the third now links to a hash that is no longer in the run.
	if err := VerifyAuditChain([]*AuditEvent{events[0], events[2]}); err == nil {
		t.Error("gap in the chain verified")
	}
	// A run that starts part-way through is fine: the first event's link is not checked.
	if err := VerifyAuditChain(events[1:]); err != nil {
		t.Errorf("partial run: %v", err)
	}
}

func TestAuditHashOfRejectsUnknownVersion(t *testing.T) {
	if _, err := AuditHashOf(99, "", "", "x", "{}"); err == nil {
		t.Error("unknown hash version accepted")
	}
}
