package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Audit hash versions. A row records the version it was hashed with, so the chain can mix old and new rows.
const (
	// AuditHashV1 is the original format: SHA-256(prev_hash || {event_type, payload, prev_hash}). It does not
	// cover the time the event was recorded, so the timestamp could be changed without breaking the chain.
	AuditHashV1 = 1
	// AuditHashV2 also covers recorded_at, the RFC 3339 time (UTC, nanoseconds) the event was recorded. The
	// string is stored exactly as hashed, so a database round trip cannot change what is verified.
	AuditHashV2 = 2
)

// AuditHashOf computes the hash of one audit event under the given version. recordedAt is ignored for v1.
func AuditHashOf(version int, prevHash, recordedAt, eventType, payload string) (string, error) {
	var raw []byte
	var err error
	switch version {
	case AuditHashV1:
		raw, err = json.Marshal(map[string]string{"event_type": eventType, "payload": payload, "prev_hash": prevHash})
	case AuditHashV2:
		raw, err = json.Marshal(map[string]string{
			"version":     "2",
			"event_type":  eventType,
			"payload":     payload,
			"prev_hash":   prevHash,
			"recorded_at": recordedAt,
		})
	default:
		return "", fmt.Errorf("audit: unknown hash version %d", version)
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(prevHash), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// VerifyAuditChain checks a run of consecutive events. Each event's hash must recompute from its own
// fields, and each event after the first must link to the one before it. The first event's link to the
// rest of the chain is not checked, because a proof may start part-way through the log.
func VerifyAuditChain(events []*AuditEvent) error {
	for i, e := range events {
		version := e.HashVersion
		if version == 0 {
			version = AuditHashV1 // rows written before versioning are v1
		}
		if i > 0 && e.PrevHash != events[i-1].Hash {
			return fmt.Errorf("audit: seq %d links to %q, want %q", e.Seq, e.PrevHash, events[i-1].Hash)
		}
		got, err := AuditHashOf(version, e.PrevHash, e.RecordedAt, e.EventType, e.Payload)
		if err != nil {
			return fmt.Errorf("audit: seq %d: %w", e.Seq, err)
		}
		if got != e.Hash {
			return fmt.Errorf("audit: seq %d hash does not recompute", e.Seq)
		}
	}
	return nil
}
