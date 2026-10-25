package store

import (
	"context"
	"time"
)

// migrateDIDComm creates the table of received DIDComm message ids. Called from migrate().
func (s *SQLStore) migrateDIDComm() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS didcomm_seen (
		sender     TEXT NOT NULL,
		message_id TEXT NOT NULL,
		seen_until DATETIME NOT NULL,
		PRIMARY KEY (sender, message_id)
	);
	CREATE INDEX IF NOT EXISTS idx_didcomm_seen_until ON didcomm_seen(seen_until);
	`)
	return err
}

func (s *SQLStore) RecordDIDCommMessage(ctx context.Context, sender, messageID string, until time.Time) error {
	// Forget entries that can no longer be replayed, so the table stays bounded by the replay window.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM didcomm_seen WHERE seen_until < ?`, time.Now().UTC()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO didcomm_seen (sender, message_id, seen_until) VALUES (?,?,?)`, sender, messageID, until.UTC())
	if err != nil && isUniqueViolation(err) {
		return ErrDIDCommReplay
	}
	return err
}
