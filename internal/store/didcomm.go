package store

import (
	"context"
	"time"
)

func (s *SQLStore) SaveDIDCommInbox(ctx context.Context, m *DIDCommInboxMessage) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO didcomm_inbox (sender, message_id, type, received_at, body) VALUES (?,?,?,?,?)`,
		m.Sender, m.MessageID, m.Type, m.ReceivedAt.UTC(), m.Body)
	if err != nil && isUniqueViolation(err) {
		return ErrDIDCommReplay
	}
	return err
}

func (s *SQLStore) ListDIDCommInbox(ctx context.Context, limit, offset int) ([]*DIDCommInboxMessage, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM didcomm_inbox`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT sender, message_id, type, received_at, body FROM didcomm_inbox ORDER BY received_at DESC, message_id LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*DIDCommInboxMessage
	for rows.Next() {
		var m DIDCommInboxMessage
		if err := rows.Scan(&m.Sender, &m.MessageID, &m.Type, &m.ReceivedAt, &m.Body); err != nil {
			return nil, 0, err
		}
		out = append(out, &m)
	}
	return out, total, rows.Err()
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
