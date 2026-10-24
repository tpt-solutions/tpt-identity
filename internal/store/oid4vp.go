package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// migrateOID4VP creates the OID4VP state tables. Called from migrate().
func (s *SQLiteStore) migrateOID4VP() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS oid4vp_requests (
		id          TEXT PRIMARY KEY,
		data        TEXT NOT NULL,
		expires_at  DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS oid4vp_responses (
		request_id  TEXT PRIMARY KEY,
		data        TEXT NOT NULL,
		received_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_oid4vp_requests_expiry ON oid4vp_requests(expires_at);
	`)
	return err
}

func (s *SQLiteStore) SaveOID4VPRequest(ctx context.Context, id string, data []byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oid4vp_requests (id, data, expires_at) VALUES (?,?,?)`, id, string(data), expiresAt)
	if err != nil && isUniqueViolation(err) {
		return ErrOID4VPRequestExists
	}
	return err
}

func (s *SQLiteStore) GetOID4VPRequest(ctx context.Context, id string) ([]byte, time.Time, error) {
	var data string
	var expires time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT data, expires_at FROM oid4vp_requests WHERE id=?`, id).Scan(&data, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	return []byte(data), expires, nil
}

func (s *SQLiteStore) SaveOID4VPResponse(ctx context.Context, requestID string, data []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oid4vp_responses (request_id, data, received_at) VALUES (?,?,?)`,
		requestID, string(data), time.Now().UTC())
	if err != nil && isUniqueViolation(err) {
		return ErrOID4VPResponseExists
	}
	return err
}

func (s *SQLiteStore) GetOID4VPResponse(ctx context.Context, requestID string) ([]byte, error) {
	var data string
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM oid4vp_responses WHERE request_id=?`, requestID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(data), nil
}

func (s *SQLiteStore) DeleteExpiredOID4VP(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM oid4vp_responses WHERE request_id IN (SELECT id FROM oid4vp_requests WHERE expires_at < ?)`, now)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM oid4vp_requests WHERE expires_at < ?`, now)
	return err
}

// isUniqueViolation reports whether err is a unique or primary-key constraint failure from SQLite.
func isUniqueViolation(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "PRIMARY KEY"))
}
