package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func (s *SQLStore) SaveOID4VPRequest(ctx context.Context, id string, data []byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oid4vp_requests (id, data, expires_at) VALUES (?,?,?)`, id, string(data), expiresAt)
	if err != nil && isUniqueViolation(err) {
		return ErrOID4VPRequestExists
	}
	return err
}

func (s *SQLStore) GetOID4VPRequest(ctx context.Context, id string) ([]byte, time.Time, error) {
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

func (s *SQLStore) SaveOID4VPResponse(ctx context.Context, requestID string, data []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oid4vp_responses (request_id, data, received_at) VALUES (?,?,?)`,
		requestID, string(data), time.Now().UTC())
	if err != nil && isUniqueViolation(err) {
		return ErrOID4VPResponseExists
	}
	return err
}

func (s *SQLStore) GetOID4VPResponse(ctx context.Context, requestID string) ([]byte, error) {
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

func (s *SQLStore) DeleteExpiredOID4VP(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM oid4vp_responses WHERE request_id IN (SELECT id FROM oid4vp_requests WHERE expires_at < ?)`, now)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM oid4vp_requests WHERE expires_at < ?`, now)
	return err
}

// isUniqueViolation reports whether err is a unique or primary-key constraint failure, from SQLite
// or PostgreSQL (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "PRIMARY KEY")
}
