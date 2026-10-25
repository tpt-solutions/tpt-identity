package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SaveSDJWTIssued records an SD-JWT credential this server issued.
func (s *SQLStore) SaveSDJWTIssued(ctx context.Context, rec *SDJWTIssued) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sdjwt_issued (id, subject_did, status_list, status_index, issued_at, expires_at) VALUES (?,?,?,?,?,?)`,
		rec.ID, rec.SubjectDID, rec.StatusList, rec.StatusIndex, rec.IssuedAt.UTC(), rec.ExpiresAt.UTC())
	return err
}

// GetSDJWTIssued returns the record for an issued SD-JWT credential, or ErrNotFound.
func (s *SQLStore) GetSDJWTIssued(ctx context.Context, id string) (*SDJWTIssued, error) {
	var rec SDJWTIssued
	err := s.db.QueryRowContext(ctx,
		`SELECT id, subject_did, status_list, status_index, issued_at, expires_at FROM sdjwt_issued WHERE id=?`, id).
		Scan(&rec.ID, &rec.SubjectDID, &rec.StatusList, &rec.StatusIndex, &rec.IssuedAt, &rec.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get sd-jwt record: %w", err)
	}
	return &rec, nil
}
