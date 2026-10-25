package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

func (s *SQLStore) PutCredential(ctx context.Context, cred *vc.VerifiableCredential) error {
	b, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	schemaID := ""
	if cred.CredentialSchema != nil {
		schemaID = cred.CredentialSchema.ID
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO credentials (id, subject_did, issuer_did, schema_id, valid_from, valid_until, credential, created_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET credential=excluded.credential, valid_from=excluded.valid_from, valid_until=excluded.valid_until`,
		cred.ID, cred.CredentialSubject.ID, cred.Issuer, schemaID, cred.ValidFrom, cred.ValidUntil, string(b), time.Now())
	return err
}

func (s *SQLStore) CreateStatusList(ctx context.Context, rec *StatusListRecord) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO status_lists (id, issuer_did, size_bits, next_index, bits, updated_at, created_at) VALUES (?,?,?,?,?,?,?)`,
		rec.ID, rec.IssuerDID, rec.SizeBits, rec.NextIndex, rec.Bits, now, now)
	return err
}

func (s *SQLStore) GetStatusList(ctx context.Context, id string) (*StatusListRecord, error) {
	return scanStatusList(s.db.QueryRowContext(ctx, `
		SELECT id, issuer_did, size_bits, next_index, bits, updated_at FROM status_lists WHERE id=?`, id))
}

func (s *SQLStore) ActiveStatusList(ctx context.Context, issuerDID string) (*StatusListRecord, error) {
	return scanStatusList(s.db.QueryRowContext(ctx, `
		SELECT id, issuer_did, size_bits, next_index, bits, updated_at FROM status_lists
		WHERE issuer_did=? AND next_index < size_bits ORDER BY created_at DESC NULLS LAST LIMIT 1`, issuerDID))
}

// AllocateStatusIndex reserves the next index. Read and write share a transaction, so two issuances
// never receive the same index.
func (s *SQLStore) AllocateStatusIndex(ctx context.Context, listID string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.lock(ctx, "status_list:"+listID); err != nil {
		return 0, err
	}

	var next, size int
	err = tx.QueryRowContext(ctx, `SELECT next_index, size_bits FROM status_lists WHERE id=?`, listID).Scan(&next, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if next >= size {
		return 0, ErrStatusListFull
	}
	if _, err := tx.ExecContext(ctx, `UPDATE status_lists SET next_index=?, updated_at=? WHERE id=?`,
		next+1, time.Now().UTC(), listID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

// SetStatusBit sets the revocation bit at index. The read-modify-write runs in one transaction.
func (s *SQLStore) SetStatusBit(ctx context.Context, listID string, index int) (*StatusListRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.lock(ctx, "status_list:"+listID); err != nil {
		return nil, err
	}

	rec, err := scanStatusList(tx.QueryRowContext(ctx, `
		SELECT id, issuer_did, size_bits, next_index, bits, updated_at FROM status_lists WHERE id=?`, listID))
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= rec.SizeBits {
		return nil, fmt.Errorf("status list: index %d out of range (size %d)", index, rec.SizeBits)
	}
	rec.Bits[index/8] |= 1 << (uint(index) % 8)
	rec.UpdatedAt = time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE status_lists SET bits=?, updated_at=? WHERE id=?`,
		rec.Bits, rec.UpdatedAt, listID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return rec, nil
}

func scanStatusList(row *sql.Row) (*StatusListRecord, error) {
	var rec StatusListRecord
	if err := row.Scan(&rec.ID, &rec.IssuerDID, &rec.SizeBits, &rec.NextIndex, &rec.Bits, &rec.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &rec, nil
}
