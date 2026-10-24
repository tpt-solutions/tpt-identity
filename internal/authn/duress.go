package authn

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// DuressManager stores and checks duress passphrases for each subject.
// A duress passphrase is a secondary credential that authenticates normally
// but fires a session.duress event — used to signal coercion silently.
type DuressManager struct {
	store duressStore
}

type duressStore interface {
	SaveDuressConfig(ctx context.Context, subjectDID, hash string) error
	GetDuressHash(ctx context.Context, subjectDID string) (string, error)
	DeleteDuressConfig(ctx context.Context, subjectDID string) error
}

// NewDuressManager creates a DuressManager backed by the given store.
func NewDuressManager(store duressStore) *DuressManager {
	return &DuressManager{store: store}
}

// Enrol stores a hashed duress passphrase for subjectDID.
// The passphrase must differ from the account's normal password.
func (m *DuressManager) Enrol(ctx context.Context, subjectDID, passphrase string) error {
	if passphrase == "" {
		return errors.New("duress: passphrase must not be empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("duress: generate salt: %w", err)
	}
	hash := argon2HashDuress([]byte(passphrase), salt)
	stored := hex.EncodeToString(salt) + ":" + hash
	return m.store.SaveDuressConfig(ctx, subjectDID, stored)
}

// CheckDuress returns true when provided matches the stored duress passphrase.
// It is designed to be called after a successful normal-password auth to detect
// whether the user authenticated under duress.
func (m *DuressManager) CheckDuress(ctx context.Context, subjectDID, provided string) (bool, error) {
	stored, err := m.store.GetDuressHash(ctx, subjectDID)
	if err != nil || stored == "" {
		return false, nil // no duress passphrase enrolled — not duress
	}
	saltHex, hashStored, ok := splitDuressStored(stored)
	if !ok {
		return false, nil
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false, nil
	}
	hashProvided := argon2HashDuress([]byte(provided), salt)
	return subtle.ConstantTimeCompare([]byte(hashProvided), []byte(hashStored)) == 1, nil
}

// Remove deletes the duress configuration for subjectDID.
func (m *DuressManager) Remove(ctx context.Context, subjectDID string) error {
	return m.store.DeleteDuressConfig(ctx, subjectDID)
}

func argon2HashDuress(pass, salt []byte) string {
	// Use the same Argon2id parameters as the TOTP manager.
	dk := argon2.IDKey(pass, salt, totpArgonTime, totpArgonMemory, totpArgonThreads, totpKeyLen)
	return hex.EncodeToString(dk)
}

func splitDuressStored(s string) (saltHex, hash string, ok bool) {
	for i, c := range s {
		if c == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
