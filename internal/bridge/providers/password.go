package providers

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — must match keystore.go.
const (
	pwArgon2Memory  = 64 * 1024
	pwArgon2Time    = 3
	pwArgon2Threads = 4
	pwArgon2KeyLen  = 32
	pwSaltLen       = 32
)

// PasswordHashStore is the interface for storing/retrieving hashed passwords.
// Implement this against the platform store (e.g. a dedicated passwords table).
type PasswordHashStore interface {
	SavePasswordHash(ctx context.Context, identifier, hash string) error
	GetPasswordHash(ctx context.Context, identifier string) (string, error)
}

// PasswordBridge provides password-based authentication as a legacy bridge.
// IMPORTANT: Must be explicitly enabled via config — passkeys and magic links are preferred.
// On first successful login, clients should prompt users to enrol a passkey.
type PasswordBridge struct {
	hashStore PasswordHashStore
}

// NewPasswordBridge creates a password bridge.
func NewPasswordBridge(hashStore PasswordHashStore) *PasswordBridge {
	return &PasswordBridge{hashStore: hashStore}
}

func (b *PasswordBridge) Name() string { return "password" }

func (b *PasswordBridge) Authenticate(ctx context.Context, r *http.Request) (*bridge.ExternalIdentity, error) {
	return nil, errors.New("password: use VerifyCredentials instead")
}

// VerifyCredentials checks identifier+password and returns the external identity.
func (b *PasswordBridge) VerifyCredentials(ctx context.Context, identifier, password string) (*bridge.ExternalIdentity, error) {
	storedHash, err := b.hashStore.GetPasswordHash(ctx, normaliseEmail(identifier))
	if err != nil {
		// Constant-time dummy check to prevent timing oracle on unknown users.
		hashPassword("dummy-guard", make([]byte, pwSaltLen))
		return nil, errors.New("password: invalid credentials")
	}
	if err := verifyArgon2(password, storedHash); err != nil {
		return nil, errors.New("password: invalid credentials")
	}
	return &bridge.ExternalIdentity{
		Provider:   b.Name(),
		ExternalID: normaliseEmail(identifier),
		Claims:     map[string]string{"identifier": identifier},
	}, nil
}

// SetPassword hashes and stores a new password for the given identifier.
func (b *PasswordBridge) SetPassword(ctx context.Context, identifier, password string) error {
	if len(password) < 12 {
		return errors.New("password: minimum length is 12 characters")
	}
	salt := make([]byte, pwSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("password: generate salt: %w", err)
	}
	hash := encodeArgon2Hash(hashPassword(password, salt), salt)
	return b.hashStore.SavePasswordHash(ctx, normaliseEmail(identifier), hash)
}

func hashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, pwArgon2Time, pwArgon2Memory, pwArgon2Threads, pwArgon2KeyLen)
}

func encodeArgon2Hash(hash, salt []byte) string {
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash)
}

func verifyArgon2(password, stored string) error {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid hash format")
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return errors.New("invalid salt")
	}
	expected, err := hex.DecodeString(parts[1])
	if err != nil {
		return errors.New("invalid hash")
	}
	actual := hashPassword(password, salt)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return errors.New("mismatch")
	}
	return nil
}
