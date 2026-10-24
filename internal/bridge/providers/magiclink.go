package providers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

const magicLinkTTL = 15 * time.Minute

// MagicLinkBridge generates and verifies single-use email tokens.
// It stores pending tokens in the store; email delivery is the caller's responsibility
// (bridge HTTP handler calls Sender after generating the token).
type MagicLinkBridge struct {
	st store.Store
}

// NewMagicLink creates a magic link bridge.
func NewMagicLink(st store.Store) *MagicLinkBridge {
	return &MagicLinkBridge{st: st}
}

func (b *MagicLinkBridge) Name() string { return "magiclink-email" }

// Authenticate satisfies the Bridge interface but is not used directly.
// Use GenerateToken and VerifyToken instead.
func (b *MagicLinkBridge) Authenticate(ctx context.Context, r *http.Request) (*bridge.ExternalIdentity, error) {
	return nil, errors.New("magiclink: use VerifyToken instead")
}

// GenerateToken creates a new magic link token for the given email address.
// Returns the raw token (to be included in the email link) and the expiry time.
func (b *MagicLinkBridge) GenerateToken(ctx context.Context, email string) (rawToken string, expiresAt time.Time, err error) {
	raw, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	hash := hashMagicToken(raw)
	expiry := time.Now().Add(magicLinkTTL)

	t := &store.MagicLinkToken{
		Hash:      hash,
		Email:     normaliseEmail(email),
		ExpiresAt: expiry,
		CreatedAt: time.Now(),
	}
	if err := b.st.SaveMagicLinkToken(ctx, t); err != nil {
		return "", time.Time{}, err
	}
	return raw, expiry, nil
}

// VerifyToken validates a raw token and returns the ExternalIdentity for the email address.
// The token is deleted on successful verification (single-use).
func (b *MagicLinkBridge) VerifyToken(ctx context.Context, rawToken string) (*bridge.ExternalIdentity, error) {
	hash := hashMagicToken(rawToken)

	t, err := b.st.GetMagicLinkToken(ctx, hash)
	if err != nil {
		return nil, errors.New("magiclink: invalid or expired token")
	}
	if time.Now().After(t.ExpiresAt) {
		_ = b.st.DeleteMagicLinkToken(ctx, hash)
		return nil, errors.New("magiclink: token expired")
	}

	// Consume the token immediately (single-use).
	_ = b.st.DeleteMagicLinkToken(ctx, hash)

	return &bridge.ExternalIdentity{
		Provider:   b.Name(),
		ExternalID: t.Email,
		Claims:     map[string]string{"email": t.Email, "email_verified": "true"}, // possession of the mailbox proves the address
	}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashMagicToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func normaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
