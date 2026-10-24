// Package authn provides authentication factors: TOTP and brute-force lockout.
package authn

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP uses SHA-1 per RFC 6238
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

const (
	totpDigits  = 6
	totpPeriod  = 30 // seconds
	totpWindow  = 1  // allow ±1 period for clock skew
	totpSaltLen = 32
	totpKeyLen  = 32
)

// Argon2id parameters for TOTP secret encryption.
const (
	totpArgonMemory  = 64 * 1024
	totpArgonTime    = 3
	totpArgonThreads = 4
)

// TOTPManager handles TOTP enrolment and verification.
type TOTPManager struct {
	st         store.Store
	passphrase string // platform passphrase for encrypting TOTP secrets
	issuer     string // displayed in authenticator apps
}

// NewTOTPManager creates a TOTPManager.
func NewTOTPManager(st store.Store, passphrase, issuer string) *TOTPManager {
	return &TOTPManager{st: st, passphrase: passphrase, issuer: issuer}
}

// Enrol generates a new TOTP secret for the subject, encrypts it, and stores it.
// Returns the OTP Auth URI for QR code generation.
func (m *TOTPManager) Enrol(subjectDID, accountName string) (otpauthURI string, err error) {
	return m.EnrolCtx(context.Background(), subjectDID, accountName)
}

// EnrolCtx is the context-aware version of Enrol.
func (m *TOTPManager) EnrolCtx(ctx context.Context, subjectDID, accountName string) (string, error) {
	// Generate a 20-byte (160-bit) random secret.
	secret := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", fmt.Errorf("totp: generate secret: %w", err)
	}

	encrypted, err := m.encryptSecret(secret)
	if err != nil {
		return "", fmt.Errorf("totp: encrypt secret: %w", err)
	}

	cred := &store.TOTPCredential{
		SubjectDID:      subjectDID,
		EncryptedSecret: encrypted,
		AccountName:     accountName,
		CreatedAt:       time.Now(),
	}
	if err := m.st.SaveTOTPCredential(ctx, cred); err != nil {
		return "", fmt.Errorf("totp: save credential: %w", err)
	}

	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		urlEscape(m.issuer), urlEscape(accountName), b32, urlEscape(m.issuer), totpDigits, totpPeriod)
	return uri, nil
}

// Verify checks a TOTP code for the given subject. Returns nil on success.
func (m *TOTPManager) Verify(subjectDID, code string) error {
	return m.VerifyCtx(context.Background(), subjectDID, code)
}

// VerifyCtx is the context-aware version of Verify.
func (m *TOTPManager) VerifyCtx(ctx context.Context, subjectDID, code string) error {
	cred, err := m.st.GetTOTPCredential(ctx, subjectDID)
	if err != nil {
		return errors.New("totp: no credential enrolled")
	}

	secret, err := m.decryptSecret(cred.EncryptedSecret)
	if err != nil {
		return fmt.Errorf("totp: decrypt secret: %w", err)
	}

	now := time.Now().Unix()
	counter := now / int64(totpPeriod)
	for delta := int64(-totpWindow); delta <= int64(totpWindow); delta++ {
		step := counter + delta
		if !timingSafeEqual(code, generateTOTP(secret, step)) {
			continue
		}
		// A matching code is accepted once. The step must be newer than the last one used.
		ok, err := m.st.ConsumeTOTPStep(ctx, subjectDID, step)
		if err != nil {
			return fmt.Errorf("totp: record step: %w", err)
		}
		if !ok {
			return errors.New("totp: code already used")
		}
		return nil
	}
	return errors.New("totp: invalid code")
}

// IsEnrolled returns true if the subject has a verified TOTP factor. A pending factor
// (enrolled but never verified) does not count.
func (m *TOTPManager) IsEnrolled(subjectDID string) bool {
	cred, err := m.st.GetTOTPCredential(context.Background(), subjectDID)
	return err == nil && cred.VerifiedAt != nil
}

// Unenrol removes the TOTP credential for the subject.
func (m *TOTPManager) Unenrol(subjectDID string) error {
	return m.st.DeleteTOTPCredential(context.Background(), subjectDID)
}

// generateTOTP computes a 6-digit TOTP value (RFC 6238 / RFC 4226).
func generateTOTP(secret []byte, counter int64) string {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))

	mac := hmac.New(sha1.New, secret) //nolint:gosec
	mac.Write(msg)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := (int(h[offset]&0x7f) << 24) |
		(int(h[offset+1]) << 16) |
		(int(h[offset+2]) << 8) |
		int(h[offset+3])
	code = code % int(math.Pow10(totpDigits))
	return fmt.Sprintf("%0*d", totpDigits, code)
}

func (m *TOTPManager) encryptSecret(secret []byte) (string, error) {
	salt := make([]byte, totpSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	dk := argon2.IDKey([]byte(m.passphrase), salt, totpArgonTime, totpArgonMemory, totpArgonThreads, totpKeyLen)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, secret, nil)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(nonce) + ":" + hex.EncodeToString(ct), nil
}

func (m *TOTPManager) decryptSecret(encoded string) ([]byte, error) {
	parts := strings.SplitN(encoded, ":", 3)
	if len(parts) != 3 {
		return nil, errors.New("invalid encrypted secret format")
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("totp: invalid encrypted secret (salt): %w", err)
	}
	nonce, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("totp: invalid encrypted secret (nonce): %w", err)
	}
	ct, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("totp: invalid encrypted secret (ciphertext): %w", err)
	}
	dk := argon2.IDKey([]byte(m.passphrase), salt, totpArgonTime, totpArgonMemory, totpArgonThreads, totpKeyLen)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func timingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func urlEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteRune(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
