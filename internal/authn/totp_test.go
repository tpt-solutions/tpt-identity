package authn

import (
	"context"
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
)

const totpTestDID = "did:peer:totp-holder"

// RFC 6238 Appendix B, SHA-1 vector: the secret is the ASCII string "12345678901234567890" and
// T=59 gives the 8-digit value 94287082. The 6-digit form is its last six digits.
func TestGenerateTOTPMatchesRFC6238Vector(t *testing.T) {
	secret := []byte("12345678901234567890")
	if got := generateTOTP(secret, 1); got != "287082" {
		t.Errorf("counter 1: want 287082, got %s", got)
	}
}

// secretFromURI recovers the raw enrolment secret from an otpauth URI.
func secretFromURI(t *testing.T, uri string) []byte {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return raw
}

func currentCounter() int64 { return time.Now().Unix() / int64(totpPeriod) }

func enrolTOTP(t *testing.T, m *TOTPManager, subject string) []byte {
	t.Helper()
	uri, err := m.EnrolCtx(context.Background(), subject, "alice@example.com")
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("not an otpauth URI: %s", uri)
	}
	return secretFromURI(t, uri)
}

func TestTOTPAcceptsCurrentCodeOnceOnly(t *testing.T) {
	st := storetest.New(t)
	m := NewTOTPManager(st, "passphrase-for-totp-test", "tpt-identity")
	secret := enrolTOTP(t, m, totpTestDID)

	code := generateTOTP(secret, currentCounter())
	if err := m.Verify(totpTestDID, code); err != nil {
		t.Fatalf("current code: want accepted, got %v", err)
	}
	if err := m.Verify(totpTestDID, code); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("replayed code: want 'already used', got %v", err)
	}
}

func TestTOTPWindowIsOnePeriodEachSide(t *testing.T) {
	st := storetest.New(t)
	m := NewTOTPManager(st, "passphrase-for-totp-test", "tpt-identity")
	secret := enrolTOTP(t, m, totpTestDID)

	// One period back is inside the ±1 window for any clock reading taken during the test.
	if err := m.Verify(totpTestDID, generateTOTP(secret, currentCounter()-1)); err != nil {
		t.Errorf("code one period back: want accepted, got %v", err)
	}

	// Three periods back is outside the window whatever the clock reads now.
	st2 := storetest.New(t)
	m2 := NewTOTPManager(st2, "passphrase-for-totp-test", "tpt-identity")
	secret2 := enrolTOTP(t, m2, totpTestDID)
	if err := m2.Verify(totpTestDID, generateTOTP(secret2, currentCounter()-3)); err == nil {
		t.Error("code three periods back: want rejected")
	}
}

func TestTOTPRejectsWrongCodeAndUnenrolledSubject(t *testing.T) {
	st := storetest.New(t)
	m := NewTOTPManager(st, "passphrase-for-totp-test", "tpt-identity")

	if err := m.Verify(totpTestDID, "000000"); err == nil {
		t.Error("unenrolled subject: want error")
	}

	secret := enrolTOTP(t, m, totpTestDID)
	wrong := generateTOTP(secret, currentCounter()+5) // far outside the window
	if err := m.Verify(totpTestDID, wrong); err == nil || !strings.Contains(err.Error(), "invalid code") {
		t.Errorf("wrong code: want 'invalid code', got %v", err)
	}
}

// A pending factor (enrolled, never verified through the enrolment flow) does not count as enrolled.
func TestTOTPPendingFactorIsNotEnrolled(t *testing.T) {
	st := storetest.New(t)
	m := NewTOTPManager(st, "passphrase-for-totp-test", "tpt-identity")
	enrolTOTP(t, m, totpTestDID)

	if m.IsEnrolled(totpTestDID) {
		t.Error("pending factor reported as enrolled")
	}
}

func TestTOTPUnenrolRemovesFactor(t *testing.T) {
	st := storetest.New(t)
	m := NewTOTPManager(st, "passphrase-for-totp-test", "tpt-identity")
	secret := enrolTOTP(t, m, totpTestDID)

	if err := m.Unenrol(totpTestDID); err != nil {
		t.Fatalf("unenrol: %v", err)
	}
	if err := m.Verify(totpTestDID, generateTOTP(secret, currentCounter())); err == nil {
		t.Error("code after unenrol: want rejected")
	}
}

// The secret is encrypted under the platform passphrase; a different passphrase cannot decrypt it.
func TestTOTPSecretNeedsTheSamePassphrase(t *testing.T) {
	st := storetest.New(t)
	m := NewTOTPManager(st, "passphrase-for-totp-test", "tpt-identity")
	secret := enrolTOTP(t, m, totpTestDID)

	other := NewTOTPManager(st, "a-different-passphrase", "tpt-identity")
	if err := other.Verify(totpTestDID, generateTOTP(secret, currentCounter())); err == nil {
		t.Error("different passphrase: want decrypt failure")
	}
}
