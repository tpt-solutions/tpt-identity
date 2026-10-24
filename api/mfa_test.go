package api_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 is defined over HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const mfaDID = "did:peer:mfa-user"

// rfc6238 returns the 6-digit code for a 30-second step, from a base32 secret.
func rfc6238(t *testing.T, secretB32 string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// enrolURI starts enrolment and returns the otpauth URI.
func enrolURI(t *testing.T, srv *api.Server, tok string) string {
	t.Helper()
	w := mfaCall(t, srv, http.MethodPost, "/api/v1/me/totp/enrol", tok, `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("enrol: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		URI string `json:"otpauth_uri"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode enrol: %v", err)
	}
	return out.URI
}

func secretFromURI(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	return u.Query().Get("secret")
}

func newMFAServer(t *testing.T) (*api.Server, string) {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now()
	if err := st.SaveIdentity(context.Background(), &store.Identity{
		DID: mfaDID, Method: "peer", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		APIKey:         testAPIKey,
		Issuer:         testIssuer,
		SigningKey:     priv,
		TotpPassphrase: "test-totp-passphrase",
		Store:          st,
		OIDC:           oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:       resolver.New(time.Minute),
	})
	tok, err := oidc.IssueAccessToken(testIssuer, mfaDID, "client-1", time.Hour, priv, "test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	return srv, tok
}

func mfaCall(t *testing.T, srv *api.Server, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, srv, method, path, body, map[string]string{
		"Authorization": "Bearer " + bearer, "Content-Type": "application/json",
	})
}

// A new factor is pending until its first correct code, and that code cannot be reused.
func TestTOTPPendingUntilVerifiedAndNoReplay(t *testing.T) {
	srv, tok := newMFAServer(t)
	secret := secretFromURI(t, enrolURI(t, srv, tok))
	code := rfc6238(t, secret, time.Now().Unix()/30)

	if w := mfaCall(t, srv, http.MethodPost, "/api/v1/me/totp/verify", tok, `{"code":"`+code+`"}`); w.Code != http.StatusOK {
		t.Fatalf("first verify: want 200, got %d", w.Code)
	}
	if w := mfaCall(t, srv, http.MethodPost, "/api/v1/me/totp/verify", tok, `{"code":"`+code+`"}`); w.Code == http.StatusOK {
		t.Error("TOTP code replayed inside its window")
	}
}

// Replacing or removing an active factor needs a current code from it.
func TestTOTPReplaceAndRemoveNeedCurrentCode(t *testing.T) {
	srv, tok := newMFAServer(t)
	secret := secretFromURI(t, enrolURI(t, srv, tok))
	if w := mfaCall(t, srv, http.MethodPost, "/api/v1/me/totp/verify", tok, `{"code":"`+rfc6238(t, secret, time.Now().Unix()/30)+`"}`); w.Code != http.StatusOK {
		t.Fatalf("activate: %d", w.Code)
	}

	if w := mfaCall(t, srv, http.MethodPost, "/api/v1/me/totp/enrol", tok, `{}`); w.Code != http.StatusForbidden {
		t.Errorf("replace without code: want 403, got %d", w.Code)
	}
	if w := mfaCall(t, srv, http.MethodDelete, "/api/v1/me/totp", tok, `{}`); w.Code != http.StatusForbidden {
		t.Errorf("remove without code: want 403, got %d", w.Code)
	}
}
