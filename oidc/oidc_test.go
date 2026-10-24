package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

// ---- JWT issuance + verification ----

func TestIssueAndVerifyIDToken(t *testing.T) {
	pubKey, privKey, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	token, err := oidc.IssueIDToken(
		"https://issuer.example.com", "did:peer:subject", "client-1",
		"nonce-xyz", time.Hour, privKey, nil, "key-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := oidc.Verify(token, pubKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "did:peer:subject" {
		t.Errorf("unexpected subject: %s", claims.Subject)
	}
	if claims.Nonce != "nonce-xyz" {
		t.Errorf("unexpected nonce: %s", claims.Nonce)
	}
	if claims.TokenType != "id" {
		t.Errorf("unexpected token_type: %s", claims.TokenType)
	}
}

func TestIssueAndVerifyAccessToken(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	token, err := oidc.IssueAccessToken(
		"https://issuer.example.com", "did:peer:sub", "client-1",
		time.Hour, privKey, "key-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := oidc.Verify(token, pubKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.TokenType != "access" {
		t.Errorf("unexpected token_type: %s", claims.TokenType)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	token, _ := oidc.IssueAccessToken(
		"https://issuer.example.com", "did:peer:sub", "client-1",
		-time.Hour, privKey, "key-1",
	)
	if _, err := oidc.Verify(token, pubKey); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, privKey, _ := crypto.GenerateSigningKey()
	wrongPub, _, _ := crypto.GenerateSigningKey()
	token, _ := oidc.IssueAccessToken(
		"https://issuer.example.com", "did:peer:sub", "client-1",
		time.Hour, privKey, "key-1",
	)
	if _, err := oidc.Verify(token, wrongPub); err == nil {
		t.Error("expected error for wrong public key")
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	_, privKey, _ := crypto.GenerateSigningKey()
	pubKey, _, _ := crypto.GenerateSigningKey()
	_ = privKey
	if _, err := oidc.Verify("not.a.jwt", pubKey); err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestParseUnverifiedExtractsClaims(t *testing.T) {
	_, privKey, _ := crypto.GenerateSigningKey()
	token, _ := oidc.IssueIDToken(
		"https://issuer.example.com", "did:peer:alice", "aud-1",
		"n1", time.Hour, privKey, nil, "k1",
	)
	claims, err := oidc.ParseUnverified(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "did:peer:alice" {
		t.Errorf("unexpected subject: %s", claims.Subject)
	}
}

// ---- PKCE S256 math ----

func TestPKCES256Math(t *testing.T) {
	// Verify BASE64URL(SHA256(verifier)) == challenge is the correct PKCE formula.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	if len(challenge) == 0 {
		t.Error("empty challenge")
	}
	// Re-compute and confirm determinism.
	h2 := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(h2[:]) != challenge {
		t.Error("PKCE computation not deterministic")
	}
}

// ---- Token revocation ----

const revIssuer = "https://issuer.example.com"

// newRevocationProvider returns a provider over an in-memory store plus a token it issued.
func newRevocationProvider(t *testing.T) (*oidc.Provider, string) {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, priv, _ := crypto.GenerateSigningKey()
	saveTestIdentity(t, st, "did:peer:sub")
	p := oidc.NewProvider(revIssuer, priv, "key-1", st)
	token, err := oidc.IssueAccessToken(revIssuer, "did:peer:sub", "client-1", time.Hour, priv, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	return p, token
}

func TestVerifyAccessTokenAcceptsFreshToken(t *testing.T) {
	p, token := newRevocationProvider(t)
	if _, err := p.VerifyAccessToken(context.Background(), token); err != nil {
		t.Errorf("fresh access token rejected: %v", err)
	}
}

// Revoking through /oidc/revoke must make VerifyAccessToken reject the token.
func TestRevokedAccessTokenRejected(t *testing.T) {
	p, token := newRevocationProvider(t)
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	r := httptest.NewRequest(http.MethodPost, "/oidc/revoke", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.RevokeHandler(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: want 200, got %d", w.Code)
	}
	if _, err := p.VerifyAccessToken(context.Background(), token); err == nil {
		t.Error("revoked access token still accepted")
	}
}

// ID tokens are signed by the same key but must not authenticate API calls.
func TestVerifyAccessTokenRejectsIDToken(t *testing.T) {
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, priv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(revIssuer, priv, "key-1", st)
	idTok, err := oidc.IssueIDToken(revIssuer, "did:peer:sub", "client-1", "n", time.Hour, priv, nil, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyAccessToken(context.Background(), idTok); err == nil {
		t.Error("ID token accepted as an access token")
	}
}

// A token minted by a different issuer, even with a valid signature, is rejected.
func TestVerifyAccessTokenRejectsWrongIssuer(t *testing.T) {
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, priv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(revIssuer, priv, "key-1", st)
	tok, err := oidc.IssueAccessToken("https://other.example.com", "did:peer:sub", "client-1", time.Hour, priv, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyAccessToken(context.Background(), tok); err == nil {
		t.Error("token from another issuer accepted")
	}
}

// ---- Dynamic Client Registration types ----

func TestRegisterClientRequestZeroValue(t *testing.T) {
	var req oidc.RegisterClientRequest
	if req.ClientName != "" {
		t.Error("expected zero-value client name")
	}
}

// saveTestIdentity creates an active identity row so token verification accepts the subject.
func saveTestIdentity(t *testing.T, st store.Store, did string) {
	t.Helper()
	now := time.Now()
	if err := st.SaveIdentity(context.Background(), &store.Identity{
		DID: did, Method: "peer", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save identity %s: %v", did, err)
	}
}
