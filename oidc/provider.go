package oidc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

const (
	codeTTL          = 5 * time.Minute
	idTokenTTL       = time.Hour
	accessTokenTTL   = time.Hour
	refreshTokenTTL  = 30 * 24 * time.Hour // 30 days
)

// Provider handles OIDC authorization code flow endpoints.
type Provider struct {
	issuer     string
	signingKey ed25519.PrivateKey
	signingPub ed25519.PublicKey
	keyID      string
	store      store.Store
	// devicePolls records the last poll time per device_code for slow_down enforcement.
	devicePolls sync.Map
}

// NewProvider creates an OIDC Provider.
func NewProvider(issuer string, key ed25519.PrivateKey, keyID string, st store.Store) *Provider {
	return &Provider{
		issuer:     issuer,
		signingKey: key,
		signingPub: key.Public().(ed25519.PublicKey),
		keyID:      keyID,
		store:      st,
	}
}

// AuthorizeHandler handles GET /authorize.
// Validates the registered client, redirect_uri, and optional PKCE challenge.
// Supports PAR (RFC 9126) via request_uri query parameter.
func (p *Provider) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// PAR support: if request_uri is present, load params from stored PAR request.
	if requestURI := q.Get("request_uri"); requestURI != "" {
		params, err := p.resolvePARRequest(r, requestURI)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		// Merge PAR params into query — PAR params take precedence.
		newQ := r.URL.Query()
		for k, v := range params {
			newQ.Set(k, v)
		}
		r.URL.RawQuery = newQ.Encode()
		q = r.URL.Query()
	}

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	nonce := q.Get("nonce")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	if clientID == "" || redirectURI == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}
	// The end-user must already hold a valid, signed access token. The subject is
	// taken from that token, never from a client-supplied header.
	subjectDID, err := p.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tpt-identity"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "login_required", "error_description": "authenticated session required"})
		return
	}
	// state is required to prevent CSRF.
	if state == "" {
		writeError(w, "invalid_request", "state parameter is required")
		return
	}
	// PKCE is mandatory on all authorization code flows.
	if codeChallenge == "" {
		writeError(w, "invalid_request", "code_challenge is required (PKCE, RFC 7636)")
		return
	}
	if codeChallengeMethod != "S256" {
		writeError(w, "invalid_request", "code_challenge_method must be S256")
		return
	}

	// Validate client and redirect_uri against registration.
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeError(w, "unauthorized_client", "unknown client_id")
		return
	}
	if !containsURI(client.RedirectURIs, redirectURI) {
		writeError(w, "invalid_request", "redirect_uri not registered for this client")
		return
	}

	code, err := randomHex(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sess := &store.OIDCSession{
		ID:                  randomID(),
		SubjectDID:          subjectDID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               nonce,
		State:               state,
		Code:                code,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UserAgent:           r.UserAgent(),
		IPAddress:           remoteIP(r),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(codeTTL),
	}
	if err := p.store.SaveSession(r.Context(), sess); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redirect := redirectURI + "?code=" + code
	if state != "" {
		redirect += "&state=" + state
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// TokenHandler handles POST /token — authorization code exchange and refresh token rotation.
func (p *Provider) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType == "" {
		grantType = "authorization_code"
	}

	switch grantType {
	case "authorization_code":
		p.handleAuthCodeExchange(w, r)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r)
	case "client_credentials":
		p.handleClientCredentialsGrant(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		p.handleDeviceGrant(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		p.handleTokenExchange(w, r)
	default:
		writeError(w, "unsupported_grant_type", "supported: authorization_code, refresh_token, client_credentials, urn:ietf:params:oauth:grant-type:device_code, urn:ietf:params:oauth:grant-type:token-exchange")
	}
}

func (p *Provider) handleAuthCodeExchange(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")
	if code == "" {
		writeError(w, "invalid_request", "missing code")
		return
	}

	// The code is consumed atomically here, before any other check, so a code can
	// never be redeemed twice even by concurrent requests.
	sess, err := p.store.TakeSessionByCode(r.Context(), code)
	if err != nil || time.Now().After(sess.ExpiresAt) {
		writeError(w, "invalid_grant", "code not found or expired")
		return
	}

	// Validate client matches.
	if clientID != "" && clientID != sess.ClientID {
		writeError(w, "invalid_grant", "client_id mismatch")
		return
	}

	// PKCE verification (RFC 7636) — mandatory on all authorization code flows.
	if codeVerifier == "" {
		writeError(w, "invalid_grant", "code_verifier is required (PKCE)")
		return
	}
	if sess.CodeChallenge == "" {
		// Should not happen for any code issued after PKCE enforcement was added.
		writeError(w, "invalid_grant", "no PKCE challenge found for this code")
		return
	}
	if err := verifyPKCE(sess.CodeChallenge, codeVerifier); err != nil {
		writeError(w, "invalid_grant", "code_verifier mismatch")
		return
	}

	// Validate client secret for confidential clients.
	if err := p.validateClientAuth(r, sess.ClientID); err != nil {
		writeError(w, "invalid_client", err.Error())
		return
	}

	idToken, err := IssueIDToken(p.issuer, sess.SubjectDID, sess.ClientID, sess.Nonce, idTokenTTL, p.signingKey, nil, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	accessToken, err := IssueAccessToken(p.issuer, sess.SubjectDID, sess.ClientID, accessTokenTTL, p.signingKey, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rawRefresh, refreshHash, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Persist refresh token. It starts a new rotation family.
	familyID, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rt := &store.RefreshToken{
		Hash:       refreshHash,
		FamilyID:   familyID,
		SubjectDID: sess.SubjectDID,
		ClientID:   sess.ClientID,
		Scope:      sess.Scope,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(refreshTokenTTL),
	}
	if err := p.store.SaveRefreshToken(r.Context(), rt); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeTokenResponse(w, accessToken, idToken, rawRefresh, sess.Scope, accessTokenTTL)
}

func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	rawToken := r.FormValue("refresh_token")
	if rawToken == "" {
		writeError(w, "invalid_request", "missing refresh_token")
		return
	}

	hash := hashToken(rawToken)
	rt, err := p.store.GetRefreshToken(r.Context(), hash)
	if err != nil {
		writeError(w, "invalid_grant", "refresh token not found")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		_ = p.store.DeleteRefreshToken(r.Context(), hash)
		writeError(w, "invalid_grant", "refresh token expired")
		return
	}
	// Replay of a rotated token indicates theft: end the whole rotation family.
	if rt.UsedAt != nil {
		_ = p.store.DeleteRefreshTokenFamily(r.Context(), rt.FamilyID)
		_ = p.store.DeleteRefreshToken(r.Context(), hash)
		writeError(w, "invalid_grant", "refresh token already used")
		return
	}

	// Validate client auth.
	if err := p.validateClientAuth(r, rt.ClientID); err != nil {
		writeError(w, "invalid_client", err.Error())
		return
	}

	// Claim the token atomically. If a concurrent request claimed it first, that is a replay.
	claimed, err := p.store.MarkRefreshTokenUsed(r.Context(), hash, time.Now())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !claimed {
		_ = p.store.DeleteRefreshTokenFamily(r.Context(), rt.FamilyID)
		writeError(w, "invalid_grant", "refresh token already used")
		return
	}

	// Issue new tokens.
	accessToken, err := IssueAccessToken(p.issuer, rt.SubjectDID, rt.ClientID, accessTokenTTL, p.signingKey, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rawRefresh, refreshHash, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newRT := &store.RefreshToken{
		Hash:       refreshHash,
		FamilyID:   rt.FamilyID,
		SubjectDID: rt.SubjectDID,
		ClientID:   rt.ClientID,
		Scope:      rt.Scope,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(refreshTokenTTL),
	}
	if err := p.store.SaveRefreshToken(r.Context(), newRT); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeTokenResponse(w, accessToken, "", rawRefresh, rt.Scope, accessTokenTTL)
}

// handleClientCredentialsGrant issues an access token for M2M clients (RFC 6749 §4.4).
// No user session is created; sub is set to client_id. No refresh token is issued.
func (p *Provider) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	if clientID == "" {
		if id, _, ok := r.BasicAuth(); ok {
			clientID = id
		}
	}
	if clientID == "" {
		writeError(w, "invalid_client", "client_id required")
		return
	}
	if err := p.validateClientAuth(r, clientID); err != nil {
		writeError(w, "invalid_client", err.Error())
		return
	}
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeError(w, "invalid_client", "unknown client")
		return
	}
	// Only confidential clients (non-"none" auth method) may use client_credentials.
	if client.TokenEndpointAuthMethod == "none" {
		writeError(w, "unauthorized_client", "public clients may not use client_credentials grant")
		return
	}
	scope := r.FormValue("scope")
	if scope == "" {
		scope = client.Scope
	}
	// sub = client_id for M2M tokens (no user DID).
	accessToken, err := IssueAccessToken(p.issuer, clientID, clientID, accessTokenTTL, p.signingKey, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
		"access_token": accessToken,
		"scope":        scope,
	})
}

// UserinfoHandler handles GET /userinfo.
func (p *Provider) UserinfoHandler(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	claims, err := p.VerifyAccessToken(r.Context(), bearer)
	if err != nil {
		http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub": claims.Subject,
		"did": claims.DID,
		"amr": claims.AMR,
	})
}

// IssueSessionForDIDCtx issues an authorization code for the given subject DID.
// Used by bridge handlers after external authentication completes.
// codeChallenge/Method carry PKCE params from the initiating client.
func (p *Provider) IssueSessionForDIDCtx(r *http.Request, subjectDID, clientID, redirectURI, scope, nonce, codeChallenge, codeChallengeMethod string, amr []string) (string, error) {
	code, err := randomHex(32)
	if err != nil {
		return "", err
	}
	sess := &store.OIDCSession{
		ID:                  randomID(),
		SubjectDID:          subjectDID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               nonce,
		Code:                code,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UserAgent:           r.UserAgent(),
		IPAddress:           remoteIP(r),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(codeTTL),
	}
	return code, p.store.SaveSession(r.Context(), sess)
}

// SubjectFromBearer extracts and verifies the subject DID from a Bearer access token.
func (p *Provider) SubjectFromBearer(authHeader string) (string, error) {
	bearer := strings.TrimPrefix(authHeader, "Bearer ")
	if bearer == "" {
		return "", fmt.Errorf("no bearer token")
	}
	claims, err := p.VerifyAccessToken(context.Background(), bearer)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// VerifyAccessToken validates a platform-issued access token for use against the API.
// It checks the signature, issuer, expiry, token_type, presence of an audience and the
// persistent revocation list. ID tokens are rejected, even though they are signed by
// the same key.
func (p *Provider) VerifyAccessToken(ctx context.Context, token string) (*Claims, error) {
	claims, err := Verify(token, p.signingPub)
	if err != nil {
		return nil, err
	}
	if claims.Issuer != p.issuer {
		return nil, fmt.Errorf("jwt: issuer mismatch")
	}
	if claims.TokenType != "access" {
		return nil, fmt.Errorf("jwt: not an access token")
	}
	if claims.Audience == "" {
		return nil, fmt.Errorf("jwt: missing audience")
	}
	if p.isAccessTokenRevoked(ctx, token) {
		return nil, fmt.Errorf("jwt: token revoked")
	}
	// Suspended and deleted identities lose API access at once, even with an unexpired
	// token. A lookup error also denies access.
	id, err := p.store.GetIdentity(ctx, claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("jwt: subject not found")
	}
	if id.Role == "suspended" || id.Role == "deleted" {
		return nil, fmt.Errorf("jwt: subject is not active")
	}
	return claims, nil
}

// validateClientAuth checks the client secret for confidential clients.
func (p *Provider) validateClientAuth(r *http.Request, clientID string) error {
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		return fmt.Errorf("unknown client")
	}
	if client.TokenEndpointAuthMethod == "none" {
		return nil // public client, no secret required
	}
	// Check Authorization: Basic or client_secret form param.
	var providedSecret string
	if user, pass, ok := r.BasicAuth(); ok && user == clientID {
		providedSecret = pass
	} else {
		providedSecret = r.FormValue("client_secret")
	}
	if providedSecret == "" {
		return fmt.Errorf("client authentication required")
	}
	if subtle.ConstantTimeCompare([]byte(hashSecret(providedSecret)), []byte(client.ClientSecretHash)) != 1 {
		return fmt.Errorf("invalid client credentials")
	}
	return nil
}

func writeTokenResponse(w http.ResponseWriter, accessToken, idToken, refreshToken, scope string, ttl time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]any{
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"scope":         scope,
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	json.NewEncoder(w).Encode(resp)
}

func generateRefreshToken() (raw, hash string, err error) {
	raw, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	return raw, hashToken(raw), nil
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// verifyPKCE checks that sha256(code_verifier) == code_challenge (S256 method).
func verifyPKCE(challenge, verifier string) error {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return errors.New("pkce: challenge mismatch")
	}
	return nil
}

func containsURI(list []string, uri string) bool {
	for _, u := range list {
		if u == uri {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		return ip[:idx]
	}
	return ip
}

func writeError(w http.ResponseWriter, code, desc string) {
	writeErrorStatus(w, http.StatusBadRequest, code, desc)
}

func writeErrorStatus(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomID() string {
	s, _ := randomHex(16)
	return fmt.Sprintf("sess_%s", s)
}
