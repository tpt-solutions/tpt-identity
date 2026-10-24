package oidc

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

const (
	deviceCodeTTL      = 15 * time.Minute
	devicePollInterval = 5 // seconds
)

// DeviceAuthorizationHandler implements POST /device_authorization (RFC 8628 §3.1).
//
// The client receives a device_code, a human-friendly user_code, and a
// verification_uri. The user visits the URI on any browser, enters the user_code,
// authenticates, and the client polls /token until the code is approved or expires.
func (p *Provider) DeviceAuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid_request", "could not parse form")
		return
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		writeError(w, "invalid_client", "client_id required")
		return
	}
	if err := p.validateClientAuth(r, clientID); err != nil {
		writeError(w, "invalid_client", err.Error())
		return
	}

	scope := r.FormValue("scope")

	devCode, err := randomHex(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	userCode := generateUserCode()

	dc := &store.DeviceCode{
		DeviceCode:   devCode,
		UserCode:     userCode,
		ClientID:     clientID,
		Scope:        scope,
		ExpiresAt:    time.Now().Add(deviceCodeTTL),
		IntervalSecs: devicePollInterval,
		CreatedAt:    time.Now(),
	}
	if err := p.store.SaveDeviceCode(r.Context(), dc); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	verificationURI := fmt.Sprintf("%s/device", p.issuer)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"device_code":               devCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": fmt.Sprintf("%s?user_code=%s", verificationURI, userCode),
		"expires_in":                int(deviceCodeTTL.Seconds()),
		"interval":                  devicePollInterval,
	})
}

// DeviceVerifyHandler serves GET /device — renders the user-code entry page.
// In a production deployment this would be a proper HTML form; here it returns
// a minimal JSON prompt suitable for API clients and testing.
func (p *Provider) DeviceVerifyHandler(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"prompt": "Enter the user_code shown on your device at this URL, then POST to /device/approve.",
		})
		return
	}
	// If user_code is pre-filled in the URL, confirm it's valid.
	dc, err := p.store.GetDeviceCodeByUserCode(r.Context(), strings.ToUpper(userCode))
	if err != nil || time.Now().After(dc.ExpiresAt) {
		writeError(w, "invalid_request", "user_code not found or expired")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"client_id": dc.ClientID,
		"scope":     dc.Scope,
		"message":   "Authenticate and POST to /device/approve with {user_code, subject_did} to approve.",
	})
}

// DeviceApproveHandler handles POST /device/approve — called by the authorisation
// UI once the end-user is signed in. The approving subject is taken from the
// caller's verified bearer token; a form-supplied subject is never trusted.
func (p *Provider) DeviceApproveHandler(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := p.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeErrorStatus(w, http.StatusUnauthorized, "login_required", "authenticated session required")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid_request", "could not parse form")
		return
	}
	userCode := strings.ToUpper(r.FormValue("user_code"))
	if userCode == "" {
		writeError(w, "invalid_request", "user_code required")
		return
	}

	dc, err := p.store.GetDeviceCodeByUserCode(r.Context(), userCode)
	if err != nil || time.Now().After(dc.ExpiresAt) {
		writeError(w, "invalid_request", "user_code not found or expired")
		return
	}
	if dc.Approved || dc.Denied {
		writeError(w, "invalid_request", "device request already decided")
		return
	}
	dc.SubjectDID = subjectDID
	dc.Approved = true
	if err := p.store.UpdateDeviceCode(r.Context(), dc); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
}

// handleDeviceGrant is called from TokenHandler when grant_type=urn:ietf:params:oauth:grant-type:device_code.
func (p *Provider) handleDeviceGrant(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.FormValue("device_code")
	clientID := r.FormValue("client_id")
	if deviceCode == "" {
		writeError(w, "invalid_request", "device_code required")
		return
	}

	dc, err := p.store.GetDeviceCode(r.Context(), deviceCode)
	if err != nil {
		writeError(w, "invalid_grant", "device_code not found")
		return
	}
	if clientID != "" && clientID != dc.ClientID {
		writeError(w, "invalid_client", "client_id mismatch")
		return
	}
	if time.Now().After(dc.ExpiresAt) {
		_ = p.store.DeleteDeviceCode(r.Context(), deviceCode)
		writeError(w, "expired_token", "device_code expired")
		return
	}
	if dc.Denied {
		_ = p.store.DeleteDeviceCode(r.Context(), deviceCode)
		writeError(w, "access_denied", "user denied the request")
		return
	}
	if !dc.Approved {
		// RFC 8628 §3.5: polling faster than the interval must back off with slow_down.
		now := time.Now()
		last, polled := p.devicePolls.Load(deviceCode)
		p.devicePolls.Store(deviceCode, now)
		if polled && now.Sub(last.(time.Time)) < time.Duration(dc.IntervalSecs)*time.Second {
			writeError(w, "slow_down", "polling too fast; increase the interval")
			return
		}
		// RFC 8628 §3.5: return authorization_pending until approved or expired.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "authorization_pending",
			"error_description": "The user has not yet approved the device request; keep polling.",
		})
		return
	}

	// Approved — issue tokens.
	accessToken, err := IssueAccessToken(p.issuer, dc.SubjectDID, dc.ClientID, accessTokenTTL, p.signingKey, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rawRefresh, refreshHash, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	familyID, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rt := &store.RefreshToken{
		Hash:       refreshHash,
		FamilyID:   familyID,
		SubjectDID: dc.SubjectDID,
		ClientID:   dc.ClientID,
		Scope:      dc.Scope,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(refreshTokenTTL),
	}
	if err := p.store.SaveRefreshToken(r.Context(), rt); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = p.store.DeleteDeviceCode(r.Context(), deviceCode) // single-use
	p.devicePolls.Delete(deviceCode)
	writeTokenResponse(w, accessToken, "", rawRefresh, dc.Scope, accessTokenTTL)
}

// generateUserCode returns a memorable 8-character user code in XXXX-XXXX format.
// Uses only unambiguous uppercase letters (no I, O, 0, 1 confusion).
func generateUserCode() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 32 symbols: a byte mod 32 is unbiased
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("oidc: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}
