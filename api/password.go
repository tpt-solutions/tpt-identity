package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	bridgeproviders "github.com/PhillipC05/tpt-identity/internal/bridge/providers"
	"github.com/PhillipC05/tpt-identity/internal/store"
)

// PasswordResetSender delivers a password-reset token to the account holder out of band.
// Implementations must not log the token or publish it on any event bus.
type PasswordResetSender interface {
	SendPasswordReset(ctx context.Context, identifier, rawToken string, expiresAt time.Time) error
}

var (
	errPasswordNotEnabled = errors.New("password bridge not enabled")
	errNoPasswordAccount  = errors.New("no password account for this identity")
)

// passwordBridge returns the configured password bridge.
func (s *Server) passwordBridge() (*bridgeproviders.PasswordBridge, error) {
	if s.bridges == nil {
		return nil, errPasswordNotEnabled
	}
	b, ok := s.bridges.Get("password")
	if !ok {
		return nil, errPasswordNotEnabled
	}
	pb, ok := b.(*bridgeproviders.PasswordBridge)
	if !ok {
		return nil, errors.New("password bridge misconfigured")
	}
	return pb, nil
}

// hasPasswordAccount reports whether identifier already has a stored password. Password
// reset must never create one: the bridge's SetPassword is an upsert.
func (s *Server) hasPasswordAccount(ctx context.Context, identifier string) bool {
	_, err := s.store.GetPasswordHash(ctx, identifier)
	return err == nil
}

// passwordIdentifierFor returns the password-bridge identifier linked to subjectDID.
func (s *Server) passwordIdentifierFor(ctx context.Context, subjectDID string) (string, error) {
	links, err := s.store.ListExternalLinks(ctx, subjectDID)
	if err != nil {
		return "", err
	}
	for _, l := range links {
		if l.Provider == "password" {
			return l.ExternalID, nil
		}
	}
	return "", errNoPasswordAccount
}

// revokeSubjectSessions ends every session and refresh-token family held by subjectDID.
func (s *Server) revokeSubjectSessions(ctx context.Context, subjectDID string) {
	sessions, err := s.store.ListSessionsBySubject(ctx, subjectDID)
	if err != nil {
		return
	}
	for _, sess := range sessions {
		if sess.RefreshTokenHash != "" {
			if rt, rtErr := s.store.GetRefreshToken(ctx, sess.RefreshTokenHash); rtErr == nil {
				_ = s.store.DeleteRefreshTokenFamily(ctx, rt.FamilyID)
			}
			_ = s.store.DeleteRefreshToken(ctx, sess.RefreshTokenHash)
		}
		_ = s.store.DeleteSession(ctx, sess.ID)
	}
}

// handlePasswordChange handles POST /auth/password/change.
//
// Requires a valid OIDC bearer token (proves identity) plus the current password.
// Body (JSON): { "current_password": "...", "new_password": "..." }
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if body.CurrentPassword == "" || body.NewPassword == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "current_password and new_password required")
		return
	}

	pb, err := s.passwordBridge()
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "not_supported", err.Error())
		return
	}
	identifier, err := s.passwordIdentifierFor(r.Context(), subjectDID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "not_supported", err.Error())
		return
	}
	if err := s.lockout.CheckLocked(r.Context(), identifier); err != nil {
		writeJSONError(w, http.StatusTooManyRequests, "locked", "account temporarily locked")
		return
	}

	if _, err := pb.VerifyCredentials(r.Context(), identifier, body.CurrentPassword); err != nil {
		_ = s.lockout.RecordFailure(r.Context(), identifier)
		writeJSONError(w, http.StatusUnauthorized, "invalid_credentials", "current password is incorrect")
		return
	}
	s.lockout.RecordSuccess(r.Context(), identifier)

	if err := pb.SetPassword(r.Context(), identifier, body.NewPassword); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handlePasswordResetRequest handles POST /auth/password/reset/request.
//
// Body (JSON): { "identifier": "user@example.com" }
// Always returns 200 to avoid identifier enumeration. A token is issued only for an
// identifier that already has a password, and is delivered only through the sender.
// POST /auth/password/reset/request
func (s *Server) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Identifier string `json:"identifier"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&body); err != nil || body.Identifier == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "identifier required")
		return
	}

	identifier := strings.ToLower(strings.TrimSpace(body.Identifier))

	// Rate-limit: 3 reset attempts per identifier per lockout window.
	count, _, _ := s.store.GetAuthFailures(r.Context(), "reset:"+identifier)
	if count < 3 && s.passwordResets != nil && s.hasPasswordAccount(r.Context(), identifier) {
		rawToken, err := randomHex(32)
		if err == nil {
			h := sha256.Sum256([]byte(rawToken))
			tok := &store.PasswordResetToken{
				Hash:       hex.EncodeToString(h[:]),
				Identifier: identifier,
				ExpiresAt:  time.Now().Add(15 * time.Minute),
				CreatedAt:  time.Now(),
			}
			if saveErr := s.store.SavePasswordResetToken(r.Context(), tok); saveErr == nil {
				if sendErr := s.passwordResets.SendPasswordReset(r.Context(), identifier, rawToken, tok.ExpiresAt); sendErr != nil {
					s.logger.Error("password reset delivery failed", "error", sendErr)
				} else {
					// The event carries the identifier only, never the token.
					s.events.Publish(r.Context(), "password.reset_requested", map[string]string{
						"identifier": identifier,
						"expires_at": tok.ExpiresAt.Format(time.RFC3339),
					})
				}
			}
		}
		_ = s.store.RecordAuthFailure(r.Context(), "reset:"+identifier)
	}

	// Always return 200 — do not reveal whether identifier exists.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "If this identifier is registered, a reset link has been sent.",
	})
}

// handlePasswordResetConfirm handles POST /auth/password/reset/confirm.
//
// Body (JSON): { "token": "...", "new_password": "..." }
// The token is consumed atomically, so it can be used once. A successful reset ends
// every session the account holds.
func (s *Server) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if body.Token == "" || body.NewPassword == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "token and new_password required")
		return
	}

	h := sha256.Sum256([]byte(body.Token))
	tok, err := s.store.ConsumePasswordResetToken(r.Context(), hex.EncodeToString(h[:]))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusBadRequest, "invalid_token", "token not found or already used")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "could not redeem token")
		return
	}
	if time.Now().After(tok.ExpiresAt) {
		writeJSONError(w, http.StatusBadRequest, "invalid_token", "token expired")
		return
	}

	pb, err := s.passwordBridge()
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "not_supported", err.Error())
		return
	}
	if !s.hasPasswordAccount(r.Context(), tok.Identifier) {
		writeJSONError(w, http.StatusBadRequest, "invalid_token", "token not found or already used")
		return
	}
	if err := pb.SetPassword(r.Context(), tok.Identifier, body.NewPassword); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	_ = s.store.ClearAuthFailures(r.Context(), tok.Identifier)
	_ = s.store.ClearAuthFailures(r.Context(), "reset:"+tok.Identifier)
	if link, err := s.store.GetExternalLink(r.Context(), "password", tok.Identifier); err == nil {
		s.revokeSubjectSessions(r.Context(), link.SubjectDID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
