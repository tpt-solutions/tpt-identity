package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleGetMe handles GET /api/v1/me — returns the authenticated user's full profile.
//
// Authenticated via OIDC bearer token (the user's own access token, not api_key).
// Returns: DID, linked providers, active session count, active consents, credentials summary.
func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Fetch all relevant data in parallel using goroutines.
	type result struct {
		sessions   int
		links      int
		creds      int
		grants     int
		hasTOTP    bool
		hasPasskey bool
		hasDuress  bool
	}
	ch := make(chan result, 1)
	go func() {
		var res result
		if sessions, _ := s.store.ListSessionsBySubject(r.Context(), subjectDID); sessions != nil {
			res.sessions = len(sessions)
		}
		if links, _ := s.store.ListExternalLinks(r.Context(), subjectDID); links != nil {
			res.links = len(links)
		}
		if creds, _ := s.store.ListCredentials(r.Context(), subjectDID); creds != nil {
			res.creds = len(creds)
		}
		if grants, _ := s.store.ListGrants(r.Context(), subjectDID); grants != nil {
			res.grants = len(grants)
		}
		if _, err := s.store.GetTOTPCredential(r.Context(), subjectDID); err == nil {
			res.hasTOTP = true
		}
		if passkeys, _ := s.store.ListWebAuthnCredentials(r.Context(), subjectDID); len(passkeys) > 0 {
			res.hasPasskey = true
		}
		if _, err := s.store.GetDuressHash(r.Context(), subjectDID); err == nil {
			res.hasDuress = true
		}
		ch <- res
	}()

	identity, err := s.store.GetIdentity(r.Context(), subjectDID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "identity not found")
		return
	}

	res := <-ch

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"did":    subjectDID,
		"method": identity.Method,
		"role":   identity.Role,
		"summary": map[string]any{
			"active_sessions":  res.sessions,
			"linked_providers": res.links,
			"credentials":      res.creds,
			"consent_grants":   res.grants,
		},
		"mfa": map[string]bool{
			"totp":    res.hasTOTP,
			"passkey": res.hasPasskey,
			"duress":  res.hasDuress,
		},
		"created_at": identity.CreatedAt,
	})
}

// handleExportMe handles GET /api/v1/me/export — GDPR/Privacy Act data portability.
//
// Returns a JSON bundle containing all data held for the authenticated user:
// identity, credentials, consent grants, consent receipts, linked providers,
// and audit events mentioning the subject DID.
// exportedSession is the subset of an OIDC session included in a user's data export.
type exportedSession struct {
	ID         string     `json:"id"`
	ClientID   string     `json:"clientId"`
	Scope      string     `json:"scope"`
	UserAgent  string     `json:"userAgent,omitempty"`
	IPAddress  string     `json:"ipAddress,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
}

func (s *Server) handleExportMe(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	identity, err := s.store.GetIdentity(r.Context(), subjectDID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "identity not found")
		return
	}

	creds, _ := s.store.ListCredentials(r.Context(), subjectDID)
	grants, _ := s.store.ListGrants(r.Context(), subjectDID)
	receipts, _ := s.store.ListReceipts(r.Context(), subjectDID)
	links, _ := s.store.ListExternalLinks(r.Context(), subjectDID)
	sessions, _ := s.store.ListSessionsBySubject(r.Context(), subjectDID)
	disclosures, _ := s.store.ListDisclosures(r.Context(), subjectDID, "")

	// Sessions hold live credentials (authorization codes, PKCE material, access tokens, refresh
	// token hashes); only the metadata a user needs to recognise a session is exported.
	sessionView := make([]exportedSession, 0, len(sessions))
	for _, sess := range sessions {
		sessionView = append(sessionView, exportedSession{
			ID:         sess.ID,
			ClientID:   sess.ClientID,
			Scope:      sess.Scope,
			UserAgent:  sess.UserAgent,
			IPAddress:  sess.IPAddress,
			LastUsedAt: sess.LastUsedAt,
			CreatedAt:  sess.CreatedAt,
			ExpiresAt:  sess.ExpiresAt,
		})
	}

	export := map[string]any{
		"export_timestamp": time.Now().UTC(),
		"subject_did":      subjectDID,
		"identity": map[string]any{
			"did":        identity.DID,
			"method":     identity.Method,
			"role":       identity.Role,
			"created_at": identity.CreatedAt,
		},
		"credentials":         creds,
		"consent_grants":      grants,
		"consent_receipts":    receipts,
		"linked_providers":    links,
		"sessions":            sessionView,
		"privacy_disclosures": disclosures,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="tpt-identity-export.json"`)
	_ = json.NewEncoder(w).Encode(export)
}
