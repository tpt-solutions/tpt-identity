package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// handleListMySessions lists active sessions for the authenticated subject.
// GET /api/v1/me/sessions
func (s *Server) handleListMySessions(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessions, err := s.store.ListSessionsBySubject(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Strip sensitive fields before returning.
	type sessionView struct {
		ID         string `json:"id"`
		ClientID   string `json:"client_id"`
		UserAgent  string `json:"user_agent,omitempty"`
		IPAddress  string `json:"ip_address,omitempty"`
		LastUsedAt any    `json:"last_used_at,omitempty"`
		CreatedAt  any    `json:"created_at"`
		ExpiresAt  any    `json:"expires_at"`
	}
	views := make([]sessionView, 0, len(sessions))
	for _, sess := range sessions {
		views = append(views, sessionView{
			ID:         sess.ID,
			ClientID:   sess.ClientID,
			UserAgent:  sess.UserAgent,
			IPAddress:  sess.IPAddress,
			LastUsedAt: sess.LastUsedAt,
			CreatedAt:  sess.CreatedAt,
			ExpiresAt:  sess.ExpiresAt,
		})
	}

	limit, offset := parsePagination(r, 100, 500)
	total := len(views)
	if offset > total {
		offset = total
	}
	views = views[offset:]
	if len(views) > limit {
		views = views[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	_ = json.NewEncoder(w).Encode(views)
}

// handleRevokeMySession revokes a specific session belonging to the authenticated subject.
// DELETE /api/v1/me/sessions/{id}
func (s *Server) handleRevokeMySession(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		http.Error(w, "session id required", http.StatusBadRequest)
		return
	}

	// Verify the session belongs to this subject before deleting.
	sess, err := s.store.GetSession(r.Context(), sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if sess.SubjectDID != subjectDID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := s.store.DeleteSession(r.Context(), sessionID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.events.Publish(r.Context(), "session.revoked", map[string]string{
		"session_id":  sessionID,
		"subject_did": subjectDID,
	})

	w.WriteHeader(http.StatusNoContent)
}
