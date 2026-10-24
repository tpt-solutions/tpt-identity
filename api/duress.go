package api

import (
	"encoding/json"
	"net/http"

	"github.com/tpt-solutions/tpt-identity/internal/authn"
)

// handleDuressEnrol sets (or replaces) the duress passphrase for the authenticated subject.
// POST /api/v1/me/duress/enrol
func (s *Server) handleDuressEnrol(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		DuressPassphrase string `json:"duress_passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DuressPassphrase == "" {
		http.Error(w, "duress_passphrase required", http.StatusBadRequest)
		return
	}

	mgr := authn.NewDuressManager(s.store)
	if err := mgr.Enrol(r.Context(), subjectDID, req.DuressPassphrase); err != nil {
		http.Error(w, "enrolment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Duress passphrase enrolled. Use it instead of your normal password when under coercion — authentication will succeed silently and a security alert will fire.",
	})
}

// handleDuressRemove removes the duress passphrase for the authenticated subject.
// DELETE /api/v1/me/duress
func (s *Server) handleDuressRemove(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	mgr := authn.NewDuressManager(s.store)
	if err := mgr.Remove(r.Context(), subjectDID); err != nil {
		http.Error(w, "remove failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
