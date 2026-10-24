package api

import (
	"encoding/json"
	"net/http"
)

// handleStatusList serves GET /api/v1/status/{listId}.
// Returns the BitstringStatusListCredential VC as JSON.
// Verifiers fetch this to check whether a specific credential has been revoked.
func (s *Server) handleStatusList(w http.ResponseWriter, r *http.Request) {
	listID := r.PathValue("listId")
	if listID == "" {
		http.Error(w, "missing listId", http.StatusBadRequest)
		return
	}

	// The status list VC is stored as a regular credential with the full URL as its ID.
	// Convention: stored under id = <issuer>/api/v1/status/<listId>
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	credID := scheme + "://" + r.Host + "/api/v1/status/" + listID

	cred, err := s.store.GetCredential(r.Context(), credID)
	if err != nil {
		http.Error(w, "status list not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vc+ld+json")
	w.Header().Set("Cache-Control", "public, max-age=300") // 5-minute cache for verifiers
	_ = json.NewEncoder(w).Encode(cred)
}
