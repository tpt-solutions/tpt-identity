package api

import (
	"encoding/json"
	"net/http"
)

// handleStatusList serves GET /api/v1/status/{listId}.
// Returns the BitstringStatusListCredential VC as JSON.
// Verifiers fetch this to check whether a specific credential has been revoked.
//
// The list's identity comes from the configured issuer, never from the request's Host header:
// a forged Host must not change which list is served.
func (s *Server) handleStatusList(w http.ResponseWriter, r *http.Request) {
	listID := r.PathValue("listId")
	if listID == "" {
		http.Error(w, "missing listId", http.StatusBadRequest)
		return
	}

	cred, err := s.store.GetCredential(r.Context(), s.issuer+statusListPath+listID)
	if err != nil {
		http.Error(w, "status list not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vc+ld+json")
	w.Header().Set("Cache-Control", "public, max-age=300") // 5-minute cache for verifiers
	_ = json.NewEncoder(w).Encode(cred)
}
