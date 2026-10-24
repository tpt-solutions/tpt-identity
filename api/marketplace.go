package api

import (
	"encoding/json"
	"net/http"
)

// handleListMarketplace returns all advertised issuer+schema pairs.
// GET /api/v1/marketplace
func (s *Server) handleListMarketplace(w http.ResponseWriter, r *http.Request) {
	if s.marketplace == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]struct{}{})
		return
	}
	entries := s.marketplace.List()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}
