package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// handleAdminListDIDCommInbox lists the DIDComm messages the server has kept, newest first.
// GET /admin/v1/didcomm/inbox?limit=100&offset=0
func (s *Server) handleAdminListDIDCommInbox(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r, 100, 500)
	msgs, total, err := s.store.ListDIDCommInbox(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, "list inbox: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	_ = json.NewEncoder(w).Encode(msgs)
}
