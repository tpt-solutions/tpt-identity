package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// handleListAuditLog returns paginated audit log entries in sequence order.
// GET /api/v1/audit-log
func (s *Server) handleListAuditLog(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r, 100, 500)
	events, total, err := s.store.ListAuditEvents(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	_ = json.NewEncoder(w).Encode(events)
}

// handleAuditProof returns the hash chain from a given sequence number to the
// current head, allowing third parties to verify log integrity.
// GET /api/v1/audit-log/proof/{seq}
func (s *Server) handleAuditProof(w http.ResponseWriter, r *http.Request) {
	seqStr := r.PathValue("seq")
	fromSeq, err := strconv.ParseInt(seqStr, 10, 64)
	if err != nil || fromSeq < 1 {
		http.Error(w, "invalid seq", http.StatusBadRequest)
		return
	}

	head, err := s.store.GetAuditHead(r.Context())
	if err != nil {
		http.Error(w, "audit log empty", http.StatusNotFound)
		return
	}

	// Return all events from fromSeq to the head so verifiers can walk the chain.
	limit := int(head.Seq - fromSeq + 1)
	if limit <= 0 {
		http.Error(w, "seq not found", http.StatusNotFound)
		return
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := int(fromSeq - 1)
	events, _, err := s.store.ListAuditEvents(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"from_seq":  fromSeq,
		"head_seq":  head.Seq,
		"head_hash": head.Hash,
		"chain":     events,
	})
}
