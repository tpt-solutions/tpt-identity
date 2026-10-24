package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// handleGetPrivacyBudget handles GET /api/v1/me/privacy-budget.
//
// Returns disclosure counts per schema, so users can see how many distinct
// verifiers have received each field and make informed revocation decisions.
func (s *Server) handleGetPrivacyBudget(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	disclosures, err := s.store.ListDisclosures(r.Context(), subjectDID, "")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	// Aggregate by schema_id.
	type schemaStats struct {
		SchemaID        string         `json:"schema_id"`
		TotalShares     int            `json:"total_shares"`
		UniqueVerifiers int            `json:"unique_verifiers"`
		LastSharedAt    *time.Time     `json:"last_shared_at,omitempty"`
		VerifierCounts  map[string]int `json:"verifier_counts"` // verifier_did → count
	}
	statsMap := map[string]*schemaStats{}
	verifierSets := map[string]map[string]bool{} // schema_id → set of verifier DIDs

	for _, d := range disclosures {
		st := statsMap[d.SchemaID]
		if st == nil {
			st = &schemaStats{
				SchemaID:       d.SchemaID,
				VerifierCounts: map[string]int{},
			}
			statsMap[d.SchemaID] = st
			verifierSets[d.SchemaID] = map[string]bool{}
		}
		st.TotalShares++
		st.VerifierCounts[d.VerifierDID]++
		verifierSets[d.SchemaID][d.VerifierDID] = true
		t := d.DisclosedAt
		if st.LastSharedAt == nil || t.After(*st.LastSharedAt) {
			st.LastSharedAt = &t
		}
	}

	out := make([]*schemaStats, 0, len(statsMap))
	for sid, st := range statsMap {
		st.UniqueVerifiers = len(verifierSets[sid])
		out = append(out, st)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject_did":    subjectDID,
		"total_shares":   len(disclosures),
		"schema_budgets": out,
	})
}

// handleRecordDisclosure handles POST /api/v1/me/privacy-budget/record.
//
// Called by a relying party or the server after a selective-disclosure presentation.
// Body (JSON): { "schema_id": "...", "verifier_did": "...", "field_names": [...] }
func (s *Server) handleRecordDisclosure(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		// Also accept api_key auth (for RP-submitted disclosures).
		if s.apiKey == "" || extractBearer(r) != s.apiKey {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized", "bearer token or api_key required")
			return
		}
		// api_key auth: require subject_did in body
		subjectDID = ""
	}

	var body struct {
		SubjectDID  string   `json:"subject_did"`
		SchemaID    string   `json:"schema_id"`
		VerifierDID string   `json:"verifier_did"`
		FieldNames  []string `json:"field_names"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if subjectDID == "" {
		subjectDID = body.SubjectDID
	}
	if subjectDID == "" || body.SchemaID == "" || body.VerifierDID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "subject_did, schema_id, and verifier_did required")
		return
	}

	id, _ := randomHex(16)
	d := &store.PrivacyDisclosure{
		ID:          id,
		SubjectDID:  subjectDID,
		SchemaID:    body.SchemaID,
		VerifierDID: body.VerifierDID,
		FieldNames:  body.FieldNames,
		DisclosedAt: time.Now().UTC(),
	}
	if err := s.store.RecordDisclosure(r.Context(), d); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(d)
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
