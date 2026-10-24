package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/PhillipC05/tpt-identity/pkg/consent"
	"github.com/PhillipC05/tpt-identity/pkg/schema"
)

// handleListGrants lists the caller's own consent grants (including revoked ones, for the audit trail).
// GET /api/v1/consents/grants
func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authenticated session required")
		return
	}
	grants, err := s.store.ListGrants(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "list grants: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(grants)
}

// handleCreateGrant records consent from the signed-in subject. The subject comes from the
// token and the ID is generated here; the body supplies only the scope and relying party.
// POST /api/v1/consents/grants
func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authenticated session required")
		return
	}
	var body struct {
		RelyingDID          string             `json:"relyingDid"`
		Level               consent.GrantLevel `json:"level"`
		ScopeID             string             `json:"scopeId"`
		ExpiresAt           *time.Time         `json:"expiresAt,omitempty"`
		ExplicitlyConfirmed bool               `json:"explicitlyConfirmed"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	id, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	g := consent.Grant{
		ID:                  "grant_" + id,
		SubjectDID:          subjectDID,
		RelyingDID:          body.RelyingDID,
		Level:               body.Level,
		ScopeID:             body.ScopeID,
		GrantedAt:           time.Now().UTC(),
		ExpiresAt:           body.ExpiresAt,
		ExplicitlyConfirmed: body.ExplicitlyConfirmed,
	}
	// Category grants, extra-sensitive schemas and unknown scopes are all refused here.
	if err := consent.ValidateGrant(g); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	if err := s.store.SaveGrant(r.Context(), &g); err != nil {
		http.Error(w, "save grant", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(g)
}

// handleRevokeGrant withdraws one of the caller's grants. The record is kept with revoked_at
// set, not deleted, for the audit trail. A grant that belongs to someone else reads as not found.
// DELETE /api/v1/consents/grants/{id}
func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authenticated session required")
		return
	}
	id := r.PathValue("id")
	g, err := s.store.GetGrant(r.Context(), id)
	if err != nil || g.SubjectDID != subjectDID {
		writeJSONError(w, http.StatusNotFound, "not_found", "grant not found")
		return
	}
	revoked, err := s.store.RevokeGrant(r.Context(), id, time.Now())
	if err != nil {
		http.Error(w, "revoke grant", http.StatusInternalServerError)
		return
	}
	if !revoked {
		writeJSONError(w, http.StatusConflict, "already_revoked", "grant is already revoked")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSubmitReceipt records a new consent receipt — called by a relying party
// immediately after accessing a subject's credential.
// POST /api/v1/consents/receipts
func (s *Server) handleSubmitReceipt(w http.ResponseWriter, r *http.Request) {
	if s.signingKey == nil {
		http.Error(w, "platform signing key not configured", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		SubjectDID string             `json:"subject_did"`
		RelyingDID string             `json:"relying_did"`
		SchemaID   string             `json:"schema_id"`
		LegalBasis consent.LegalBasis `json:"legal_basis"`
		Purpose    string             `json:"purpose,omitempty"`
		ExpiresAt  *time.Time         `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.SubjectDID == "" || req.RelyingDID == "" || req.SchemaID == "" {
		http.Error(w, "subject_did, relying_did, and schema_id are required", http.StatusBadRequest)
		return
	}
	if req.LegalBasis == "" {
		req.LegalBasis = consent.LegalBasisConsent
	}
	receipt, err := consent.Issue(consent.IssueOptions{
		SubjectDID: req.SubjectDID,
		RelyingDID: req.RelyingDID,
		SchemaID:   req.SchemaID,
		Purpose:    req.Purpose,
		LegalBasis: req.LegalBasis,
		ExpiresAt:  req.ExpiresAt,
		SignerKey:   s.signingKey,
		SignerKeyID: s.signingKeyID,
	})
	if err != nil {
		http.Error(w, "issue receipt: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.SaveReceipt(r.Context(), receipt); err != nil {
		http.Error(w, "save receipt: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(receipt)
}

func (s *Server) handleListReceipts(w http.ResponseWriter, r *http.Request) {
	subjectDID := r.URL.Query().Get("subject")
	if subjectDID == "" {
		http.Error(w, "subject query parameter required", http.StatusBadRequest)
		return
	}
	receipts, err := s.store.ListReceipts(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "list receipts: "+err.Error(), http.StatusInternalServerError)
		return
	}
	limit, offset := parsePagination(r, 100, 500)
	total := len(receipts)
	if offset > total {
		offset = total
	}
	receipts = receipts[offset:]
	if len(receipts) > limit {
		receipts = receipts[:limit]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	json.NewEncoder(w).Encode(receipts)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteSession(r.Context(), id); err != nil {
		http.Error(w, "delete session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSchemas(w http.ResponseWriter, r *http.Request) {
	cats := schema.AllCategories()
	type categoryWithSchemas struct {
		schema.Category
		Schemas []schema.Schema `json:"schemas"`
	}
	result := make([]categoryWithSchemas, 0, len(cats))
	for _, cat := range cats {
		result = append(result, categoryWithSchemas{
			Category: cat,
			Schemas:  schema.SchemasForCategory(cat.ID),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
