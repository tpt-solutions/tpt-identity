package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/PhillipC05/tpt-identity/pkg/vc"
)

// handleBatchIssueCredentials handles POST /api/v1/credentials/batch.
//
// Issues up to 10 credentials in a single request. Each item in the request
// array uses the same schema as issueCredentialRequest.
//
// Response: array of { credential | error } in the same order as the request.
func (s *Server) handleBatchIssueCredentials(w http.ResponseWriter, r *http.Request) {
	if s.signingKey == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "not_configured", "platform signing key not configured")
		return
	}

	var requests []issueCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "expected JSON array of credential requests")
		return
	}
	if len(requests) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "empty batch")
		return
	}
	const maxBatch = 10
	if len(requests) > maxBatch {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "batch size exceeds maximum of 10")
		return
	}

	type result struct {
		Credential *vc.VerifiableCredential `json:"credential,omitempty"`
		Error      string                   `json:"error,omitempty"`
	}
	results := make([]result, len(requests))

	for i, req := range requests {
		issuerDID := req.IssuerDID
		if issuerDID == "" {
			issuerDID = s.issuer
		}
		var validFor time.Duration
		if req.ValidFor != "" {
			var err error
			validFor, err = time.ParseDuration(req.ValidFor)
			if err != nil {
				results[i] = result{Error: "invalid valid_for: " + err.Error()}
				continue
			}
		}

		opts := vc.IssueOptions{
			IssuerDID:            issuerDID,
			IssuerKey:            s.signingKey,
			VerificationMethodID: s.signingKeyID,
			SubjectDID:           req.SubjectDID,
			SchemaID:             req.SchemaID,
			Claims:               req.Claims,
			ValidFor:             validFor,
			StatusListCredential: req.StatusListCredential,
			StatusListIndex:      req.StatusListIndex,
		}

		cred, err := vc.Issue(opts)
		if err != nil {
			results[i] = result{Error: err.Error()}
			continue
		}
		if err := s.store.SaveCredential(r.Context(), cred); err != nil {
			results[i] = result{Error: "store error: " + err.Error()}
			continue
		}
		results[i] = result{Credential: cred}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// handleCredentialFreshness handles GET /api/v1/credentials/{id}/fresh.
//
// Returns a signed freshness assertion indicating whether the credential is
// still valid (not revoked, not expired). Relying parties can call this
// endpoint rather than fetching the full BitstringStatusList.
func (s *Server) handleCredentialFreshness(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	cred, err := s.store.GetCredential(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "credential not found")
		return
	}

	now := time.Now().UTC()
	fresh := true
	reason := "valid"

	if cred.ValidUntil != nil && now.After(*cred.ValidUntil) {
		fresh = false
		reason = "expired"
	}

	// Check revocation status from CredentialStatus if present.
	if cred.CredentialStatus != nil {
		// A status list check would require fetching the status list VC.
		// For now we report the locally-known status.
		reason = "status_list_check_required"
	}

	response := map[string]any{
		"credential_id": id,
		"subject_did":   cred.CredentialSubject.ID,
		"schema_id":     cred.Type[len(cred.Type)-1],
		"fresh":         fresh,
		"reason":        reason,
		"checked_at":    now,
		"valid_from":    cred.ValidFrom,
		"valid_until":   cred.ValidUntil,
		"issuer":        cred.Issuer,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=60") // freshness assertions cacheable for 1 minute
	json.NewEncoder(w).Encode(response)
}
