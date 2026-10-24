package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// issueCredentialRequest is the JSON body for POST /api/v1/credentials.
// The platform signing key is used automatically — callers never submit private keys.
type issueCredentialRequest struct {
	// IssuerDID defaults to the server's configured issuer if omitted.
	IssuerDID  string            `json:"issuer_did,omitempty"`
	SubjectDID string            `json:"subject_did"`
	SchemaID   string            `json:"schema_id"`
	Claims     map[string]string `json:"claims"`
	// ValidFor is a Go duration string, e.g. "8760h". Zero means no expiry.
	ValidFor             string `json:"valid_for,omitempty"`
	StatusListCredential string `json:"status_list_credential,omitempty"`
	StatusListIndex      int    `json:"status_list_index,omitempty"`
}

func (s *Server) handleIssueCredential(w http.ResponseWriter, r *http.Request) {
	if s.signingKey == nil {
		http.Error(w, "platform signing key not configured", http.StatusServiceUnavailable)
		return
	}

	var req issueCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	issuerDID, err := s.issuerForRequest(req.IssuerDID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_issuer", err.Error())
		return
	}

	var validFor time.Duration
	if req.ValidFor != "" {
		var err error
		validFor, err = time.ParseDuration(req.ValidFor)
		if err != nil {
			http.Error(w, "invalid valid_for duration: "+err.Error(), http.StatusBadRequest)
			return
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
		http.Error(w, "issue: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.SaveCredential(r.Context(), cred); err != nil {
		http.Error(w, "save credential: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.events.Publish(r.Context(), "credential.issued", map[string]string{
		"id":         cred.ID,
		"subject":    cred.CredentialSubject.ID,
		"schema_id":  req.SchemaID,
		"issuer_did": issuerDID,
	})
	CredentialsIssuedTotal.WithLabelValues("vc").Inc()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cred)
}

func (s *Server) handleVerifyCredential(w http.ResponseWriter, r *http.Request) {
	var cred vc.VerifiableCredential
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	verifier := vc.NewVerifier(s.resolver)
	if err := verifier.Verify(&cred); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"valid": "false", "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"valid": "true"})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	subjectDID := r.URL.Query().Get("subject")
	if subjectDID == "" {
		http.Error(w, "subject query parameter required", http.StatusBadRequest)
		return
	}
	creds, err := s.store.ListCredentials(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	limit, offset := parsePagination(r, 100, 500)
	total := len(creds)
	if offset > total {
		offset = total
	}
	creds = creds[offset:]
	if len(creds) > limit {
		creds = creds[:limit]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	_ = json.NewEncoder(w).Encode(creds)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteCredential(r.Context(), id); err != nil {
		http.Error(w, "delete: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
