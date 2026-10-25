package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// ──────────────────────────────────────────────────────────────────────────────
// Issue SD-JWT credential
// ──────────────────────────────────────────────────────────────────────────────

// issueSDJWTRequest is the JSON request body for POST /api/v1/credentials/sd-jwt.
// The platform signing key is used automatically — callers never submit private keys.
type issueSDJWTRequest struct {
	// IssuerDID is the DID that will appear in the iss claim.
	// Defaults to the server's configured issuer if omitted.
	IssuerDID string `json:"issuer_did,omitempty"`
	// SubjectDID is the DID of the credential holder.
	SubjectDID string `json:"subject_did"`
	// SchemaID is validated against the registered schema taxonomy (e.g. "identity.legal-name").
	SchemaID string `json:"schema_id,omitempty"`
	// SelectiveClaims are individually hashed; the holder reveals subsets per verifier.
	SelectiveClaims map[string]any `json:"selective_claims"`
	// AlwaysVisibleClaims are embedded directly in the JWT payload (not hashed).
	AlwaysVisibleClaims map[string]any `json:"always_visible_claims,omitempty"`
	// ValidFor is the credential lifetime as a Go duration string, e.g. "8760h". Default 24h.
	ValidFor string `json:"valid_for,omitempty"`
	// ReturnFormat controls the response shape.
	// "full"       — JWT + structured disclosure list (default; holder stores this)
	// "serialized" — also include the full serialized SD-JWT string
	ReturnFormat string `json:"return_format,omitempty"`
}

type disclosureView struct {
	Key     string `json:"key"`
	Encoded string `json:"encoded"` // base64url([salt, key, value])
}

type issueSDJWTResponse struct {
	// ID is the credential's jti. Revoke the credential with POST /api/v1/credentials/sd-jwt/{id}/revoke.
	ID          string           `json:"id,omitempty"`
	JWT         string           `json:"jwt"`
	Disclosures []disclosureView `json:"disclosures"`
	// Serialized is only present when return_format is "serialized".
	Serialized string `json:"serialized,omitempty"`
}

// handleIssueSDJWT issues an SD-JWT credential using the platform signing key.
// POST /api/v1/credentials/sd-jwt
func (s *Server) handleIssueSDJWT(w http.ResponseWriter, r *http.Request) {
	if s.signingKey == nil {
		http.Error(w, "platform signing key not configured", http.StatusServiceUnavailable)
		return
	}

	var req issueSDJWTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.SubjectDID == "" {
		http.Error(w, "subject_did required", http.StatusBadRequest)
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
	if validFor <= 0 {
		validFor = 24 * time.Hour
	}

	// Every credential the platform issues gets a bit in a token status list, so it can be revoked.
	opts := vc.SDJWTIssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            s.signingKey,
		VerificationMethodID: s.signingKeyID,
		SubjectDID:           req.SubjectDID,
		SchemaID:             req.SchemaID,
		SelectiveClaims:      req.SelectiveClaims,
		AlwaysVisibleClaims:  req.AlwaysVisibleClaims,
		ValidFor:             validFor,
	}
	var listID string
	var statusIndex int
	if issuerDID == s.platformDID {
		listURL, idx, err := s.allocateStatus(r.Context())
		if err != nil {
			http.Error(w, "status entry: "+err.Error(), http.StatusInternalServerError)
			return
		}
		listID, statusIndex = listURL, idx
		id, err := randomSDJWTID()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		opts.ID = id
		opts.Status = &vc.SDJWTStatus{ListURI: s.tokenStatusURI(listURL), Index: idx}
	}
	token, err := vc.IssueSDJWT(opts)
	if err != nil {
		http.Error(w, "issue sd-jwt: "+err.Error(), http.StatusBadRequest)
		return
	}
	if opts.ID != "" {
		now := time.Now()
		if err := s.store.SaveSDJWTIssued(r.Context(), &store.SDJWTIssued{
			ID:          opts.ID,
			SubjectDID:  req.SubjectDID,
			StatusList:  listID,
			StatusIndex: statusIndex,
			IssuedAt:    now,
			ExpiresAt:   now.Add(validFor),
		}); err != nil {
			http.Error(w, "record sd-jwt: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	resp := issueSDJWTResponse{
		ID:          opts.ID,
		JWT:         token.JWT,
		Disclosures: make([]disclosureView, 0, len(token.Disclosures)),
	}
	for _, d := range token.Disclosures {
		enc, _ := d.Encode()
		resp.Disclosures = append(resp.Disclosures, disclosureView{
			Key:     d.Key,
			Encoded: enc,
		})
	}
	if req.ReturnFormat == "serialized" {
		resp.Serialized = token.Serialize()
	}

	CredentialsIssuedTotal.WithLabelValues("sdjwt").Inc()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp) //nolint:gosec // G117: the holder receives this credential by design
}

// ──────────────────────────────────────────────────────────────────────────────
// Verify SD-JWT presentation
// ──────────────────────────────────────────────────────────────────────────────

type verifySDJWTRequest struct {
	// Token is the SD-JWT presentation string:
	//   <issuer-jwt>~<disc1>~...~          (no key binding)
	//   <issuer-jwt>~<disc1>~<kb-jwt>      (with key binding)
	Token string `json:"token"`
	// ExpectedNonce, when non-empty, requires a KB-JWT with a matching nonce (anti-replay).
	ExpectedNonce string `json:"expected_nonce,omitempty"`
	// ExpectedAudience, when non-empty, requires a KB-JWT with a matching aud claim.
	ExpectedAudience string `json:"expected_audience,omitempty"`
}

type verifySDJWTResponse struct {
	Valid              bool           `json:"valid"`
	IssuerDID          string         `json:"issuer_did,omitempty"`
	SubjectDID         string         `json:"subject_did,omitempty"`
	SchemaID           string         `json:"schema_id,omitempty"`
	DisclosedClaims    map[string]any `json:"disclosed_claims,omitempty"`
	AlwaysClaims       map[string]any `json:"always_claims,omitempty"`
	IssuedAt           *time.Time     `json:"issued_at,omitempty"`
	ExpiresAt          *time.Time     `json:"expires_at,omitempty"`
	KeyBindingVerified bool           `json:"key_binding_verified"`
	Error              string         `json:"error,omitempty"`
}

// handleVerifySDJWT verifies an SD-JWT presentation and returns the disclosed claims.
// POST /api/v1/credentials/sd-jwt/verify
func (s *Server) handleVerifySDJWT(w http.ResponseWriter, r *http.Request) {
	var req verifySDJWTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}

	verifier := vc.NewSDJWTVerifier(s.resolver)
	result, err := verifier.Verify(req.Token, req.ExpectedNonce, req.ExpectedAudience)
	if err == nil {
		err = s.checkSDJWTStatus(r.Context(), result.AlwaysClaims)
	}
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(verifySDJWTResponse{Valid: false, Error: err.Error()})
		return
	}

	resp := verifySDJWTResponse{
		Valid:              true,
		IssuerDID:          result.IssuerDID,
		SubjectDID:         result.SubjectDID,
		SchemaID:           result.SchemaID,
		DisclosedClaims:    result.DisclosedClaims,
		AlwaysClaims:       result.AlwaysClaims,
		KeyBindingVerified: result.KeyBindingVerified,
	}
	if !result.IssuedAt.IsZero() {
		resp.IssuedAt = &result.IssuedAt
	}
	if !result.ExpiresAt.IsZero() {
		resp.ExpiresAt = &result.ExpiresAt
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
