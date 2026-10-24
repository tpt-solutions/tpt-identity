package api

import (
	"encoding/json"
	"net/http"

	vcpkg "github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// handleIssueAgeProof handles POST /api/v1/credentials/zkp/age.
//
// Derives a signed "age-over-N" VC from a subject's verified DOB credential.
// The DOB is never returned — only the binary result is in the issued credential.
//
// Body (JSON):
//
//	{
//	  "dob_credential_id": "urn:uuid:...",
//	  "age_threshold":     18,
//	  "subject_did":       "did:web:...",
//	  "verifier_did":      "did:web:verifier.example.com"  // optional audience binding
//	}
//
// This endpoint requires api_key auth. The DOB credential must already be in the store.
func (s *Server) handleIssueAgeProof(w http.ResponseWriter, r *http.Request) {
	if s.signingKey == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "not_configured", "platform signing key not configured")
		return
	}

	var req vcpkg.AgeProofRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if req.DOBCredentialID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "dob_credential_id required")
		return
	}
	if req.AgeThreshold <= 0 || req.AgeThreshold > 150 {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "age_threshold must be 1–150")
		return
	}

	// Retrieve the DOB credential from the store.
	dobVC, err := s.store.GetCredential(r.Context(), req.DOBCredentialID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "DOB credential not found")
		return
	}

	// Confirm the credential belongs to the requested subject (if supplied).
	if req.SubjectDID != "" && dobVC.CredentialSubject.ID != req.SubjectDID {
		writeJSONError(w, http.StatusForbidden, "forbidden", "credential does not belong to subject_did")
		return
	}

	result, err := vcpkg.IssueAgeProof(
		dobVC,
		req.AgeThreshold,
		s.platformDID,
		s.signingKey,
		s.signingKeyID,
		req.VerifierDID,
	)
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "proof_failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

// handleSDJWTPresentWithWatermark handles POST /api/v1/credentials/sd-jwt/present.
//
// The holder POSTs their SD-JWT token and selects which claims to reveal.
// The server embeds a watermark for leak tracing and returns the presentation string.
//
// Body (JSON):
//
//	{
//	  "sd_jwt":       "<issuer-jwt>~<disc1>~...",
//	  "reveal_keys":  ["givenNames", "dateOfBirth"],
//	  "verifier_did": "did:web:verifier.example.com"
//	}
func (s *Server) handleSDJWTPresentWithWatermark(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SDJWT       string   `json:"sd_jwt"`
		RevealKeys  []string `json:"reveal_keys"`
		VerifierDID string   `json:"verifier_did"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if body.SDJWT == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "sd_jwt required")
		return
	}

	// Parse then reconstruct as SDJWTToken so we can call PresentWithWatermark.
	parsed, err := vcpkg.ParseSDJWT(body.SDJWT)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "could not parse sd_jwt: "+err.Error())
		return
	}
	var discs []vcpkg.Disclosure
	for _, enc := range parsed.Disclosures {
		d, decErr := vcpkg.ParseDisclosure(enc)
		if decErr != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "bad disclosure: "+decErr.Error())
			return
		}
		discs = append(discs, d)
	}
	token := &vcpkg.SDJWTToken{JWT: parsed.JWT, Disclosures: discs}

	presentation, record, err := token.PresentWithWatermark(body.RevealKeys, body.VerifierDID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"presentation":    presentation,
		"presentation_id": record.PresentationID,
		"verifier_did":    record.VerifierDID,
		"disclosed_at":    record.IssuedAt,
	})
}
