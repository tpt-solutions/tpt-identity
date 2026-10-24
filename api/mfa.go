package api

import (
	"encoding/json"
	"net/http"

	"github.com/tpt-solutions/tpt-identity/internal/authn"
)

// handleTOTPEnrol starts TOTP enrolment for the authenticated subject. The new factor is
// pending until its first code is verified. Replacing an active factor requires a current
// code from that factor, so a stolen bearer token alone cannot lock the owner out.
// POST /api/v1/me/totp/enrol
func (s *Server) handleTOTPEnrol(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		AccountName string `json:"account_name"`
		// CurrentCode is required when an active factor already exists.
		CurrentCode string `json:"current_code"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req)
	if req.AccountName == "" {
		req.AccountName = subjectDID
	}

	mgr := authn.NewTOTPManager(s.store, s.totpPassphrase, s.issuer)
	if mgr.IsEnrolled(subjectDID) {
		if req.CurrentCode == "" || mgr.VerifyCtx(r.Context(), subjectDID, req.CurrentCode) != nil {
			writeJSONError(w, http.StatusForbidden, "factor_required", "a current code from the enrolled authenticator is required to replace it")
			return
		}
	}

	uri, err := mgr.EnrolCtx(r.Context(), subjectDID, req.AccountName)
	if err != nil {
		http.Error(w, "enrolment failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"otpauth_uri": uri,
		"message":     "Scan the URI with your authenticator app, then verify with POST /api/v1/me/totp/verify",
	})
}

// handleTOTPVerify checks a TOTP code. The first success activates a pending factor. Each
// time step is accepted only once.
// POST /api/v1/me/totp/verify
func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req); err != nil || req.Code == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}

	mgr := authn.NewTOTPManager(s.store, s.totpPassphrase, s.issuer)
	if err := mgr.VerifyCtx(r.Context(), subjectDID, req.Code); err != nil {
		_ = s.lockout.RecordFailure(r.Context(), subjectDID)
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	s.lockout.RecordSuccess(r.Context(), subjectDID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
}

// handleTOTPUnenrol removes the TOTP factor. An active factor needs a current code.
// DELETE /api/v1/me/totp
func (s *Server) handleTOTPUnenrol(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	mgr := authn.NewTOTPManager(s.store, s.totpPassphrase, s.issuer)
	if mgr.IsEnrolled(subjectDID) {
		var req struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req); err != nil || req.Code == "" {
			writeJSONError(w, http.StatusForbidden, "factor_required", "a current code from the enrolled authenticator is required to remove it")
			return
		}
		if err := mgr.VerifyCtx(r.Context(), subjectDID, req.Code); err != nil {
			_ = s.lockout.RecordFailure(r.Context(), subjectDID)
			writeJSONError(w, http.StatusForbidden, "factor_required", "the code is incorrect")
			return
		}
	}

	if err := mgr.Unenrol(subjectDID); err != nil {
		http.Error(w, "unenrol failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
