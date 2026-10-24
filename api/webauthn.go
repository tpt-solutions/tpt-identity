package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// waSessionEntry holds transient WebAuthn session data between Begin and Finish.
type waSessionEntry struct {
	session   gowebauthn.SessionData
	expiresAt time.Time
}

// waUser adapts a platform identity and its stored credentials to the webauthn.User interface.
type waUser struct {
	subjectDID string
	creds      []*store.WebAuthnCredential
}

func (u *waUser) WebAuthnID() []byte          { return []byte(u.subjectDID) }
func (u *waUser) WebAuthnName() string        { return u.subjectDID }
func (u *waUser) WebAuthnDisplayName() string { return u.subjectDID }
func (u *waUser) WebAuthnIcon() string        { return "" } //nolint:staticcheck // required by webauthn.User interface

func (u *waUser) WebAuthnCredentials() []gowebauthn.Credential {
	out := make([]gowebauthn.Credential, len(u.creds))
	for i, c := range u.creds {
		credID, _ := base64.RawURLEncoding.DecodeString(c.CredentialID)
		transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
		for j, t := range c.Transports {
			transports[j] = protocol.AuthenticatorTransport(t)
		}
		out[i] = gowebauthn.Credential{
			ID:        credID,
			PublicKey: c.PublicKeyCBOR,
			Authenticator: gowebauthn.Authenticator{
				SignCount: c.SignCount,
			},
			Transport: transports,
		}
	}
	return out
}

// ---- Registration ----

// handleWebAuthnRegisterBegin starts a WebAuthn registration ceremony for the
// authenticated subject.
// POST /api/v1/me/webauthn/register/begin
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		http.Error(w, "webauthn not configured", http.StatusNotImplemented)
		return
	}
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	creds, err := s.store.ListWebAuthnCredentials(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user := &waUser{subjectDID: subjectDID, creds: creds}

	creation, session, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, "begin registration failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID := waRandomID()
	s.waRegSessions.Store(sessionID, &waSessionEntry{
		session:   *session,
		expiresAt: time.Now().Add(5 * time.Minute),
	})
	http.SetCookie(w, waCookie("wa_reg_session", sessionID, 300))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creation)
}

// handleWebAuthnRegisterFinish completes the WebAuthn registration ceremony and
// persists the new credential, anchoring its public key in the subject's DID Document.
// POST /api/v1/me/webauthn/register/finish
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		http.Error(w, "webauthn not configured", http.StatusNotImplemented)
		return
	}
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cookie, err := r.Cookie("wa_reg_session")
	if err != nil {
		http.Error(w, "registration session not found — call begin first", http.StatusBadRequest)
		return
	}
	raw, ok := s.waRegSessions.LoadAndDelete(cookie.Value)
	if !ok || time.Now().After(raw.(*waSessionEntry).expiresAt) {
		http.Error(w, "registration session expired", http.StatusBadRequest)
		return
	}
	entry := raw.(*waSessionEntry)

	creds, err := s.store.ListWebAuthnCredentials(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user := &waUser{subjectDID: subjectDID, creds: creds}

	credential, err := s.webAuthn.FinishRegistration(user, entry.session, r)
	if err != nil {
		http.Error(w, "registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}
	aaguidStr := ""
	if len(credential.Authenticator.AAGUID) == 16 {
		aaguidStr = uuid.UUID(credential.Authenticator.AAGUID).String()
	}
	now := time.Now()
	stored := &store.WebAuthnCredential{
		CredentialID:    credIDStr,
		SubjectDID:      subjectDID,
		PublicKeyCBOR:   credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          aaguidStr,
		SignCount:       credential.Authenticator.SignCount,
		Transports:      transports,
		CreatedAt:       now,
	}
	if err := s.store.SaveWebAuthnCredential(r.Context(), stored); err != nil {
		http.Error(w, "save credential: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Anchor the public key in the subject's DID Document.
	anchorWebAuthnKey(r.Context(), s.store, subjectDID, credIDStr, credential.PublicKey)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"credential_id": credIDStr,
		"subject_did":   subjectDID,
		"status":        "registered",
	})
}

// ---- Authentication (passkey / discoverable login) ----

// handleWebAuthnLoginBegin starts a WebAuthn assertion ceremony.
// No user identification is required upfront; the authenticator discovers credentials.
// POST /api/v1/webauthn/login/begin
func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		http.Error(w, "webauthn not configured", http.StatusNotImplemented)
		return
	}

	assertion, session, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, "begin login failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID := waRandomID()
	s.waAuthSessions.Store(sessionID, &waSessionEntry{
		session:   *session,
		expiresAt: time.Now().Add(5 * time.Minute),
	})
	http.SetCookie(w, waCookie("wa_auth_session", sessionID, 300))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(assertion)
}

// handleWebAuthnLoginFinish validates the authenticator assertion and returns the
// subject's DID on success. The client should then proceed with a normal OIDC flow.
// POST /api/v1/webauthn/login/finish
func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		http.Error(w, "webauthn not configured", http.StatusNotImplemented)
		return
	}

	cookie, err := r.Cookie("wa_auth_session")
	if err != nil {
		http.Error(w, "login session not found — call begin first", http.StatusBadRequest)
		return
	}
	raw, ok := s.waAuthSessions.LoadAndDelete(cookie.Value)
	if !ok || time.Now().After(raw.(*waSessionEntry).expiresAt) {
		http.Error(w, "login session expired", http.StatusUnauthorized)
		return
	}
	entry := raw.(*waSessionEntry)

	handler := func(rawID, userHandle []byte) (gowebauthn.User, error) {
		subjectDID := string(userHandle)
		creds, err := s.store.ListWebAuthnCredentials(r.Context(), subjectDID)
		if err != nil {
			return nil, err
		}
		return &waUser{subjectDID: subjectDID, creds: creds}, nil
	}

	user, credential, err := s.webAuthn.FinishPasskeyLogin(handler, entry.session, r)
	if err != nil {
		http.Error(w, "login failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Update the sign count and last-used timestamp for theft detection.
	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	if existing, storeErr := s.store.GetWebAuthnCredential(r.Context(), credIDStr); storeErr == nil && existing != nil {
		existing.SignCount = credential.Authenticator.SignCount
		now := time.Now()
		existing.LastUsedAt = &now
		_ = s.store.UpdateWebAuthnCredential(r.Context(), existing)
	}

	subjectDID := user.(*waUser).subjectDID
	s.events.Publish(r.Context(), "session.created", map[string]string{
		"subject_did": subjectDID,
		"method":      "webauthn",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"subject_did": subjectDID,
		"status":      "authenticated",
	})
}

// ---- Credential management ----

// handleListWebAuthnCredentials lists registered passkeys for the authenticated subject.
// GET /api/v1/me/webauthn/credentials
func (s *Server) handleListWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	creds, err := s.store.ListWebAuthnCredentials(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Redact the raw CBOR key from the list view.
	type view struct {
		CredentialID    string     `json:"credential_id"`
		Name            string     `json:"name,omitempty"`
		Transports      []string   `json:"transports,omitempty"`
		AttestationType string     `json:"attestation_type,omitempty"`
		CreatedAt       time.Time  `json:"created_at"`
		LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	}
	out := make([]view, len(creds))
	for i, c := range creds {
		out[i] = view{
			CredentialID:    c.CredentialID,
			Name:            c.Name,
			Transports:      c.Transports,
			AttestationType: c.AttestationType,
			CreatedAt:       c.CreatedAt,
			LastUsedAt:      c.LastUsedAt,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleDeleteWebAuthnCredential removes a passkey for the authenticated subject.
// DELETE /api/v1/me/webauthn/credentials/{id}
func (s *Server) handleDeleteWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	credID := r.PathValue("id")
	if credID == "" {
		http.Error(w, "credential id required", http.StatusBadRequest)
		return
	}
	existing, err := s.store.GetWebAuthnCredential(r.Context(), credID)
	if err != nil {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	if existing.SubjectDID != subjectDID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteWebAuthnCredential(r.Context(), credID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Helpers ----

// anchorWebAuthnKey adds a WebAuthn public key as a verification method in the
// subject's DID Document. The COSE key bytes are encoded as multibase (base64url).
// This allows verifiers to look up the authenticator key via DID resolution.
func anchorWebAuthnKey(ctx context.Context, st store.Store, subjectDID, credID string, pubKey []byte) {
	doc, err := st.GetDocument(ctx, subjectDID)
	if err != nil {
		// No document yet — create a minimal one.
		doc = &did.Document{
			Context: did.DefaultContext(),
			ID:      subjectDID,
		}
	}

	// Derive a stable verification-method ID from the credential ID prefix.
	shortID := credID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	vmID := subjectDID + "#webauthn-" + shortID

	// Idempotent: skip if already anchored.
	for _, vm := range doc.VerificationMethod {
		if vm.ID == vmID {
			return
		}
	}

	// Multibase base64url (prefix 'u') encodes the raw CBOR COSE key bytes.
	multibase := "u" + base64.RawURLEncoding.EncodeToString(pubKey)
	doc.VerificationMethod = append(doc.VerificationMethod, did.VerificationMethod{
		ID:                 vmID,
		Type:               "WebAuthnPublicKey2023",
		Controller:         subjectDID,
		PublicKeyMultibase: &multibase,
	})
	doc.Authentication = append(doc.Authentication, vmID)
	_ = st.SaveDocument(ctx, doc)
}

// waRandomID returns a cryptographically random 16-byte hex string for session IDs.
func waRandomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// waCookie builds a short-lived, HTTP-only, SameSite-Strict cookie for a WebAuthn session.
func waCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
		Path:     "/",
	}
}
