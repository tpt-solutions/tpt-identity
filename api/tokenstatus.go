package api

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/events"
)

// tokenStatusPath serves the IETF Token Status List form of the platform's status lists. It covers the same
// bits as the bitstring status list at statusListPath, so one revocation shows in both.
const tokenStatusPath = "/api/v1/token-status/"

// tokenStatusTTL is how long a served status list may be cached (the ttl claim, in seconds).
const tokenStatusTTL = 300

// tokenStatusURI is the URI an SD-JWT's status claim points at for the list with the given id.
func (s *Server) tokenStatusURI(listID string) string {
	return s.issuer + tokenStatusPath + strings.TrimPrefix(listID, s.issuer+statusListPath)
}

// randomSDJWTID returns the jti of a new SD-JWT credential.
func randomSDJWTID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sdj_" + hex.EncodeToString(b), nil
}

// handleTokenStatusList serves GET /api/v1/token-status/{listId}: the status list as a signed
// statuslist+jwt, in the IETF Token Status List form. Bits are packed least-significant-bit first, which is
// the order the store keeps them in, so no conversion is needed.
func (s *Server) handleTokenStatusList(w http.ResponseWriter, r *http.Request) {
	listID := r.PathValue("listId")
	if listID == "" || s.signingKey == nil {
		http.Error(w, "status list not found", http.StatusNotFound)
		return
	}
	rec, err := s.store.GetStatusList(r.Context(), s.issuer+statusListPath+listID)
	if err != nil {
		http.Error(w, "status list not found", http.StatusNotFound)
		return
	}

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(rec.Bits); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := zw.Close(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	token, err := signStatusListJWT(map[string]any{
		"sub": s.tokenStatusURI(s.issuer + statusListPath + listID),
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"ttl": tokenStatusTTL,
		"status_list": map[string]any{
			"bits": 1,
			"lst":  base64.RawURLEncoding.EncodeToString(compressed.Bytes()),
		},
	}, s.signingKey, s.signingKeyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", tokenStatusTTL))
	_, _ = w.Write([]byte(token))
}

// signStatusListJWT signs a statuslist+jwt with EdDSA.
func signStatusListJWT(claims map[string]any, key ed25519.PrivateKey, kid string) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "statuslist+jwt", "kid": kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(key, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// checkSDJWTStatus reports an error when a presented SD-JWT's status bit is set, or when its status list is
// not one this server hosts (the check fails closed: revocation cannot be confirmed). A credential with no
// status claim predates status entries and is not checked.
func (s *Server) checkSDJWTStatus(ctx context.Context, always map[string]any) error {
	raw, ok := always["status"]
	if !ok {
		return nil
	}
	status, _ := raw.(map[string]any)
	list, _ := status["status_list"].(map[string]any)
	uri, _ := list["uri"].(string)
	idxF, idxOK := list["idx"].(float64)
	if uri == "" || !idxOK {
		return errors.New("status claim is malformed")
	}
	if !strings.HasPrefix(uri, s.issuer+tokenStatusPath) {
		return errors.New("status list is not hosted by this issuer; revocation cannot be checked")
	}
	listID := s.issuer + statusListPath + strings.TrimPrefix(uri, s.issuer+tokenStatusPath)
	rec, err := s.store.GetStatusList(ctx, listID)
	if err != nil {
		return fmt.Errorf("status list unavailable: %w", err)
	}
	idx := int(idxF)
	if idx < 0 || idx/8 >= len(rec.Bits) {
		return errors.New("status index is outside its list")
	}
	if rec.Bits[idx/8]&(1<<(uint(idx)%8)) != 0 {
		return errors.New("credential has been revoked")
	}
	return nil
}

// handleRevokeSDJWT revokes an SD-JWT credential this server issued, by its id. It sets the credential's bit in
// its status list and republishes the bitstring list, so both forms agree.
// POST /api/v1/credentials/sd-jwt/{id}/revoke
func (s *Server) handleRevokeSDJWT(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := s.store.GetSDJWTIssued(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "credential not found")
		return
	}
	if !s.hostsStatusList(rec.StatusList) {
		writeJSONError(w, http.StatusConflict, "status_list_not_hosted", "the credential's status list is not hosted by this issuer")
		return
	}
	updated, err := s.store.SetStatusBit(r.Context(), rec.StatusList, rec.StatusIndex)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	if err := s.publishStatusList(r.Context(), updated); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "publish_failed", err.Error())
		return
	}
	s.events.Publish(r.Context(), events.CredentialRevoked, map[string]any{
		"id":          id,
		"status_list": rec.StatusList,
		"index":       rec.StatusIndex,
	})
	w.WriteHeader(http.StatusNoContent)
}
