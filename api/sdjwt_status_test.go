package api_test

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// jwtClaims decodes the payload of a compact JWS.
func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// bitSet reads bit idx from a token status list payload (lst: zlib-compressed, least significant bit first).
func bitSet(t *testing.T, statusJWT string, idx int) bool {
	t.Helper()
	claims := jwtClaims(t, statusJWT)
	list := claims["status_list"].(map[string]any)
	compressed, err := base64.RawURLEncoding.DecodeString(list["lst"].(string))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	bits, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return bits[idx/8]&(1<<(uint(idx)%8)) != 0
}

// The full lifecycle of a platform SD-JWT: verifies, is revoked by id, is then refused, and its bit appears in
// the signed token status list.
func TestSDJWTRevocationLifecycle(t *testing.T) {
	srv := newTestServer(t)
	w := authed(t, srv, http.MethodPost, "/api/v1/credentials/sd-jwt",
		`{"subject_did":"did:peer:sdjwt-holder","schema_id":"identity.legal-name",`+
			`"selective_claims":{"givenNames":"Alice"},"return_format":"serialized"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	var issued struct {
		ID         string `json:"id"`
		JWT        string `json:"jwt"`
		Serialized string `json:"serialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(issued.ID, "sdj_") {
		t.Fatalf("issued credential has no id: %+v", issued)
	}

	verify := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"token": issued.Serialized})
		return authed(t, srv, http.MethodPost, "/api/v1/credentials/sd-jwt/verify", string(body))
	}
	if w := verify(); w.Code != http.StatusOK {
		t.Fatalf("before revocation: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// The status claim points at the token status list, and the list is served from that URI.
	status := jwtClaims(t, issued.JWT)["status"].(map[string]any)["status_list"].(map[string]any)
	uri := status["uri"].(string)
	idx := int(status["idx"].(float64))
	path := strings.TrimPrefix(uri, testIssuer)
	listW := do(t, srv, http.MethodGet, path, "", nil)
	if listW.Code != http.StatusOK || listW.Header().Get("Content-Type") != "application/statuslist+jwt" {
		t.Fatalf("token status list: %d %s", listW.Code, listW.Header().Get("Content-Type"))
	}
	if bitSet(t, listW.Body.String(), idx) {
		t.Fatal("bit set before revocation")
	}

	if w := authed(t, srv, http.MethodPost, "/api/v1/credentials/sd-jwt/"+issued.ID+"/revoke", ""); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: want 204, got %d: %s", w.Code, w.Body.String())
	}

	if w := verify(); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "revoked") {
		t.Errorf("after revocation: want 422 revoked, got %d: %s", w.Code, w.Body.String())
	}
	listW = do(t, srv, http.MethodGet, path, "", nil)
	if !bitSet(t, listW.Body.String(), idx) {
		t.Error("revoked bit not set in the token status list")
	}
	if bitSet(t, listW.Body.String(), idx+1) {
		t.Error("a neighbouring bit was set by the revocation")
	}
}

// Revoking an unknown SD-JWT id is a 404.
func TestSDJWTRevokeUnknownIDIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	if w := authed(t, srv, http.MethodPost, "/api/v1/credentials/sd-jwt/sdj_unknown/revoke", ""); w.Code != http.StatusNotFound {
		t.Errorf("unknown id: want 404, got %d", w.Code)
	}
}

// A caller cannot set issuer-owned claims through always_visible_claims: the platform must not sign a token
// that names another issuer.
func TestSDJWTCallerCannotForgeIssuerClaim(t *testing.T) {
	srv := newTestServer(t)
	body := `{"subject_did":"did:peer:sdjwt-holder","schema_id":"identity.legal-name",` +
		`"selective_claims":{"givenNames":"Alice"},"always_visible_claims":{"iss":"did:web:evil.example"}}`
	if w := authed(t, srv, http.MethodPost, "/api/v1/credentials/sd-jwt", body); w.Code != http.StatusBadRequest {
		t.Errorf("forged iss: want 400, got %d: %s", w.Code, w.Body.String())
	}
}

// The token status list URL is public, and unknown lists are not found.
func TestTokenStatusListUnknownIs404(t *testing.T) {
	srv := newTestServer(t)
	if w := do(t, srv, http.MethodGet, "/api/v1/token-status/nope", "", nil); w.Code != http.StatusNotFound {
		t.Errorf("unknown list: want 404, got %d", w.Code)
	}
}
