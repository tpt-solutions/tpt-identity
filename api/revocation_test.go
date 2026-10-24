package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tpt-solutions/tpt-identity/api"
)

const legalNameBody = `{"subject_did":"did:peer:holder","schema_id":"identity.legal-name","claims":{"givenNames":"Alice","familyName":"Smith"}}`

// issueForRevocation issues a platform credential and returns its id, its JSON body and the URL of
// its status list.
func issueForRevocation(t *testing.T, srv *api.Server) (id, body, listURL string) {
	t.Helper()
	w := authed(t, srv, http.MethodPost, "/api/v1/credentials", legalNameBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	var cred struct {
		ID     string `json:"id"`
		Status *struct {
			StatusListCredential string `json:"statusListCredential"`
		} `json:"credentialStatus"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cred); err != nil {
		t.Fatal(err)
	}
	if cred.Status == nil {
		t.Fatalf("issued credential has no credentialStatus: %s", w.Body.String())
	}
	return cred.ID, w.Body.String(), cred.Status.StatusListCredential
}

func verifyBody(t *testing.T, srv *api.Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	return authed(t, srv, http.MethodPost, "/api/v1/credentials/verify", body)
}

// A credential is issued with a status entry under the configured issuer, verifies, is revoked, and
// then fails verification and freshness. The published list shows the revoked bit.
func TestRevocationEndToEnd(t *testing.T) {
	srv := newTestServer(t)
	id, body, listURL := issueForRevocation(t, srv)

	if !strings.HasPrefix(listURL, testIssuer+"/api/v1/status/") {
		t.Fatalf("status list %q is not under the configured issuer", listURL)
	}
	if w := verifyBody(t, srv, body); w.Code != http.StatusOK {
		t.Fatalf("before revocation: want 200, got %d: %s", w.Code, w.Body.String())
	}

	if w := authed(t, srv, http.MethodPost, "/api/v1/credentials/"+id+"/revoke", ""); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: want 204, got %d: %s", w.Code, w.Body.String())
	}
	if w := authed(t, srv, http.MethodPost, "/api/v1/credentials/"+id+"/revoke", ""); w.Code != http.StatusNoContent {
		t.Errorf("second revoke: want 204, got %d", w.Code)
	}

	if w := verifyBody(t, srv, body); w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "revoked") {
		t.Errorf("after revocation: want a revoked failure, got %d: %s", w.Code, w.Body.String())
	}

	fresh := do(t, srv, http.MethodGet, "/api/v1/credentials/"+id+"/fresh", "", nil)
	var f map[string]any
	if err := json.Unmarshal(fresh.Body.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if f["fresh"] != false || f["reason"] != "revoked" {
		t.Errorf("freshness after revocation = %v / %v, want false / revoked", f["fresh"], f["reason"])
	}

	listID := listURL[strings.LastIndex(listURL, "/")+1:]
	pub := do(t, srv, http.MethodGet, "/api/v1/status/"+listID, "", nil)
	if pub.Code != http.StatusOK || !strings.Contains(pub.Body.String(), "encodedList") {
		t.Fatalf("status list: %d %s", pub.Code, pub.Body.String())
	}
}

// The status list is served from the configured issuer. A forged Host header must not change which
// list is returned.
func TestStatusListIgnoresForgedHost(t *testing.T) {
	srv := newTestServer(t)
	_, _, listURL := issueForRevocation(t, srv)
	listID := listURL[strings.LastIndex(listURL, "/")+1:]

	w := do(t, srv, http.MethodGet, "/api/v1/status/"+listID, "", map[string]string{"Host": "evil.example"})
	if w.Code != http.StatusOK {
		t.Errorf("forged Host changed the list: %d", w.Code)
	}
}

// A credential whose list is hosted elsewhere cannot be revoked here.
func TestRevokeRefusesForeignStatusList(t *testing.T) {
	srv := newTestServer(t)
	body := `{"subject_did":"did:peer:holder","schema_id":"identity.legal-name",` +
		`"claims":{"givenNames":"Alice","familyName":"Smith"},` +
		`"status_list_credential":"https://other.example/api/v1/status/x","status_list_index":3}`
	w := authed(t, srv, http.MethodPost, "/api/v1/credentials", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	var cred struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &cred)

	if r := authed(t, srv, http.MethodPost, "/api/v1/credentials/"+cred.ID+"/revoke", ""); r.Code != http.StatusConflict {
		t.Errorf("revoke of a foreign list: want 409, got %d", r.Code)
	}
}

func TestRevokeUnknownCredentialIsNotFound(t *testing.T) {
	srv := newTestServer(t)
	if w := authed(t, srv, http.MethodPost, "/api/v1/credentials/no-such-id/revoke", ""); w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}
