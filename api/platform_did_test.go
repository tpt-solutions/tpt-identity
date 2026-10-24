package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tpt-solutions/tpt-identity/api"
)

func TestPlatformDIDEncoding(t *testing.T) {
	cases := map[string]string{
		"https://id.example.com":      "did:web:id.example.com",
		"https://id.example.com:8443": "did:web:id.example.com%3A8443",
	}
	for issuer, want := range cases {
		got, err := api.PlatformDID(issuer)
		if err != nil || got != want {
			t.Errorf("PlatformDID(%s) = %q, %v; want %q", issuer, got, err, want)
		}
	}
	if _, err := api.PlatformDID("not a url"); err == nil {
		t.Error("relative issuer accepted")
	}
}

// The DID document is served at the well-known path and names the platform DID.
func TestDIDDocumentServed(t *testing.T) {
	srv := newTestServer(t)
	w := do(t, srv, http.MethodGet, "/.well-known/did.json", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("did.json: want 200, got %d", w.Code)
	}
	var doc struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode did.json: %v", err)
	}
	if want := "did:web:test.tpt-identity.example"; doc.ID != want {
		t.Errorf("document id = %q, want %q", doc.ID, want)
	}
}

// A credential may not claim an issuer other than the platform that signs it.
func TestCredentialIssuerMustBePlatform(t *testing.T) {
	srv := newTestServer(t)
	body := `{"subject_did":"did:peer:x","schema_id":"identity.legal-name","claims":{"givenNames":"A","familyName":"B"},"issuer_did":"did:web:someone-else.example"}`
	w := authed(t, srv, http.MethodPost, "/api/v1/credentials", body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("foreign issuer_did: want 400, got %d: %s", w.Code, w.Body.String())
	}
}
