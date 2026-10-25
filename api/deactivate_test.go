package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// deactivateFixture creates a did:key identity through the API and returns its DID and the server.
func deactivateFixture(t *testing.T) (string, *api.Server) {
	t.Helper()
	srv := newScopedTestServer(t)
	w := do(t, srv, http.MethodPost, "/api/v1/identities", `{"method":"key"}`, bearerJSON(testAPIKey))
	if w.Code != http.StatusCreated {
		t.Fatalf("create identity: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		DID string `json:"did"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.DID == "" {
		t.Fatalf("create identity response: %v", err)
	}
	return resp.DID, srv
}

// resolve fetches the identity's document through the API.
func resolve(t *testing.T, srv *api.Server, id string) (did.Document, int) {
	t.Helper()
	w := do(t, srv, http.MethodGet, "/api/v1/identities/"+id, "", bearer(testAPIKey))
	var doc did.Document
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
	}
	return doc, w.Code
}

// After deactivation the DID resolves with no keys and is marked deactivated.
func TestDeactivatedDIDResolvesWithoutKeys(t *testing.T) {
	id, srv := deactivateFixture(t)
	before, code := resolve(t, srv, id)
	if code != http.StatusOK || len(before.VerificationMethod) == 0 {
		t.Fatalf("before deactivation: want keys, got %d with %d methods", code, len(before.VerificationMethod))
	}

	if w := do(t, srv, http.MethodPost, "/admin/v1/identities/"+id+"/deactivate", "", bearer(testAdminKey)); w.Code != http.StatusNoContent {
		t.Fatalf("deactivate: want 204, got %d: %s", w.Code, w.Body.String())
	}

	after, code := resolve(t, srv, id)
	if code != http.StatusOK {
		t.Fatalf("after deactivation: want 200, got %d", code)
	}
	if !after.Deactivated {
		t.Error("document not marked deactivated")
	}
	if len(after.VerificationMethod) != 0 || len(after.AssertionMethod) != 0 || len(after.Authentication) != 0 {
		t.Errorf("deactivated document still publishes keys: %+v", after)
	}
}

// Deactivation is permanent: suspension and unsuspension are refused, and a repeat deactivation is fine.
func TestDeactivationCannotBeReversed(t *testing.T) {
	id, srv := deactivateFixture(t)
	deactivate := func() int {
		return do(t, srv, http.MethodPost, "/admin/v1/identities/"+id+"/deactivate", "", bearer(testAdminKey)).Code
	}
	if code := deactivate(); code != http.StatusNoContent {
		t.Fatalf("deactivate: %d", code)
	}
	if code := deactivate(); code != http.StatusNoContent {
		t.Errorf("repeat deactivation: want 204, got %d", code)
	}
	for _, action := range []string{"suspend", "unsuspend"} {
		w := do(t, srv, http.MethodPost, "/admin/v1/identities/"+id+"/"+action, "", bearer(testAdminKey))
		if w.Code != http.StatusConflict {
			t.Errorf("%s of a deactivated DID: want 409, got %d", action, w.Code)
		}
	}
}

// Deactivating an unknown DID is a 404, not a silent success.
func TestDeactivateUnknownDIDIsNotFound(t *testing.T) {
	_, srv := deactivateFixture(t)
	w := do(t, srv, http.MethodPost, "/admin/v1/identities/did:key:z6MkUnknown/deactivate", "", bearer(testAdminKey))
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown DID: want 404, got %d", w.Code)
	}
}
