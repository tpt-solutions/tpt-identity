package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const (
	testAcmeKey   = "test-acme-tenant-key-3456"
	testGlobexKey = "test-globex-tenant-key-7890"
)

// newTenantTestServer builds a server with the master key and two tenant-bound identity keys.
func newTenantTestServer(t *testing.T) *api.Server {
	t.Helper()
	st := storetest.New(t)

	_, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return api.NewServer(api.Config{
		APIKey: testAPIKey,
		ScopedKeys: []api.ScopedKey{
			{Name: "acme", Key: testAcmeKey, Scopes: []string{"identities", "credentials", "consents"}, TenantID: "acme"},
			{Name: "globex", Key: testGlobexKey, Scopes: []string{"*"}, TenantID: "globex"},
		},
		Issuer:       testIssuer,
		SigningKey:   priv,
		SigningKeyID: testPlatformDID + "#signing-key-1",
		Store:        st,
		Resolver:     resolver.New(5 * time.Minute),
		OIDC:         oidc.NewProvider(testIssuer, priv, "test-key-1", st),
	})
}

// createKeyIdentity creates a did:key identity with the given bearer and returns its DID.
func createKeyIdentity(t *testing.T, srv *api.Server, token string) string {
	t.Helper()
	w := do(t, srv, http.MethodPost, "/api/v1/identities", `{"method":"key"}`, bearerJSON(token))
	if w.Code != http.StatusCreated {
		t.Fatalf("create identity: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		DID string `json:"did"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || resp.DID == "" {
		t.Fatalf("create identity response: %v", err)
	}
	return resp.DID
}

func bearerJSON(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}
}

// A tenant key sees the identities it created and nothing a different tenant or the platform owns.
func TestTenantKeyIdentityIsolation(t *testing.T) {
	srv := newTenantTestServer(t)

	acmeDID := createKeyIdentity(t, srv, testAcmeKey)
	globexDID := createKeyIdentity(t, srv, testGlobexKey)
	platformDID := createKeyIdentity(t, srv, testAPIKey)

	if w := do(t, srv, http.MethodGet, "/api/v1/identities/"+acmeDID, "", bearer(testAcmeKey)); w.Code != http.StatusOK {
		t.Errorf("acme reads its own identity: want 200, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/identities/"+globexDID, "", bearer(testAcmeKey)); w.Code != http.StatusNotFound {
		t.Errorf("acme reads globex identity: want 404, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/identities/"+platformDID, "", bearer(testAcmeKey)); w.Code != http.StatusNotFound {
		t.Errorf("acme reads platform identity: want 404, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/identities/"+acmeDID, "", bearer(testAPIKey)); w.Code != http.StatusOK {
		t.Errorf("platform key reads tenant identity: want 200, got %d", w.Code)
	}
}

// Tenant keys are refused on every scope outside tenantScopes, and never reach admin.
func TestTenantKeysRefusedOutsideTenantScopes(t *testing.T) {
	srv := newTenantTestServer(t)

	if w := do(t, srv, http.MethodGet, "/api/v1/webhooks", "", bearer(testGlobexKey)); w.Code != http.StatusForbidden {
		t.Errorf("tenant key with * on webhooks: want 403, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodPost, "/api/v1/credentials/sd-jwt", "{}", bearerJSON(testGlobexKey)); w.Code != http.StatusForbidden {
		t.Errorf("tenant wildcard key on unfiltered credential route: want 403, got %d", w.Code)
	}
	// Tenant-aware route: authorised, then rejected by the handler (no subject query) rather than by auth.
	if w := do(t, srv, http.MethodGet, "/api/v1/credentials", "", bearer(testAcmeKey)); w.Code != http.StatusBadRequest {
		t.Errorf("tenant key on tenant-aware credential route without subject: want 400, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/webhooks", "", bearer(testAcmeKey)); w.Code != http.StatusUnauthorized {
		t.Errorf("tenant key without webhooks scope: want 401, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/admin/v1/identities", "", bearer(testGlobexKey)); w.Code != http.StatusUnauthorized {
		t.Errorf("tenant key on admin route: want 401, got %d", w.Code)
	}
}

// Tenant credentials are issued, listed and deleted only for subjects of the caller's tenant.
func TestTenantCredentialsAreScopedToSubject(t *testing.T) {
	srv := newTenantTestServer(t)

	acmeDID := createKeyIdentity(t, srv, testAcmeKey)
	globexDID := createKeyIdentity(t, srv, testGlobexKey)
	issue := func(token, subject string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"subject_did":%q,"schema_id":"identity.legal-name","claims":{"givenNames":"Alice","familyName":"Smith"}}`, subject)
		return do(t, srv, http.MethodPost, "/api/v1/credentials", body, bearerJSON(token))
	}

	w := issue(testAcmeKey, acmeDID)
	if w.Code != http.StatusCreated {
		t.Fatalf("acme issues to acme subject: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var cred struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&cred); err != nil || cred.ID == "" {
		t.Fatalf("issued credential id: %v", err)
	}

	if w := issue(testAcmeKey, globexDID); w.Code != http.StatusNotFound {
		t.Errorf("acme issues to globex subject: want 404, got %d", w.Code)
	}
	withIssuer := fmt.Sprintf(`{"subject_did":%q,"issuer_did":"did:web:elsewhere.example","schema_id":"identity.legal-name","claims":{}}`, acmeDID)
	if w := do(t, srv, http.MethodPost, "/api/v1/credentials", withIssuer, bearerJSON(testAcmeKey)); w.Code != http.StatusBadRequest {
		t.Errorf("tenant key with foreign issuer_did: want 400, got %d", w.Code)
	}

	if w := do(t, srv, http.MethodGet, "/api/v1/credentials?subject="+acmeDID, "", bearer(testAcmeKey)); w.Code != http.StatusOK {
		t.Errorf("acme lists own subject: want 200, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/credentials?subject="+globexDID, "", bearer(testAcmeKey)); w.Code != http.StatusNotFound {
		t.Errorf("acme lists globex subject: want 404, got %d", w.Code)
	}

	if w := do(t, srv, http.MethodDelete, "/api/v1/credentials/"+cred.ID, "", bearer(testGlobexKey)); w.Code != http.StatusNotFound {
		t.Errorf("globex deletes acme credential: want 404, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodDelete, "/api/v1/credentials/"+cred.ID, "", bearer(testAcmeKey)); w.Code != http.StatusNoContent {
		t.Errorf("acme deletes own credential: want 204, got %d", w.Code)
	}
}

// Consent receipts are recorded and listed only for subjects of the caller's tenant.
func TestTenantReceiptsAreScopedToSubject(t *testing.T) {
	srv := newTenantTestServer(t)
	acmeDID := createKeyIdentity(t, srv, testAcmeKey)
	globexDID := createKeyIdentity(t, srv, testGlobexKey)

	submit := func(subject string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"subject_did":%q,"relying_did":"did:web:rp.example","schema_id":"identity.legal-name"}`, subject)
		return do(t, srv, http.MethodPost, "/api/v1/consents/receipts", body, bearerJSON(testAcmeKey))
	}
	if w := submit(acmeDID); w.Code != http.StatusCreated {
		t.Errorf("receipt for own subject: want 201, got %d: %s", w.Code, w.Body.String())
	}
	if w := submit(globexDID); w.Code != http.StatusNotFound {
		t.Errorf("receipt for another tenant's subject: want 404, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/consents/receipts?subject="+acmeDID, "", bearer(testAcmeKey)); w.Code != http.StatusOK {
		t.Errorf("list own receipts: want 200, got %d", w.Code)
	}
	if w := do(t, srv, http.MethodGet, "/api/v1/consents/receipts?subject="+globexDID, "", bearer(testAcmeKey)); w.Code != http.StatusNotFound {
		t.Errorf("list another tenant's receipts: want 404, got %d", w.Code)
	}
}
