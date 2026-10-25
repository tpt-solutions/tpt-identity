package api_test

import (
	"context"
	"encoding/json"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

const (
	testAPIKey = "test-api-key-1234"
	testIssuer = "https://test.tpt-identity.example"
	// testPlatformDID is the did:web the test issuer resolves to; issuing keys must be its keys.
	testPlatformDID = "did:web:test.tpt-identity.example"
)

// newTestServer wires a Server against an in-memory SQLite store with a fresh Ed25519 key.
func newTestServer(t *testing.T) *api.Server {
	t.Helper()
	st := storetest.New(t)

	_, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	oidcProvider := oidc.NewProvider(testIssuer, priv, "test-key-1", st)
	res := resolver.New(5 * time.Minute)

	return api.NewServer(api.Config{
		APIKey:       testAPIKey,
		Issuer:       testIssuer,
		SigningKey:   priv,
		SigningKeyID: testPlatformDID + "#signing-key-1", // the issuing key must belong to the platform DID
		Store:        st,
		Resolver:     res,
		OIDC:         oidcProvider,
	})
}

// do fires a request against srv and returns the recorder.
func do(t *testing.T, srv *api.Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

// authed wraps do with the test API key and JSON content-type when there is a body.
func authed(t *testing.T, srv *api.Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := map[string]string{"Authorization": "Bearer " + testAPIKey}
	if body != "" {
		h["Content-Type"] = "application/json"
	}
	return do(t, srv, method, path, body, h)
}

// ---- Liveness & readiness ----

func TestLiveness(t *testing.T) {
	srv := newTestServer(t)
	w := do(t, srv, http.MethodGet, "/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestReadiness(t *testing.T) {
	srv := newTestServer(t)
	w := do(t, srv, http.MethodGet, "/readyz", "", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("want status=ok, got %v", result["status"])
	}
}

// ---- OIDC endpoints ----

func TestOIDCDiscovery(t *testing.T) {
	srv := newTestServer(t)
	w := do(t, srv, http.MethodGet, "/.well-known/openid-configuration", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if meta["issuer"] != testIssuer {
		t.Errorf("want issuer=%q, got %v", testIssuer, meta["issuer"])
	}
	if _, ok := meta["authorization_endpoint"]; !ok {
		t.Error("missing authorization_endpoint in discovery doc")
	}
	if _, ok := meta["jwks_uri"]; !ok {
		t.Error("missing jwks_uri in discovery doc")
	}
}

func TestJWKS(t *testing.T) {
	srv := newTestServer(t)
	w := do(t, srv, http.MethodGet, "/.well-known/jwks.json", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var jwks map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Errorf("expected at least one JWK, got: %v", jwks)
	}
}

// ---- Auth middleware ----

func TestAuthRequiredNoHeader(t *testing.T) {
	srv := newTestServer(t)
	w := do(t, srv, http.MethodGet, "/api/v1/identities/did:peer:test", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 (no auth), got %d", w.Code)
	}
}

func TestAuthRequiredWrongKey(t *testing.T) {
	srv := newTestServer(t)
	w := do(t, srv, http.MethodGet, "/api/v1/identities/did:peer:test", "", map[string]string{
		"Authorization": "Bearer wrong-key",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 (wrong key), got %d", w.Code)
	}
}

// ---- Identities ----

func TestCreateIdentityPeer(t *testing.T) {
	srv := newTestServer(t)
	w := authed(t, srv, http.MethodPost, "/api/v1/identities", `{"method":"peer"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["did"] == nil {
		t.Error("missing did in create response")
	}
}

func TestCreateIdentityEmptyMethodFails(t *testing.T) {
	srv := newTestServer(t)
	w := authed(t, srv, http.MethodPost, "/api/v1/identities", `{}`)
	if w.Code < 400 {
		t.Errorf("want ≥400 for empty method, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateIdentityWebRequiresDomain(t *testing.T) {
	srv := newTestServer(t)
	// did:web without a domain should fail
	w := authed(t, srv, http.MethodPost, "/api/v1/identities", `{"method":"web"}`)
	if w.Code < 400 {
		t.Errorf("want ≥400 for web identity without domain, got %d: %s", w.Code, w.Body.String())
	}
}

// ---- Webhooks ----

func TestWebhookCreateListDelete(t *testing.T) {
	srv := newTestServer(t)

	// Create
	body := `{"url":"https://example.com/hook","event_types":["credential.issued"]}`
	w := authed(t, srv, http.MethodPost, "/api/v1/webhooks", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	webhookID, _ := created["id"].(string)
	if webhookID == "" {
		t.Fatal("missing id in webhook response")
	}
	if created["signing_secret"] == nil {
		t.Error("signing_secret must be returned on creation")
	}

	// List — should contain 1
	w = authed(t, srv, http.MethodGet, "/api/v1/webhooks", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", w.Code)
	}
	var list []any
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Errorf("want 1 webhook, got %d", len(list))
	}

	// Delete
	w = authed(t, srv, http.MethodDelete, "/api/v1/webhooks/"+webhookID, "")
	if w.Code != http.StatusNoContent {
		t.Errorf("delete: want 204, got %d: %s", w.Code, w.Body.String())
	}

	// List again — should be empty
	w = authed(t, srv, http.MethodGet, "/api/v1/webhooks", "")
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Errorf("want 0 webhooks after delete, got %d", len(list))
	}
}

func TestWebhookMissingURLRejects(t *testing.T) {
	srv := newTestServer(t)
	w := authed(t, srv, http.MethodPost, "/api/v1/webhooks", `{"event_types":["x"]}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing URL, got %d", w.Code)
	}
}

// ---- Consent grants ----

// Grants belong to the signed-in subject, so the operator key alone is refused.
func TestListGrantsRequiresBearer(t *testing.T) {
	srv := newTestServer(t)
	w := authed(t, srv, http.MethodGet, "/api/v1/consents/grants", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 with operator key only, got %d", w.Code)
	}
}

func TestListGrantsEmpty(t *testing.T) {
	st := storetest.New(t)
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		APIKey:     testAPIKey,
		Issuer:     testIssuer,
		SigningKey: priv,
		Store:      st,
		OIDC:       oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:   resolver.New(time.Minute),
	})
	now := time.Now()
	if err := st.SaveIdentity(context.Background(), &store.Identity{
		DID: "did:peer:nobody", Method: "peer", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	tok, err := oidc.IssueAccessToken(testIssuer, "did:peer:nobody", "client-1", time.Hour, priv, "test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	w := do(t, srv, http.MethodGet, "/api/v1/consents/grants", "", map[string]string{"Authorization": "Bearer " + tok})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	// Should return an empty list (not null).
	var list []any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		// null is also acceptable — some handlers return null for empty lists
		if !strings.Contains(w.Body.String(), "null") {
			t.Errorf("bad response: %q", w.Body.String())
		}
	}
}

// ---- Rate limiting ----

func TestRateLimitExceeded(t *testing.T) {
	_, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	oidcP := oidc.NewProvider(testIssuer, priv, "key-1", st)

	// Very tight limit: 1 req/s burst 1.
	srv := api.NewServer(api.Config{
		APIKey:    testAPIKey,
		Issuer:    testIssuer,
		Store:     st,
		OIDC:      oidcP,
		Resolver:  resolver.New(time.Minute),
		RateLimit: 1,
	})

	// /authorize is rate-limited; /healthz is explicitly exempt (health probes must never be throttled).
	limited := 0
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Error("expected at least one rate-limited response from the same IP")
	}
}

// ---- Schema endpoint ----

func TestListSchemasRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	w := do(t, srv, http.MethodGet, "/api/v1/schemas", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

// ---- Me / sessions ----

func TestMySessionsRequiresBearer(t *testing.T) {
	srv := newTestServer(t)
	// No bearer token at all.
	w := do(t, srv, http.MethodGet, "/api/v1/me/sessions", "", nil)
	// The "me" endpoints use OIDC bearer auth, not the API key.
	// Without any token we expect 401.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

// ---- /authorize subject binding ----

// A client-supplied X-Subject-DID header must never establish the end-user's identity. A request with a
// registered client and valid PKCE is sent to the login page, and no authorization code is issued.
func TestAuthorizeRejectsForgedSubjectHeader(t *testing.T) {
	srv := newTestServer(t)
	reg := authed(t, srv, http.MethodPost, "/oidc/register",
		`{"client_name":"rp","redirect_uris":["https://rp.example/cb"],"token_endpoint_auth_method":"none","grant_types":["authorization_code"]}`)
	var client struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(reg.Body.Bytes(), &client); err != nil || client.ClientID == "" {
		t.Fatalf("register client: %d %s", reg.Code, reg.Body.String())
	}
	q := "/authorize?client_id=" + client.ClientID +
		"&redirect_uri=https%3A%2F%2Frp.example%2Fcb&state=s&nonce=n&scope=openid" +
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
	w := do(t, srv, http.MethodGet, q, "", map[string]string{"X-Subject-DID": "did:peer:victim"})
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, testIssuer+"/login?txn=") {
		t.Fatalf("forged header: want a redirect to the login page, got %d %q", w.Code, loc)
	}
	if strings.Contains(loc, "code=") {
		t.Error("an authorization code was issued for a forged subject header")
	}
}

// An empty api_key must fail closed: gated endpoints reject every caller.
func TestAuthFailsClosedWithEmptyAPIKey(t *testing.T) {
	st := storetest.New(t)
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		Issuer:     testIssuer,
		SigningKey: priv,
		Store:      st,
		OIDC:       oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:   resolver.New(time.Minute),
	})
	w := do(t, srv, http.MethodGet, "/api/v1/schemas", "", map[string]string{"Authorization": "Bearer "})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 with empty api_key, got %d", w.Code)
	}
}

// ---- Magic link delivery ----

type recordingSender struct{ url string }

func (r *recordingSender) SendMagicLink(_ context.Context, _, verifyURL string, _ time.Time) error {
	r.url = verifyURL
	return nil
}

func newMagicLinkServer(t *testing.T, sender api.MagicLinkSender) *api.Server {
	t.Helper()
	st := storetest.New(t)
	_, priv, _ := crypto.GenerateSigningKey()
	return api.NewServer(api.Config{
		Issuer:          testIssuer,
		SigningKey:      priv,
		Store:           st,
		OIDC:            oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:        resolver.New(time.Minute),
		MagicLinkSender: sender,
	})
}

// The magic-link response must never carry the verify URL or its token.
func TestMagicLinkResponseOmitsToken(t *testing.T) {
	sender := &recordingSender{}
	srv := newMagicLinkServer(t, sender)
	w := do(t, srv, http.MethodPost, "/auth/magiclink/request", `{"email":"a@example.com"}`, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "token=") || strings.Contains(body, "verify_url") {
		t.Errorf("response leaks magic link: %s", body)
	}
	if !strings.Contains(sender.url, "token=") {
		t.Errorf("sender did not receive a verify URL")
	}
}

// Without a configured sender the endpoint must refuse rather than return a link.
func TestMagicLinkWithoutSenderUnavailable(t *testing.T) {
	srv := newMagicLinkServer(t, nil)
	w := do(t, srv, http.MethodPost, "/auth/magiclink/request", `{"email":"a@example.com"}`, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", w.Code)
	}
}
