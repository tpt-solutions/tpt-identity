package api_test

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PhillipC05/tpt-identity/api"
	"github.com/PhillipC05/tpt-identity/internal/resolver"
	"github.com/PhillipC05/tpt-identity/internal/store"
	"github.com/PhillipC05/tpt-identity/oidc"
	"github.com/PhillipC05/tpt-identity/pkg/crypto"
)

const (
	recSubject = "did:peer:recovery-subject"
	recG1      = "did:peer:guardian-1"
	recG2      = "did:peer:guardian-2"
	recG3      = "did:peer:guardian-3"
)

// newRecoveryServer returns a server with a 2-of-3 recovery config enrolled for recSubject.
func newRecoveryServer(t *testing.T) (*api.Server, ed25519.PrivateKey) {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		APIKey:     testAPIKey,
		Issuer:     testIssuer,
		SigningKey: priv,
		Store:      st,
		OIDC:       oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:   resolver.New(time.Minute),
	})
	if err := st.SaveRecoveryConfig(t.Context(), &store.RecoveryConfig{
		SubjectDID:   recSubject,
		Threshold:    2,
		GuardianDIDs: []string{recG1, recG2, recG3},
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("save recovery config: %v", err)
	}
	for _, did := range []string{recSubject, recG1, recG2, recG3} {
		saveTestIdentity(t, st, did)
	}
	return srv, priv
}

// guardianBearer mints an access token whose subject is did.
func guardianBearer(t *testing.T, priv ed25519.PrivateKey, did string) map[string]string {
	t.Helper()
	tok, err := oidc.IssueAccessToken(testIssuer, did, "client-1", time.Hour, priv, "test-key-1")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
}

// initiateRecovery starts a recovery as the operator and returns the request ID and shares.
func initiateRecovery(t *testing.T, srv *api.Server) (string, map[string]string) {
	t.Helper()
	body := `{"subject_did":"` + recSubject + `"}`
	w := authed(t, srv, http.MethodPost, "/api/v1/recovery/initiate", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("initiate: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		RequestID string            `json:"request_id"`
		Shares    map[string]string `json:"shares"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode initiate: %v", err)
	}
	return out.RequestID, out.Shares
}

// Initiating recovery is operator-only: without the API key it is refused.
func TestRecoveryInitiateRequiresOperator(t *testing.T) {
	srv, _ := newRecoveryServer(t)
	w := do(t, srv, http.MethodPost, "/api/v1/recovery/initiate", `{"subject_did":"`+recSubject+`"}`, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without operator key, got %d", w.Code)
	}
}

// A guardian who submits a share it was not issued is refused.
func TestRecoveryApproveRejectsForeignShare(t *testing.T) {
	srv, priv := newRecoveryServer(t)
	reqID, shares := initiateRecovery(t, srv)

	body := `{"share":"` + shares[recG2] + `"}`
	w := do(t, srv, http.MethodPost, "/api/v1/recovery/"+reqID+"/approve", body, guardianBearer(t, priv, recG3))
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403 for another guardian's share, got %d", w.Code)
	}
}

// Two valid guardian shares complete the recovery; a duplicate approval is refused.
func TestRecoveryCompletesAtThreshold(t *testing.T) {
	srv, priv := newRecoveryServer(t)
	reqID, shares := initiateRecovery(t, srv)
	path := "/api/v1/recovery/" + reqID + "/approve"

	w := do(t, srv, http.MethodPost, path, `{"share":"`+shares[recG1]+`"}`, guardianBearer(t, priv, recG1))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"pending"`) {
		t.Fatalf("first approval: want pending 200, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, srv, http.MethodPost, path, `{"share":"`+shares[recG1]+`"}`, guardianBearer(t, priv, recG1))
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate approval: want 409, got %d", w.Code)
	}

	w = do(t, srv, http.MethodPost, path, `{"share":"`+shares[recG2]+`"}`, guardianBearer(t, priv, recG2))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"completed"`) {
		t.Fatalf("threshold approval: want completed 200, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, srv, http.MethodPost, path, `{"share":"`+shares[recG3]+`"}`, guardianBearer(t, priv, recG3))
	if w.Code != http.StatusConflict {
		t.Errorf("approval after completion: want 409, got %d", w.Code)
	}
}

// Recovery status is operator-only and must not expose the commitment.
func TestRecoveryGetRequiresOperatorAndHidesCommitment(t *testing.T) {
	srv, _ := newRecoveryServer(t)
	reqID, _ := initiateRecovery(t, srv)

	if w := do(t, srv, http.MethodGet, "/api/v1/recovery/"+reqID, "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated get: want 401, got %d", w.Code)
	}
	w := authed(t, srv, http.MethodGet, "/api/v1/recovery/"+reqID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("authed get: want 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "commitment") {
		t.Errorf("status response exposes commitment: %s", w.Body.String())
	}
}

// saveTestIdentity creates an active identity so token verification accepts the subject.
func saveTestIdentity(t *testing.T, st store.Store, did string) {
	t.Helper()
	now := time.Now()
	if err := st.SaveIdentity(t.Context(), &store.Identity{
		DID: did, Method: "peer", Role: "user", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save identity %s: %v", did, err)
	}
}
