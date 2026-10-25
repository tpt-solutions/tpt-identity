package api_test

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

const rotationKeyOld = testPlatformDID + "#signing-key-1"
const rotationKeyNew = testPlatformDID + "#signing-key-2"

// rotationServer runs the platform with signing key priv, and retired keys for verification. Two
// servers in one test share st, as two replicas on one database would.
func rotationServer(t *testing.T, st store.Store, priv ed25519.PrivateKey, keyID string, retired []did.RetiredKey) *api.Server {
	t.Helper()
	return api.NewServer(api.Config{
		APIKey:             testAPIKey,
		Issuer:             testIssuer,
		SigningKey:         priv,
		SigningKeyID:       keyID,
		RetiredSigningKeys: retired,
		Store:              st,
		Resolver:           resolver.New(5 * time.Minute),
		OIDC:               oidc.NewProvider(testIssuer, priv, keyID, st),
	})
}

// A credential issued before a rotation still verifies after it, because the platform DID document
// keeps the old key. Without the retired key the same credential is refused.
func TestCredentialSurvivesKeyRotation(t *testing.T) {
	st := storetest.New(t)
	oldPub, oldPriv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, newPriv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	before := rotationServer(t, st, oldPriv, rotationKeyOld, nil)
	w := do(t, before, http.MethodPost, "/api/v1/credentials", legalNameBody, bearer(testAPIKey))
	if w.Code != http.StatusCreated {
		t.Fatalf("issue before rotation: %d %s", w.Code, w.Body.String())
	}
	oldCred := w.Body.String()

	after := rotationServer(t, st, newPriv, rotationKeyNew, []did.RetiredKey{{ID: rotationKeyOld, Pub: oldPub}})
	if w := do(t, after, http.MethodPost, "/api/v1/credentials/verify", oldCred, bearer(testAPIKey)); w.Code != http.StatusOK {
		t.Errorf("old credential after rotation: want 200, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, after, http.MethodPost, "/api/v1/credentials", legalNameBody, bearer(testAPIKey))
	if w.Code != http.StatusCreated {
		t.Fatalf("issue after rotation: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, after, http.MethodPost, "/api/v1/credentials/verify", w.Body.String(), bearer(testAPIKey)); w.Code != http.StatusOK {
		t.Errorf("new credential: want 200, got %d", w.Code)
	}

	// Control: a server that drops the retired key cannot verify the old credential.
	dropped := rotationServer(t, st, newPriv, rotationKeyNew, nil)
	if w := do(t, dropped, http.MethodPost, "/api/v1/credentials/verify", oldCred, bearer(testAPIKey)); w.Code == http.StatusOK {
		t.Error("old credential verified without its retired key")
	}
}

// The served document lists the current key for assertions and the retired key only for verification.
func TestServedDocumentRetiresKeyWithoutAssertion(t *testing.T) {
	st := storetest.New(t)
	oldPub, _, _ := crypto.GenerateSigningKey()
	_, newPriv, _ := crypto.GenerateSigningKey()
	srv := rotationServer(t, st, newPriv, rotationKeyNew, []did.RetiredKey{{ID: rotationKeyOld, Pub: oldPub}})

	w := do(t, srv, http.MethodGet, "/.well-known/did.json", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("did.json: %d", w.Code)
	}
	var doc did.Document
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.VerificationMethod) != 2 {
		t.Errorf("want current and retired keys, got %d methods", len(doc.VerificationMethod))
	}
	if len(doc.AssertionMethod) != 1 || doc.AssertionMethod[0] != rotationKeyNew {
		t.Errorf("assertionMethod: want only the new key, got %v", doc.AssertionMethod)
	}
}
