package oidc_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

const vpVerifier = "did:peer:verifier-rp"

type vpFixture struct {
	h          *oidc.OID4VPHandler
	issuerDID  string
	issuerPriv []byte
	holderDID  string
	holderPriv []byte
	credential vc.VerifiableCredential
}

// newVPFixture builds an issuer and a holder (both did:peer, resolvable offline), a legal-name
// credential issued to the holder, and an OID4VP handler with a resolver.
func newVPFixture(t *testing.T) *vpFixture {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	issuerPub, issuerPriv, _ := crypto.GenerateSigningKey()
	issuerDID, _, err := did.Create("peer", did.CreateOptions{SigningPub: issuerPub})
	if err != nil {
		t.Fatal(err)
	}
	holderPub, holderPriv, _ := crypto.GenerateSigningKey()
	holderDID, _, err := did.Create("peer", did.CreateOptions{SigningPub: holderPub})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := vc.Issue(vc.IssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            issuerPriv,
		VerificationMethodID: issuerDID + "#key-1",
		SchemaID:             "identity.legal-name",
		SubjectDID:           holderDID,
		Claims:               map[string]string{"givenNames": "Alice", "familyName": "Smith"},
		ValidFor:             time.Hour,
	})
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	_, platformPriv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider("https://issuer.example.com", platformPriv, "key-1", st)
	h := oidc.NewOID4VPHandler(p)
	h.SetResolver(resolver.New(time.Minute))
	return &vpFixture{
		h: h, issuerDID: issuerDID, issuerPriv: issuerPriv,
		holderDID: holderDID, holderPriv: holderPriv, credential: *cred,
	}
}

// createRequest opens a presentation request and returns its id and nonce.
func (f *vpFixture) createRequest(t *testing.T) (id, nonce string) {
	t.Helper()
	body := `{"client_id":"` + vpVerifier + `","presentation_definition":{"id":"pd"}}`
	r := httptest.NewRequest(http.MethodPost, "/oid4vp/requests", strings.NewReader(body))
	w := httptest.NewRecorder()
	f.h.CreateRequestHandler(w, r)
	var resp struct {
		RequestID string `json:"request_id"`
		Nonce     string `json:"nonce"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.RequestID == "" {
		t.Fatalf("create request: %d %s", w.Code, w.Body.String())
	}
	return resp.RequestID, resp.Nonce
}

// presentation signs a VP for the holder, bound to nonce and domain.
func (f *vpFixture) presentation(t *testing.T, nonce, domain string) string {
	t.Helper()
	vp, err := vc.Present(vc.PresentOptions{
		HolderDID:            f.holderDID,
		HolderKey:            f.holderPriv,
		VerificationMethodID: f.holderDID + "#key-1",
		Credentials:          []vc.VerifiableCredential{f.credential},
		Challenge:            nonce,
		Domain:               domain,
	})
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	raw, err := json.Marshal(vp)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (f *vpFixture) post(t *testing.T, state, vpToken string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"state": {state}, "vp_token": {vpToken}}
	r := httptest.NewRequest(http.MethodPost, "/oid4vp/responses", bytes.NewBufferString(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.h.PostResponseHandler(w, r)
	return w
}

// A presentation bound to the request's nonce and client is accepted once.
func TestOID4VPAcceptsValidPresentationOnce(t *testing.T) {
	f := newVPFixture(t)
	id, nonce := f.createRequest(t)

	if w := f.post(t, id, f.presentation(t, nonce, vpVerifier)); w.Code != http.StatusOK {
		t.Fatalf("valid presentation: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := f.post(t, id, f.presentation(t, nonce, vpVerifier)); w.Code != http.StatusConflict {
		t.Errorf("second response: want 409, got %d", w.Code)
	}
}

// A presentation signed for another request's nonce is refused, and nothing is recorded, so the
// wallet can retry with the right one.
func TestOID4VPRefusesWrongNonce(t *testing.T) {
	f := newVPFixture(t)
	id, _ := f.createRequest(t)

	if w := f.post(t, id, f.presentation(t, "some-other-nonce", vpVerifier)); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong nonce: want 422, got %d: %s", w.Code, w.Body.String())
	}
}

// A presentation addressed to a different verifier is refused.
func TestOID4VPRefusesWrongDomain(t *testing.T) {
	f := newVPFixture(t)
	id, nonce := f.createRequest(t)

	if w := f.post(t, id, f.presentation(t, nonce, "did:peer:someone-else")); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong domain: want 422, got %d: %s", w.Code, w.Body.String())
	}
}

// Without a resolver the handler cannot verify, so it refuses every presentation.
func TestOID4VPRefusesWithoutResolver(t *testing.T) {
	f := newVPFixture(t)
	_, key, _ := crypto.GenerateSigningKey()
	f.h = oidc.NewOID4VPHandler(oidc.NewProvider("https://issuer.example.com", key, "key-1", nil))
	id, nonce := f.createRequest(t)

	if w := f.post(t, id, f.presentation(t, nonce, vpVerifier)); w.Code == http.StatusOK {
		t.Fatalf("accepted a presentation without a resolver: %s", w.Body.String())
	}
}
