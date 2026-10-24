package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

func createOffer(t *testing.T, st store.Store) (offerID, pin string) {
	t.Helper()
	_, priv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider("https://issuer.example.com", priv, "key-1", st)
	body := `{"schema_ids":["identity.legal-name"],"subject_did":"` + proofHolder + `"}`
	r := httptest.NewRequest(http.MethodPost, "/oid4vci/offers", strings.NewReader(body))
	w := httptest.NewRecorder()
	p.CreateCredentialOfferHandler(priv, "key-1", st).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("create offer: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		OfferID string `json:"offer_id"`
		TxCode  string `json:"tx_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.OfferID, resp.TxCode
}

func redeem(t *testing.T, st store.Store, offerID string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	_, priv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider("https://issuer.example.com", priv, "key-1", st)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	form.Set("pre-authorized_code", offerID)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler(w, r)
	return w
}

// The PIN shown to the operator is six digits and is never stored in clear.
func TestOfferPINIsSixDigitsAndStoredHashed(t *testing.T) {
	st := newProofStore(t)
	id, pin := createOffer(t, st)
	if !regexp.MustCompile(`^\d{6}$`).MatchString(pin) {
		t.Fatalf("pin %q is not six digits", pin)
	}
	offer, err := st.GetCredentialOffer(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if offer.TxCodeHash == "" || offer.TxCodeHash == pin {
		t.Errorf("offer stores %q; want a hash, not the PIN", offer.TxCodeHash)
	}
}

// The right PIN redeems the offer once.
func TestOfferRedeemsWithRightPIN(t *testing.T) {
	st := newProofStore(t)
	id, pin := createOffer(t, st)
	if w := redeem(t, st, id, url.Values{"tx_code": {pin}}); w.Code != http.StatusOK {
		t.Fatalf("right PIN: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := redeem(t, st, id, url.Values{"tx_code": {pin}}); w.Code == http.StatusOK {
		t.Error("offer redeemed twice")
	}
}

// A request without the PIN is refused, and the offer stays open for the holder who has it.
func TestOfferRefusesMissingPIN(t *testing.T) {
	st := newProofStore(t)
	id, pin := createOffer(t, st)
	if w := redeem(t, st, id, url.Values{}); w.Code == http.StatusOK {
		t.Fatal("offer redeemed without a PIN")
	}
	if w := redeem(t, st, id, url.Values{"tx_code": {pin}}); w.Code != http.StatusOK {
		t.Errorf("right PIN after a missing-PIN attempt: want 200, got %d", w.Code)
	}
}

// A wrong PIN burns the offer, so the right PIN no longer works. This stops guessing.
func TestWrongPINBurnsOffer(t *testing.T) {
	st := newProofStore(t)
	id, pin := createOffer(t, st)
	wrong := "000000"
	if wrong == pin {
		wrong = "111111"
	}
	if w := redeem(t, st, id, url.Values{"tx_code": {wrong}}); w.Code == http.StatusOK {
		t.Fatal("wrong PIN was accepted")
	}
	if w := redeem(t, st, id, url.Values{"tx_code": {pin}}); w.Code == http.StatusOK {
		t.Error("offer still redeemable after a wrong PIN")
	}
}

// An offer with no stored PIN hash (created before tx_code existed) is refused.
func TestOfferWithoutHashRefused(t *testing.T) {
	st := newProofStore(t)
	legacy := &store.CredentialOffer{
		ID: "legacy-offer", SchemaIDs: []string{proofSchema}, IssuerDID: "did:web:issuer.example.com",
		SubjectDID: proofHolder, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}
	if err := st.SaveCredentialOffer(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	if w := redeem(t, st, "legacy-offer", url.Values{"tx_code": {"123456"}}); w.Code == http.StatusOK {
		t.Error("offer without a PIN hash was redeemed")
	}
}
