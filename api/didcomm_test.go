package api_test

import (
	"encoding/json"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/tpt-solutions/tpt-identity/pkg/didcomm"
)

const dcRecipKID = testPlatformDID + "#enc-key-1"

type dcFixture struct {
	srv        *api.Server
	recipPub   [32]byte
	senderDID  string
	senderKID  string
	senderPriv [32]byte
}

// newDIDCommFixture starts a server with an X25519 receive key and makes a did:peer sender with its
// own X25519 key.
// newDIDCommFixture accepts the ping type used by most tests.
func newDIDCommFixture(t *testing.T) *dcFixture {
	t.Helper()
	return newDIDCommFixtureTypes(t, []string{"https://example.com/ping"})
}

// newDIDCommFixtureTypes starts the server with the given accepted message types.
func newDIDCommFixtureTypes(t *testing.T, types []string) *dcFixture {
	t.Helper()
	st := storetest.New(t)

	_, signPriv, _ := crypto.GenerateSigningKey()
	recipPub, recipPriv, _ := crypto.GenerateEncryptionKey()
	res := resolver.New(time.Minute)
	srv := api.NewServer(api.Config{
		APIKey:               testAPIKey,
		Issuer:               testIssuer,
		SigningKey:           signPriv,
		SigningKeyID:         testPlatformDID + "#signing-key-1",
		EncKey:               recipPriv,
		EncKeyID:             dcRecipKID,
		DIDCommAcceptedTypes: types,
		Store:                st,
		Resolver:             res,
		OIDC:                 oidc.NewProvider(testIssuer, signPriv, "test-key-1", st),
	})

	senderSign, _, _ := crypto.GenerateSigningKey()
	senderEncPub, senderEncPriv, _ := crypto.GenerateEncryptionKey()
	senderDID, _, err := did.Create("peer", did.CreateOptions{SigningPub: senderSign, EncPub: senderEncPub[:]})
	if err != nil {
		t.Fatal(err)
	}
	return &dcFixture{
		srv:        srv,
		recipPub:   recipPub,
		senderDID:  senderDID,
		senderKID:  senderDID + "#key-2",
		senderPriv: senderEncPriv,
	}
}

func (f *dcFixture) message(t *testing.T, m didcomm.Message) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *dcFixture) post(t *testing.T, envelope []byte) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, f.srv, http.MethodPost, "/didcomm", string(envelope), map[string]string{
		"Content-Type": didcomm.MediaTypeEncrypted,
	})
}

func (f *dcFixture) recipients() []didcomm.Recipient {
	return []didcomm.Recipient{{KID: dcRecipKID, PubKey: f.recipPub}}
}

// An authenticated message is accepted once; the same message again is a replay.
func TestDIDCommAcceptsAuthenticatedMessageOnce(t *testing.T) {
	f := newDIDCommFixture(t)
	msg := f.message(t, didcomm.Message{ID: "m-1", Type: "https://example.com/ping", From: f.senderDID, CreatedTime: time.Now().Unix()})
	env, err := didcomm.PackAuthcrypt(msg, f.recipients(), f.senderKID, f.senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.post(t, env); w.Code != http.StatusAccepted {
		t.Fatalf("first delivery: want 202, got %d: %s", w.Code, w.Body.String())
	}
	if w := f.post(t, env); w.Code != http.StatusConflict {
		t.Errorf("replay: want 409, got %d", w.Code)
	}
}

// from must name the authenticated sender. A different from is refused.
func TestDIDCommRefusesForgedFrom(t *testing.T) {
	f := newDIDCommFixture(t)
	msg := f.message(t, didcomm.Message{ID: "m-2", Type: "https://example.com/ping", From: "did:peer:someone-else", CreatedTime: time.Now().Unix()})
	env, err := didcomm.PackAuthcrypt(msg, f.recipients(), f.senderKID, f.senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.post(t, env); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "sender_mismatch") {
		t.Errorf("forged from: want 400 sender_mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

// A message past its expires_time is refused.
func TestDIDCommRefusesExpiredMessage(t *testing.T) {
	f := newDIDCommFixture(t)
	msg := f.message(t, didcomm.Message{ID: "m-3", Type: "https://example.com/ping", ExpiresTime: time.Now().Add(-time.Minute).Unix()})
	env, err := didcomm.PackAnoncrypt(msg, f.recipients())
	if err != nil {
		t.Fatal(err)
	}
	if w := f.post(t, env); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "message_expired") {
		t.Errorf("expired: want 400 message_expired, got %d: %s", w.Code, w.Body.String())
	}
}

// An anonymous message names a sender in from, but that claim is not trusted: the message is
// accepted as unauthenticated.
func TestDIDCommAnoncryptFromIsNotTrusted(t *testing.T) {
	f := newDIDCommFixture(t)
	msg := f.message(t, didcomm.Message{ID: "m-4", Type: "https://example.com/ping", From: f.senderDID, CreatedTime: time.Now().Unix()})
	env, err := didcomm.PackAnoncrypt(msg, f.recipients())
	if err != nil {
		t.Fatal(err)
	}
	if w := f.post(t, env); w.Code != http.StatusAccepted {
		t.Errorf("anoncrypt: want 202, got %d: %s", w.Code, w.Body.String())
	}
}

// A message without an id cannot be checked for replay, so it is refused.
func TestDIDCommRefusesMessageWithoutID(t *testing.T) {
	f := newDIDCommFixture(t)
	msg := f.message(t, didcomm.Message{Type: "https://example.com/ping", CreatedTime: time.Now().Unix()})
	env, err := didcomm.PackAnoncrypt(msg, f.recipients())
	if err != nil {
		t.Fatal(err)
	}
	if w := f.post(t, env); w.Code != http.StatusBadRequest {
		t.Errorf("no id: want 400, got %d", w.Code)
	}
}
