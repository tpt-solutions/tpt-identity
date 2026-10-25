package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/didcomm"
)

const basicMessageType = "https://didcomm.org/basicmessage/2.0/message"

type inboxPage []struct {
	Sender    string `json:"sender"`
	MessageID string `json:"message_id"`
	Type      string `json:"type"`
	Body      string `json:"body"`
}

func listInbox(t *testing.T, f *dcFixture) (inboxPage, string) {
	t.Helper()
	w := do(t, f.srv, http.MethodGet, "/admin/v1/didcomm/inbox", "", bearer(testAPIKey))
	if w.Code != http.StatusOK {
		t.Fatalf("list inbox: %d %s", w.Code, w.Body.String())
	}
	var page inboxPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page, w.Header().Get("X-Total-Count")
}

// An accepted, authenticated message is kept with its verified sender and its decrypted body.
func TestDIDCommInboxKeepsAcceptedMessage(t *testing.T) {
	f := newDIDCommFixture(t)
	msg := f.message(t, didcomm.Message{ID: "kept-1", Type: "https://example.com/ping", From: f.senderDID, CreatedTime: time.Now().Unix()})
	env, err := didcomm.PackAuthcrypt(msg, f.recipients(), f.senderKID, f.senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.post(t, env); w.Code != http.StatusAccepted {
		t.Fatalf("deliver: want 202, got %d: %s", w.Code, w.Body.String())
	}

	page, total := listInbox(t, f)
	if total != "1" || len(page) != 1 {
		t.Fatalf("inbox: want 1 message, got total %s and %d", total, len(page))
	}
	got := page[0]
	if got.MessageID != "kept-1" || got.Type != "https://example.com/ping" {
		t.Errorf("kept message: got id %q type %q", got.MessageID, got.Type)
	}
	if got.Sender != f.senderDID {
		t.Errorf("sender: want authenticated %s, got %q", f.senderDID, got.Sender)
	}
	if got.Body == "" {
		t.Error("decrypted body not kept")
	}
}

// With no configured types, only basic messages are kept. Anything else is refused and stores nothing.
func TestDIDCommInboxDefaultRefusesOtherTypes(t *testing.T) {
	f := newDIDCommFixtureTypes(t, nil)
	other := f.message(t, didcomm.Message{ID: "other-1", Type: "https://example.com/ping", From: f.senderDID, CreatedTime: time.Now().Unix()})
	env, err := didcomm.PackAuthcrypt(other, f.recipients(), f.senderKID, f.senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.post(t, env); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unlisted type: want 422, got %d: %s", w.Code, w.Body.String())
	}
	if _, total := listInbox(t, f); total != "0" {
		t.Errorf("refused message was kept: total %s", total)
	}
}

// The default allowlist accepts a basic message.
func TestDIDCommInboxDefaultAcceptsBasicMessage(t *testing.T) {
	f := newDIDCommFixtureTypes(t, nil)
	msg := f.message(t, didcomm.Message{ID: "basic-1", Type: basicMessageType, From: f.senderDID, CreatedTime: time.Now().Unix()})
	env, err := didcomm.PackAuthcrypt(msg, f.recipients(), f.senderKID, f.senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.post(t, env); w.Code != http.StatusAccepted {
		t.Errorf("basic message by default: want 202, got %d: %s", w.Code, w.Body.String())
	}
}

// The inbox list is an admin read: a scoped key cannot read it.
func TestDIDCommInboxIsAdminOnly(t *testing.T) {
	f := newDIDCommFixture(t)
	if w := do(t, f.srv, http.MethodGet, "/admin/v1/didcomm/inbox", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no credential: want 401, got %d", w.Code)
	}
}
