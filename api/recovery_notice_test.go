package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/storetest"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

// fakeNotices records recovery notices and can be set to fail.
type fakeNotices struct {
	mu     sync.Mutex
	fail   bool
	sentTo []string
}

func (f *fakeNotices) SendRecoveryNotice(_ context.Context, email, requestID, subjectDID string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("smtp down")
	}
	if requestID == "" || subjectDID == "" {
		return errors.New("notice without a request or subject")
	}
	f.sentTo = append(f.sentTo, email)
	return nil
}

// noticeServer is a recovery server whose guardian 1 has an address and the others do not.
func noticeServer(t *testing.T, sender api.RecoveryNoticeSender) *api.Server {
	t.Helper()
	st := storetest.New(t)
	_, priv, _ := crypto.GenerateSigningKey()
	srv := api.NewServer(api.Config{
		APIKey:               testAPIKey,
		Issuer:               testIssuer,
		SigningKey:           priv,
		Store:                st,
		OIDC:                 oidc.NewProvider(testIssuer, priv, "test-key-1", st),
		Resolver:             resolver.New(time.Minute),
		RecoveryNoticeSender: sender,
	})
	if err := st.SaveRecoveryConfig(t.Context(), &store.RecoveryConfig{
		SubjectDID:     recSubject,
		Threshold:      2,
		GuardianDIDs:   []string{recG1, recG2, recG3},
		GuardianEmails: map[string]string{recG1: "guardian1@example.com"},
		CreatedAt:      time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return srv
}

type initiateResponse struct {
	Notified []string `json:"notified_guardians"`
	Failed   []string `json:"notice_failed_guardians"`
	Shares   map[string]string
}

func initiateWithNotices(t *testing.T, srv *api.Server) (int, initiateResponse) {
	t.Helper()
	w := authed(t, srv, http.MethodPost, "/api/v1/recovery/initiate", `{"subject_did":"`+recSubject+`"}`)
	var resp initiateResponse
	if w.Code == http.StatusCreated {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, resp
}

// A guardian with an address is notified. A guardian without one is not, and is not reported as failed.
func TestRecoveryNoticesGoOnlyToGuardiansWithAddresses(t *testing.T) {
	sender := &fakeNotices{}
	code, resp := initiateWithNotices(t, noticeServer(t, sender))
	if code != http.StatusCreated {
		t.Fatalf("initiate: want 201, got %d", code)
	}
	if len(resp.Notified) != 1 || resp.Notified[0] != recG1 {
		t.Errorf("notified: want [%s], got %v", recG1, resp.Notified)
	}
	if len(resp.Failed) != 0 {
		t.Errorf("failed: want none, got %v", resp.Failed)
	}
	if len(sender.sentTo) != 1 || sender.sentTo[0] != "guardian1@example.com" {
		t.Errorf("sent to %v", sender.sentTo)
	}
	// The notice is for a guardian; the response must not expose the address.
	if resp.Notified[0] == "guardian1@example.com" {
		t.Error("response exposed a guardian address")
	}
}

// A delivery failure does not stop the recovery: the shares are still issued, and the failure is reported.
func TestRecoveryNoticeFailureIsReportedNotFatal(t *testing.T) {
	code, resp := initiateWithNotices(t, noticeServer(t, &fakeNotices{fail: true}))
	if code != http.StatusCreated {
		t.Fatalf("initiate with a failing mailer: want 201, got %d", code)
	}
	if len(resp.Failed) != 1 || resp.Failed[0] != recG1 {
		t.Errorf("failed: want [%s], got %v", recG1, resp.Failed)
	}
	if len(resp.Shares) != 3 {
		t.Errorf("shares issued: want 3, got %d", len(resp.Shares))
	}
}

// Without a configured sender, guardians with addresses are reported as not notified.
func TestRecoveryWithoutSenderReportsNotNotified(t *testing.T) {
	code, resp := initiateWithNotices(t, noticeServer(t, nil))
	if code != http.StatusCreated {
		t.Fatalf("initiate: want 201, got %d", code)
	}
	if len(resp.Notified) != 0 || len(resp.Failed) != 1 {
		t.Errorf("no sender: want 0 notified and 1 failed, got %v / %v", resp.Notified, resp.Failed)
	}
}
