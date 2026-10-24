package api_test

import (
	"net/http"
	"testing"
)

// Webhook targets must be https and must not name non-public addresses.
func TestWebhookRegistrationPolicy(t *testing.T) {
	srv := newTestServer(t)
	rejected := []string{
		`{"url":"http://hooks.example.com/in"}`,
		`{"url":"https://10.0.0.5/in"}`,
		`{"url":"https://127.0.0.1/in"}`,
		`{"url":"https://user:pw@hooks.example.com/in"}`,
	}
	for _, body := range rejected {
		if w := authed(t, srv, http.MethodPost, "/api/v1/webhooks", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", body, w.Code)
		}
	}
	w := authed(t, srv, http.MethodPost, "/api/v1/webhooks", `{"url":"https://hooks.example.com/in"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid webhook: want 201, got %d: %s", w.Code, w.Body.String())
	}
}
