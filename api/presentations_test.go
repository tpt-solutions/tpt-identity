package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A submission must name a stored request; an unknown one is refused.
func TestPresentationSubmitNeedsStoredRequest(t *testing.T) {
	srv := newTestServer(t)
	w := authed(t, srv, http.MethodPost, "/api/v1/presentations/submit",
		`{"request_id":"preq_nope","presentation":{},"submission":{}}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown request: want 404, got %d", w.Code)
	}
}

// A request is single-use: the first submission consumes it even when it fails verification.
func TestPresentationRequestSingleUse(t *testing.T) {
	srv := newTestServer(t)
	body := `{"presentation_definition":{"id":"pd-1","input_descriptors":[{"id":"age","schema":{"uri":"x"}}]}}`
	w := authed(t, srv, http.MethodPost, "/api/v1/presentations/request", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create request: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	submit := `{"request_id":"` + created.RequestID + `","presentation":{"type":["VerifiablePresentation"]},"submission":{}}`
	if w := authed(t, srv, http.MethodPost, "/api/v1/presentations/submit", submit); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unsigned presentation: want 422, got %d", w.Code)
	}
	if w := authed(t, srv, http.MethodPost, "/api/v1/presentations/submit", submit); w.Code != http.StatusNotFound {
		t.Errorf("request reused: want 404, got %d", w.Code)
	}
}
