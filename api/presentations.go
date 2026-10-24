package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/pe"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// presentationRequestTTL is how long a verifier's request accepts a presentation.
const presentationRequestTTL = 10 * time.Minute

// maxPendingPresentations bounds the pending-request map.
const maxPendingPresentations = 10000

// presentationRequests holds the verifier's requests until they are answered. A request
// is single-use: the first submission against it consumes it.
type presentationRequests struct {
	mu   sync.Mutex
	reqs map[string]pe.PresentationRequest
	exp  map[string]time.Time
}

func newPresentationRequests() *presentationRequests {
	return &presentationRequests{reqs: map[string]pe.PresentationRequest{}, exp: map[string]time.Time{}}
}

// add stores req. It returns false when the map is full.
func (p *presentationRequests) add(req pe.PresentationRequest, expiresAt time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for id, e := range p.exp {
		if now.After(e) {
			delete(p.reqs, id)
			delete(p.exp, id)
		}
	}
	if len(p.reqs) >= maxPendingPresentations {
		return false
	}
	p.reqs[req.ID] = req
	p.exp[req.ID] = expiresAt
	return true
}

// take removes and returns the request with id, if it is still live.
func (p *presentationRequests) take(id string) (pe.PresentationRequest, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	req, ok := p.reqs[id]
	if !ok || time.Now().After(p.exp[id]) {
		delete(p.reqs, id)
		delete(p.exp, id)
		return pe.PresentationRequest{}, false
	}
	delete(p.reqs, id)
	delete(p.exp, id)
	return req, true
}

type presentationRequestBody struct {
	Definition pe.PresentationDefinition `json:"presentation_definition"`
	Domain     string                    `json:"domain,omitempty"`
}

type presentationRequestResponse struct {
	RequestID  string                    `json:"request_id"`
	Nonce      string                    `json:"nonce"`
	Definition pe.PresentationDefinition `json:"presentation_definition"`
	ExpiresAt  string                    `json:"expires_at"`
}

// handleCreatePresentationRequest records a verifier's request and returns its nonce.
// POST /api/v1/presentations/request
func (s *Server) handleCreatePresentationRequest(w http.ResponseWriter, r *http.Request) {
	var body presentationRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if body.Definition.ID == "" || len(body.Definition.InputDescriptors) == 0 {
		http.Error(w, "presentation_definition with at least one input_descriptor required", http.StatusBadRequest)
		return
	}

	nonce, err := randomNonce(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id, err := randomNonce(8)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req := pe.PresentationRequest{
		ID:         "preq_" + id,
		Definition: body.Definition,
		Nonce:      nonce,
		Domain:     body.Domain,
	}
	expiresAt := time.Now().Add(presentationRequestTTL)
	if !s.presentations.add(req, expiresAt) {
		writeJSONError(w, http.StatusServiceUnavailable, "busy", "too many pending presentation requests")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(presentationRequestResponse{
		RequestID:  req.ID,
		Nonce:      req.Nonce,
		Definition: req.Definition,
		ExpiresAt:  expiresAt.UTC().Format(time.RFC3339),
	})
}

type submitPresentationBody struct {
	// RequestID names the stored request. The definition and nonce come from the server,
	// never from the submission.
	RequestID    string                    `json:"request_id"`
	Presentation vc.VerifiablePresentation `json:"presentation"`
	Submission   pe.PresentationSubmission `json:"submission"`
}

// handleSubmitPresentation checks a holder's presentation against a stored request. It
// verifies the holder's signature, the nonce and domain of that request, and every enclosed
// credential. It also requires each credential to name the presenting holder as its subject.
// POST /api/v1/presentations/submit
func (s *Server) handleSubmitPresentation(w http.ResponseWriter, r *http.Request) {
	var body submitPresentationBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if body.RequestID == "" {
		http.Error(w, "request_id required", http.StatusBadRequest)
		return
	}

	// Single-use: the request is consumed whatever the outcome.
	req, ok := s.presentations.take(body.RequestID)
	if !ok {
		http.Error(w, "unknown or expired request", http.StatusNotFound)
		return
	}

	verifier := vc.NewVerifier(s.resolver)
	if err := verifier.VerifyPresentation(&body.Presentation, vc.VerifyPresentationOptions{
		ExpectedChallenge: req.Nonce,
		ExpectedDomain:    req.Domain,
	}); err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "invalid_presentation", err.Error())
		return
	}
	for _, cred := range body.Presentation.VerifiableCredential {
		if cred.CredentialSubject.ID != body.Presentation.Holder {
			writeJSONError(w, http.StatusUnprocessableEntity, "holder_mismatch",
				"credential subject does not match the presenting holder")
			return
		}
	}

	result, err := pe.Evaluate(&req.Definition, &body.Submission, &body.Presentation)
	if err != nil {
		http.Error(w, "evaluation error: "+err.Error(), http.StatusBadRequest)
		return
	}

	status := http.StatusOK
	if !result.Satisfied {
		status = http.StatusUnprocessableEntity
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"satisfied":           result.Satisfied,
		"errors":              result.Errors,
		"matched_credentials": len(result.MatchedCredentials),
	})
}

func randomNonce(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
