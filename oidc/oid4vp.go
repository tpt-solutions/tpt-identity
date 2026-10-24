// OID4VP implements OpenID for Verifiable Presentations
// (draft-ietf-oauth-openid-for-verifiable-presentations).
//
// Flow:
//  1. Verifier creates a presentation request via POST /oid4vp/requests
//  2. Request is encoded as openid4vp://?request_uri=<uri> QR code
//  3. Wallet fetches the request object from GET /oid4vp/requests/{id}
//  4. Wallet selects matching credentials and builds a VP
//  5. Wallet POSTs the VP to POST /oid4vp/responses
//  6. Verifier retrieves the result via GET /oid4vp/responses/{id}
package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// OID4VPRequest is an OID4VP authorization request.
type OID4VPRequest struct {
	ID                   string    `json:"id"`
	ClientID             string    `json:"client_id"`             // verifier DID or client_id
	ResponseType         string    `json:"response_type"`         // "vp_token"
	ResponseMode         string    `json:"response_mode"`         // "direct_post"
	ResponseURI          string    `json:"response_uri"`          // where wallet POSTs the response
	Nonce                string    `json:"nonce"`
	PresentationDefinition any     `json:"presentation_definition"` // DIF PE v2
	State                string    `json:"state,omitempty"`
	ExpiresAt            time.Time `json:"expires_at"`
	CreatedAt            time.Time `json:"created_at"`
}

// OID4VPResponse holds the wallet's response to a presentation request.
type OID4VPResponse struct {
	RequestID  string    `json:"request_id"`
	VPToken    string    `json:"vp_token"`    // JSON-encoded VP or JWT
	State      string    `json:"state,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	Error      string    `json:"error,omitempty"`
}

// maxOID4VPResponses bounds the response map so unauthenticated posts cannot grow it without limit.
const maxOID4VPResponses = 10000

// OID4VPStore is an in-memory store for OID4VP requests and responses.
// In production this should be backed by the persistent store; for now
// in-memory is sufficient for the request/response round-trip TTL.
type OID4VPStore struct {
	mu        sync.RWMutex
	requests  map[string]*OID4VPRequest
	responses map[string]*OID4VPResponse
}

func newOID4VPStore() *OID4VPStore {
	s := &OID4VPStore{
		requests:  make(map[string]*OID4VPRequest),
		responses: make(map[string]*OID4VPResponse),
	}
	// Periodic cleanup of expired entries.
	go func() {
		for range time.Tick(5 * time.Minute) {
			s.evict()
		}
	}()
	return s
}

func (s *OID4VPStore) evict() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, req := range s.requests {
		if req.ExpiresAt.Before(now) {
			delete(s.requests, id)
			delete(s.responses, id)
		}
	}
}

// OID4VPHandler provides the handler methods for OID4VP endpoints.
// It holds a reference to the Provider and an in-memory request/response store.
type OID4VPHandler struct {
	p     *Provider
	store *OID4VPStore
}

// NewOID4VPHandler creates a new OID4VP handler attached to the given provider.
func NewOID4VPHandler(p *Provider) *OID4VPHandler {
	return &OID4VPHandler{p: p, store: newOID4VPStore()}
}

// CreateRequestHandler handles POST /oid4vp/requests — creates a presentation request.
//
// Request body (JSON):
//
//	{
//	  "client_id":              "did:web:verifier.example.com",
//	  "presentation_definition": { ... DIF PE v2 ... },
//	  "expires_in":             300
//	}
func (h *OID4VPHandler) CreateRequestHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID               string `json:"client_id"`
		PresentationDefinition any    `json:"presentation_definition"`
		ExpiresIn              int    `json:"expires_in"`
		ResponseMode           string `json:"response_mode"` // "direct_post" (default) or "direct_post.jwt"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid_request", "invalid JSON body")
		return
	}
	if req.PresentationDefinition == nil {
		writeError(w, "invalid_request", "presentation_definition required")
		return
	}

	ttl := time.Duration(req.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if req.ResponseMode == "" {
		req.ResponseMode = "direct_post"
	}

	id, _ := randomHex(16)
	nonce, _ := randomHex(16)

	pReq := &OID4VPRequest{
		ID:                   id,
		ClientID:             req.ClientID,
		ResponseType:         "vp_token",
		ResponseMode:         req.ResponseMode,
		ResponseURI:          fmt.Sprintf("%s/oid4vp/responses", h.p.issuer),
		Nonce:                nonce,
		PresentationDefinition: req.PresentationDefinition,
		ExpiresAt:            time.Now().Add(ttl),
		CreatedAt:            time.Now(),
	}

	h.store.mu.Lock()
	h.store.requests[id] = pReq
	h.store.mu.Unlock()

	requestURI := fmt.Sprintf("%s/oid4vp/requests/%s", h.p.issuer, id)
	deepLink := fmt.Sprintf("openid4vp://?request_uri=%s&client_id=%s", requestURI, req.ClientID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"request_id":  id,
		"request_uri": requestURI,
		"deep_link":   deepLink,
		"qr_data":     deepLink,
		"nonce":       nonce,
		"expires_at":  pReq.ExpiresAt,
	})
}

// GetRequestHandler handles GET /oid4vp/requests/{id} — returns the JWT-encoded
// authorisation request object for the wallet to parse.
func (h *OID4VPHandler) GetRequestHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.store.mu.RLock()
	pReq, ok := h.store.requests[id]
	h.store.mu.RUnlock()

	if !ok {
		http.Error(w, "request not found", http.StatusNotFound)
		return
	}
	if time.Now().After(pReq.ExpiresAt) {
		http.Error(w, "request expired", http.StatusGone)
		return
	}

	// Return the request object as a JWT (signed request object per OID4VP §5).
	obj := map[string]any{
		"response_type":           pReq.ResponseType,
		"response_mode":           pReq.ResponseMode,
		"response_uri":            pReq.ResponseURI,
		"client_id":               pReq.ClientID,
		"nonce":                   pReq.Nonce,
		"presentation_definition": pReq.PresentationDefinition,
		"state":                   pReq.ID, // state = request ID for correlation
	}

	// token_type is distinct from "access" so the request object can never be presented
	// as a bearer token to the API.
	obj["token_type"] = "oid4vp_request"
	reqJWT, err := issueJWTWithExtra(h.p.issuer, pReq.ClientID, h.p.issuer,
		time.Until(pReq.ExpiresAt), h.p.signingKey, h.p.keyID, obj)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	w.Write([]byte(reqJWT))
}

// PostResponseHandler handles POST /oid4vp/responses — the wallet posts the VP token.
//
// Form params (application/x-www-form-urlencoded per OID4VP direct_post):
//   - vp_token — the verifiable presentation (JSON string or JWT)
//   - presentation_submission — the DIF PE v2 submission mapping
//   - state — the request ID (echoed back for correlation)
func (h *OID4VPHandler) PostResponseHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid_request", "could not parse form")
		return
	}

	vpToken := r.FormValue("vp_token")
	state := r.FormValue("state") // correlates to request ID
	if vpToken == "" {
		writeError(w, "invalid_request", "vp_token required")
		return
	}

	resp := &OID4VPResponse{
		RequestID:  state,
		VPToken:    vpToken,
		State:      state,
		ReceivedAt: time.Now(),
	}

	// The state must correspond to a live request, and each request accepts one response.
	h.store.mu.Lock()
	pReq, known := h.store.requests[state]
	switch {
	case !known || time.Now().After(pReq.ExpiresAt):
		h.store.mu.Unlock()
		writeError(w, "invalid_request", "unknown or expired request state")
		return
	case h.store.responses[state] != nil:
		h.store.mu.Unlock()
		writeErrorStatus(w, http.StatusConflict, "invalid_request", "a response was already received for this request")
		return
	case len(h.store.responses) >= maxOID4VPResponses:
		h.store.mu.Unlock()
		writeErrorStatus(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many pending responses")
		return
	}
	h.store.responses[state] = resp
	h.store.mu.Unlock()

	// OID4VP §6.2: redirect_uri or direct_post response is 200 with redirect_uri.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect_uri": fmt.Sprintf("%s/oid4vp/responses/%s/result", h.p.issuer, state),
	})
}

// GetResponseHandler handles GET /oid4vp/responses/{id} — the verifier polls
// for the wallet's response after presenting the request URI.
func (h *OID4VPHandler) GetResponseHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	h.store.mu.RLock()
	resp, ok := h.store.responses[id]
	h.store.mu.RUnlock()

	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "pending",
			"message": "Waiting for wallet to submit presentation.",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":     "complete",
		"vp_token":   resp.VPToken,
		"received_at": resp.ReceivedAt,
	})
}
