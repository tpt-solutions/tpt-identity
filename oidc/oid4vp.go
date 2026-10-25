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
//
// Requests and responses are kept in the store, so any replica can serve any step.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	vcpkg "github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// OID4VPRequest is an OID4VP authorization request.
type OID4VPRequest struct {
	ID                     string    `json:"id"`
	ClientID               string    `json:"client_id"`     // verifier DID or client_id
	ResponseType           string    `json:"response_type"` // "vp_token"
	ResponseMode           string    `json:"response_mode"` // "direct_post"
	ResponseURI            string    `json:"response_uri"`  // where wallet POSTs the response
	Nonce                  string    `json:"nonce"`
	PresentationDefinition any       `json:"presentation_definition"` // DIF PE v2
	State                  string    `json:"state,omitempty"`
	ExpiresAt              time.Time `json:"expires_at"`
	CreatedAt              time.Time `json:"created_at"`
}

// OID4VPResponse holds the wallet's response to a presentation request.
type OID4VPResponse struct {
	RequestID  string    `json:"request_id"`
	VPToken    string    `json:"vp_token"` // JSON-encoded VP or JWT
	State      string    `json:"state,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	Error      string    `json:"error,omitempty"`
}

// errOID4VPNotFound means no request has the id, or it has expired.
var errOID4VPNotFound = errors.New("unknown or expired request state")

// OID4VPStore keeps OID4VP requests and responses in the shared store.
type OID4VPStore struct {
	st store.Store
}

func (s *OID4VPStore) saveRequest(ctx context.Context, req *OID4VPRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return s.st.SaveOID4VPRequest(ctx, req.ID, b, req.ExpiresAt)
}

// loadRequest returns the request with id, or errOID4VPNotFound. An expired request is not returned.
func (s *OID4VPStore) loadRequest(ctx context.Context, id string) (*OID4VPRequest, error) {
	b, expires, err := s.st.GetOID4VPRequest(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errOID4VPNotFound
	}
	if err != nil {
		return nil, err
	}
	var req OID4VPRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("oid4vp: stored request: %w", err)
	}
	req.ExpiresAt = expires
	if time.Now().After(expires) {
		return nil, errOID4VPNotFound
	}
	return &req, nil
}

// saveResponse stores the one response a request accepts. A second one returns
// store.ErrOID4VPResponseExists.
func (s *OID4VPStore) saveResponse(ctx context.Context, resp *OID4VPResponse) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return s.st.SaveOID4VPResponse(ctx, resp.RequestID, b)
}

func (s *OID4VPStore) loadResponse(ctx context.Context, requestID string) (*OID4VPResponse, error) {
	b, err := s.st.GetOID4VPResponse(ctx, requestID)
	if err != nil {
		return nil, err
	}
	var resp OID4VPResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("oid4vp: stored response: %w", err)
	}
	return &resp, nil
}

// prune removes expired requests and their responses. Best effort: a failure does not stop a request.
func (s *OID4VPStore) prune(ctx context.Context) {
	_ = s.st.DeleteExpiredOID4VP(ctx, time.Now())
}

// OID4VPHandler provides the handler methods for OID4VP endpoints.
type OID4VPHandler struct {
	p     *Provider
	store *OID4VPStore
	// resolver resolves holder and issuer DIDs when a presentation is verified. Without it,
	// every response is refused.
	resolver *resolver.Resolver
}

// NewOID4VPHandler creates a new OID4VP handler attached to the given provider. The provider's store
// holds the request and response state.
func NewOID4VPHandler(p *Provider) *OID4VPHandler {
	return &OID4VPHandler{p: p, store: &OID4VPStore{st: p.store}}
}

// SetResolver sets the DID resolver used to verify presentations.
func (h *OID4VPHandler) SetResolver(r *resolver.Resolver) {
	h.resolver = r
}

// verifyVPToken checks a JSON verifiable presentation against the request. The holder's proof
// must cover the request nonce and be addressed to the request's client_id; every enclosed
// credential must verify and name the presenting holder as its subject.
func (h *OID4VPHandler) verifyVPToken(vpToken string, req *OID4VPRequest) error {
	if h.resolver == nil {
		return errors.New("presentation verification is not configured")
	}
	if strings.HasPrefix(strings.TrimSpace(vpToken), "{") {
		return h.verifyJSONVPToken(vpToken, req)
	}
	return h.verifyJWTVPToken(strings.TrimSpace(vpToken), req)
}

// verifyJSONVPToken checks a JSON-LD style presentation: the holder's embedded DataIntegrityProof.
func (h *OID4VPHandler) verifyJSONVPToken(vpToken string, req *OID4VPRequest) error {
	var vp vcpkg.VerifiablePresentation
	if err := json.Unmarshal([]byte(vpToken), &vp); err != nil {
		return fmt.Errorf("vp_token must be a JSON verifiable presentation: %w", err)
	}
	if err := vcpkg.NewVerifier(h.resolver).VerifyPresentation(&vp, vcpkg.VerifyPresentationOptions{
		ExpectedChallenge: req.Nonce,
		ExpectedDomain:    req.ClientID,
	}); err != nil {
		return err
	}
	for i, cred := range vp.VerifiableCredential {
		if cred.CredentialSubject.ID != vp.Holder {
			return fmt.Errorf("credential[%d] subject does not match the presenting holder", i)
		}
	}
	return nil
}

// CreateRequestHandler handles POST /oid4vp/requests — creates a presentation request.
//
// Request body (JSON):
//
//	{
//	  "client_id":              "did:web:verifier.example.com",
//	  "presentation_definition": { ... DIF PE v2 ... },
//	  "expires_in":             300,          // seconds, default 300
//	  "response_mode":          "direct_post" // default
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
		ID:                     id,
		ClientID:               req.ClientID,
		ResponseType:           "vp_token",
		ResponseMode:           req.ResponseMode,
		ResponseURI:            fmt.Sprintf("%s/oid4vp/responses", h.p.issuer),
		Nonce:                  nonce,
		PresentationDefinition: req.PresentationDefinition,
		ExpiresAt:              time.Now().Add(ttl),
		CreatedAt:              time.Now(),
	}

	h.store.prune(r.Context())
	if err := h.store.saveRequest(r.Context(), pReq); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	requestURI := fmt.Sprintf("%s/oid4vp/requests/%s", h.p.issuer, id)
	deepLink := fmt.Sprintf("openid4vp://?request_uri=%s&client_id=%s", requestURI, req.ClientID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
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

	pReq, err := h.store.loadRequest(r.Context(), id)
	if errors.Is(err, errOID4VPNotFound) {
		http.Error(w, "request not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
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
	_, _ = w.Write([]byte(reqJWT))
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

	pReq, err := h.store.loadRequest(r.Context(), state)
	if err != nil {
		writeError(w, "invalid_request", errOID4VPNotFound.Error())
		return
	}

	// Verify before storing: a presentation that fails is not recorded, so the wallet may retry.
	if err := h.verifyVPToken(vpToken, pReq); err != nil {
		writeErrorStatus(w, http.StatusUnprocessableEntity, "invalid_vp_token", err.Error())
		return
	}

	resp := &OID4VPResponse{
		RequestID:  state,
		VPToken:    vpToken,
		State:      state,
		ReceivedAt: time.Now(),
	}
	// The store accepts one response per request; a second is refused by its primary key.
	if err := h.store.saveResponse(r.Context(), resp); err != nil {
		if errors.Is(err, store.ErrOID4VPResponseExists) {
			writeErrorStatus(w, http.StatusConflict, "invalid_request", "a response was already received for this request")
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// OID4VP §6.2: redirect_uri or direct_post response is 200 with redirect_uri.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"redirect_uri": fmt.Sprintf("%s/oid4vp/responses/%s/result", h.p.issuer, state),
	})
}

// GetResponseHandler handles GET /oid4vp/responses/{id} — the verifier polls
// for the wallet's response after presenting the request URI.
func (h *OID4VPHandler) GetResponseHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	resp, err := h.store.loadResponse(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "pending",
			"message": "Waiting for wallet to submit presentation.",
		})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "complete",
		"vp_token":    resp.VPToken,
		"received_at": resp.ReceivedAt,
	})
}
