package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

const parTTL = 90 * time.Second // RFC 9126 §2.1 recommends ≤ 90 s

// PARHandler implements POST /oidc/par — Pushed Authorization Requests (RFC 9126).
//
// Clients POST the full set of authorization parameters here first, receive a
// request_uri, then redirect the user to /authorize?request_uri=<uri>&client_id=<id>.
// This prevents parameter tampering in the browser redirect and is required for
// high-assurance clients (FAPI 2.0, mTLS).
func (p *Provider) PARHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid_request", "could not parse form")
		return
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		writeError(w, "invalid_client", "client_id required")
		return
	}

	// Authenticate confidential clients.
	if err := p.validateClientAuth(r, clientID); err != nil {
		writeError(w, "invalid_client", err.Error())
		return
	}

	// Validate that redirect_uri is registered.
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI != "" {
		client, err := p.store.GetClient(r.Context(), clientID)
		if err != nil {
			writeError(w, "invalid_client", "unknown client")
			return
		}
		if !containsURI(client.RedirectURIs, redirectURI) {
			writeError(w, "invalid_request", "redirect_uri not registered for this client")
			return
		}
	}

	// Collect all non-empty form values as the authorisation parameters JSON.
	params := map[string]string{}
	for k, vv := range r.Form {
		if len(vv) > 0 && vv[0] != "" {
			params[k] = vv[0]
		}
	}
	raw, _ := json.Marshal(params)

	requestID, err := randomHex(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	requestURI := fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", requestID)

	req := &store.PARRequest{
		RequestURI: requestURI,
		ClientID:   clientID,
		Params:     string(raw),
		ExpiresAt:  time.Now().Add(parTTL),
		CreatedAt:  time.Now(),
	}
	if err := p.store.SavePARRequest(r.Context(), req); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_uri": requestURI,
		"expires_in":  int(parTTL.Seconds()),
	})
}

// resolvePARRequest looks up a request_uri from a PAR request and returns the
// stored params if the URI is valid and not expired. Called by AuthorizeHandler.
func (p *Provider) resolvePARRequest(r *http.Request, requestURI string) (map[string]string, error) {
	par, err := p.store.GetPARRequest(r.Context(), requestURI)
	if err != nil {
		return nil, fmt.Errorf("par: request_uri not found")
	}
	if time.Now().After(par.ExpiresAt) {
		_ = p.store.DeletePARRequest(r.Context(), requestURI)
		return nil, fmt.Errorf("par: request_uri expired")
	}
	_ = p.store.DeletePARRequest(r.Context(), requestURI) // single-use
	var params map[string]string
	if err := json.Unmarshal([]byte(par.Params), &params); err != nil {
		return nil, fmt.Errorf("par: malformed params")
	}
	return params, nil
}
