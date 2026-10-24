package oidc

import (
	"encoding/json"
	"net/http"
	"time"
)

// IntrospectResponse is the RFC 7662 token introspection response.
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// IntrospectHandler handles POST /oauth/introspect (RFC 7662).
// Returns token metadata for active tokens; {"active":false} for revoked or invalid ones.
func (p *Provider) IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		writeError(w, "invalid_request", "token parameter is required")
		return
	}

	inactive := IntrospectResponse{Active: false}

	// Verify signature and expiry.
	verified, err := Verify(token, p.signingPub)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inactive)
		return
	}

	// Check if token has been explicitly revoked.
	if p.isAccessTokenRevoked(r.Context(), token) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inactive)
		return
	}

	// Check expiry.
	if time.Now().Unix() > verified.ExpiresAt {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inactive)
		return
	}

	resp := IntrospectResponse{
		Active:    true,
		Sub:       verified.Subject,
		ClientID:  verified.Audience, // audience is the client_id for access tokens
		IssuedAt:  verified.IssuedAt,
		ExpiresAt: verified.ExpiresAt,
		Issuer:    verified.Issuer,
		TokenType: "Bearer",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
