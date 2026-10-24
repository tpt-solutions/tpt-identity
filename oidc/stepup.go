package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// StepUpHandler implements GET /oidc/stepup — a resource-server-initiated
// step-up authentication flow (RFC 9470 / OAuth 2.0 Step Up Authentication Challenge).
//
// When a resource server receives an access token whose `acr` claim is
// insufficient (e.g. needs "mfa" but token has "pwd"), it responds to the
// client with:
//
//	HTTP 401 WWW-Authenticate: Bearer error="insufficient_user_authentication"
//	  error_description="A different authentication level is required"
//	  acr_values="mfa"
//
// The client then calls this endpoint with the original access token and the
// required acr_values. If the current session satisfies the requirement, a new
// token with the elevated acr is issued. Otherwise a challenge is returned
// directing the user to re-authenticate via /authorize.
//
// Query params:
//   - access_token — the current bearer token (or via Authorization header)
//   - acr_values   — space-separated required ACR value(s)
//   - nonce        — optional replay protection
func (p *Provider) StepUpHandler(w http.ResponseWriter, r *http.Request) {
	bearer := r.URL.Query().Get("access_token")
	if bearer == "" {
		bearer = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if bearer == "" {
		writeError(w, "invalid_request", "access_token required")
		return
	}

	currentClaims, err := p.VerifyAccessToken(r.Context(), bearer)
	if err != nil {
		writeError(w, "invalid_token", "access_token invalid: "+err.Error())
		return
	}

	requiredACR := r.URL.Query().Get("acr_values")
	if requiredACR == "" {
		writeError(w, "invalid_request", "acr_values required")
		return
	}

	// Check if the current token already satisfies the ACR requirement.
	if acrSatisfies(currentClaims.ACR, requiredACR) {
		// Already satisfied — re-issue with an explicit acr claim.
		extra := map[string]any{
			"acr":   currentClaims.ACR,
			"scope": currentClaims.Scope,
		}
		token, err := issueJWTWithExtra(p.issuer, currentClaims.Subject, currentClaims.Audience, p.ttl.Access, p.signingKey, p.keyID, extra)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   int(p.ttl.Access.Seconds()),
			"acr":          currentClaims.ACR,
		})
		return
	}

	// Not satisfied — return a challenge directing the client to re-authenticate.
	// The client should redirect the user to /authorize with acr_values appended.
	nonce := r.URL.Query().Get("nonce")
	authorizeURL := p.issuer + "/authorize?response_type=code&acr_values=" + url.QueryEscape(requiredACR)
	if nonce != "" {
		authorizeURL += "&nonce=" + url.QueryEscape(nonce)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":             "insufficient_user_authentication",
		"error_description": "The current authentication level does not satisfy the required ACR: " + requiredACR,
		"acr_values":        requiredACR,
		"max_age":           0,
		"authorize_url":     authorizeURL,
	})
}

// acrSatisfies returns true if the token's current ACR satisfies the required value.
// The simple ordered hierarchy is: "mfa" > "pwd" > "social" > "".
func acrSatisfies(have, need string) bool {
	order := map[string]int{"mfa": 3, "pwd": 2, "social": 1, "": 0}
	haveLevel, needLevel := 0, 0
	for _, v := range strings.Fields(need) {
		if l, ok := order[v]; ok && l > needLevel {
			needLevel = l
		}
	}
	if l, ok := order[have]; ok {
		haveLevel = l
	}
	return haveLevel >= needLevel
}
