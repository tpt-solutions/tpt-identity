package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
)

// WebFingerHandler implements RFC 7033 WebFinger at GET /.well-known/webfinger.
//
// Clients query with resource=acct:user@domain or resource=https://issuer to
// discover the OIDC issuer endpoint. This is required for OIDC discovery via
// email and for federation scenarios.
//
// Example request:
//
//	GET /.well-known/webfinger?resource=acct:alice@example.com&rel=http://openid.net/specs/connect/1.0/issuer
func (p *Provider) WebFingerHandler(w http.ResponseWriter, r *http.Request) {
	resource := r.URL.Query().Get("resource")
	if resource == "" {
		http.Error(w, "resource parameter required", http.StatusBadRequest)
		return
	}

	// Accept both acct: and https: resource URIs.
	var host string
	switch {
	case strings.HasPrefix(resource, "acct:"):
		// acct:user@host — extract host part.
		parts := strings.SplitN(strings.TrimPrefix(resource, "acct:"), "@", 2)
		if len(parts) != 2 {
			http.Error(w, "invalid acct resource", http.StatusBadRequest)
			return
		}
		host = parts[1]
	case strings.HasPrefix(resource, "https://") || strings.HasPrefix(resource, "http://"):
		// Validate that the resource matches this issuer.
		if !strings.HasPrefix(resource, p.issuer) {
			writeError(w, "invalid_request", "resource does not match this issuer")
			return
		}
		host = strings.TrimPrefix(strings.TrimPrefix(resource, "https://"), "http://")
		if idx := strings.IndexByte(host, '/'); idx >= 0 {
			host = host[:idx]
		}
	default:
		http.Error(w, "unsupported resource URI scheme", http.StatusBadRequest)
		return
	}

	// Confirm the host matches our issuer domain.
	issuerHost := strings.TrimPrefix(strings.TrimPrefix(p.issuer, "https://"), "http://")
	if idx := strings.IndexByte(issuerHost, '/'); idx >= 0 {
		issuerHost = issuerHost[:idx]
	}
	if !strings.EqualFold(host, issuerHost) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	resp := map[string]any{
		"subject": resource,
		"links": []map[string]string{
			{
				"rel":  "http://openid.net/specs/connect/1.0/issuer",
				"href": p.issuer,
			},
		},
	}

	w.Header().Set("Content-Type", "application/jrd+json")
	w.Header().Set("Access-Control-Allow-Origin", "*") // WebFinger must be CORS-open
	_ = json.NewEncoder(w).Encode(resp)
}
