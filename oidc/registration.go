package oidc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/netguard"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// maxRegistrationBody caps the registration request body.
const maxRegistrationBody = 64 << 10 // 64 KiB

var (
	allowedAuthMethods   = []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"}
	allowedGrantTypes    = []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"}
	allowedResponseTypes = []string{"code"}
)

// RegisterClientRequest is the RFC 7591 client registration request body.
type RegisterClientRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	// JWKS is the client's public key set, required for private_key_jwt and refused otherwise.
	JWKS json.RawMessage `json:"jwks,omitempty"`
}

// clientJWK is one Ed25519 public key a client may sign its assertions with (RFC 8037 OKP).
type clientJWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	KID string `json:"kid,omitempty"`
}

// canonicalClientJWKS checks a client's key set and returns it in canonical form for storage. Only
// Ed25519 keys are accepted, because assertions are verified with EdDSA alone, and kids must be unique.
func canonicalClientJWKS(raw json.RawMessage) (string, error) {
	var set struct {
		Keys []clientJWK `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return "", fmt.Errorf("jwks: %w", err)
	}
	if len(set.Keys) == 0 {
		return "", errors.New("jwks: at least one key is required")
	}
	kids := map[string]bool{}
	for i, k := range set.Keys {
		if k.KTY != "OKP" || k.CRV != "Ed25519" {
			return "", fmt.Errorf("jwks: key %d must be an OKP Ed25519 key", i)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return "", fmt.Errorf("jwks: key %d has an invalid x value", i)
		}
		if k.KID != "" {
			if kids[k.KID] {
				return "", fmt.Errorf("jwks: kid %q appears twice", k.KID)
			}
			kids[k.KID] = true
		}
	}
	out, err := json.Marshal(set)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// RegisterClientResponse is the RFC 7591 client registration response.
type RegisterClientResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
}

// validateRedirectURI accepts https URLs, and http only for loopback hosts (RFC 8252 §7.3).
// Fragments and userinfo are not permitted.
func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("redirect URI %q must be an absolute URL", raw)
	}
	if u.Fragment != "" || u.User != nil {
		return fmt.Errorf("redirect URI %q must not contain a fragment or credentials", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("redirect URI %q must use https (http is allowed only for loopback)", raw)
}

// validateClientMetadata applies registration policy and returns the effective auth method,
// grant types and response types.
func validateClientMetadata(req *RegisterClientRequest) (authMethod string, grantTypes, responseTypes []string, err error) {
	if req.ClientName == "" {
		return "", nil, nil, errors.New("client_name required")
	}
	if len(req.RedirectURIs) == 0 {
		return "", nil, nil, errors.New("redirect_uris required")
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return "", nil, nil, err
		}
	}
	for _, u := range req.PostLogoutRedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return "", nil, nil, err
		}
	}

	authMethod = req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	if !slices.Contains(allowedAuthMethods, authMethod) {
		return "", nil, nil, fmt.Errorf("unsupported token_endpoint_auth_method %q", authMethod)
	}

	grantTypes = req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	for _, g := range grantTypes {
		if !slices.Contains(allowedGrantTypes, g) {
			return "", nil, nil, fmt.Errorf("unsupported grant_type %q", g)
		}
		// client_credentials issues tokens without a user; only confidential clients may use it.
		if g == "client_credentials" && authMethod == "none" {
			return "", nil, nil, errors.New("client_credentials requires a confidential client")
		}
	}

	responseTypes = req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	for _, rt := range responseTypes {
		if !slices.Contains(allowedResponseTypes, rt) {
			return "", nil, nil, fmt.Errorf("unsupported response_type %q", rt)
		}
	}

	if req.BackchannelLogoutURI != "" {
		if err := netguard.ValidateExternalURL(req.BackchannelLogoutURI); err != nil {
			return "", nil, nil, fmt.Errorf("backchannel_logout_uri: %w", err)
		}
	}
	return authMethod, grantTypes, responseTypes, nil
}

// RegisterClientHandler handles POST /oidc/register (RFC 7591).
// The route is operator-gated in the API server; see api/server.go.
func (p *Provider) RegisterClientHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterClientRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRegistrationBody)).Decode(&req); err != nil {
		writeError(w, "invalid_client_metadata", "invalid request body")
		return
	}
	authMethod, grantTypes, responseTypes, err := validateClientMetadata(&req)
	if err != nil {
		writeError(w, "invalid_client_metadata", err.Error())
		return
	}

	clientID, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var jwks string
	if authMethod == "private_key_jwt" {
		if len(req.JWKS) == 0 {
			writeError(w, "invalid_client_metadata", "private_key_jwt requires jwks")
			return
		}
		jwks, err = canonicalClientJWKS(req.JWKS)
		if err != nil {
			writeError(w, "invalid_client_metadata", err.Error())
			return
		}
	} else if len(req.JWKS) > 0 {
		writeError(w, "invalid_client_metadata", "jwks is only allowed with token_endpoint_auth_method private_key_jwt")
		return
	}

	var clientSecret string
	var secretHash string
	if authMethod == "client_secret_basic" || authMethod == "client_secret_post" {
		clientSecret, err = randomHex(32)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		secretHash = hashSecret(clientSecret)
	}

	client := &store.OIDCClient{
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scope:                   req.Scope,
		BackchannelLogoutURI:    req.BackchannelLogoutURI,
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		CreatedAt:               time.Now(),
		JWKS:                    jwks,
	}
	if err := p.store.SaveClient(r.Context(), client); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := RegisterClientResponse{
		ClientID:                clientID,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		BackchannelLogoutURI:    req.BackchannelLogoutURI,
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		ClientIDIssuedAt:        time.Now().Unix(),
	}
	if clientSecret != "" {
		resp.ClientSecret = clientSecret
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp) //nolint:gosec // G117: RFC 7591 requires returning the secret at registration
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
