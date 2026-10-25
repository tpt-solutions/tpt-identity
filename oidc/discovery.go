package oidc

import (
	"encoding/json"
	"net/http"
)

// DiscoveryDocument is the OIDC Provider Configuration per RFC 8414.
type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	// RFC 9126: Pushed Authorization Requests
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests bool   `json:"require_pushed_authorization_requests,omitempty"`
	// RFC 8628: Device Authorization Grant
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`
	// RP-Initiated Logout 1.0
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`
	// RFC 9470: Step-Up Authentication
	StepUpAuthenticationEndpoint      string   `json:"stepup_authentication_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ACRValuesSupported                []string `json:"acr_values_supported,omitempty"`
	BackchannelLogoutSupported        bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported bool     `json:"backchannel_logout_session_supported"`
	// RFC 8693: Token Exchange
	TokenExchangeSupported bool `json:"token_exchange_supported,omitempty"`
	// OID4VCI
	CredentialIssuerMetadataEndpoint string `json:"credential_issuer_metadata_endpoint,omitempty"`
	// RFC 7636 (PKCE): S256 is the only method accepted.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	// OIDC Core: the authorization response is returned as query parameters.
	ResponseModesSupported []string `json:"response_modes_supported"`
	// RFC 7662 and RFC 7009: the callers that may introspect or revoke authenticate as confidential clients.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	// OIDC Core and RFC 9126: request objects (JAR) are not accepted; request_uri (PAR) is.
	RequestParameterSupported    bool `json:"request_parameter_supported"`
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
	ClaimsParameterSupported     bool `json:"claims_parameter_supported"`
}

// DiscoveryHandler returns an HTTP handler serving the OIDC discovery document.
func (p *Provider) DiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	doc := DiscoveryDocument{
		Issuer:                p.issuer,
		AuthorizationEndpoint: p.issuer + "/authorize",
		TokenEndpoint:         p.issuer + "/token",
		UserinfoEndpoint:      p.issuer + "/userinfo",
		JwksURI:               p.issuer + "/.well-known/jwks.json",
		RegistrationEndpoint:  p.issuer + "/oidc/register",
		IntrospectionEndpoint: p.issuer + "/oauth/introspect",
		RevocationEndpoint:    p.issuer + "/oidc/revoke",
		// New protocol endpoints
		PushedAuthorizationRequestEndpoint: p.issuer + "/oidc/par",
		DeviceAuthorizationEndpoint:        p.issuer + "/device_authorization",
		EndSessionEndpoint:                 p.issuer + "/oidc/logout",
		StepUpAuthenticationEndpoint:       p.issuer + "/oidc/stepup",
		CredentialIssuerMetadataEndpoint:   p.issuer + "/.well-known/openid-credential-issuer",
		ResponseTypesSupported:             []string{"code"},
		SubjectTypesSupported:              []string{"public"},
		IDTokenSigningAlgValuesSupported:   []string{"EdDSA"},
		ScopesSupported:                    []string{"openid", "profile", "did"},
		TokenEndpointAuthMethodsSupported:  []string{"client_secret_basic", "client_secret_post", "none", "private_key_jwt"},
		ClaimsSupported:                    []string{"sub", "iss", "iat", "exp", "nonce", "did", "amr", "acr"},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		},
		ACRValuesSupported:                        []string{"social", "pwd", "mfa"},
		BackchannelLogoutSupported:                true,
		BackchannelLogoutSessionSupported:         false,
		TokenExchangeSupported:                    true,
		CodeChallengeMethodsSupported:             []string{"S256"},
		ResponseModesSupported:                    []string{"query"},
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		RevocationEndpointAuthMethodsSupported:    []string{"client_secret_basic", "client_secret_post", "none"},
		RequestURIParameterSupported:              true,
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
