// ACC (Accident Compensation Corporation) OAuth2 bridge.
//
// Registration: https://developer.acc.co.nz
// ACC uses standard OAuth 2.0 authorization code flow.
// The stable user identifier is the ACC client number extracted from the access token.

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
)

// ACCConfig configures the ACC OAuth2 bridge.
type ACCConfig struct {
	// OAuth2 endpoints — register at https://developer.acc.co.nz.
	// UAT:        https://api-uat.acc.co.nz/oauth2/v1/authorize
	// Production: https://api.acc.co.nz/oauth2/v1/authorize
	AuthEndpoint  string
	TokenEndpoint string

	// UserInfoEndpoint is optional. If set, user claims are fetched from here after
	// token exchange. If empty, claims are parsed from the JWT access token.
	UserInfoEndpoint string

	// OAuth2 client credentials.
	ClientID        string
	ClientSecret    string
	RedirectBaseURL string

	// Scopes to request. Defaults to ["openid", "profile"].
	// Add "acc:claims.read" for injury claim access if your app is registered for it.
	Scopes []string
}

// ACCBridge authenticates NZ residents via the ACC (Accident Compensation Corporation) API.
// The stable external identifier is the ACC client number (sub claim in the access token).
type ACCBridge struct {
	cfg ACCConfig
}

// NewACC creates an ACC bridge.
func NewACC(cfg ACCConfig) (*ACCBridge, error) {
	if cfg.AuthEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, errors.New("acc: AuthEndpoint and TokenEndpoint are required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile"}
	}
	return &ACCBridge{cfg: cfg}, nil
}

func (b *ACCBridge) Name() string { return "acc" }

func (b *ACCBridge) Authenticate(ctx context.Context, r *http.Request) (*bridge.ExternalIdentity, error) {
	return nil, errors.New("acc: use RedirectBridge methods (AuthorizationURL / ExchangeCode)")
}

// AuthorizationURL returns the ACC OAuth2 authorization redirect URL.
func (b *ACCBridge) AuthorizationURL(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {b.cfg.ClientID},
		"redirect_uri":  {b.callbackURL()},
		"scope":         {strings.Join(b.cfg.Scopes, " ")},
		"state":         {state},
	}
	return b.cfg.AuthEndpoint + "?" + params.Encode(), nil
}

// ExchangeCode exchanges the authorization code for an ACC access token and
// returns the normalized ExternalIdentity.
func (b *ACCBridge) ExchangeCode(ctx context.Context, code, _ string) (*bridge.ExternalIdentity, error) {
	resp, err := http.PostForm(b.cfg.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {b.callbackURL()},
		"client_id":     {b.cfg.ClientID},
		"client_secret": {b.cfg.ClientSecret},
	})
	if err != nil {
		return nil, fmt.Errorf("acc: token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acc: token endpoint returned HTTP %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("acc: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("acc: no access_token in response")
	}

	// Prefer dedicated userinfo endpoint when available.
	if b.cfg.UserInfoEndpoint != "" {
		return b.fetchUserInfo(ctx, tok.AccessToken)
	}

	// Fall back to parsing claims from the id_token (preferred) or access token.
	jwtToken := tok.IDToken
	if jwtToken == "" {
		jwtToken = tok.AccessToken
	}
	return b.parseTokenClaims(jwtToken)
}

func (b *ACCBridge) fetchUserInfo(ctx context.Context, accessToken string) (*bridge.ExternalIdentity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.cfg.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("acc: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acc: userinfo request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acc: userinfo returned HTTP %d", resp.StatusCode)
	}

	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("acc: decode userinfo: %w", err)
	}
	return b.mapClaims(info)
}

func (b *ACCBridge) parseTokenClaims(token string) (*bridge.ExternalIdentity, error) {
	var raw map[string]any
	// parseRawClaims is defined in oidc_rp.go (same package).
	if err := parseRawClaims(token, &raw); err != nil {
		return nil, fmt.Errorf("acc: parse token claims: %w", err)
	}
	if exp, ok := raw["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
		return nil, errors.New("acc: token expired")
	}
	return b.mapClaims(raw)
}

func (b *ACCBridge) mapClaims(raw map[string]any) (*bridge.ExternalIdentity, error) {
	sub, _ := raw["sub"].(string)
	if sub == "" {
		return nil, errors.New("acc: missing sub claim — cannot establish stable identifier")
	}

	claims := map[string]string{}
	for _, field := range []string{"email", "given_name", "family_name", "name"} {
		if v, ok := raw[field].(string); ok && v != "" {
			claims[field] = v
		}
	}
	// ACC-specific claims (present when acc:claims.read scope is granted).
	if v, ok := raw["acc_client_number"].(string); ok && v != "" {
		claims["acc_client_number"] = v
	}
	// Some ACC tokens use "clientNumber" as the claim name.
	if v, ok := raw["clientNumber"].(string); ok && v != "" && claims["acc_client_number"] == "" {
		claims["acc_client_number"] = v
	}

	return &bridge.ExternalIdentity{
		Provider:   "acc",
		ExternalID: sub,
		Claims:     claims,
	}, nil
}

func (b *ACCBridge) callbackURL() string {
	return strings.TrimRight(b.cfg.RedirectBaseURL, "/") + "/auth/acc/callback"
}
