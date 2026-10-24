package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PhillipC05/tpt-identity/internal/netguard"
)

// SendBackChannelLogout delivers a signed logout_token to the client's
// backchannel_logout_uri (OIDC Back-Channel Logout 1.0).
// Returns nil when the client has no back-channel URI configured.
func (p *Provider) SendBackChannelLogout(ctx context.Context, clientID, subjectDID string) error {
	client, err := p.store.GetClient(ctx, clientID)
	if err != nil || client.BackchannelLogoutURI == "" {
		return nil
	}

	jti, err := randomHex(16)
	if err != nil {
		return fmt.Errorf("backchannel: generate jti: %w", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss": p.issuer,
		"sub": subjectDID,
		"aud": clientID,
		"iat": now.Unix(),
		"jti": jti,
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}

	logoutToken, err := signJWT(claims, p.signingKey, p.keyID)
	if err != nil {
		return fmt.Errorf("backchannel: sign logout token: %w", err)
	}

	formBody := url.Values{"logout_token": {logoutToken}}.Encode()
	hc := netguard.Client(5 * time.Second)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost,
			client.BackchannelLogoutURI, strings.NewReader(formBody))
		if reqErr != nil {
			return fmt.Errorf("backchannel: build request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, doErr := hc.Do(req)
		if doErr != nil {
			lastErr = doErr
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("backchannel: server returned HTTP %d", resp.StatusCode)
	}
	return lastErr
}
