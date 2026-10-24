package oidc

import (
	"time"
)

// MintAccessToken issues an access token for subjectDID with the configured access-token lifetime.
// Non-OIDC sign-in paths (passkeys) use it to start a session. The token is checked exactly like
// one from the token endpoint, so suspended identities lose access immediately.
func (p *Provider) MintAccessToken(subjectDID, audience string) (string, time.Duration, error) {
	token, err := IssueAccessToken(p.issuer, subjectDID, audience, p.ttl.Access, p.signingKey, p.keyID)
	if err != nil {
		return "", 0, err
	}
	return token, p.ttl.Access, nil
}
