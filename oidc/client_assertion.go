package oidc

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

const (
	// clientAssertionType is the assertion type RFC 7523 §2.2 and OIDC Core §9 require.
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// maxAssertionLifetime bounds exp - now. A long-lived assertion is a long-lived credential.
	maxAssertionLifetime = 5 * time.Minute
)

// verifyClientAssertion authenticates a private_key_jwt client (RFC 7523 §3, OIDC Core §9).
//
// The assertion is an EdDSA JWS signed with one of the client's registered keys. It must name the client
// as iss and sub, and the issuer or the token endpoint as aud. It must expire within maxAssertionLifetime,
// and its jti is recorded so the same assertion cannot be used twice.
func (p *Provider) verifyClientAssertion(ctx context.Context, r *http.Request, client *store.OIDCClient) error {
	if r.FormValue("client_assertion_type") != clientAssertionType {
		return errors.New("client_assertion_type must be the JWT bearer assertion type")
	}
	assertion := r.FormValue("client_assertion")
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return errors.New("client_assertion is not a compact JWS")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("client_assertion header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("client_assertion header: %w", err)
	}
	if header.Alg != "EdDSA" {
		return fmt.Errorf("client_assertion alg %q is not EdDSA", header.Alg)
	}

	pub, err := clientKey(client.JWKS, header.KID)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("client_assertion signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("client_assertion signature invalid")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("client_assertion payload: %w", err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("client_assertion claims: %w", err)
	}
	if claims.Iss != client.ClientID || claims.Sub != client.ClientID {
		return errors.New("client_assertion iss and sub must both be the client_id")
	}
	if claims.Aud != p.issuer && claims.Aud != p.issuer+"/token" {
		return errors.New("client_assertion aud must name this issuer or its token endpoint")
	}
	now := time.Now()
	if claims.Exp == 0 {
		return errors.New("client_assertion has no exp claim")
	}
	expires := time.Unix(claims.Exp, 0)
	if !now.Before(expires) {
		return errors.New("client_assertion has expired")
	}
	if expires.Sub(now) > maxAssertionLifetime {
		return fmt.Errorf("client_assertion lives longer than %s", maxAssertionLifetime)
	}
	if claims.JTI == "" {
		return errors.New("client_assertion has no jti claim")
	}

	// The seen-message table is keyed by sender, so assertion ids get their own sender name.
	if err := p.store.RecordDIDCommMessage(ctx, "client_assertion:"+client.ClientID, claims.JTI, expires); err != nil {
		if errors.Is(err, store.ErrDIDCommReplay) {
			return errors.New("client_assertion has already been used")
		}
		return fmt.Errorf("client_assertion: record jti: %w", err)
	}
	return nil
}

// clientKey returns the Ed25519 key in a stored client key set that the assertion names by kid. With no
// kid, the set must hold exactly one key.
func clientKey(jwks, kid string) (ed25519.PublicKey, error) {
	var set struct {
		Keys []clientJWK `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &set); err != nil {
		return nil, fmt.Errorf("client has no usable key set: %w", err)
	}
	var match *clientJWK
	for i := range set.Keys {
		k := &set.Keys[i]
		switch {
		case kid != "" && k.KID == kid:
			match = k
		case kid == "" && len(set.Keys) == 1:
			match = k
		}
	}
	if match == nil {
		return nil, errors.New("client_assertion names no registered key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(match.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("client key is not a valid Ed25519 key")
	}
	return ed25519.PublicKey(raw), nil
}
