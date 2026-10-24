// Package providers contains bridge provider implementations.
package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	"github.com/tpt-solutions/tpt-identity/oidc"
)

// OIDCRPConfig configures an upstream OIDC/OAuth2 provider.
type OIDCRPConfig struct {
	// Name is the provider identifier, e.g. "google", "github", "azure-ad".
	Name string
	// Issuer is the upstream OIDC issuer URL (used for discovery).
	Issuer string
	// ClientID and ClientSecret are this platform's OAuth2 client credentials at the upstream.
	ClientID     string
	ClientSecret string
	// Scopes to request (defaults to ["openid", "email", "profile"]).
	Scopes []string
	// RedirectBaseURL is the base URL of this platform, used to build callback URLs.
	RedirectBaseURL string
}

// OIDCRPBridge implements bridge.Bridge for an upstream OIDC/OAuth2 provider.
type OIDCRPBridge struct {
	cfg          OIDCRPConfig
	mu           sync.RWMutex
	discovered   *oidcDiscovery
	discoveredAt time.Time
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// NewOIDCRP creates an OIDC relying-party bridge provider.
func NewOIDCRP(cfg OIDCRPConfig) *OIDCRPBridge {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	return &OIDCRPBridge{cfg: cfg}
}

func (b *OIDCRPBridge) Name() string { return b.cfg.Name }

// Authenticate is not used directly for OIDC RP — the bridge HTTP handlers call
// StartFlow and HandleCallback instead. This satisfies the Bridge interface.
func (b *OIDCRPBridge) Authenticate(ctx context.Context, r *http.Request) (*bridge.ExternalIdentity, error) {
	return nil, errors.New("oidc_rp: use HandleCallback instead")
}

// AuthorizationURL returns the upstream authorization URL to redirect the user to.
// state is a signed value set by the bridge HTTP handler.
func (b *OIDCRPBridge) AuthorizationURL(ctx context.Context, state string) (string, error) {
	disc, err := b.discover(ctx)
	if err != nil {
		return "", err
	}
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {b.cfg.ClientID},
		"redirect_uri":  {b.callbackURL()},
		"scope":         {strings.Join(b.cfg.Scopes, " ")},
		"state":         {state},
		"nonce":         {upstreamNonce(state)},
	}
	return disc.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// ExchangeCode exchanges the authorization code for an upstream id_token and returns
// the normalized ExternalIdentity.
func (b *OIDCRPBridge) ExchangeCode(ctx context.Context, code, state string) (*bridge.ExternalIdentity, error) {
	disc, err := b.discover(ctx)
	if err != nil {
		return nil, err
	}

	// Exchange code for tokens.
	resp, err := upstreamClient.PostForm(disc.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {b.callbackURL()},
		"client_id":     {b.cfg.ClientID},
		"client_secret": {b.cfg.ClientSecret},
	})
	if err != nil {
		return nil, fmt.Errorf("oidc_rp: token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc_rp: token endpoint returned %d", resp.StatusCode)
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("oidc_rp: decode token response: %w", err)
	}
	if tokenResp.IDToken == "" {
		return nil, errors.New("oidc_rp: no id_token in response")
	}

	// Verify the upstream id_token.
	return b.verifyIDToken(ctx, disc, tokenResp.IDToken, upstreamNonce(state))
}

func (b *OIDCRPBridge) verifyIDToken(ctx context.Context, disc *oidcDiscovery, idToken, expectedNonce string) (*bridge.ExternalIdentity, error) {
	// Parse header to find the key ID.
	header, err := oidc.ParseHeader(idToken)
	if err != nil {
		return nil, fmt.Errorf("oidc_rp: parse token header: %w", err)
	}
	kid := header["kid"]
	alg := header["alg"]

	// Fetch upstream JWKS.
	keys, err := b.fetchJWKS(ctx, disc.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("oidc_rp: fetch jwks: %w", err)
	}

	// Find matching key.
	var pubKey crypto.PublicKey
	for _, k := range keys {
		if kid == "" || k.Kid == kid {
			pk, err := jwkToPublicKey(k)
			if err != nil {
				continue
			}
			pubKey = pk
			break
		}
	}
	if pubKey == nil {
		return nil, fmt.Errorf("oidc_rp: no matching key for kid=%q alg=%q", kid, alg)
	}

	// Verify signature using the appropriate algorithm.
	if err := verifyJWTSignature(idToken, pubKey); err != nil {
		return nil, fmt.Errorf("oidc_rp: verify signature: %w", err)
	}

	// The signature is verified above. Claims are read from the raw payload so an array-valued
	// aud is handled and every check below sees the same values.
	var raw map[string]any
	if err := parseRawClaims(idToken, &raw); err != nil {
		return nil, fmt.Errorf("oidc_rp: parse claims: %w", err)
	}
	iss, _ := raw["iss"].(string)
	sub, _ := raw["sub"].(string)
	exp, _ := raw["exp"].(float64)
	if int64(exp) < time.Now().Unix() {
		return nil, errors.New("oidc_rp: id_token expired")
	}
	if strings.TrimRight(iss, "/") != strings.TrimRight(b.cfg.Issuer, "/") {
		return nil, errors.New("oidc_rp: id_token iss does not match the configured issuer")
	}
	if !audienceIncludes(raw["aud"], b.cfg.ClientID) {
		return nil, errors.New("oidc_rp: id_token aud does not include this client")
	}
	nonce, _ := raw["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return nil, errors.New("oidc_rp: id_token nonce does not match this login")
	}
	if sub == "" {
		return nil, errors.New("oidc_rp: missing sub claim")
	}

	ext := &bridge.ExternalIdentity{
		Provider:   b.cfg.Name,
		ExternalID: sub, // stable — never use email as ExternalID
		Claims:     map[string]string{"iss": iss},
	}
	for _, field := range []string{"email", "given_name", "family_name", "name", "picture"} {
		if v, ok := raw[field].(string); ok {
			ext.Claims[field] = v
		}
	}
	// Consumers that trust an email address (bootstrap credentials) must check this flag.
	ext.Claims["email_verified"] = strconv.FormatBool(emailVerified(raw["email_verified"]))
	return ext, nil
}

// upstreamClient bounds every call to an upstream provider, so a slow or hostile IdP cannot pin
// a login request open.
var upstreamClient = &http.Client{Timeout: 10 * time.Second}

// upstreamNonce derives the nonce sent to the upstream provider from the signed bridge state.
// The value is bound to the login that started the flow, so an id_token minted for another
// login is refused.
func upstreamNonce(state string) string {
	sum := sha256.Sum256([]byte("tpt-identity-nonce:" + state))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// audienceIncludes reports whether an aud claim (a string or an array of strings) names clientID.
func audienceIncludes(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// emailVerified reads the email_verified claim, which some providers send as a string.
func emailVerified(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}

func (b *OIDCRPBridge) callbackURL() string {
	return strings.TrimRight(b.cfg.RedirectBaseURL, "/") + "/auth/" + b.cfg.Name + "/callback"
}

func (b *OIDCRPBridge) discover(ctx context.Context) (*oidcDiscovery, error) {
	b.mu.RLock()
	if b.discovered != nil && time.Since(b.discoveredAt) < time.Hour {
		d := b.discovered
		b.mu.RUnlock()
		return d, nil
	}
	b.mu.RUnlock()

	discURL := strings.TrimRight(b.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	resp, err := upstreamClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc_rp: discovery fetch: %w", err)
	}
	defer resp.Body.Close()
	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("oidc_rp: discovery decode: %w", err)
	}

	b.mu.Lock()
	b.discovered = &disc
	b.discoveredAt = time.Now()
	b.mu.Unlock()
	return &disc, nil
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (b *OIDCRPBridge) fetchJWKS(ctx context.Context, uri string) ([]jwkKey, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	resp, err := upstreamClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ks struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ks); err != nil {
		return nil, err
	}
	return ks.Keys, nil
}

func jwkToPublicKey(k jwkKey) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil

	case "EC":
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil

	case "OKP":
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		if len(xb) != ed25519.PublicKeySize {
			return nil, errors.New("oidc_rp: Ed25519 jwk x is not 32 bytes")
		}
		return ed25519.PublicKey(xb), nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

func verifyJWTSignature(token string, pub crypto.PublicKey) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return errors.New("malformed jwt")
	}
	sigInput := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	// Get algorithm from header.
	headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]string
	if err := json.Unmarshal(headerRaw, &h); err != nil {
		return err
	}
	alg := h["alg"]

	switch pk := pub.(type) {
	case *rsa.PublicKey:
		return verifyRSA(pk, alg, sigInput, sig)
	case *ecdsa.PublicKey:
		return verifyECDSA(pk, alg, sigInput, sig)
	case ed25519.PublicKey:
		if !ed25519.Verify(pk, sigInput, sig) {
			return errors.New("invalid ed25519 signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %T", pub)
	}
}

func verifyRSA(pub *rsa.PublicKey, alg string, msg, sig []byte) error {
	var hash crypto.Hash
	switch alg {
	case "RS256", "PS256":
		hash = crypto.SHA256
	case "RS384", "PS384":
		hash = crypto.SHA384
	case "RS512", "PS512":
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA alg: %s", alg)
	}
	h := hash.New()
	h.Write(msg)
	digest := h.Sum(nil)

	if strings.HasPrefix(alg, "PS") {
		return rsa.VerifyPSS(pub, hash, digest, sig, nil)
	}
	return rsa.VerifyPKCS1v15(pub, hash, digest, sig)
}

func verifyECDSA(pub *ecdsa.PublicKey, alg string, msg, sig []byte) error {
	var hash crypto.Hash
	switch alg {
	case "ES256":
		hash = crypto.SHA256
	case "ES384":
		hash = crypto.SHA384
	case "ES512":
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported ECDSA alg: %s", alg)
	}
	h := hash.New()
	h.Write(msg)
	digest := h.Sum(nil)

	// DER or raw R||S format.
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) == 2*keySize {
		r := new(big.Int).SetBytes(sig[:keySize])
		s := new(big.Int).SetBytes(sig[keySize:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errors.New("invalid ecdsa signature")
		}
		return nil
	}
	// Try DER.
	r, s, err := parseDERSignature(sig)
	if err != nil {
		return fmt.Errorf("parse ecdsa sig: %w", err)
	}
	if !ecdsa.Verify(pub, digest, r, s) {
		return errors.New("invalid ecdsa signature")
	}
	return nil
}

func parseDERSignature(der []byte) (*big.Int, *big.Int, error) {
	if len(der) < 2 || der[0] != 0x30 {
		return nil, nil, errors.New("not a DER sequence")
	}
	// Minimal DER integer parser.
	inner := der[2:]
	if len(inner) < 2 || inner[0] != 0x02 {
		return nil, nil, errors.New("expected integer")
	}
	rLen := int(inner[1])
	r := new(big.Int).SetBytes(inner[2 : 2+rLen])
	inner = inner[2+rLen:]
	if len(inner) < 2 || inner[0] != 0x02 {
		return nil, nil, errors.New("expected second integer")
	}
	sLen := int(inner[1])
	s := new(big.Int).SetBytes(inner[2 : 2+sLen])
	return r, s, nil
}

func parseRawClaims(token string, out any) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return errors.New("malformed jwt")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
