// The relying party's protocol flow. It is written against the platform's public endpoints only:
//
//  1. Create a PKCE verifier, a state and a nonce.
//  2. Sign the user in at /auth/password. The platform answers with a redirect that carries an
//     authorization code. The redirect is read, not followed.
//  3. Exchange the code at /token. The client authenticates with private_key_jwt: an Ed25519 JWS signed
//     with the client's registered key.
//  4. Verify the ID token against /.well-known/jwks.json: signature, iss, aud, nonce, exp and token_type.
//  5. Read /userinfo with the access token.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// maxBody bounds every response the RP reads from the platform.
	maxBody = 1 << 20
)

// RP is one relying party registered with the platform as a private_key_jwt client.
type RP struct {
	Issuer      string // the platform base URL, without a trailing slash
	ClientID    string
	RedirectURI string
	Key         ed25519.PrivateKey // the client's registered signing key
	KeyID       string             // the kid the registered JWKS lists for Key
	HTTP        *http.Client
}

// Flow holds the values one sign-in needs, generated fresh for each attempt.
type Flow struct {
	Verifier  string // PKCE code_verifier
	Challenge string // PKCE code_challenge (S256)
	State     string
	Nonce     string
}

// Result is what a successful sign-in produces.
type Result struct {
	Subject  string         // the subject DID (the id token's sub)
	IDClaims IDClaims       // the verified id token claims
	UserInfo map[string]any // the /userinfo response
}

// IDClaims are the id token claims the RP checks.
type IDClaims struct {
	Iss       string `json:"iss"`
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	Nonce     string `json:"nonce"`
	Exp       int64  `json:"exp"`
	DID       string `json:"did"`
	TokenType string `json:"token_type"`
}

// TokenResponse is the /token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// NewFlow creates a PKCE verifier, the matching S256 challenge, a state and a nonce.
func NewFlow() (Flow, error) {
	verifier, err := randomURLSafe(32)
	if err != nil {
		return Flow{}, err
	}
	state, err := randomURLSafe(16)
	if err != nil {
		return Flow{}, err
	}
	nonce, err := randomURLSafe(16)
	if err != nil {
		return Flow{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	return Flow{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		State:     state,
		Nonce:     nonce,
	}, nil
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Run performs the whole sign-in for one user and returns the verified result.
//
// The password is sent to the platform and never stored or logged by the RP. This RP takes the password
// itself because the platform has no hosted login page yet. A production RP would redirect the user's
// browser to the platform instead.
func (rp *RP) Run(ctx context.Context, identifier, password string) (*Result, error) {
	flow, err := NewFlow()
	if err != nil {
		return nil, err
	}
	code, err := rp.Login(ctx, flow, identifier, password)
	if err != nil {
		return nil, err
	}
	tokens, err := rp.Exchange(ctx, code, flow.Verifier)
	if err != nil {
		return nil, err
	}
	claims, err := rp.VerifyIDToken(ctx, tokens.IDToken, flow.Nonce)
	if err != nil {
		return nil, err
	}
	info, err := rp.Userinfo(ctx, tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	return &Result{Subject: claims.Sub, IDClaims: claims, UserInfo: info}, nil
}

// Login signs the user in and returns the authorization code from the platform's redirect.
func (rp *RP) Login(ctx context.Context, flow Flow, identifier, password string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"identifier":            identifier,
		"password":              password,
		"client_id":             rp.ClientID,
		"redirect_uri":          rp.RedirectURI,
		"scope":                 "openid",
		"nonce":                 flow.Nonce,
		"state":                 flow.State,
		"code_challenge":        flow.Challenge,
		"code_challenge_method": "S256",
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rp.Issuer+"/auth/password", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rp.noRedirect().Do(req)
	if err != nil {
		return "", fmt.Errorf("sign in: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("sign in refused: HTTP %d", resp.StatusCode)
	}

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("sign in redirect: %w", err)
	}
	if !strings.HasPrefix(loc.String(), rp.RedirectURI) {
		return "", errors.New("sign in redirected somewhere other than the registered redirect URI")
	}
	q := loc.Query()
	if q.Get("state") != flow.State {
		return "", errors.New("state does not match: the redirect is not for this sign-in")
	}
	code := q.Get("code")
	if code == "" {
		return "", errors.New("sign in redirect carried no authorization code")
	}
	return code, nil
}

// Exchange trades the authorization code for tokens, authenticating with a signed client assertion.
func (rp *RP) Exchange(ctx context.Context, code, verifier string) (*TokenResponse, error) {
	assertion, err := rp.clientAssertion()
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {rp.RedirectURI},
		"code_verifier":         {verifier},
		"client_id":             {rp.ClientID},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
	}
	var tokens TokenResponse
	if err := rp.postForm(ctx, rp.Issuer+"/token", form, &tokens); err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	if tokens.IDToken == "" || tokens.AccessToken == "" {
		return nil, errors.New("token response is missing the id or access token")
	}
	return &tokens, nil
}

// VerifyIDToken checks an ID token's EdDSA signature against the platform's published keys, then its
// claims: iss is the platform, aud is this client, nonce is the one sent, exp is in the future, and the
// token is an ID token and not an access token.
func (rp *RP) VerifyIDToken(ctx context.Context, idToken, nonce string) (IDClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return IDClaims{}, errors.New("id token is not a compact JWS")
	}
	header, err := decodeSegment(parts[0])
	if err != nil {
		return IDClaims{}, fmt.Errorf("id token header: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return IDClaims{}, fmt.Errorf("id token header: %w", err)
	}
	if h.Alg != "EdDSA" {
		return IDClaims{}, fmt.Errorf("id token alg %q is not EdDSA", h.Alg)
	}

	key, err := rp.platformKey(ctx, h.KID)
	if err != nil {
		return IDClaims{}, err
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return IDClaims{}, fmt.Errorf("id token signature: %w", err)
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return IDClaims{}, errors.New("id token signature is invalid")
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return IDClaims{}, fmt.Errorf("id token payload: %w", err)
	}
	var c IDClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return IDClaims{}, fmt.Errorf("id token claims: %w", err)
	}
	switch {
	case c.TokenType != "id":
		return IDClaims{}, errors.New("token is not an ID token")
	case c.Iss != rp.Issuer:
		return IDClaims{}, errors.New("id token iss is not the platform")
	case c.Aud != rp.ClientID:
		return IDClaims{}, errors.New("id token aud is not this client")
	case c.Nonce != nonce:
		return IDClaims{}, errors.New("id token nonce does not match the request (replay?)")
	case time.Now().Unix() >= c.Exp:
		return IDClaims{}, errors.New("id token has expired")
	}
	return c, nil
}

// Userinfo reads /userinfo with the access token.
func (rp *RP) Userinfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rp.Issuer+"/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	var info map[string]any
	if err := rp.doJSON(req, &info); err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	return info, nil
}

// clientAssertion signs the private_key_jwt assertion (RFC 7523) that authenticates this client at /token.
func (rp *RP) clientAssertion() (string, error) {
	jti, err := randomURLSafe(16)
	if err != nil {
		return "", err
	}
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": rp.KeyID})
	payload, err := json.Marshal(map[string]any{
		"iss": rp.ClientID,
		"sub": rp.ClientID,
		"aud": rp.Issuer + "/token",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": jti,
	})
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(rp.Key, []byte(signing))), nil
}

// platformKey fetches the platform's published Ed25519 key with the given kid.
func (rp *RP) platformKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rp.Issuer+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			KTY string `json:"kty"`
			CRV string `json:"crv"`
			X   string `json:"x"`
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := rp.doJSON(req, &set); err != nil {
		return nil, fmt.Errorf("fetch platform keys: %w", err)
	}
	for _, k := range set.Keys {
		if k.KID != kid {
			continue
		}
		if k.KTY != "OKP" || k.CRV != "Ed25519" {
			return nil, fmt.Errorf("platform key %q is not Ed25519", kid)
		}
		raw, err := decodeSegment(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("platform key %q is malformed", kid)
		}
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("platform publishes no key %q", kid)
}

func (rp *RP) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return rp.doJSON(req, out)
}

// doJSON sends req and decodes a 2xx JSON body into out. Error bodies are returned in the error, bounded.
func (rp *RP) doJSON(req *http.Request, out any) error {
	resp, err := rp.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, out)
}

func (rp *RP) client() *http.Client {
	if rp.HTTP != nil {
		return rp.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// noRedirect returns a client that does not follow redirects, so the authorization redirect can be read.
func (rp *RP) noRedirect() *http.Client {
	c := *rp.client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
