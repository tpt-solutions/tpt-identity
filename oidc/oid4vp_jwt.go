package oidc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	vcpkg "github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// verifyJWTVPToken checks a JWT-format presentation: a compact JWS, EdDSA-signed by the holder.
//
// The header's kid names the holder's verification method, and its DID must be the iss claim. The
// claims bind the presentation to the request: aud is the request's client_id, nonce is the request
// nonce, and exp is required and in the future. The vp claim holds JSON credentials, and each one must
// verify and name the holder as its subject, as on the JSON path.
func (h *OID4VPHandler) verifyJWTVPToken(token string, req *OID4VPRequest) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("vp_token must be a JSON presentation or a compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("vp_token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("vp_token header: %w", err)
	}
	if header.Alg != "EdDSA" {
		return fmt.Errorf("vp_token alg %q is not EdDSA", header.Alg)
	}
	holderDID, _, _ := strings.Cut(header.KID, "#")
	if holderDID == "" || !strings.HasPrefix(holderDID, "did:") {
		return errors.New("vp_token kid must be a DID URL")
	}

	doc, err := h.resolver.Resolve(holderDID)
	if err != nil {
		return fmt.Errorf("resolve holder DID: %w", err)
	}
	pub, err := vcpkg.Ed25519KeyFromDocument(doc, header.KID)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("vp_token signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("vp_token signature invalid")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("vp_token payload: %w", err)
	}
	var claims struct {
		Iss   string          `json:"iss"`
		Aud   string          `json:"aud"`
		Nonce string          `json:"nonce"`
		Exp   int64           `json:"exp"`
		VP    json.RawMessage `json:"vp"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("vp_token claims: %w", err)
	}
	if claims.Iss != holderDID {
		return errors.New("vp_token iss does not match the signing key's DID")
	}
	if claims.Aud != req.ClientID {
		return errors.New("vp_token aud does not match the request client_id")
	}
	if claims.Nonce != req.Nonce {
		return errors.New("vp_token nonce mismatch (replay attack?)")
	}
	if claims.Exp == 0 {
		return errors.New("vp_token has no exp claim")
	}
	if time.Now().Unix() >= claims.Exp {
		return errors.New("vp_token has expired")
	}
	if len(claims.VP) == 0 {
		return errors.New("vp_token has no vp claim")
	}

	var vp vcpkg.Presentation
	if err := json.Unmarshal(claims.VP, &vp); err != nil {
		return fmt.Errorf("vp claim: %w", err)
	}
	if vp.Holder != holderDID {
		return errors.New("vp.holder does not match the signing key's DID")
	}
	verifier := vcpkg.NewVerifier(h.resolver)
	for i := range vp.VerifiableCredential {
		cred := &vp.VerifiableCredential[i]
		if err := verifier.Verify(cred); err != nil {
			return fmt.Errorf("credential[%d]: %w", i, err)
		}
		if cred.CredentialSubject.ID != holderDID {
			return fmt.Errorf("credential[%d] subject does not match the presenting holder", i)
		}
	}
	return nil
}
