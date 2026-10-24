// Package oidc implements OpenID for Verifiable Credential Issuance (OID4VCI)
// draft-ietf-oauth-openid-credential-issuance.
//
// Flow:
//  1. Issuer creates a credential offer via POST /oid4vci/offers
//  2. Offer is encoded as openid-credential-offer://?credential_offer=<json> QR code
//  3. Wallet calls GET /.well-known/openid-credential-issuer (metadata)
//  4. Wallet calls POST /token with grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
//  5. Wallet calls POST /oid4vci/credential with the access token and a key proof bound to c_nonce
//  6. Issuer returns the signed credential
package oidc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/tpt-solutions/tpt-identity/pkg/schema"
	vcpkg "github.com/tpt-solutions/tpt-identity/pkg/vc"
)

const (
	// cNonceTTL is how long a c_nonce stays valid after it is issued.
	cNonceTTL = 5 * time.Minute
	// proofMaxAge bounds how old a key proof's iat may be.
	proofMaxAge = 5 * time.Minute
	// proofJWTType is the typ header required on OID4VCI key proofs.
	proofJWTType = "openid4vci-proof+jwt"
)

// HolderKeyResolver returns the Ed25519 verification keys a holder DID publishes.
type HolderKeyResolver func(ctx context.Context, holderDID string) ([]ed25519.PublicKey, error)

// SetHolderKeyResolver enables proof-of-possession checks at the credential endpoint. Without a
// resolver the credential endpoint refuses every request, so an unverified holder can never
// receive a credential.
func (p *Provider) SetHolderKeyResolver(fn HolderKeyResolver) {
	p.holderKeys = fn
}

// CredentialIssuerMetadataHandler serves GET /.well-known/openid-credential-issuer
// (OID4VCI §11.2.3) — the credential issuer metadata document.
func (p *Provider) CredentialIssuerMetadataHandler(w http.ResponseWriter, r *http.Request) {
	// Build the list of credential configurations from the schema registry.
	configs := map[string]any{}
	for _, s := range schema.AllSchemas() {
		configs[s.ID] = map[string]any{
			"format": "jwt_vc_json",
			"scope":  "credential:" + s.ID,
			"vct":    s.ID,
			"credential_definition": map[string]any{
				"type": []string{"VerifiableCredential", s.Name},
			},
			"display": []map[string]any{{
				"name":   s.Name,
				"locale": "en-NZ",
			}},
		}
	}

	meta := map[string]any{
		"credential_issuer":                                   p.issuer,
		"authorization_servers":                               []string{p.issuer},
		"credential_endpoint":                                 p.issuer + "/oid4vci/credential",
		"deferred_credential_endpoint":                        p.issuer + "/oid4vci/deferred",
		"notification_endpoint":                               p.issuer + "/oid4vci/notification",
		"credential_response_encryption_alg_values_supported": []string{"ECDH-ES"},
		"credential_configurations_supported":                 configs,
		"batch_credential_issuance": map[string]int{
			"batch_size": 10,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

// CreateCredentialOfferHandler handles POST /oid4vci/offers (admin endpoint).
// Creates a credential offer and returns the deep-link URI and QR code data.
//
// Request body (JSON):
//
//	{
//	  "schema_ids":   ["identity.legal-name"],
//	  "subject_did":  "did:peer:...",  // optional pre-binding
//	  "client_id":    "...",           // optional
//	  "expires_in":   3600             // seconds, default 600
//	}
func (p *Provider) CreateCredentialOfferHandler(signingKey ed25519.PrivateKey, signingKeyID string, st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuerDID, err := did.PlatformDID(p.issuer)
		if err != nil {
			http.Error(w, "issuer must be an absolute https URL", http.StatusInternalServerError)
			return
		}
		var req struct {
			SchemaIDs  []string `json:"schema_ids"`
			SubjectDID string   `json:"subject_did"`
			ClientID   string   `json:"client_id"`
			ExpiresIn  int      `json:"expires_in"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON body")
			return
		}
		if len(req.SchemaIDs) == 0 {
			writeError(w, "invalid_request", "schema_ids required")
			return
		}
		ttl := time.Duration(req.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = 10 * time.Minute
		}

		id, err := randomHex(16)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		offer := &store.CredentialOffer{
			ID:         id,
			ClientID:   req.ClientID,
			SchemaIDs:  req.SchemaIDs,
			IssuerDID:  issuerDID,
			SubjectDID: req.SubjectDID,
			ExpiresAt:  time.Now().Add(ttl),
			CreatedAt:  time.Now(),
		}
		if err := st.SaveCredentialOffer(r.Context(), offer); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Build the credential_offer JSON (OID4VCI §4.1.1).
		credOfferJSON, _ := json.Marshal(map[string]any{
			"credential_issuer":            p.issuer,
			"credential_configuration_ids": req.SchemaIDs,
			"grants": map[string]any{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
					"pre-authorized_code": id,
					"tx_code": map[string]any{
						"length":      6,
						"input_mode":  "numeric",
						"description": "Enter the PIN shown on your issuer portal",
					},
				},
			},
		})
		deepLink := fmt.Sprintf("openid-credential-offer://?credential_offer=%s",
			strings.ReplaceAll(string(credOfferJSON), " ", ""))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"offer_id":   id,
			"deep_link":  deepLink,
			"qr_data":    deepLink, // caller can render this as a QR code
			"expires_at": offer.ExpiresAt,
		})
	}
}

// handlePreAuthorizedCode implements the pre-authorized_code grant for OID4VCI.
// Called from TokenHandler when grant_type is the pre-authorized_code URN.
func (p *Provider) handlePreAuthorizedCode(w http.ResponseWriter, r *http.Request, st store.Store) {
	preAuthCode := r.FormValue("pre-authorized_code")
	if preAuthCode == "" {
		writeError(w, "invalid_request", "pre-authorized_code required")
		return
	}

	offer, err := st.GetCredentialOffer(r.Context(), preAuthCode)
	if err != nil {
		writeError(w, "invalid_grant", "pre-authorized_code not found")
		return
	}
	if offer.Used {
		writeError(w, "invalid_grant", "pre-authorized_code already used")
		return
	}
	if time.Now().After(offer.ExpiresAt) {
		writeError(w, "invalid_grant", "pre-authorized_code expired")
		return
	}

	_ = st.MarkCredentialOfferUsed(r.Context(), preAuthCode)

	// Issue an access token scoped to the credential issuance. The scope lists exactly the
	// schemas named in this offer, so the token cannot be used for any other credential type.
	scopes := make([]string, len(offer.SchemaIDs))
	for i, sid := range offer.SchemaIDs {
		scopes[i] = "credential:" + sid
	}
	subject := offer.SubjectDID
	if subject == "" {
		subject = "urn:pre-auth:" + preAuthCode // anonymous pre-auth; the credential endpoint refuses it
	}
	extra := map[string]any{
		"scope":      strings.Join(scopes, " "),
		"offer_id":   offer.ID,
		"schema_ids": offer.SchemaIDs,
	}
	accessToken, err := issueJWTWithExtra(p.issuer, subject, p.issuer, p.ttl.Access, p.signingKey, p.keyID, extra)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":       accessToken,
		"token_type":         "Bearer",
		"expires_in":         int(p.ttl.Access.Seconds()),
		"c_nonce":            p.newCNonce(),
		"c_nonce_expires_in": int(cNonceTTL.Seconds()),
	})
}

// CredentialHandler handles POST /oid4vci/credential — the wallet presents the
// access token and a key proof, and requests issuance of a specific credential type.
func (p *Provider) CredentialHandler(signingKey ed25519.PrivateKey, signingKeyID string, st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" {
			writeError(w, "invalid_token", "Bearer token required")
			return
		}
		claims, err := p.VerifyAccessToken(r.Context(), bearer)
		if err != nil {
			writeError(w, "invalid_token", err.Error())
			return
		}

		var req struct {
			Format               string `json:"format"` // "jwt_vc_json" or "ldp_vc"
			CredentialDefinition struct {
				Type []string `json:"type"`
			} `json:"credential_definition"`
			VCT   string        `json:"vct"`   // SD-JWT VCT claim (for sd-jwt format)
			Proof *oid4vciProof `json:"proof"` // key proof of possession, required
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON body")
			return
		}

		// Determine which schema to issue.
		schemaID := req.VCT
		if schemaID == "" && len(req.CredentialDefinition.Type) > 0 {
			// Last type in the array is the specific credential type.
			schemaID = req.CredentialDefinition.Type[len(req.CredentialDefinition.Type)-1]
		}
		if schemaID == "" {
			writeError(w, "unsupported_credential_type", "cannot determine credential type from request")
			return
		}

		// The token must carry an explicit credential:<schema> scope for this type. Ordinary
		// user access tokens have no credential scope and must not mint credentials.
		if !hasScopeToken(claims.Scope, "credential:"+schemaID) {
			writeError(w, "insufficient_scope", "token scope does not cover credential:"+schemaID)
			return
		}

		subjectDID := claims.Subject
		if strings.HasPrefix(subjectDID, "urn:pre-auth:") {
			writeError(w, "invalid_request", "subject DID not bound to this pre-authorized_code; use subject_did binding")
			return
		}

		// The wallet must prove it holds a key the subject DID publishes, bound to a fresh c_nonce.
		if req.Proof == nil || req.Proof.ProofType != "jwt" {
			writeError(w, "invalid_proof", "a key proof with proof_type jwt is required")
			return
		}
		if err := p.verifyProof(r.Context(), req.Proof.JWT, subjectDID); err != nil {
			writeError(w, "invalid_proof", err.Error())
			return
		}

		// Retrieve existing credentials from the store as claims.
		creds, _ := st.ListCredentials(r.Context(), subjectDID)
		credClaims := map[string]any{
			"id": subjectDID,
		}
		for _, c := range creds {
			for k, v := range c.CredentialSubject.Claims {
				credClaims[k] = v
			}
		}

		// Build a string-keyed claims map from the credential subject.
		strClaims := map[string]string{}
		for k, v := range credClaims {
			if sv, ok := v.(string); ok {
				strClaims[k] = sv
			} else {
				jsonVal, _ := json.Marshal(v)
				strClaims[k] = string(jsonVal)
			}
		}
		delete(strClaims, "id") // id is SubjectDID, not a claim field

		issuerDID, err := did.PlatformDID(p.issuer)
		if err != nil {
			writeError(w, "issuance_failed", "issuer must be an absolute https URL")
			return
		}

		// Issue the VC.
		opts := vcpkg.IssueOptions{
			IssuerDID:            issuerDID,
			IssuerKey:            signingKey,
			VerificationMethodID: signingKeyID,
			SchemaID:             schemaID,
			SubjectDID:           subjectDID,
			Claims:               strClaims,
			ValidFor:             365 * 24 * time.Hour,
		}
		vc, err := vcpkg.Issue(opts)
		if err != nil {
			writeError(w, "issuance_failed", err.Error())
			return
		}

		vcJSON, _ := json.Marshal(vc)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"format":     "jwt_vc_json",
			"credential": string(vcJSON),
			"c_nonce":    p.newCNonce(),
		})
	}
}

// oid4vciProof is the key proof submitted by the wallet during credential issuance.
// It proves the wallet controls the key that will be bound to the credential.
type oid4vciProof struct {
	ProofType string `json:"proof_type"` // "jwt"
	JWT       string `json:"jwt"`
}

// proofHeader is the JOSE header of an openid4vci-proof+jwt; jwk carries the holder's key.
type proofHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	JWK struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	} `json:"jwk"`
}

// proofClaims are the claims an OID4VCI key proof must carry.
type proofClaims struct {
	Iss   string `json:"iss"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
}

// verifyProof checks an OID4VCI key proof for the holder DID: the EdDSA signature under the
// embedded jwk, the audience and freshness, a single-use c_nonce, and that the proof key is one
// the holder DID publishes.
func (p *Provider) verifyProof(ctx context.Context, token, holderDID string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("proof is not a compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("proof header is not base64url")
	}
	var hdr proofHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return errors.New("proof header is not JSON")
	}
	if hdr.Typ != proofJWTType || hdr.Alg != "EdDSA" || hdr.JWK.Kty != "OKP" || hdr.JWK.Crv != "Ed25519" {
		return fmt.Errorf("proof must have typ %s, alg EdDSA and an Ed25519 jwk", proofJWTType)
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(hdr.JWK.X)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return errors.New("proof jwk is not a 32-byte Ed25519 key")
	}
	proofKey := ed25519.PublicKey(keyBytes)

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(proofKey, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("proof signature is invalid")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("proof payload is not base64url")
	}
	var claims proofClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return errors.New("proof payload is not JSON")
	}
	if claims.Iss != holderDID {
		return errors.New("proof iss must be the subject DID")
	}
	if claims.Aud != p.issuer {
		return errors.New("proof aud must be the credential issuer")
	}
	age := time.Since(time.Unix(claims.Iat, 0))
	if age > proofMaxAge || age < -time.Minute {
		return errors.New("proof iat is outside the accepted window")
	}
	if !p.consumeCNonce(claims.Nonce) {
		return errors.New("c_nonce is missing, expired or already used")
	}

	if p.holderKeys == nil {
		return errors.New("holder key resolution is not configured")
	}
	keys, err := p.holderKeys(ctx, holderDID)
	if err != nil {
		return fmt.Errorf("resolve holder DID: %w", err)
	}
	for _, k := range keys {
		if bytes.Equal(k, proofKey) {
			return nil
		}
	}
	return errors.New("proof key is not a key published by the subject DID")
}

// newCNonce issues a single-use c_nonce and prunes expired ones.
func (p *Provider) newCNonce() string {
	now := time.Now()
	p.cNonces.Range(func(k, v any) bool {
		if now.After(v.(time.Time)) {
			p.cNonces.Delete(k)
		}
		return true
	})
	nonce := mustRandomHex(16)
	p.cNonces.Store(nonce, now.Add(cNonceTTL))
	return nonce
}

// consumeCNonce reports whether nonce was issued and is still valid, and removes it so it
// cannot be replayed.
func (p *Provider) consumeCNonce(nonce string) bool {
	if nonce == "" {
		return false
	}
	v, ok := p.cNonces.LoadAndDelete(nonce)
	return ok && time.Now().Before(v.(time.Time))
}

// hasScopeToken reports whether want appears as a whole token in a space-delimited scope string.
func hasScopeToken(scope, want string) bool {
	return slices.Contains(strings.Fields(scope), want)
}

func mustRandomHex(n int) string {
	s, _ := randomHex(n)
	return s
}
