// Package oidc implements OpenID for Verifiable Credential Issuance (OID4VCI)
// draft-ietf-oauth-openid-credential-issuance.
//
// Flow:
//  1. Issuer creates a credential offer via POST /oid4vci/offers
//  2. Offer is encoded as openid-credential-offer://?credential_offer=<json> QR code
//  3. Wallet calls GET /.well-known/openid-credential-issuer (metadata)
//  4. Wallet calls POST /token with grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
//  5. Wallet calls POST /oid4vci/credential with the access token
//  6. Issuer returns the signed credential
package oidc

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/pkg/schema"
	vcpkg "github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// CredentialIssuerMetadataHandler serves GET /.well-known/openid-credential-issuer
// (OID4VCI §11.2.3) — the credential issuer metadata document.
func (p *Provider) CredentialIssuerMetadataHandler(w http.ResponseWriter, r *http.Request) {
	// Build the list of credential configurations from the schema registry.
	configs := map[string]any{}
	for _, s := range schema.AllSchemas() {
		configs[s.ID] = map[string]any{
			"format":     "jwt_vc_json",
			"scope":      "credential:" + s.ID,
			"vct":        s.ID,
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
		"credential_issuer":                           p.issuer,
		"authorization_servers":                       []string{p.issuer},
		"credential_endpoint":                         p.issuer + "/oid4vci/credential",
		"deferred_credential_endpoint":                p.issuer + "/oid4vci/deferred",
		"notification_endpoint":                       p.issuer + "/oid4vci/notification",
		"credential_response_encryption_alg_values_supported": []string{"ECDH-ES"},
		"credential_configurations_supported":         configs,
		"batch_credential_issuance": map[string]int{
			"batch_size": 10,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
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
			IssuerDID:  p.issuer, // simplified: issuer DID = issuer URL
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
			"credential_issuer": p.issuer,
			"credential_configuration_ids": req.SchemaIDs,
			"grants": map[string]any{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
					"pre-authorized_code": id,
					"tx_code": map[string]any{
						"length":       6,
						"input_mode":   "numeric",
						"description":  "Enter the PIN shown on your issuer portal",
					},
				},
			},
		})
		deepLink := fmt.Sprintf("openid-credential-offer://?credential_offer=%s",
			strings.ReplaceAll(string(credOfferJSON), " ", ""))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"offer_id":    id,
			"deep_link":   deepLink,
			"qr_data":     deepLink, // caller can render this as a QR code
			"expires_at":  offer.ExpiresAt,
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

	// Issue an access token scoped to the credential issuance.
	scopes := make([]string, len(offer.SchemaIDs))
	for i, sid := range offer.SchemaIDs {
		scopes[i] = "credential:" + sid
	}
	subject := offer.SubjectDID
	if subject == "" {
		subject = "urn:pre-auth:" + preAuthCode // anonymous pre-auth
	}
	extra := map[string]any{
		"scope":       strings.Join(scopes, " "),
		"offer_id":    offer.ID,
		"schema_ids":  offer.SchemaIDs,
	}
	accessToken, err := issueJWTWithExtra(p.issuer, subject, p.issuer, accessTokenTTL, p.signingKey, p.keyID, extra)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
		"c_nonce":      mustRandomHex(16),
		"c_nonce_expires_in": 300,
	})
}

// CredentialHandler handles POST /oid4vci/credential — the wallet presents the
// access token and requests issuance of a specific credential type.
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
			Format string `json:"format"` // "jwt_vc_json" or "ldp_vc"
			CredentialDefinition struct {
				Type []string `json:"type"`
			} `json:"credential_definition"`
			VCT   string         `json:"vct"`   // SD-JWT VCT claim (for sd-jwt format)
			Proof *oid4vciProof  `json:"proof"` // key proof (optional for now)
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

		// Issue the VC.
		opts := vcpkg.IssueOptions{
			IssuerDID:            p.issuer,
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
		json.NewEncoder(w).Encode(map[string]any{
			"format":     "jwt_vc_json",
			"credential": string(vcJSON),
			"c_nonce":    mustRandomHex(16),
		})
	}
}

// oid4vciProof is the key proof submitted by the wallet during credential issuance.
// It proves the wallet controls the key that will be bound to the credential.
type oid4vciProof struct {
	ProofType string `json:"proof_type"` // "jwt"
	JWT       string `json:"jwt"`
}

// hasScopeToken reports whether want appears as a whole token in a space-delimited scope string.
func hasScopeToken(scope, want string) bool {
	return slices.Contains(strings.Fields(scope), want)
}

func mustRandomHex(n int) string {
	s, _ := randomHex(n)
	return s
}
