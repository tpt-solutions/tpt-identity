package oidc_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/crypto"
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
	vcpkg "github.com/tpt-solutions/tpt-identity/pkg/vc"
)

const (
	proofIssuer = "https://issuer.example.com"
	proofHolder = "did:peer:holder"
	proofSchema = "identity.legal-name"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// makeProof builds an openid4vci-proof+jwt signed by priv, with pub embedded as the jwk.
func makeProof(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, iss, aud, nonce string, iat int64) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{
		"alg": "EdDSA",
		"typ": "openid4vci-proof+jwt",
		"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64(pub)},
	})
	payload, _ := json.Marshal(map[string]any{"iss": iss, "aud": aud, "iat": iat, "nonce": nonce})
	signingInput := b64(header) + "." + b64(payload)
	return signingInput + "." + b64(ed25519.Sign(priv, []byte(signingInput)))
}

var offerSeq atomic.Int64

// preAuthSetup saves a fresh offer for proofHolder and exchanges its pre-authorized code for an
// access token and c_nonce.
func preAuthSetup(t *testing.T, st store.Store, p *oidc.Provider) (accessToken, cNonce string) {
	t.Helper()
	if _, err := st.GetIdentity(context.Background(), proofHolder); err != nil {
		saveTestIdentity(t, st, proofHolder)
	}
	offerID := "offer-" + strconv.FormatInt(offerSeq.Add(1), 10)
	err := st.SaveCredentialOffer(context.Background(), &store.CredentialOffer{
		ID:         offerID,
		SchemaIDs:  []string{proofSchema},
		IssuerDID:  "did:web:issuer.example.com",
		SubjectDID: proofHolder,
		ExpiresAt:  time.Now().Add(time.Hour),
		CreatedAt:  time.Now(),
	})
	if err != nil {
		t.Fatalf("save offer: %v", err)
	}
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {offerID},
	}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.TokenHandler(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("pre-auth token: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		CNonce      string `json:"c_nonce"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.AccessToken, resp.CNonce
}

// seedLegalName stores a signed identity.legal-name credential for the holder, so issuance has
// the claims the schema requires.
func seedLegalName(t *testing.T, st store.Store, issuerPriv ed25519.PrivateKey) {
	t.Helper()
	cred, err := vcpkg.Issue(vcpkg.IssueOptions{
		IssuerDID:            "did:web:issuer.example.com",
		IssuerKey:            issuerPriv,
		VerificationMethodID: "did:web:issuer.example.com#key-1",
		SchemaID:             proofSchema,
		SubjectDID:           proofHolder,
		Claims:               map[string]string{"givenNames": "Alice", "familyName": "Smith"},
		ValidFor:             time.Hour,
	})
	if err != nil {
		t.Fatalf("issue seed credential: %v", err)
	}
	if err := st.SaveCredential(context.Background(), cred); err != nil {
		t.Fatalf("save seed credential: %v", err)
	}
}

func credentialRequest(t *testing.T, h http.HandlerFunc, token, proof string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"vct":   proofSchema,
		"proof": map[string]string{"proof_type": "jwt", "jwt": proof},
	})
	r := httptest.NewRequest(http.MethodPost, "/oid4vci/credential", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPreAuthCredentialFlow(t *testing.T) {
	st := newProofStore(t)
	_, issuerPriv, _ := crypto.GenerateSigningKey()
	holderPub, holderPriv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(proofIssuer, issuerPriv, "key-1", st)
	p.SetHolderKeyResolver(func(_ context.Context, did string) ([]ed25519.PublicKey, error) {
		if did != proofHolder {
			t.Fatalf("resolved unexpected DID %q", did)
		}
		return []ed25519.PublicKey{holderPub}, nil
	})
	h := p.CredentialHandler(issuerPriv, "did:web:issuer.example.com#key-1", st)
	seedLegalName(t, st, issuerPriv)

	token, cNonce := preAuthSetup(t, st, p)
	if cNonce == "" {
		t.Fatal("token response carried no c_nonce")
	}
	now := time.Now().Unix()

	// A proof signed by the holder's key, bound to the issued c_nonce, earns a credential.
	w := credentialRequest(t, h, token, makeProof(t, holderPriv, holderPub, proofHolder, proofIssuer, cNonce, now))
	if w.Code != http.StatusOK {
		t.Fatalf("valid proof: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"c_nonce"`) {
		t.Errorf("credential response must rotate c_nonce: %s", w.Body.String())
	}
}

func TestCredentialProofRejections(t *testing.T) {
	st := newProofStore(t)
	_, issuerPriv, _ := crypto.GenerateSigningKey()
	holderPub, holderPriv, _ := crypto.GenerateSigningKey()
	otherPub, otherPriv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(proofIssuer, issuerPriv, "key-1", st)
	p.SetHolderKeyResolver(func(context.Context, string) ([]ed25519.PublicKey, error) {
		return []ed25519.PublicKey{holderPub}, nil
	})
	h := p.CredentialHandler(issuerPriv, "did:web:issuer.example.com#key-1", st)
	now := time.Now().Unix()

	cases := map[string]func(cNonce string) string{
		"key not published by holder": func(n string) string {
			return makeProof(t, otherPriv, otherPub, proofHolder, proofIssuer, n, now)
		},
		"wrong iss": func(n string) string {
			return makeProof(t, holderPriv, holderPub, "did:peer:someone-else", proofIssuer, n, now)
		},
		"wrong aud": func(n string) string {
			return makeProof(t, holderPriv, holderPub, proofHolder, "https://evil.example", n, now)
		},
		"stale iat": func(n string) string {
			return makeProof(t, holderPriv, holderPub, proofHolder, proofIssuer, n, now-3600)
		},
		"unknown nonce": func(string) string {
			return makeProof(t, holderPriv, holderPub, proofHolder, proofIssuer, "not-issued", now)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			token, cNonce := preAuthSetup(t, st, p)
			w := credentialRequest(t, h, token, build(cNonce))
			if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "invalid_proof") {
				t.Fatalf("want invalid_proof, got %d: %s", w.Code, w.Body.String())
			}
		})
	}

	t.Run("no proof", func(t *testing.T) {
		token, _ := preAuthSetup(t, st, p)
		r := httptest.NewRequest(http.MethodPost, "/oid4vci/credential", strings.NewReader(`{"vct":"`+proofSchema+`"}`))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !strings.Contains(w.Body.String(), "invalid_proof") {
			t.Fatalf("want invalid_proof, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("nonce is single use", func(t *testing.T) {
		seedLegalName(t, st, issuerPriv)
		token, cNonce := preAuthSetup(t, st, p)
		proof := makeProof(t, holderPriv, holderPub, proofHolder, proofIssuer, cNonce, now)
		if w := credentialRequest(t, h, token, proof); w.Code != http.StatusOK {
			t.Fatalf("first use: want 200, got %d: %s", w.Code, w.Body.String())
		}
		if w := credentialRequest(t, h, token, proof); !strings.Contains(w.Body.String(), "invalid_proof") {
			t.Fatalf("replayed nonce: want invalid_proof, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestCredentialEndpointRefusesWithoutHolderResolver(t *testing.T) {
	st := newProofStore(t)
	_, issuerPriv, _ := crypto.GenerateSigningKey()
	holderPub, holderPriv, _ := crypto.GenerateSigningKey()
	p := oidc.NewProvider(proofIssuer, issuerPriv, "key-1", st) // no SetHolderKeyResolver
	h := p.CredentialHandler(issuerPriv, "did:web:issuer.example.com#key-1", st)

	token, cNonce := preAuthSetup(t, st, p)
	w := credentialRequest(t, h, token, makeProof(t, holderPriv, holderPub, proofHolder, proofIssuer, cNonce, time.Now().Unix()))
	if w.Code == http.StatusOK {
		t.Fatalf("issued a credential without holder key resolution: %s", w.Body.String())
	}
}

func newProofStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
