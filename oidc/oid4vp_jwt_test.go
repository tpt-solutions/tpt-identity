package oidc_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

type jwtVPClaims struct {
	Iss   string          `json:"iss"`
	Aud   string          `json:"aud"`
	Nonce string          `json:"nonce"`
	Exp   int64           `json:"exp,omitempty"`
	VP    vc.Presentation `json:"vp"`
}

// signVPJWT builds a compact JWS presentation signed with key. kid names the verification method.
func signVPJWT(t *testing.T, key ed25519.PrivateKey, kid string, claims jwtVPClaims) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "vp+jwt", "kid": kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(key, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// validClaims returns claims for the fixture's holder, bound to the request.
func (f *vpFixture) validClaims(nonce string) jwtVPClaims {
	return jwtVPClaims{
		Iss:   f.holderDID,
		Aud:   vpVerifier,
		Nonce: nonce,
		Exp:   time.Now().Add(5 * time.Minute).Unix(),
		VP: vc.Presentation{
			Holder:               f.holderDID,
			VerifiableCredential: []vc.VerifiableCredential{f.credential},
		},
	}
}

func (f *vpFixture) holderKey() ed25519.PrivateKey { return ed25519.PrivateKey(f.holderPriv) }

// A JWT presentation bound to the request is accepted, and only once.
func TestOID4VPAcceptsJWTPresentation(t *testing.T) {
	f := newVPFixture(t)
	id, nonce := f.createRequest(t)
	token := signVPJWT(t, f.holderKey(), f.holderDID+"#key-1", f.validClaims(nonce))

	if w := f.post(t, id, token); w.Code != http.StatusOK {
		t.Fatalf("valid JWT presentation: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := f.post(t, id, token); w.Code != http.StatusConflict {
		t.Errorf("second response: want 409, got %d", w.Code)
	}
}

// Each binding the JWT carries is checked: a change to any of them is refused.
func TestOID4VPRefusesBadJWTPresentations(t *testing.T) {
	cases := map[string]func(c *jwtVPClaims){
		"wrong nonce":       func(c *jwtVPClaims) { c.Nonce = "not-the-nonce" },
		"wrong audience":    func(c *jwtVPClaims) { c.Aud = "did:peer:someone-else" },
		"expired":           func(c *jwtVPClaims) { c.Exp = time.Now().Add(-time.Minute).Unix() },
		"no exp":            func(c *jwtVPClaims) { c.Exp = 0 },
		"iss is not holder": func(c *jwtVPClaims) { c.Iss = "did:peer:impostor" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newVPFixture(t)
			id, nonce := f.createRequest(t)
			claims := f.validClaims(nonce)
			mutate(&claims)
			// The signing key is the holder's, so the failure comes from the claim, not the signature.
			token := signVPJWT(t, f.holderKey(), f.holderDID+"#key-1", claims)
			if w := f.post(t, id, token); w.Code != http.StatusUnprocessableEntity {
				t.Errorf("want 422, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

// A tampered signature is refused, and nothing is recorded, so the wallet may retry.
func TestOID4VPRefusesTamperedJWTSignature(t *testing.T) {
	f := newVPFixture(t)
	id, nonce := f.createRequest(t)
	token := signVPJWT(t, f.holderKey(), f.holderDID+"#key-1", f.validClaims(nonce))
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	if w := f.post(t, id, tampered); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("tampered signature: want 422, got %d", w.Code)
	}
	if w := f.post(t, id, token); w.Code != http.StatusOK {
		t.Errorf("valid retry after a refused attempt: want 200, got %d", w.Code)
	}
}

// A JWT signed by a key that is not the holder's is refused, even when the claims are right.
func TestOID4VPRefusesJWTSignedByOtherKey(t *testing.T) {
	f := newVPFixture(t)
	id, nonce := f.createRequest(t)
	_, otherKey, _ := ed25519.GenerateKey(nil)
	token := signVPJWT(t, otherKey, f.holderDID+"#key-1", f.validClaims(nonce))

	if w := f.post(t, id, token); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("signature by another key: want 422, got %d", w.Code)
	}
}

// A credential validly signed by the issuer but issued to someone else is refused: the holder must be
// the subject of every credential it presents.
func TestOID4VPRefusesCredentialIssuedToAnotherSubject(t *testing.T) {
	f := newVPFixture(t)
	id, nonce := f.createRequest(t)
	other, err := vc.Issue(vc.IssueOptions{
		IssuerDID:            f.issuerDID,
		IssuerKey:            f.issuerPriv,
		VerificationMethodID: f.issuerDID + "#key-1",
		SchemaID:             "identity.legal-name",
		SubjectDID:           "did:peer:someone-else",
		Claims:               map[string]string{"givenNames": "Bob", "familyName": "Jones"},
		ValidFor:             time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := f.validClaims(nonce)
	claims.VP.VerifiableCredential = []vc.VerifiableCredential{*other}
	token := signVPJWT(t, f.holderKey(), f.holderDID+"#key-1", claims)

	if w := f.post(t, id, token); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("credential for another subject: want 422, got %d: %s", w.Code, w.Body.String())
	}
}
