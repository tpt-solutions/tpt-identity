package vc_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// A credential bound to a holder key (cnf) must be presented with a key-binding JWT, even when the
// verifier did not ask for a nonce. A bare presentation of it is refused.
func TestSDJWTVerifyRequiresKBForHolderBoundCredential(t *testing.T) {
	issuerDID, vmID, priv := testSDJWTIssuer(t)
	holderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := vc.IssueSDJWT(vc.SDJWTIssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            priv,
		VerificationMethodID: vmID,
		SubjectDID:           "did:peer:holder123",
		SchemaID:             "identity.legal-name",
		SelectiveClaims:      map[string]any{"givenNames": "Alice"},
		AlwaysVisibleClaims: map[string]any{
			"cnf": map[string]any{"jwk": map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(holderPub),
			}},
		},
		ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueSDJWT: %v", err)
	}

	v := vc.NewSDJWTVerifier(resolver.New(time.Minute))
	if _, err := v.Verify(token.Present([]string{"givenNames"}), "", ""); err == nil {
		t.Fatal("holder-bound credential accepted without a key-binding JWT")
	}
}

// The verifier must refuse a KB-JWT when the issuer JWT has no cnf key to check it against.
func TestSDJWTVerifyRejectsKBWithoutCnf(t *testing.T) {
	issuerDID, vmID, priv := testSDJWTIssuer(t)
	token := issueWithKID(t, issuerDID, vmID, priv)
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderDID, _, _ := did.Create("peer", did.CreateOptions{SigningPub: holderPub})

	presented, err := token.PresentWithKeyBinding(
		[]string{"givenNames"}, holderPriv, holderDID+"#signing-key-1", "nonce-1", "https://verifier.example",
	)
	if err != nil {
		t.Fatal(err)
	}
	v := vc.NewSDJWTVerifier(resolver.New(time.Minute))
	if _, err := v.Verify(presented, "nonce-1", "https://verifier.example"); err == nil {
		t.Fatal("KB-JWT accepted for a credential with no cnf key")
	}
}

// A holder-bound credential presented with a key-binding JWT over the verifier's nonce and audience must verify.
// The sd_hash in the KB-JWT is computed over the presentation the verifier receives.
func TestSDJWTKeyBindingVerifies(t *testing.T) {
	issuerDID, vmID, priv := testSDJWTIssuer(t)
	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderDID, _, err := did.Create("peer", did.CreateOptions{SigningPub: holderPub})
	if err != nil {
		t.Fatal(err)
	}
	token, err := vc.IssueSDJWT(vc.SDJWTIssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            priv,
		VerificationMethodID: vmID,
		SubjectDID:           holderDID,
		SchemaID:             "identity.legal-name",
		SelectiveClaims:      map[string]any{"givenNames": "Alice", "familyName": "Smith"},
		AlwaysVisibleClaims: map[string]any{
			"cnf": map[string]any{"jwk": map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(holderPub),
			}},
		},
		ValidFor: time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueSDJWT: %v", err)
	}

	presented, err := token.PresentWithKeyBinding([]string{"givenNames"}, holderPriv, holderDID+"#signing-key-1", "nonce-1", "https://verifier.example")
	if err != nil {
		t.Fatal(err)
	}
	v := vc.NewSDJWTVerifier(resolver.New(time.Minute))
	res, err := v.Verify(presented, "nonce-1", "https://verifier.example")
	if err != nil {
		t.Fatalf("key-bound presentation refused: %v", err)
	}
	if res.DisclosedClaims["givenNames"] != "Alice" || len(res.DisclosedClaims) != 1 {
		t.Errorf("disclosed %v, want only givenNames", res.DisclosedClaims)
	}
}
