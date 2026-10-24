package vc_test

import (
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// The issuer key is the one named by the JWT kid. A kid the DID document does not publish is
// refused, so a token cannot be checked against an unrelated key.
func TestSDJWTVerifyHonoursKid(t *testing.T) {
	issuerDID, vmID, priv := testSDJWTIssuer(t)
	v := vc.NewSDJWTVerifier(resolver.New(time.Minute))

	good := issueWithKID(t, issuerDID, vmID, priv)
	if _, err := v.Verify(good.Present(nil), "", ""); err != nil {
		t.Fatalf("token signed under its own kid rejected: %v", err)
	}

	unknown := issueWithKID(t, issuerDID, issuerDID+"#key-99", priv)
	if _, err := v.Verify(unknown.Present(nil), "", ""); err == nil {
		t.Fatal("token with a kid the DID document does not publish was accepted")
	}
}

func issueWithKID(t *testing.T, issuerDID, vmID string, priv []byte) *vc.SDJWTToken {
	t.Helper()
	token, err := vc.IssueSDJWT(vc.SDJWTIssueOptions{
		IssuerDID:            issuerDID,
		IssuerKey:            priv,
		VerificationMethodID: vmID,
		SubjectDID:           "did:peer:holder123",
		SchemaID:             "identity.legal-name",
		SelectiveClaims:      map[string]any{"givenNames": "Alice", "familyName": "Smith"},
		ValidFor:             time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueSDJWT: %v", err)
	}
	return token
}
