package vc_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

func issueSDJWTForTest(t *testing.T, always map[string]any, opts func(*vc.SDJWTIssueOptions)) (*vc.SDJWTToken, error) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	io := vc.SDJWTIssueOptions{
		IssuerDID:            "did:web:issuer.example",
		IssuerKey:            priv,
		VerificationMethodID: "did:web:issuer.example#signing-key-1",
		SubjectDID:           "did:peer:holder",
		SelectiveClaims:      map[string]any{"givenNames": "Alice"},
		AlwaysVisibleClaims:  always,
		ValidFor:             time.Hour,
	}
	if opts != nil {
		opts(&io)
	}
	return vc.IssueSDJWT(io)
}

// payloadOf decodes the claims of an issued SD-JWT's issuer JWT.
func payloadOf(t *testing.T, tok *vc.SDJWTToken) map[string]any {
	t.Helper()
	parts := strings.Split(tok.JWT, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// The issuer's own claims cannot be supplied by the caller. A caller that could set iss or sub would have
// the platform sign a token that names someone else.
func TestSDJWTRefusesCallerSuppliedIssuerClaims(t *testing.T) {
	for _, name := range []string{"iss", "sub", "exp", "iat", "jti", "status", "_sd", "vct"} {
		if _, err := issueSDJWTForTest(t, map[string]any{name: "forged"}, nil); err == nil {
			t.Errorf("caller-supplied %q accepted", name)
		}
	}
}

// Other always-visible claims, such as cnf for key binding, are still allowed.
func TestSDJWTAcceptsOrdinaryAlwaysVisibleClaims(t *testing.T) {
	tok, err := issueSDJWTForTest(t, map[string]any{"assurance": "LOA2"}, nil)
	if err != nil {
		t.Fatalf("ordinary always-visible claim refused: %v", err)
	}
	if payloadOf(t, tok)["assurance"] != "LOA2" {
		t.Error("ordinary claim missing from the payload")
	}
}

// A status reference and a jti are placed in the payload by the issuer.
func TestSDJWTCarriesStatusAndID(t *testing.T) {
	tok, err := issueSDJWTForTest(t, nil, func(o *vc.SDJWTIssueOptions) {
		o.ID = "sdj_abc"
		o.Status = &vc.SDJWTStatus{ListURI: "https://issuer.example/api/v1/token-status/list-1", Index: 42}
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := payloadOf(t, tok)
	if claims["jti"] != "sdj_abc" {
		t.Errorf("jti: got %v", claims["jti"])
	}
	status, ok := claims["status"].(map[string]any)
	if !ok {
		t.Fatalf("status claim missing: %v", claims["status"])
	}
	list, _ := status["status_list"].(map[string]any)
	if list["idx"] != float64(42) || list["uri"] != "https://issuer.example/api/v1/token-status/list-1" {
		t.Errorf("status_list: got %v", list)
	}
}
