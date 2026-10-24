package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The OIDC discovery document and the RFC 8414 OAuth metadata are the same document, and both
// advertise the capabilities a client needs to choose its flow.
func TestDiscoveryDocumentsAgree(t *testing.T) {
	srv := newTestServer(t)
	oidcDoc := do(t, srv, http.MethodGet, "/.well-known/openid-configuration", "", nil)
	asDoc := do(t, srv, http.MethodGet, "/.well-known/oauth-authorization-server", "", nil)
	if oidcDoc.Code != http.StatusOK || asDoc.Code != http.StatusOK {
		t.Fatalf("want 200 from both, got %d and %d", oidcDoc.Code, asDoc.Code)
	}
	if oidcDoc.Body.String() != asDoc.Body.String() {
		t.Error("the two metadata documents differ")
	}

	var meta map[string]any
	if err := json.Unmarshal(oidcDoc.Body.Bytes(), &meta); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	methods, _ := meta["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", methods)
	}
	if meta["request_uri_parameter_supported"] != true || meta["request_parameter_supported"] != false {
		t.Errorf("request parameter flags wrong: %v / %v", meta["request_parameter_supported"], meta["request_uri_parameter_supported"])
	}
}
