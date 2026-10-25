package did

import "testing"

func TestDIDWebURL(t *testing.T) {
	cases := []struct {
		name    string
		did     string
		want    string
		wantErr bool
	}{
		{"bare domain", "did:web:example.com", "https://example.com/.well-known/did.json", false},
		{"path", "did:web:example.com:user:bob", "https://example.com/user/bob/did.json", false},
		{"encoded port", "did:web:example.com%3A8443", "https://example.com:8443/.well-known/did.json", false},
		{"encoded port with path", "did:web:example.com%3A8443:user", "https://example.com:8443/user/did.json", false},
		{"non-numeric port", "did:web:example.com%3Aabc", "", true},
		{"port out of range", "did:web:example.com%3A70000", "", true},
		{"not did:web", "did:key:z6Mk", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := didWebURL(tc.did)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("didWebURL(%q) = %q, want error", tc.did, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("didWebURL(%q) error: %v", tc.did, err)
			}
			if got != tc.want {
				t.Fatalf("didWebURL(%q) = %q, want %q", tc.did, got, tc.want)
			}
		})
	}
}

func TestDIDWebAllowlistUsesHostWithoutPort(t *testing.T) {
	w := newWebMethod(WebResolverConfig{AllowedDomains: []string{"trusted.example"}})
	if err := w.checkAllowlist("did:web:trusted.example%3A8443"); err != nil {
		t.Fatalf("allowed host with port rejected: %v", err)
	}
	if err := w.checkAllowlist("did:web:a.trusted.example:user"); err != nil {
		t.Fatalf("subdomain rejected: %v", err)
	}
	if err := w.checkAllowlist("did:web:evil.example%3A8443"); err == nil {
		t.Fatal("host outside allowlist accepted")
	}
}
