package netguard_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/netguard"
)

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":         true,
		"2606:4700::1111": true,
		"127.0.0.1":       false,
		"10.1.2.3":        false,
		"192.168.1.1":     false,
		"172.16.0.1":      false,
		"169.254.169.254": false,
		"::1":             false,
		"fc00::1":         false,
		"0.0.0.0":         false,
	}
	for s, want := range cases {
		if got := netguard.IsPublicIP(net.ParseIP(s)); got != want {
			t.Errorf("IsPublicIP(%s) = %v, want %v", s, got, want)
		}
	}
}

// The guarded client must refuse a loopback target, even when it is reachable.
func TestClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := netguard.Client(2 * time.Second).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("guarded client connected to a loopback address")
	}
}

func TestValidateExternalURL(t *testing.T) {
	ok := []string{"https://rp.example/logout"}
	bad := []string{"http://rp.example/x", "https://user:pw@rp.example/x", "https://10.0.0.5/x", "https://[::1]/x", "rp.example/x"}
	for _, u := range ok {
		if err := netguard.ValidateExternalURL(u); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := netguard.ValidateExternalURL(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}
