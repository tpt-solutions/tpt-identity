package netguard_test

import (
	"net"
	"testing"

	"github.com/tpt-solutions/tpt-identity/internal/netguard"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestClientIPIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}
	got := netguard.ClientIP("203.0.113.9:4444", "198.51.100.1", trusted)
	if got != "203.0.113.9" {
		t.Errorf("untrusted peer: want its own address, got %q", got)
	}
}

func TestClientIPWalksForwardedForRightToLeft(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}
	// The client prepends a fake address; the trusted proxy appends the real one.
	got := netguard.ClientIP("10.0.0.2:443", "1.2.3.4, 198.51.100.7, 10.0.0.5", trusted)
	if got != "198.51.100.7" {
		t.Errorf("want the first untrusted hop from the right, got %q", got)
	}
}

func TestClientIPAllTrustedHopsUsesLeftmost(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}
	got := netguard.ClientIP("10.0.0.2:443", "10.1.1.1, 10.0.0.5", trusted)
	if got != "10.1.1.1" {
		t.Errorf("want leftmost when every hop is trusted, got %q", got)
	}
}

func TestClientIPNoTrustedProxies(t *testing.T) {
	got := netguard.ClientIP("192.0.2.1:80", "9.9.9.9", nil)
	if got != "192.0.2.1" {
		t.Errorf("no trusted proxies: want RemoteAddr host, got %q", got)
	}
}
