package netguard

import (
	"net"
	"strings"
)

// ClientIP returns the address of the client that made a request. The TCP peer (remoteAddr) is
// used unless it is inside one of the trusted proxy ranges; only then is X-Forwarded-For read.
//
// X-Forwarded-For is walked right to left. Each hop is appended by the proxy that received it,
// so the rightmost entries are the most trustworthy. Trusted proxy hops are skipped and the first
// untrusted hop is the client. Reading the leftmost entry instead would let a client choose its
// own address.
func ClientIP(remoteAddr, xForwardedFor string, trusted []*net.IPNet) string {
	peer := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		peer = host
	}
	if xForwardedFor == "" || !isTrusted(peer, trusted) {
		return peer
	}

	hops := strings.Split(xForwardedFor, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		if !isTrusted(hop, trusted) {
			return hop
		}
	}
	// Every hop is a trusted proxy: the leftmost one is the best available answer.
	if first := strings.TrimSpace(hops[0]); first != "" {
		return first
	}
	return peer
}

// isTrusted reports whether the textual IP falls in any trusted range.
func isTrusted(host string, trusted []*net.IPNet) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
