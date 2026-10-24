// Package netguard provides outbound HTTP clients that refuse to connect to private,
// loopback or link-local addresses. It is used for URLs supplied by third parties
// (back-channel logout, webhooks) to prevent server-side request forgery.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrNonPublicAddress is returned when a target resolves to a non-public address.
var ErrNonPublicAddress = errors.New("netguard: target resolves to a non-public address")

var nonPublicRanges = func() []*net.IPNet {
	var blocks []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8",      // "this" network
		"10.0.0.0/8",     // RFC 1918
		"100.64.0.0/10",  // shared address space (RFC 6598)
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"172.16.0.0/12",  // RFC 1918
		"192.0.0.0/24",   // IETF protocol assignments
		"192.168.0.0/16", // RFC 1918
		"198.18.0.0/15",  // benchmarking (RFC 2544)
		"224.0.0.0/4",    // multicast
		"240.0.0.0/4",    // reserved
		"::1/128",        // loopback
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"ff00::/8",       // multicast
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("netguard: bad CIDR " + cidr)
		}
		blocks = append(blocks, block)
	}
	return blocks
}()

// IsPublicIP reports whether ip is a globally routable unicast address.
func IsPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, block := range nonPublicRanges {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

// dialPublic resolves addr once, rejects the whole answer if any address is non-public,
// and then dials the vetted IPs directly. Because the connection is made to a checked
// IP rather than the hostname, a later DNS answer cannot redirect it (no rebinding window).
func dialPublic(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netguard: parse addr: %w", err)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("netguard: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("netguard: %s has no addresses", host)
	}
	for _, ipa := range ips {
		if !IsPublicIP(ipa.IP) {
			return nil, ErrNonPublicAddress
		}
	}
	var d net.Dialer
	var lastErr error
	for _, ipa := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Client returns an HTTP client for calling third-party URLs. It connects only to
// public addresses, ignores proxy environment variables (a proxy would hide the real
// destination from the check), and does not follow redirects.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:       dialPublic,
			Proxy:             nil,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ValidateExternalURL checks a URL that will be called on behalf of a registered client.
// It must be absolute https with a host, contain no userinfo, and must not name a
// non-public IP literal. Hostnames are checked again at connect time by Client.
func ValidateExternalURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return errors.New("must be an absolute URL")
	}
	if u.Scheme != "https" {
		return errors.New("must use https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("must include a host")
	}
	if u.User != nil {
		return errors.New("must not contain credentials")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !IsPublicIP(ip) {
		return errors.New("must not target a non-public address")
	}
	return nil
}
