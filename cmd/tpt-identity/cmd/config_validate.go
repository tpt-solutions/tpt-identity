package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/url"
)

// validateIssuer checks the canonical issuer URL. It is the OIDC issuer and the base of the
// platform did:web, so it must be an absolute https URL. Plain http is accepted only for a
// loopback host, for local development.
func validateIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("issuer must be set in config (the canonical https URL of this server)")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return fmt.Errorf("issuer %q is not an absolute URL", issuer)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("issuer %q must be an https URL (http is allowed only for localhost)", issuer)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
