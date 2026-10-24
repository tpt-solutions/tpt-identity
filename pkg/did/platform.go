package did

import (
	"fmt"
	"net/url"
)

// PlatformDID returns the did:web identifier for the server at issuer, for example
// https://id.example.com -> did:web:id.example.com. A port is written as %3A, as the
// did:web method requires. Verifiers resolve the platform DID at /.well-known/did.json.
func PlatformDID(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("issuer %q is not an absolute URL", issuer)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("issuer %q has no host", issuer)
	}
	domain := host
	if port := u.Port(); port != "" {
		domain = host + "%3A" + port
	}
	return "did:web:" + domain, nil
}
