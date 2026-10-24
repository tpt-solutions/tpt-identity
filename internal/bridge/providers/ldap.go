//go:build ldap

// LDAP bridge requires: go get github.com/go-ldap/ldap/v3
// Build with: go build -tags ldap ./...

package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/tpt-solutions/tpt-identity/internal/bridge"
)

// LDAPConfig configures the LDAP/Active Directory bridge.
type LDAPConfig struct {
	// URL is the LDAP server URL, e.g. "ldaps://ldap.example.com:636".
	// ldaps:// (LDAPS) or ldap:// with STARTTLS is required. Plaintext is rejected.
	URL string
	// BindDN is the service account DN used to search for the user.
	BindDN string
	// BindPassword is the service account password.
	BindPassword string
	// UserBaseDN is the search base for user lookups, e.g. "OU=Users,DC=example,DC=com".
	UserBaseDN string
	// UserFilter is the LDAP filter to find users, e.g. "(sAMAccountName=%s)".
	UserFilter string
	// AttributeMap maps LDAP attribute names to standard claim names.
	// Defaults: {"mail": "email", "givenName": "given_name", "sn": "family_name"}.
	AttributeMap map[string]string
}

// LDAPBridge implements bridge.Bridge for an LDAP/Active Directory directory.
type LDAPBridge struct {
	cfg LDAPConfig
}

// NewLDAP creates an LDAP bridge.
// Returns an error if the URL does not use a secure scheme.
func NewLDAP(cfg LDAPConfig) (*LDAPBridge, error) {
	if len(cfg.URL) < 7 {
		return nil, errors.New("ldap: URL too short")
	}
	scheme := cfg.URL[:7]
	if scheme != "ldaps://" && cfg.URL[:5] != "ldap:" {
		return nil, errors.New("ldap: URL must start with ldaps:// or ldap://")
	}
	if scheme == "ldap://" {
		// Plaintext LDAP is a hard error, not a warning.
		return nil, errors.New("ldap: plaintext ldap:// is not permitted; use ldaps:// or STARTTLS")
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(sAMAccountName=%s)"
	}
	if cfg.AttributeMap == nil {
		cfg.AttributeMap = map[string]string{
			"mail":        "email",
			"givenName":   "given_name",
			"sn":          "family_name",
			"displayName": "name",
			"memberOf":    "groups",
		}
	}
	return &LDAPBridge{cfg: cfg}, nil
}

func (b *LDAPBridge) Name() string { return "ldap" }

func (b *LDAPBridge) Authenticate(ctx context.Context, r *http.Request) (*bridge.ExternalIdentity, error) {
	return nil, errors.New("ldap: use VerifyCredentials instead")
}

// VerifyCredentials authenticates identifier+password against the LDAP directory.
func (b *LDAPBridge) VerifyCredentials(ctx context.Context, identifier, password string) (*bridge.ExternalIdentity, error) {
	conn, err := ldap.DialURL(b.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	defer conn.Close()

	// Service account bind to search for the user.
	if err := conn.Bind(b.cfg.BindDN, b.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: service bind: %w", err)
	}

	// Search for the user.
	attrs := []string{"dn"}
	for ldapAttr := range b.cfg.AttributeMap {
		attrs = append(attrs, ldapAttr)
	}
	filter := fmt.Sprintf(b.cfg.UserFilter, ldap.EscapeFilter(identifier))
	searchReq := ldap.NewSearchRequest(
		b.cfg.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap: search: %w", err)
	}
	if len(result.Entries) == 0 {
		// Constant-time: don't reveal whether user exists.
		_ = conn.Bind("cn=nonexistent,dc=invalid", "wrongpassword")
		return nil, errors.New("ldap: invalid credentials")
	}
	if len(result.Entries) > 1 {
		return nil, errors.New("ldap: ambiguous user search result")
	}
	userDN := result.Entries[0].DN

	// Bind as the user to verify their password.
	if err := conn.Bind(userDN, password); err != nil {
		return nil, errors.New("ldap: invalid credentials")
	}

	// Extract attributes.
	claims := make(map[string]string, len(b.cfg.AttributeMap))
	for ldapAttr, claimName := range b.cfg.AttributeMap {
		if vals := result.Entries[0].GetAttributeValues(ldapAttr); len(vals) > 0 {
			claims[claimName] = vals[0]
		}
	}

	return &bridge.ExternalIdentity{
		Provider:   b.Name(),
		ExternalID: userDN, // DN is the stable LDAP identifier
		Claims:     claims,
	}, nil
}
