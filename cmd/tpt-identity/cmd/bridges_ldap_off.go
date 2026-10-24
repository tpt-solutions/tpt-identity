//go:build !ldap

package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/viper"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
)

// registerLDAPBridges refuses to start when LDAP is configured but the binary was built without
// the ldap tag, rather than silently dropping the bridge.
func registerLDAPBridges(_ *bridge.Manager, _ *slog.Logger) error {
	if viper.IsSet("bridges.ldap") {
		return fmt.Errorf("bridges.ldap is configured but this binary was built without -tags ldap")
	}
	return nil
}
