//go:build ldap

package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/viper"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	bridgeproviders "github.com/tpt-solutions/tpt-identity/internal/bridge/providers"
)

// registerLDAPBridges builds the LDAP/AD bind bridge from bridges.ldap. ldaps:// is enforced by
// the provider; a plaintext URL fails here at startup.
func registerLDAPBridges(bridges *bridge.Manager, logger *slog.Logger) error {
	if !viper.IsSet("bridges.ldap") {
		return nil
	}
	var cfg struct {
		URL          string            `mapstructure:"url"`
		BindDN       string            `mapstructure:"bind_dn"`
		BindPassword string            `mapstructure:"bind_password"`
		UserBaseDN   string            `mapstructure:"user_base_dn"`
		UserFilter   string            `mapstructure:"user_filter"`
		AttributeMap map[string]string `mapstructure:"attribute_map"`
	}
	if err := viper.UnmarshalKey("bridges.ldap", &cfg); err != nil {
		return fmt.Errorf("bridges.ldap: %w", err)
	}
	b, err := bridgeproviders.NewLDAP(bridgeproviders.LDAPConfig{
		URL:          cfg.URL,
		BindDN:       cfg.BindDN,
		BindPassword: cfg.BindPassword,
		UserBaseDN:   cfg.UserBaseDN,
		UserFilter:   cfg.UserFilter,
		AttributeMap: cfg.AttributeMap,
	})
	if err != nil {
		return fmt.Errorf("ldap bridge: %w", err)
	}
	bridges.Register(b)
	logger.Info("bridge registered", "provider", "ldap", "type", "ldap")
	return nil
}
