//go:build !saml

package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spf13/viper"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
)

// registerSAMLBridges refuses to start when SAML is configured but the binary was built without
// the saml tag, rather than silently dropping the bridge.
func registerSAMLBridges(_ context.Context, _ *bridge.Manager, _ *slog.Logger) error {
	if viper.IsSet("bridges.saml") {
		return fmt.Errorf("bridges.saml is configured but this binary was built without -tags saml")
	}
	return nil
}
