//go:build saml

package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spf13/viper"

	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	bridgeproviders "github.com/tpt-solutions/tpt-identity/internal/bridge/providers"
)

// registerSAMLBridges builds one SAML 2.0 SP bridge per entry under bridges.saml.
func registerSAMLBridges(ctx context.Context, bridges *bridge.Manager, logger *slog.Logger) error {
	var entries []struct {
		Name           string `mapstructure:"name"`
		IDPMetadataURL string `mapstructure:"idp_metadata_url"`
		EntityID       string `mapstructure:"entity_id"`
		ACSPath        string `mapstructure:"acs_path"`
		MetadataPath   string `mapstructure:"metadata_path"`
		CertFile       string `mapstructure:"cert_file"`
		KeyFile        string `mapstructure:"key_file"`
	}
	if err := viper.UnmarshalKey("bridges.saml", &entries); err != nil {
		return fmt.Errorf("bridges.saml: %w", err)
	}
	for _, e := range entries {
		b, err := bridgeproviders.NewSAML(ctx, bridgeproviders.SAMLConfig{
			Name:           e.Name,
			IDPMetadataURL: e.IDPMetadataURL,
			EntityID:       e.EntityID,
			ACSPath:        e.ACSPath,
			MetadataPath:   e.MetadataPath,
			CertFile:       e.CertFile,
			KeyFile:        e.KeyFile,
		})
		if err != nil {
			return fmt.Errorf("saml bridge %q: %w", e.Name, err)
		}
		bridges.Register(b)
		logger.Info("bridge registered", "provider", e.Name, "type", "saml")
	}
	return nil
}
