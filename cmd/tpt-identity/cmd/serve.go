package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tpt-solutions/tpt-identity/api"
	"github.com/tpt-solutions/tpt-identity/internal/auditlog"
	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	bridgeproviders "github.com/tpt-solutions/tpt-identity/internal/bridge/providers"
	"github.com/tpt-solutions/tpt-identity/internal/events"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
	"github.com/tpt-solutions/tpt-identity/pkg/marketplace"
	// Import all core schemas so their init() functions register at startup.
	_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func serveCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "serve",
		Short: "Start the tpt-identity server",
		RunE: func(cmd *cobra.Command, args []string) error {
			viper.SetConfigFile(cfgFile)
			viper.SetEnvPrefix("TPT_IDENTITY")
			viper.AutomaticEnv()
			if err := viper.ReadInConfig(); err != nil {
				return fmt.Errorf("read config: %w", err)
			}
			// Admin and metrics endpoints are gated by api_key; refuse to start without one
			// rather than exposing them unauthenticated.
			if viper.GetString("api_key") == "" {
				return fmt.Errorf("api_key must be set in config (or TPT_IDENTITY_API_KEY)")
			}

			logLevel := new(slog.LevelVar)
			switch viper.GetString("log.level") {
			case "debug":
				logLevel.Set(slog.LevelDebug)
			case "warn", "warning":
				logLevel.Set(slog.LevelWarn)
			case "error":
				logLevel.Set(slog.LevelError)
			default:
				logLevel.Set(slog.LevelInfo)
			}
			var logHandler slog.Handler
			if viper.GetString("log.format") == "text" {
				logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
			} else {
				logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
			}
			logger := slog.New(logHandler)

			db, err := store.OpenSQLite(viper.GetString("db_path"))
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()

			ks, err := keystore.LoadSigning(
				viper.GetString("identity.signing_key"),
				viper.GetString("identity.passphrase"),
			)
			if err != nil {
				return fmt.Errorf("load signing key: %w", err)
			}

			// Load X25519 encryption key for DIDComm v2 (optional).
			encKeyPath := viper.GetString("identity.enc_key")
			if encKeyPath != "" {
				if err := keystore.LoadEncryption(ks, encKeyPath, viper.GetString("identity.passphrase")); err != nil {
					return fmt.Errorf("load enc key: %w", err)
				}
			}

			issuer := viper.GetString("issuer")
			// Key IDs are fragments of the platform did:web, so verifiers can resolve them
			// from /.well-known/did.json.
			platformDID, err := api.PlatformDID(issuer)
			if err != nil {
				return fmt.Errorf("issuer: %w", err)
			}
			keyID := viper.GetString("identity.key_id")
			if keyID == "" {
				keyID = platformDID + "#signing-key-1"
			}
			encKeyID := viper.GetString("identity.enc_key_id")
			if encKeyID == "" && ks.HasEnc {
				encKeyID = platformDID + "#enc-key-1"
			}

			res := resolver.New(5 * time.Minute)
			oidcProvider := oidc.NewProvider(issuer, ks.SigningPriv, keyID, db)

			// ── Build bridge manager ──────────────────────────────────────
			bridges := bridge.NewManager()

			// OIDC relying-party bridges (e.g. Google, GitHub, Azure AD).
			type oidcBridgeCfg struct {
				Name         string   `mapstructure:"name"`
				Issuer       string   `mapstructure:"issuer"`
				ClientID     string   `mapstructure:"client_id"`
				ClientSecret string   `mapstructure:"client_secret"`
				Scopes       []string `mapstructure:"scopes"`
			}
			var oidcBridges []oidcBridgeCfg
			if err := viper.UnmarshalKey("bridges.oidc", &oidcBridges); err == nil {
				for _, bc := range oidcBridges {
					rp := bridgeproviders.NewOIDCRP(bridgeproviders.OIDCRPConfig{
						Name:            bc.Name,
						Issuer:          bc.Issuer,
						ClientID:        bc.ClientID,
						ClientSecret:    bc.ClientSecret,
						Scopes:          bc.Scopes,
						RedirectBaseURL: issuer,
					})
					bridges.Register(rp)
					logger.Info("bridge registered", "provider", bc.Name, "type", "oidc_rp")
				}
			}

			// Magic link bridge is always available.
			bridges.Register(bridgeproviders.NewMagicLink(db))
			logger.Info("bridge registered", "provider", "magiclink-email", "type", "magic_link")

			// Password bridge — opt-in only.
			if viper.GetBool("bridges.password.enabled") {
				bridges.Register(bridgeproviders.NewPasswordBridge(db))
				logger.Info("bridge registered", "provider", "password", "type", "password")
			}

			// TOTP passphrase — fall back to signing key passphrase if not set.
			totpPassphrase := viper.GetString("totp_passphrase")
			if totpPassphrase == "" {
				totpPassphrase = viper.GetString("identity.passphrase")
			}

			// ── Event bus ────────────────────────────────────────────────
			eventBus := events.NewBus(db, logger)

			// ── Audit log (subscribes to all events) ─────────────────────
			auditLogger := auditlog.New(db, logger)
			auditLogger.Subscribe(eventBus)

			// ── Credential marketplace ────────────────────────────────────
			var market *marketplace.Registry
			if viper.GetBool("marketplace.advertise") {
				market = marketplace.New()
				// Subscribe to credential.issued to track issuance counts.
				eventBus.Subscribe(func(ctx context.Context, event events.Event) {
					if event.Type != events.CredentialIssued {
						return
					}
					if p, ok := event.Payload.(map[string]string); ok {
						market.RecordIssuance(p["issuer_did"], p["schema_id"])
					}
				})
				logger.Info("marketplace enabled")
			}

			srv := api.NewServer(api.Config{
				APIKey:             viper.GetString("api_key"),
				BridgeSecret:       viper.GetString("bridge_secret"),
				Issuer:             issuer,
				TotpPassphrase:     totpPassphrase,
				SigningKey:         ks.SigningPriv,
				SigningKeyID:       keyID,
				EncKey:             ks.EncPriv,
				EncKeyID:           encKeyID,
				Store:              db,
				Resolver:           res,
				OIDC:               oidcProvider,
				Bridges:            bridges,
				Events:             eventBus,
				Logger:             logger,
				RateLimit:          viper.GetFloat64("rate_limit"),
				TrustedProxies:     viper.GetStringSlice("server.trusted_proxies"),
				CORSAllowedOrigins: viper.GetStringSlice("cors.allowed_origins"),
				Marketplace:        market,
			})

			// ── Consent expiry warning goroutine ──────────────────────────
			warningDays := viper.GetInt("consent.expiry_warning_days")
			if warningDays == 0 {
				warningDays = 7
			}
			go func() {
				ticker := time.NewTicker(24 * time.Hour)
				defer ticker.Stop()
				for range ticker.C {
					within := time.Duration(warningDays) * 24 * time.Hour
					grants, err := db.ListExpiringGrants(context.Background(), within)
					if err != nil {
						logger.Warn("consent expiry check failed", "err", err)
						continue
					}
					for _, g := range grants {
						eventBus.Publish(context.Background(), "consent.expiring_soon", map[string]any{
							"grant_id":    g.ID,
							"subject_did": g.SubjectDID,
							"schema_id":   g.ScopeID,
							"expires_at":  g.ExpiresAt,
						})
					}
				}
			}()

			addr := viper.GetString("listen_addr")
			if addr == "" {
				addr = ":8080"
			}
			// Timeouts bound slow-client resource use. Shutdown drains in-flight requests on SIGINT/SIGTERM.
			httpSrv := &http.Server{
				Addr:              addr,
				Handler:           srv,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       120 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}
			logger.Info("tpt-identity server starting", "addr", addr, "issuer", issuer)

			stop, cancelSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancelSignals()
			errCh := make(chan error, 1)
			go func() { errCh <- httpSrv.ListenAndServe() }()

			select {
			case err := <-errCh:
				return err
			case <-stop.Done():
			}
			logger.Info("shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return httpSrv.Shutdown(shutdownCtx)
		},
	}
	return c
}
