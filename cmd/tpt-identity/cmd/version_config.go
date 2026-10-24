package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version is the release version. Set it at build time with
// -ldflags "-X github.com/tpt-solutions/tpt-identity/cmd/tpt-identity/cmd.Version=v0.x.y".
var Version = "dev"

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the tpt-identity version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "tpt-identity %s\n", Version)
		},
	}
}

func configCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Inspect the configuration file",
	}
	c.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Check the configuration file and report every problem found",
		Long: `Reads the config file (and TPT_IDENTITY_* environment overrides) and reports
each problem: missing secrets, a non-https issuer, bad durations, malformed scoped keys
and missing key files. Warnings do not fail the check. The command exits non-zero on errors.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true, // a failed check reports its problems, not the usage text
		RunE: func(cmd *cobra.Command, _ []string) error {
			problems := validateConfig(cfgFile)
			out := cmd.OutOrStdout()
			var errs []string
			for _, p := range problems {
				fmt.Fprintf(out, "%-7s %s\n", p.level, p.msg)
				if p.level == "error" {
					errs = append(errs, p.msg)
				}
			}
			if len(problems) == 0 {
				fmt.Fprintln(out, "ok: configuration is valid")
			}
			if len(errs) > 0 {
				return fmt.Errorf("%d configuration error(s)", len(errs))
			}
			return nil
		},
	})
	return c
}

type configProblem struct {
	level string // "error" or "warning"
	msg   string
}

// validateConfig loads path and returns every problem found, in a stable order.
func validateConfig(path string) []configProblem {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("TPT_IDENTITY")
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		return []configProblem{{"error", fmt.Sprintf("cannot read %s: %v", path, err)}}
	}

	var out []configProblem
	add := func(level, format string, args ...any) {
		out = append(out, configProblem{level, fmt.Sprintf(format, args...)})
	}

	if v.GetString("api_key") == "" {
		add("error", "api_key is not set (the server refuses to start without it)")
	}
	if v.GetString("admin_api_key") == "" {
		add("warning", "admin_api_key is not set; admin endpoints accept the master api_key")
	}
	if err := validateIssuer(v.GetString("issuer")); err != nil {
		add("error", "%v", err)
	}

	for _, key := range []string{"oidc.code_ttl", "oidc.id_token_ttl", "oidc.access_token_ttl", "oidc.refresh_token_ttl"} {
		if !v.IsSet(key) {
			continue
		}
		if d := v.GetDuration(key); d <= 0 {
			add("error", "%s must be a positive duration such as \"5m\" or \"720h\"", key)
		}
	}

	var scoped []struct {
		Name   string   `mapstructure:"name"`
		Key    string   `mapstructure:"key"`
		Scopes []string `mapstructure:"scopes"`
	}
	if v.IsSet("scoped_api_keys") {
		if err := v.UnmarshalKey("scoped_api_keys", &scoped); err != nil {
			add("error", "scoped_api_keys is malformed: %v", err)
		}
	}
	for i, k := range scoped {
		label := k.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		switch {
		case k.Key == "":
			add("error", "scoped_api_keys %s has no key", label)
		case len(k.Key) < 16:
			add("warning", "scoped_api_keys %s has a short key (under 16 characters)", label)
		}
		if len(k.Scopes) == 0 {
			add("error", "scoped_api_keys %s grants no scopes", label)
		}
	}

	if signingKey := v.GetString("identity.signing_key"); signingKey != "" {
		if _, err := os.Stat(signingKey); err != nil {
			add("error", "identity.signing_key %q: %v (generate keys with tpt-identity keygen)", signingKey, err)
		}
	} else {
		add("error", "identity.signing_key is not set")
	}

	if v.GetDuration("oidc.access_token_ttl") > 24*time.Hour {
		add("warning", "oidc.access_token_ttl is longer than 24h; short access tokens limit the damage of a leak")
	}
	if strings.TrimSpace(v.GetString("bridge_secret")) == "" {
		add("warning", "bridge_secret is not set; in-flight bridge logins will not survive a restart")
	}
	return out
}
