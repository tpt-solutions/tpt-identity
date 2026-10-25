package cmd

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	_ "modernc.org/sqlite" // database/sql driver for the migration runner

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/internal/store/migrations"
	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
)

// passphraseEnv names the environment variable that supplies the key passphrase for the prod profile.
// It is read from the environment so the passphrase does not land in shell history.
const passphraseEnv = "TPT_IDENTITY_PASSPHRASE"

func initCmd() *cobra.Command {
	var (
		dir     string
		profile string
		issuer  string
		force   bool
	)
	c := &cobra.Command{
		Use:   "init",
		Short: "Create keys, a config file with fresh secrets, and the database",
		Long: `init writes everything a new deployment needs into --dir:

  keys/ed25519.pem, keys/x25519.pem   signing and encryption keys
  config.yaml                         api_key, admin_api_key and bridge_secret, freshly random
  tpt-identity.db                     the schema, with migrations recorded

Profiles:
  dev   plaintext keys; an http://localhost issuer is allowed. For local work only.
  prod  an https issuer and keys encrypted with the passphrase in ` + passphraseEnv + `.

init refuses to overwrite an existing config.yaml unless --force is given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd, initOptions{Dir: dir, Profile: profile, Issuer: issuer, Force: force})
		},
	}
	c.Flags().StringVar(&dir, "dir", ".", "directory to write into")
	c.Flags().StringVar(&profile, "profile", "dev", "dev or prod")
	c.Flags().StringVar(&issuer, "issuer", "", "canonical issuer URL (default http://localhost:8080 for dev)")
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing config.yaml")
	return c
}

type initOptions struct {
	Dir     string
	Profile string
	Issuer  string
	Force   bool
}

func runInit(cmd *cobra.Command, opts initOptions) error {
	out := cmd.OutOrStdout()
	if opts.Profile != "dev" && opts.Profile != "prod" {
		return fmt.Errorf("profile must be dev or prod, not %q", opts.Profile)
	}
	issuer := opts.Issuer
	if issuer == "" {
		if opts.Profile == "prod" {
			return errors.New("prod needs --issuer: the canonical https URL of this server")
		}
		issuer = "http://localhost:8080"
	}
	if err := validateIssuer(issuer); err != nil {
		return err
	}
	if opts.Profile == "prod" {
		if u, _ := url.Parse(issuer); u == nil || u.Scheme != "https" {
			return fmt.Errorf("prod needs an https issuer, got %q", issuer)
		}
	}

	passphrase := ""
	if opts.Profile == "prod" {
		passphrase = os.Getenv(passphraseEnv)
		if passphrase == "" {
			return fmt.Errorf("prod keys are encrypted: set %s to the passphrase", passphraseEnv)
		}
	}

	cfgPath := filepath.Join(opts.Dir, "config.yaml")
	if _, err := os.Stat(cfgPath); err == nil && !opts.Force {
		return fmt.Errorf("%s already exists; use --force to overwrite it", cfgPath)
	}
	if err := os.MkdirAll(filepath.Join(opts.Dir, "keys"), 0o700); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}

	secrets := make(map[string]string, 3)
	for _, name := range []string{"api_key", "admin_api_key", "bridge_secret"} {
		v, err := randomSecret()
		if err != nil {
			return err
		}
		secrets[name] = v
	}

	signPath := filepath.Join(opts.Dir, "keys", "ed25519.pem")
	encPath := filepath.Join(opts.Dir, "keys", "x25519.pem")
	ks, err := keystore.Generate()
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}
	if err := keystore.SaveSigning(ks, signPath, passphrase); err != nil {
		return fmt.Errorf("save signing key: %w", err)
	}
	if err := keystore.SaveEncryption(ks, encPath, passphrase); err != nil {
		return fmt.Errorf("save encryption key: %w", err)
	}

	dbPath := filepath.Join(opts.Dir, "tpt-identity.db")
	if err := initSchema(dbPath); err != nil {
		return err
	}

	cfg := renderConfig(configValues{
		Issuer:  issuer,
		DBPath:  dbPath,
		SignKey: signPath,
		EncKey:  encPath,
		Secrets: secrets,
	})
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Wrote %s, %s, %s and %s.\n", cfgPath, signPath, encPath, dbPath)
	if opts.Profile == "dev" {
		_, _ = fmt.Fprintln(out, "Keys are plaintext. Do not use this profile in production.")
	} else {
		_, _ = fmt.Fprintln(out, "Keys are encrypted. Give serve the passphrase with TPT_IDENTITY_IDENTITY_PASSPHRASE; it is not written to the config.")
	}
	_, _ = fmt.Fprintf(out, "Next: tpt-identity config validate --config %s, then tpt-identity serve --config %s\n", cfgPath, cfgPath)
	return nil
}

// initSchema creates the tables and records the migration versions, so that a new install's schema
// and its version record agree.
func initSchema(dbPath string) error {
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	if err := st.Close(); err != nil {
		return fmt.Errorf("close store: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if err := migrations.Up(db); err != nil {
		return fmt.Errorf("record migrations: %w", err)
	}
	return nil
}

// randomSecret returns 32 random bytes, hex-encoded: a 64-character secret.
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

type configValues struct {
	Issuer  string
	DBPath  string
	SignKey string
	EncKey  string
	Secrets map[string]string
}

// renderConfig writes a complete config.yaml. Values are quoted, so a path or secret can never break
// the YAML structure.
func renderConfig(v configValues) string {
	q := strconv.Quote
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by tpt-identity init. Keep this file private: it holds secrets.\n")
	fmt.Fprintf(&b, "issuer: %s\n", q(v.Issuer))
	fmt.Fprintf(&b, "db_path: %s\n", q(v.DBPath))
	fmt.Fprintf(&b, "listen_addr: \":8080\"\n")
	fmt.Fprintf(&b, "api_key: %s\n", q(v.Secrets["api_key"]))
	fmt.Fprintf(&b, "admin_api_key: %s\n", q(v.Secrets["admin_api_key"]))
	fmt.Fprintf(&b, "bridge_secret: %s\n", q(v.Secrets["bridge_secret"]))
	fmt.Fprintf(&b, "identity:\n")
	fmt.Fprintf(&b, "  signing_key: %s\n", q(v.SignKey))
	fmt.Fprintf(&b, "  enc_key: %s\n", q(v.EncKey))
	fmt.Fprintf(&b, "  passphrase: \"\"\n")
	fmt.Fprintf(&b, "log:\n  level: \"info\"\n  format: \"json\"\n")
	return b.String()
}
