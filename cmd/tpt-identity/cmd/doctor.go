package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/tpt-solutions/tpt-identity/internal/store"
)

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the config and the host before the first start",
		Long: `Runs every config check from "config validate", then checks what the server needs at
runtime: the database (the SQLite directory, or that the PostgreSQL server answers), the DIDComm
key file and the listen address. Each problem is printed with the step that fixes it. The command exits non-zero when an error is found.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true, // a failed check reports its problems, not the usage text
		RunE: func(cmd *cobra.Command, _ []string) error {
			problems := validateConfig(cfgFile)
			// Host checks need the values from the file. When it cannot be read, the config
			// error above is the only useful report.
			if cfg, err := readConfig(cfgFile); err == nil {
				dsn := cfg.GetString("db_path")
				problems = append(problems, hostProblems(dsn, cfg.GetString("identity.enc_key"), cfg.GetString("listen_addr"))...)
				if store.IsPostgresDSN(dsn) {
					problems = append(problems, databaseProblems(dsn)...)
				}
			}
			out := cmd.OutOrStdout()
			var errs int
			for _, p := range problems {
				if _, err := fmt.Fprintf(out, "%-7s %s\n", p.level, p.msg); err != nil {
					return err
				}
				if p.level == "error" {
					errs++
				}
			}
			if len(problems) == 0 {
				if _, err := fmt.Fprintln(out, "ok: no problems found"); err != nil {
					return err
				}
			}
			if errs > 0 {
				return fmt.Errorf("%d problem(s) must be fixed before the server starts", errs)
			}
			return nil
		},
	}
}

// hostProblems checks the runtime requirements that the config file alone cannot show: the
// database directory must exist so SQLite can create its file, the DIDComm key file must be
// readable when it is configured, and the listen address must parse.
func hostProblems(dbPath, encKey, listenAddr string) []configProblem {
	var out []configProblem
	add := func(level, format string, args ...any) {
		out = append(out, configProblem{level, fmt.Sprintf(format, args...)})
	}

	switch {
	case dbPath == "":
		add("error", "db_path is not set; set it to a SQLite file path or a postgres:// URL")
	case store.IsPostgresDSN(dbPath):
		// The server connects to PostgreSQL; databaseProblems checks that it answers.
	default:
		if dir := filepath.Dir(dbPath); dir != "." {
			if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
				add("error", "db_path %q: directory %q does not exist; create it or change db_path", dbPath, dir)
			}
		}
	}

	if encKey != "" {
		if _, err := os.Stat(encKey); err != nil {
			add("error", "identity.enc_key %q: %v (generate keys with tpt-identity keygen)", encKey, err)
		}
	}

	if listenAddr != "" {
		if _, _, err := net.SplitHostPort(listenAddr); err != nil {
			add("error", "listen_addr %q is not host:port (for example \":8080\")", listenAddr)
		}
	}
	return out
}

// databaseProblems checks that a PostgreSQL server named by dsn answers. It does not create the
// schema or any table: doctor only reports whether the server the config names is reachable.
func databaseProblems(dsn string) []configProblem {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return []configProblem{{"error", fmt.Sprintf("db_path: invalid postgres:// URL: %v", err)}}
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return []configProblem{{"error", fmt.Sprintf("db_path: cannot reach PostgreSQL (%v); check the host, port, credentials and that the server accepts connections", err)}}
	}
	return nil
}
