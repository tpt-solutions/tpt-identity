package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func errorsOf(problems []configProblem) []string {
	var msgs []string
	for _, p := range problems {
		if p.level == "error" {
			msgs = append(msgs, p.msg)
		}
	}
	return msgs
}

func TestHostProblemsReportsMissingDBDirectory(t *testing.T) {
	db := filepath.Join(t.TempDir(), "missing", "identity.db")
	errs := errorsOf(hostProblems(db, "", ":8080"))
	if len(errs) != 1 || !strings.Contains(errs[0], "does not exist") {
		t.Fatalf("want one missing-directory error, got %v", errs)
	}
}

func TestHostProblemsAcceptsExistingDBDirectory(t *testing.T) {
	db := filepath.Join(t.TempDir(), "identity.db")
	if errs := errorsOf(hostProblems(db, "", ":8080")); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestHostProblemsRequiresDBPath(t *testing.T) {
	errs := errorsOf(hostProblems("", "", ":8080"))
	if len(errs) != 1 || !strings.Contains(errs[0], "db_path is not set") {
		t.Fatalf("want db_path error, got %v", errs)
	}
}

func TestHostProblemsReportsMissingEncKey(t *testing.T) {
	db := filepath.Join(t.TempDir(), "identity.db")
	errs := errorsOf(hostProblems(db, filepath.Join(t.TempDir(), "x25519.pem"), ":8080"))
	if len(errs) != 1 || !strings.Contains(errs[0], "identity.enc_key") {
		t.Fatalf("want enc_key error, got %v", errs)
	}
}

func TestHostProblemsRejectsBadListenAddr(t *testing.T) {
	db := filepath.Join(t.TempDir(), "identity.db")
	errs := errorsOf(hostProblems(db, "", "8080"))
	if len(errs) != 1 || !strings.Contains(errs[0], "listen_addr") {
		t.Fatalf("want listen_addr error, got %v", errs)
	}
}

func TestRootRegistersEachCommandOnce(t *testing.T) {
	seen := map[string]int{}
	for _, c := range Root().Commands() {
		seen[c.Name()]++
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("command %q registered %d times", name, n)
		}
	}
	if seen["doctor"] != 1 {
		t.Error("doctor command not registered")
	}
}

func TestHostProblemsSkipsDirectoryCheckForPostgres(t *testing.T) {
	// A postgres:// URL names a server, not a file, so no local directory is required.
	if errs := errorsOf(hostProblems("postgres://tpt:x@127.0.0.1:1/tpt", "", ":8080")); len(errs) != 0 {
		t.Fatalf("postgres DSN produced host errors: %v", errs)
	}
}
