package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// handleReadiness checks that the server can serve traffic: the DB must be reachable.
// GET /readyz → 200 {"status":"ok"} or 503 {"status":"degraded"}.
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	type check struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}

	result := struct {
		Status string           `json:"status"`
		Checks map[string]check `json:"checks"`
	}{
		Status: "ok",
		Checks: make(map[string]check),
	}

	if dbOK, dbErr := s.pingStore(ctx); dbOK {
		result.Checks["database"] = check{OK: true}
	} else {
		result.Checks["database"] = check{OK: false, Error: dbErr}
		result.Status = "degraded"
	}

	// The schema must be at the version this build expects. A database behind it runs queries that
	// name columns it lacks, so the server is not ready until `tpt-identity migrate up` has run.
	if applied, latest, err := s.store.SchemaVersion(ctx); err != nil {
		result.Checks["schema"] = check{OK: false, Error: err.Error()}
		result.Status = "degraded"
	} else if applied < latest {
		result.Checks["schema"] = check{OK: false, Error: fmt.Sprintf("schema at version %d, server needs %d", applied, latest)}
		result.Status = "degraded"
	} else {
		result.Checks["schema"] = check{OK: true}
	}

	// Without the platform signing key the server cannot issue or verify anything.
	if s.signingKey != nil {
		result.Checks["signing_key"] = check{OK: true}
	} else {
		result.Checks["signing_key"] = check{OK: false, Error: "platform signing key not loaded"}
		result.Status = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	if result.Status != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(result)
}

// pingStore probes the database with a cheap read. Returns (true, "") when healthy,
// or (false, reason) when not.
func (s *Server) pingStore(ctx context.Context) (bool, string) {
	_, err := s.store.GetIdentity(ctx, "did:web:healthcheck.internal")
	if err == nil {
		return true, ""
	}
	msg := err.Error()
	// "not found" / "no rows" means the query reached the DB — it's alive.
	if strings.Contains(msg, "not found") || strings.Contains(msg, "no rows") {
		return true, ""
	}
	return false, msg
}
