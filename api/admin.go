package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// ── Admin API (/admin/v1/) ────────────────────────────────────────────────────
// All endpoints require api_key authentication.

// handleAdminListIdentities returns a paginated list of all identities.
// GET /admin/v1/identities?limit=100&offset=0&role=user
func (s *Server) handleAdminListIdentities(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r, 100, 500)
	ids, total, err := s.store.ListIdentities(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, "list identities: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Optional role filter applied in-memory (the table is small).
	if role := r.URL.Query().Get("role"); role != "" {
		filtered := ids[:0]
		for _, id := range ids {
			if id.Role == role {
				filtered = append(filtered, id)
			}
		}
		ids = filtered
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	json.NewEncoder(w).Encode(ids)
}

// handleAdminSuspendIdentity sets an identity's role to "suspended".
// POST /admin/v1/identities/{did}/suspend
func (s *Server) handleAdminSuspendIdentity(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	id, err := s.store.GetIdentity(r.Context(), did)
	if err != nil {
		http.Error(w, "identity not found: "+err.Error(), http.StatusNotFound)
		return
	}
	id.Role = "suspended"
	id.UpdatedAt = time.Now()
	if err := s.store.UpdateIdentity(r.Context(), id); err != nil {
		http.Error(w, "update identity: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// End live sessions now; the role check in token verification blocks new use.
	s.revokeSubjectSessions(r.Context(), did)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(id)
}

// handleAdminUnsuspendIdentity restores a suspended identity's role to "user".
// POST /admin/v1/identities/{did}/unsuspend
func (s *Server) handleAdminUnsuspendIdentity(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	id, err := s.store.GetIdentity(r.Context(), did)
	if err != nil {
		http.Error(w, "identity not found: "+err.Error(), http.StatusNotFound)
		return
	}
	if id.Role == "suspended" {
		id.Role = "user"
	}
	id.UpdatedAt = time.Now()
	if err := s.store.UpdateIdentity(r.Context(), id); err != nil {
		http.Error(w, "update identity: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(id)
}

// handleAdminDeleteIdentity removes an identity and its linked credentials.
// DELETE /admin/v1/identities/{did}
func (s *Server) handleAdminDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	if _, err := s.store.GetIdentity(r.Context(), did); err != nil {
		http.Error(w, "identity not found: "+err.Error(), http.StatusNotFound)
		return
	}
	// Delete all credentials for the identity.
	creds, err := s.store.ListCredentials(r.Context(), did)
	if err == nil {
		for _, c := range creds {
			_ = s.store.DeleteCredential(r.Context(), c.ID)
		}
	}
	// Revoke all active sessions and refresh-token families.
	s.revokeSubjectSessions(r.Context(), did)
	// Remove every login method, so the account cannot be reached through any bridge.
	if links, err := s.store.ListExternalLinks(r.Context(), did); err == nil {
		for _, l := range links {
			_ = s.store.DeleteExternalLink(r.Context(), l.Provider, l.ExternalID)
			if l.Provider == "password" {
				_ = s.store.DeletePasswordHash(r.Context(), l.ExternalID)
			}
		}
	}
	_ = s.store.DeleteDuressConfig(r.Context(), did)
	// The Identity row itself — overwrite role to mark as deleted so audit history is preserved.
	id := &store.Identity{
		DID:       did,
		Role:      "deleted",
		UpdatedAt: time.Now(),
	}
	if err := s.store.UpdateIdentity(r.Context(), id); err != nil {
		http.Error(w, "update identity: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminListClients returns all registered OIDC clients.
// GET /admin/v1/clients
func (s *Server) handleAdminListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		http.Error(w, "list clients: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(len(clients)))
	json.NewEncoder(w).Encode(clients)
}

// handleAdminDeleteClient removes a registered OIDC client.
// DELETE /admin/v1/clients/{id}
func (s *Server) handleAdminDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("id")
	if err := s.store.DeleteClient(r.Context(), clientID); err != nil {
		http.Error(w, "delete client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminClearLockout clears the brute-force lockout for a subject or email.
// POST /admin/v1/lockout/{subject}/clear
func (s *Server) handleAdminClearLockout(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := s.store.ClearAuthFailures(r.Context(), subject); err != nil {
		http.Error(w, "clear lockout: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminStats returns basic platform statistics.
// GET /admin/v1/stats
func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	_, identityTotal, err := s.store.ListIdentities(r.Context(), 0, 0)
	if err != nil {
		http.Error(w, "stats: "+err.Error(), http.StatusInternalServerError)
		return
	}
	clients, err := s.store.ListClients(r.Context())
	clientCount := 0
	if err == nil {
		clientCount = len(clients)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"identity_count": identityTotal,
		"client_count":   clientCount,
	})
}
