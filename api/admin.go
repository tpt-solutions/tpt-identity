package api

import (
	"context"
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
	role := r.URL.Query().Get("role")
	if role == "" {
		ids, total, err := s.store.ListIdentities(r.Context(), limit, offset)
		if err != nil {
			http.Error(w, "list identities: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
		_ = json.NewEncoder(w).Encode(ids)
		return
	}

	// A role filter must apply before pagination, or pages come back short and the total is wrong.
	// Scan the table in batches and keep the matches.
	var matches []*store.Identity
	const batch = 500
	for scan := 0; ; scan += batch {
		page, _, err := s.store.ListIdentities(r.Context(), batch, scan)
		if err != nil {
			http.Error(w, "list identities: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, id := range page {
			if id.Role == role {
				matches = append(matches, id)
			}
		}
		if len(page) < batch {
			break
		}
	}
	end := min(offset+limit, len(matches))
	page := []*store.Identity{}
	if offset < len(matches) {
		page = matches[offset:end]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(len(matches)))
	_ = json.NewEncoder(w).Encode(page)
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
	if id.Role == "deactivated" {
		http.Error(w, "a deactivated identity cannot be suspended; it is already unusable", http.StatusConflict)
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
	s.auditAdmin(r.Context(), r, "identity.suspended", did)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(id)
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
	if id.Role == "deactivated" {
		http.Error(w, "a deactivated identity cannot be reactivated", http.StatusConflict)
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
	s.auditAdmin(r.Context(), r, "identity.unsuspended", did)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(id)
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
	s.auditAdmin(r.Context(), r, "identity.deleted", did)
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
	_ = json.NewEncoder(w).Encode(clients)
}

// handleAdminDeleteClient removes a registered OIDC client.
// DELETE /admin/v1/clients/{id}
func (s *Server) handleAdminDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("id")
	if err := s.store.DeleteClient(r.Context(), clientID); err != nil {
		http.Error(w, "delete client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditAdmin(r.Context(), r, "client.deleted", clientID)
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
	s.auditAdmin(r.Context(), r, "lockout.cleared", subject)
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
	_ = json.NewEncoder(w).Encode(map[string]int{
		"identity_count": identityTotal,
		"client_count":   clientCount,
	})
}

// auditAdmin records an administrative action in the verifiable audit log, through the event bus. Admin
// calls carry an API key, not a user identity, so the actor is recorded as the admin credential. The
// key itself is never recorded.
func (s *Server) auditAdmin(ctx context.Context, r *http.Request, action, target string) {
	s.events.Publish(ctx, "admin."+action, map[string]string{
		"actor":  "admin-credential",
		"target": target,
		"ip":     s.clientIP(r),
	})
}
