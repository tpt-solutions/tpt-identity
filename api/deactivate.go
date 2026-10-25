package api

import (
	"context"
	"net/http"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// roleDeactivated is the identity role of a deactivated DID. Unlike suspension, it cannot be undone.
const roleDeactivated = "deactivated"

// handleAdminDeactivateIdentity permanently deactivates a DID (DID Core §3.6). The identity loses
// access at once, and its DID document resolves with no keys, so no verifier can accept anything
// the identity signs from now on. The stored document is kept for the audit trail. Deactivating an
// identity twice is harmless.
// POST /admin/v1/identities/{did}/deactivate
func (s *Server) handleAdminDeactivateIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("did")
	ident, err := s.store.GetIdentity(r.Context(), id)
	if err != nil {
		http.Error(w, "identity not found", http.StatusNotFound)
		return
	}
	if ident.Role != roleDeactivated {
		ident.Role = roleDeactivated
		ident.UpdatedAt = time.Now()
		if err := s.store.UpdateIdentity(r.Context(), ident); err != nil {
			http.Error(w, "update identity: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.revokeSubjectSessions(r.Context(), id)
	s.auditAdmin(r.Context(), r, "identity.deactivated", id)
	w.WriteHeader(http.StatusNoContent)
}

// hostedDocument is what resolution answers for a DID this server hosts. A deactivated DID resolves to
// an empty document, so no key is published for it. Any other hosted DID resolves to its stored document.
func (s *Server) hostedDocument(ctx context.Context, id string) (*did.Document, bool) {
	ident, err := s.store.GetIdentity(ctx, id)
	if err == nil && ident.Role == roleDeactivated {
		return &did.Document{Context: did.DefaultContext(), ID: id, Deactivated: true}, true
	}
	doc, err := s.store.GetDocument(ctx, id)
	if err != nil || doc == nil {
		return nil, false
	}
	return doc, true
}
