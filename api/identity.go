package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/tpt-solutions/tpt-identity/pkg/keystore"
)

type createIdentityRequest struct {
	Method string `json:"method"` // "web", "key", "peer"
	Domain string `json:"domain"` // required for did:web
}

// createIdentityResponse carries the new DID and, once, its private keys. The server does
// not keep them: whoever creates the identity must store them.
type createIdentityResponse struct {
	DID      string        `json:"did"`
	Document *did.Document `json:"document"`
	Keys     identityKeys  `json:"private_keys"`
	Warning  string        `json:"warning"`
}

type identityKeys struct {
	// Ed25519Seed is the 32-byte signing seed, base64 (standard encoding).
	Ed25519Seed string `json:"ed25519_seed"`
	// X25519Private is the 32-byte key-agreement scalar, base64 (standard encoding).
	X25519Private string `json:"x25519_private"`
}

// handleCreateIdentity creates a DID and its document in one transaction. The private
// keys are returned once in the response. POST /api/v1/identities (operator key required).
func (s *Server) handleCreateIdentity(w http.ResponseWriter, r *http.Request) {
	var req createIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ks, err := keystore.Generate()
	if err != nil {
		http.Error(w, "keygen failed", http.StatusInternalServerError)
		return
	}
	id, doc, err := did.Create(req.Method, did.CreateOptions{
		Domain:     req.Domain,
		SigningPub: ks.SigningPub,
		EncPub:     ks.EncPub[:],
	})
	if err != nil {
		http.Error(w, "create DID: "+err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now()
	identity := &store.Identity{
		DID:       id,
		Method:    req.Method,
		TenantID:  callerTenant(r),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreateIdentityWithDocument(r.Context(), identity, doc); err != nil {
		http.Error(w, "save identity", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createIdentityResponse{
		DID:      id,
		Document: doc,
		Keys: identityKeys{
			Ed25519Seed:   base64.StdEncoding.EncodeToString(ks.SigningPriv.Seed()),
			X25519Private: base64.StdEncoding.EncodeToString(ks.EncPriv[:]),
		},
		Warning: "Store the private keys now. They are not kept on the server and are not returned again.",
	})
}

// callerOwns reports whether the caller may act on the records of did. A platform key may act on
// any record. A tenant key may act only on identities of its own tenant, so an unknown DID is
// refused too; the caller gets the same answer whether the DID is absent or belongs to another tenant.
func (s *Server) callerOwns(r *http.Request, did string) bool {
	tenant := callerTenant(r)
	if tenant == "" {
		return true
	}
	stored, err := s.store.GetIdentity(r.Context(), did)
	return err == nil && stored.TenantID == tenant
}

// handleGetIdentity resolves a DID document. A tenant key sees only identities of its own tenant;
// anything else answers 404 so the response does not reveal that another tenant holds the DID.
func (s *Server) handleGetIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("did")
	if !s.callerOwns(r, id) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	doc, err := s.resolver.Resolve(id)
	if err != nil {
		http.Error(w, "resolve: "+err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	_ = json.NewEncoder(w).Encode(doc)
}
