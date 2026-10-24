package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tpt-solutions/tpt-identity/internal/events"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// statusListPath is the path under which this issuer publishes its status lists.
const statusListPath = "/api/v1/status/"

// hostsStatusList reports whether a status list URL belongs to this issuer. Only lists this server
// stores can be checked or revoked here.
func (s *Server) hostsStatusList(listURL string) bool {
	return s.issuer != "" && strings.HasPrefix(listURL, s.issuer+statusListPath)
}

// activeStatusList returns the list new credentials are assigned from, creating and publishing one
// the first time it is needed.
func (s *Server) activeStatusList(ctx context.Context) (*store.StatusListRecord, error) {
	rec, err := s.store.ActiveStatusList(ctx, s.platformDID)
	if err == nil {
		return rec, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	id := vc.NewStatusListID(s.issuer)
	rec = &store.StatusListRecord{
		ID:        id,
		IssuerDID: s.platformDID,
		SizeBits:  vc.StatusListMinSize,
		Bits:      vc.NewStatusList(id, vc.StatusListMinSize).Bytes(),
	}
	if err := s.store.CreateStatusList(ctx, rec); err != nil {
		return nil, fmt.Errorf("create status list: %w", err)
	}
	if err := s.publishStatusList(ctx, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// allocateStatus gives a credential its revocation entry: the list URL and a free index.
// A list that fills up is replaced by a new one.
func (s *Server) allocateStatus(ctx context.Context) (listURL string, index int, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		rec, err := s.activeStatusList(ctx)
		if err != nil {
			return "", 0, err
		}
		idx, err := s.store.AllocateStatusIndex(ctx, rec.ID)
		if errors.Is(err, store.ErrStatusListFull) {
			continue
		}
		if err != nil {
			return "", 0, err
		}
		return rec.ID, idx, nil
	}
	return "", 0, errors.New("could not allocate a status index")
}

// publishStatusList signs the list as a BitstringStatusListCredential and stores it under the list
// URL, so the status endpoint and the verifier read the same bits.
func (s *Server) publishStatusList(ctx context.Context, rec *store.StatusListRecord) error {
	list := vc.StatusListFromBytes(rec.ID, rec.Bits)
	cred, err := list.IssueStatusListVC(s.platformDID, s.signingKey, s.signingKeyID)
	if err != nil {
		return fmt.Errorf("issue status list: %w", err)
	}
	if err := s.store.PutCredential(ctx, cred); err != nil {
		return fmt.Errorf("store status list: %w", err)
	}
	return nil
}

// statusChecker checks a credentialStatus entry against the bits this server stores. A list this
// issuer does not host cannot be checked, so the check fails closed.
func (s *Server) statusChecker() vc.StatusChecker {
	return func(st *vc.CredentialStatus) error {
		if !s.hostsStatusList(st.StatusListCredential) {
			return fmt.Errorf("status list %s is not hosted by this issuer; revocation cannot be checked", st.StatusListCredential)
		}
		rec, err := s.store.GetStatusList(context.Background(), st.StatusListCredential)
		if err != nil {
			return fmt.Errorf("status list unavailable: %w", err)
		}
		return vc.CheckStatus(rec.Bits, st)
	}
}

// handleRevokeCredential handles POST /api/v1/credentials/{id}/revoke. It sets the credential's bit,
// republishes the list, and emits credential.revoked. Revoking twice is harmless.
func (s *Server) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cred, err := s.store.GetCredential(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "credential not found")
		return
	}
	st := cred.CredentialStatus
	if st == nil {
		writeJSONError(w, http.StatusConflict, "no_status_entry", "credential has no status entry and cannot be revoked")
		return
	}
	if !s.hostsStatusList(st.StatusListCredential) {
		writeJSONError(w, http.StatusConflict, "status_list_not_hosted", "the credential's status list is not hosted by this issuer")
		return
	}
	rec, err := s.store.SetStatusBit(r.Context(), st.StatusListCredential, st.StatusListIndex)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	if err := s.publishStatusList(r.Context(), rec); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "publish_failed", err.Error())
		return
	}
	s.events.Publish(r.Context(), events.CredentialRevoked, map[string]any{
		"id":          id,
		"status_list": st.StatusListCredential,
		"index":       st.StatusListIndex,
	})
	w.WriteHeader(http.StatusNoContent)
}
