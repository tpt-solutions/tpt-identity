package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/pkg/recovery"
)

// recoveryRequestTTL bounds how long a recovery request can collect approvals.
const recoveryRequestTTL = 24 * time.Hour

// recoveryCollector holds raw shares submitted for in-flight recovery requests.
// Raw shares are kept in process memory only and never written to the store, so a
// restart discards partial progress (the request must then be re-initiated).
type recoveryCollector struct {
	mu     sync.Mutex
	shares map[string]map[string]recovery.Share // requestID -> guardianDID -> share
}

func newRecoveryCollector() *recoveryCollector {
	return &recoveryCollector{shares: map[string]map[string]recovery.Share{}}
}

// add records guardian's share. It returns duplicate=true if the guardian already
// approved this request. When the count reaches threshold, it returns the collected
// shares and clears them from memory.
func (c *recoveryCollector) add(requestID, guardianDID string, share recovery.Share, threshold int) (ready []recovery.Share, count int, duplicate bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	req := c.shares[requestID]
	if req == nil {
		req = map[string]recovery.Share{}
		c.shares[requestID] = req
	}
	if _, ok := req[guardianDID]; ok {
		return nil, len(req), true
	}
	req[guardianDID] = share
	if len(req) < threshold {
		return nil, len(req), false
	}
	for _, sh := range req {
		ready = append(ready, sh)
	}
	delete(c.shares, requestID)
	return ready, len(ready), false
}

// discard drops any collected shares for requestID.
func (c *recoveryCollector) discard(requestID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.shares, requestID)
}

// hashShare is the per-guardian commitment stored at initiation: hex(sha256(share.Hex())).
func hashShare(encoded string) string {
	h := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(h[:])
}

// handleRecoveryEnrol sets up M-of-N guardian recovery for the authenticated subject.
// POST /api/v1/me/recovery/enrol
func (s *Server) handleRecoveryEnrol(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		GuardianDIDs []string `json:"guardian_dids"`
		Threshold    int      `json:"threshold"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(req.GuardianDIDs) < 2 || req.Threshold < 2 || req.Threshold > len(req.GuardianDIDs) {
		http.Error(w, "threshold must be 2..len(guardian_dids)", http.StatusBadRequest)
		return
	}

	cfg := &store.RecoveryConfig{
		SubjectDID:   subjectDID,
		Threshold:    req.Threshold,
		GuardianDIDs: req.GuardianDIDs,
		CreatedAt:    time.Now(),
	}
	if err := s.store.SaveRecoveryConfig(r.Context(), cfg); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.events.Publish(r.Context(), "recovery.enrolled", map[string]any{
		"subject_did":    subjectDID,
		"threshold":      req.Threshold,
		"guardian_count": len(req.GuardianDIDs),
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"message":        "Recovery enrolled",
		"threshold":      req.Threshold,
		"guardian_count": len(req.GuardianDIDs),
	})
}

// handleGetRecoveryConfig returns the recovery config for the authenticated subject.
// GET /api/v1/me/recovery
func (s *Server) handleGetRecoveryConfig(w http.ResponseWriter, r *http.Request) {
	subjectDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cfg, err := s.store.GetRecoveryConfig(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "no recovery config", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// handleRecoveryInitiate starts a recovery for a subject. The recovery token is
// split into Shamir shares, one per guardian. The shares are returned once, in this
// response, for out-of-band delivery to each guardian. They are never published on
// the event bus or stored in plaintext. Only the operator (API key) may call this.
// POST /api/v1/recovery/initiate
func (s *Server) handleRecoveryInitiate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectDID string `json:"subject_did"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req); err != nil || req.SubjectDID == "" {
		http.Error(w, "subject_did required", http.StatusBadRequest)
		return
	}

	cfg, err := s.store.GetRecoveryConfig(r.Context(), req.SubjectDID)
	if err != nil {
		http.Error(w, "no recovery config for subject", http.StatusNotFound)
		return
	}

	token, err := recovery.NewRecoveryToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	shares, err := recovery.Split(token, cfg.Threshold, len(cfg.GuardianDIDs))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	reqID, err := randomRecoveryID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tokenHash := sha256.Sum256(token)
	if err := s.store.SaveRecoveryRequest(r.Context(), &store.RecoveryRequest{
		ID:         reqID,
		SubjectDID: req.SubjectDID,
		StartedAt:  time.Now(),
		Commitment: hex.EncodeToString(tokenHash[:]),
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	out := make(map[string]string, len(cfg.GuardianDIDs))
	for i, guardianDID := range cfg.GuardianDIDs {
		encoded := shares[i].Hex()
		if err := s.store.SaveRecoveryShare(r.Context(), &store.RecoveryShare{
			RequestID:   reqID,
			GuardianDID: guardianDID,
			ShareHash:   hashShare(encoded),
		}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out[guardianDID] = encoded
	}

	s.events.Publish(r.Context(), "recovery.initiated", map[string]any{
		"request_id":  reqID,
		"subject_did": req.SubjectDID,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"request_id": reqID,
		"threshold":  cfg.Threshold,
		"shares":     out,
		"message":    "Deliver each share only to its guardian. Shares are shown once and are not stored in plaintext.",
	})
}

// handleRecoveryApprove records a guardian's share for a recovery request. The
// share must belong to the calling guardian and match the commitment stored at
// initiation. Once the threshold is reached, the shares are recombined and checked
// against the commitment before the request is marked completed.
// POST /api/v1/recovery/{id}/approve
func (s *Server) handleRecoveryApprove(w http.ResponseWriter, r *http.Request) {
	guardianDID, err := s.oidc.SubjectFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	requestID := r.PathValue("id")
	var req struct {
		Share string `json:"share"` // hex-encoded share, as delivered to the guardian
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req); err != nil || req.Share == "" {
		http.Error(w, "share required", http.StatusBadRequest)
		return
	}
	share, err := recovery.ParseHex(req.Share)
	if err != nil {
		http.Error(w, "malformed share", http.StatusBadRequest)
		return
	}

	recovReq, err := s.store.GetRecoveryRequest(r.Context(), requestID)
	if err != nil {
		http.Error(w, "recovery request not found", http.StatusNotFound)
		return
	}
	if recovReq.Completed {
		http.Error(w, "recovery already completed", http.StatusConflict)
		return
	}
	if time.Since(recovReq.StartedAt) > recoveryRequestTTL {
		s.recoveries.discard(requestID)
		http.Error(w, "recovery request expired", http.StatusGone)
		return
	}

	cfg, err := s.store.GetRecoveryConfig(r.Context(), recovReq.SubjectDID)
	if err != nil || !slices.Contains(cfg.GuardianDIDs, guardianDID) {
		http.Error(w, "not a guardian for this subject", http.StatusForbidden)
		return
	}

	rows, err := s.store.ListRecoveryShares(r.Context(), requestID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var expected string
	for _, row := range rows {
		if row.GuardianDID == guardianDID {
			expected = row.ShareHash
		}
	}
	if expected == "" || subtle.ConstantTimeCompare([]byte(hashShare(share.Hex())), []byte(expected)) != 1 {
		http.Error(w, "share does not match this guardian's commitment", http.StatusForbidden)
		return
	}

	ready, count, duplicate := s.recoveries.add(requestID, guardianDID, share, cfg.Threshold)
	if duplicate {
		http.Error(w, "share already submitted", http.StatusConflict)
		return
	}
	recovReq.SharesCollected = count
	_ = s.store.UpdateRecoveryRequest(r.Context(), recovReq)

	s.events.Publish(r.Context(), "recovery.approved", map[string]any{
		"request_id":       requestID,
		"guardian_did":     guardianDID,
		"shares_collected": count,
	})

	w.Header().Set("Content-Type", "application/json")
	if ready == nil {
		json.NewEncoder(w).Encode(map[string]any{
			"request_id":       requestID,
			"status":           "pending",
			"shares_collected": count,
			"threshold":        cfg.Threshold,
		})
		return
	}

	token, err := recovery.Combine(ready)
	tokenHash := sha256.Sum256(token)
	if err != nil || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(tokenHash[:])), []byte(recovReq.Commitment)) != 1 {
		// Bad shares: reset the request so it cannot be finished with these shares.
		recovReq.SharesCollected = 0
		_ = s.store.UpdateRecoveryRequest(r.Context(), recovReq)
		s.events.Publish(r.Context(), "recovery.failed", map[string]any{"request_id": requestID})
		http.Error(w, "recovered secret does not match commitment", http.StatusUnprocessableEntity)
		return
	}

	recovReq.Completed = true
	_ = s.store.UpdateRecoveryRequest(r.Context(), recovReq)
	s.events.Publish(r.Context(), "recovery.completed", map[string]any{
		"request_id":  requestID,
		"subject_did": recovReq.SubjectDID,
	})
	json.NewEncoder(w).Encode(map[string]any{
		"request_id": requestID,
		"status":     "completed",
	})
}

// handleGetRecovery returns the status of a recovery request. Operator-only.
// GET /api/v1/recovery/{id}
func (s *Server) handleGetRecovery(w http.ResponseWriter, r *http.Request) {
	recovReq, err := s.store.GetRecoveryRequest(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recovReq)
}

func randomRecoveryID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "recov_" + hex.EncodeToString(b), nil
}
