package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/multiformats/go-multibase"

	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/tpt-solutions/tpt-identity/pkg/didcomm"
)

// handleDIDCommReceive handles POST /didcomm.
// It decrypts an incoming DIDComm v2 JWE envelope addressed to the platform DID,
// parses the plaintext message, and returns 202 Accepted with the message metadata.
func (s *Server) handleDIDCommReceive(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if ct != didcomm.MediaTypeEncrypted && !strings.HasPrefix(ct, didcomm.MediaTypeEncrypted+";") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "invalid_media_type",
			"Content-Type must be "+didcomm.MediaTypeEncrypted)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read_error", "failed to read request body")
		return
	}

	if s.encKeyID == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "not_configured",
			"DIDComm encryption key not configured; set identity.enc_key in config")
		return
	}

	recipKeyFn := func(kid string) ([32]byte, error) {
		if kid == s.encKeyID {
			return s.encKey, nil
		}
		return [32]byte{}, fmt.Errorf("unknown recipient key: %s", kid)
	}

	senderPubFn := func(skid string) ([32]byte, error) {
		// skid format: "did:method:...#fragment"
		hashIdx := strings.LastIndex(skid, "#")
		if hashIdx < 0 {
			return [32]byte{}, fmt.Errorf("invalid sender key ID: %s", skid)
		}
		didStr := skid[:hashIdx]
		doc, err := s.resolver.Resolve(didStr)
		if err != nil {
			return [32]byte{}, fmt.Errorf("resolve sender DID %s: %w", didStr, err)
		}
		return extractX25519KeyFromDoc(doc, skid)
	}

	plaintext, senderKID, err := didcomm.Unpack(body, recipKeyFn, senderPubFn)
	if err != nil {
		s.logger.Warn("didcomm: decryption failed",
			"ip", s.clientIP(r),
			"err", err,
		)
		writeJSONError(w, http.StatusBadRequest, "decryption_failed", "failed to decrypt envelope")
		return
	}

	var msg didcomm.Message
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_message", "decrypted content is not a valid DIDComm message")
		return
	}

	s.logger.Info("didcomm message received",
		"message_id", msg.ID,
		"type", msg.Type,
		"from", msg.From,
		"sender_kid", senderKID,
		"ip", s.clientIP(r),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message_id": msg.ID,
		"type":       msg.Type,
	})
}

// extractX25519KeyFromDoc finds an X25519KeyAgreementKey2020 in doc by key ID and
// returns its 32-byte raw public key.
func extractX25519KeyFromDoc(doc *did.Document, kid string) ([32]byte, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.ID != kid {
			continue
		}
		if vm.Type != "X25519KeyAgreementKey2020" {
			return [32]byte{}, fmt.Errorf("key %q has type %q, want X25519KeyAgreementKey2020", kid, vm.Type)
		}
		if vm.PublicKeyMultibase == nil {
			return [32]byte{}, fmt.Errorf("key %q has no publicKeyMultibase", kid)
		}
		return decodeX25519Multibase(*vm.PublicKeyMultibase)
	}
	return [32]byte{}, fmt.Errorf("key %q not found in DID document", kid)
}

// decodeX25519Multibase decodes a multibase-encoded X25519 public key.
// Supports standard multibase (z = base58btc) and the base64url-with-prefix-u
// or prefix-z encoding used by did:peer in this codebase.
func decodeX25519Multibase(mb string) ([32]byte, error) {
	if len(mb) < 2 {
		return [32]byte{}, errors.New("x25519 key too short")
	}
	_, raw, err := multibase.Decode(mb)
	if err != nil {
		// Fallback: try base64url-nopad regardless of the prefix character.
		// did:peer in this codebase stores enc keys as prefix + base64url(multicodec||key).
		raw, err = base64.RawURLEncoding.DecodeString(mb[1:])
		if err != nil {
			return [32]byte{}, fmt.Errorf("decode x25519 key multibase: %w", err)
		}
	}
	// Expect multicodec prefix for x25519-pub: 0xEC 0x01 (varint 236), then 32 key bytes.
	if len(raw) < 34 || raw[0] != 0xEC || raw[1] != 0x01 {
		return [32]byte{}, errors.New("x25519 key has unexpected multicodec prefix (expected x25519-pub 0xEC 0x01)")
	}
	var out [32]byte
	copy(out[:], raw[2:34])
	return out, nil
}
