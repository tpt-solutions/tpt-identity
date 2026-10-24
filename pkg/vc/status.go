package vc

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	tptcrypto "github.com/tpt-solutions/tpt-identity/pkg/crypto"
)

// StatusListMinSize is the minimum number of status entries per the W3C spec.
const StatusListMinSize = 131_072

// StatusList manages a BitstringStatusList for credential revocation.
// The bitstring is gzip-compressed and base64url-encoded when published.
type StatusList struct {
	mu   sync.Mutex
	id   string // public URL of this status list VC
	bits []byte
	size int
}

// NewStatusList creates a new StatusList with the given public URL and at least minSize entries.
func NewStatusList(id string, size int) *StatusList {
	if size < StatusListMinSize {
		size = StatusListMinSize
	}
	byteLen := (size + 7) / 8
	return &StatusList{id: id, bits: make([]byte, byteLen), size: byteLen * 8}
}

// Revoke sets the revocation bit for the credential at index.
func (s *StatusList) Revoke(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkIndex(index); err != nil {
		return err
	}
	s.bits[index/8] |= 1 << (uint(index) % 8)
	return nil
}

// Unrevoke clears the revocation bit (for correctional use only).
func (s *StatusList) Unrevoke(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkIndex(index); err != nil {
		return err
	}
	s.bits[index/8] &^= 1 << (uint(index) % 8)
	return nil
}

// IsRevoked reports whether the credential at index is revoked.
func (s *StatusList) IsRevoked(index int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkIndex(index); err != nil {
		return false, err
	}
	return s.bits[index/8]&(1<<(uint(index)%8)) != 0, nil
}

func (s *StatusList) checkIndex(index int) error {
	if index < 0 || index >= s.size {
		return fmt.Errorf("status list: index %d out of range (size %d)", index, s.size)
	}
	return nil
}

// EncodedList returns the gzip-compressed, base64url-encoded bitstring for publication.
func (s *StatusList) EncodedList() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(s.bits); err != nil {
		return "", fmt.Errorf("status list compress: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("status list compress close: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// IssueStatusListVC creates a signed BitstringStatusListCredential VC.
func (s *StatusList) IssueStatusListVC(
	issuerDID string,
	issuerKey ed25519.PrivateKey,
	verificationMethodID string,
) (*VerifiableCredential, error) {
	encodedList, err := s.EncodedList()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	cred := Credential{
		Context:   append(DefaultContext(), "https://www.w3.org/ns/credentials/status/v1"),
		ID:        s.id,
		Type:      []string{TypeVC, "BitstringStatusListCredential"},
		Issuer:    issuerDID,
		ValidFrom: now,
		CredentialSubject: CredentialSubject{
			ID: s.id + "#list",
			Claims: map[string]string{
				"type":          "BitstringStatusList",
				"statusPurpose": "revocation",
				"encodedList":   encodedList,
			},
		},
	}

	proofOptions := map[string]string{
		"type":               "DataIntegrityProof",
		"cryptosuite":        "eddsa-jcs-2022",
		"created":            now.Format(time.RFC3339),
		"verificationMethod": verificationMethodID,
		"proofPurpose":       "assertionMethod",
	}
	proofOptionsBytes, err := tptcrypto.JCS(proofOptions)
	if err != nil {
		return nil, fmt.Errorf("status list vc: jcs proof options: %w", err)
	}
	documentBytes, err := tptcrypto.JCS(cred)
	if err != nil {
		return nil, fmt.Errorf("status list vc: jcs document: %w", err)
	}
	proofHash := sha256.Sum256(proofOptionsBytes)
	docHash := sha256.Sum256(documentBytes)
	hashData := append(proofHash[:], docHash[:]...)
	sig := ed25519.Sign(issuerKey, hashData)

	return &VerifiableCredential{
		Credential: cred,
		Proof: &Proof{
			Type:               "DataIntegrityProof",
			Cryptosuite:        "eddsa-jcs-2022",
			Created:            now.Format(time.RFC3339),
			VerificationMethod: verificationMethodID,
			ProofPurpose:       "assertionMethod",
			ProofValue:         base64.RawURLEncoding.EncodeToString(sig),
		},
	}, nil
}

// NewStatusListID generates a unique status list URL under the given server base URL.
func NewStatusListID(serverBase string) string {
	return serverBase + "/api/v1/status/" + uuid.NewString()
}

// ParseEncodedList decodes a BitstringStatusList encodedList field.
func ParseEncodedList(encoded string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("status list: base64 decode: %w", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("status list: gzip open: %w", err)
	}
	defer func() { _ = gz.Close() }() // read-only reader: nothing to flush
	bits, err := io.ReadAll(io.LimitReader(gz, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("status list: gzip read: %w", err)
	}
	return bits, nil
}

// CheckStatus checks whether the given CredentialStatus entry is revoked
// using a pre-fetched decoded bitstring.
func CheckStatus(bits []byte, status *CredentialStatus) error {
	if status == nil {
		return nil
	}
	idx := status.StatusListIndex
	if idx < 0 {
		return fmt.Errorf("status list: index %d out of range", idx)
	}
	byteIdx := idx / 8
	bitIdx := uint(idx) % 8
	if byteIdx >= len(bits) {
		return fmt.Errorf("status list: index %d out of range", idx)
	}
	if bits[byteIdx]&(1<<bitIdx) != 0 {
		return ErrCredentialRevoked
	}
	return nil
}

// StatusListFromBytes rebuilds a status list from a stored bitstring, so a persisted list can be
// revoked against and republished. bits must be the full byte slice produced by a StatusList.
func StatusListFromBytes(id string, bits []byte) *StatusList {
	cp := make([]byte, len(bits))
	copy(cp, bits)
	return &StatusList{id: id, bits: cp, size: len(cp) * 8}
}

// Bytes returns a copy of the raw bitstring, for persistence.
func (s *StatusList) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(s.bits))
	copy(cp, s.bits)
	return cp
}

// ErrCredentialRevoked is returned by CheckStatus when the credential's bit is set.
var ErrCredentialRevoked = errors.New("credential is revoked")
