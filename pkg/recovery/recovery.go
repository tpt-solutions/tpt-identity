// Package recovery implements M-of-N guardian-based key recovery using
// Shamir Secret Sharing over GF(256) (the standard algorithm used in most
// implementations, e.g. HashiCorp Vault).
package recovery

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// Share is a single guardian's piece of the secret.
type Share struct {
	Index byte   // x-coordinate (1-based, never 0)
	Value []byte // f(Index) for each byte of the secret
}

// Hex encodes the share as "HEX(index):HEX(value)" for storage.
func (s Share) Hex() string {
	return fmt.Sprintf("%02x:%s", s.Index, hex.EncodeToString(s.Value))
}

// ParseHex decodes a share produced by Share.Hex.
func ParseHex(encoded string) (Share, error) {
	if len(encoded) < 4 || encoded[2] != ':' {
		return Share{}, errors.New("recovery: invalid share format")
	}
	idxBytes, err := hex.DecodeString(encoded[:2])
	if err != nil || len(idxBytes) != 1 {
		return Share{}, errors.New("recovery: invalid share index")
	}
	val, err := hex.DecodeString(encoded[3:])
	if err != nil {
		return Share{}, fmt.Errorf("recovery: invalid share value: %w", err)
	}
	return Share{Index: idxBytes[0], Value: val}, nil
}

// Split splits secret into n shares, of which any threshold are needed to
// reconstruct it. secret must be non-empty; threshold must be 2 ≤ t ≤ n ≤ 255.
func Split(secret []byte, threshold, n int) ([]Share, error) {
	if len(secret) == 0 {
		return nil, errors.New("recovery: secret must not be empty")
	}
	if threshold < 2 || threshold > n || n > 255 {
		return nil, fmt.Errorf("recovery: invalid parameters (threshold=%d, n=%d)", threshold, n)
	}

	shares := make([]Share, n)
	for i := range shares {
		shares[i] = Share{Index: byte(i + 1), Value: make([]byte, len(secret))}
	}

	// For each byte of the secret, generate a random polynomial of degree
	// threshold-1 and evaluate at each share index.
	coefficients := make([]byte, threshold)
	for byteIdx := range secret {
		coefficients[0] = secret[byteIdx]
		if _, err := rand.Read(coefficients[1:]); err != nil {
			return nil, fmt.Errorf("recovery: generate coefficients: %w", err)
		}
		for _, sh := range shares {
			shares[sh.Index-1].Value[byteIdx] = gfPolyEval(coefficients, sh.Index)
		}
	}
	return shares, nil
}

// Combine reconstructs the secret from threshold-or-more shares using
// Lagrange interpolation over GF(256).
func Combine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("recovery: need at least 2 shares")
	}
	// Verify all shares have the same length.
	length := len(shares[0].Value)
	seen := make(map[byte]bool, len(shares))
	for _, s := range shares {
		if len(s.Value) != length {
			return nil, errors.New("recovery: shares have inconsistent lengths")
		}
		// Index 0 is the secret itself, and a repeated index makes the Lagrange system singular.
		if s.Index == 0 {
			return nil, errors.New("recovery: share index 0 is reserved")
		}
		if seen[s.Index] {
			return nil, fmt.Errorf("recovery: duplicate share index %d", s.Index)
		}
		seen[s.Index] = true
	}

	secret := make([]byte, length)
	for byteIdx := range secret {
		xs := make([]byte, len(shares))
		ys := make([]byte, len(shares))
		for i, s := range shares {
			xs[i] = s.Index
			ys[i] = s.Value[byteIdx]
		}
		secret[byteIdx] = gfLagrange(xs, ys)
	}
	return secret, nil
}

// NewRecoveryToken generates a random 32-byte recovery token.
func NewRecoveryToken() ([]byte, error) {
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, fmt.Errorf("recovery: generate token: %w", err)
	}
	return tok, nil
}

// ── GF(256) arithmetic (primitive polynomial: x^8 + x^4 + x^3 + x + 1) ──────

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b // low 8 bits of gfPrim
		}
		b >>= 1
	}
	return p
}

func gfPolyEval(coeffs []byte, x byte) byte {
	result := byte(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gfMul(result, x) ^ coeffs[i]
	}
	return result
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	result := byte(1)
	exp := byte(254) // Fermat: a^(255-1) = a^-1 in GF(256)
	for exp > 0 {
		if exp&1 != 0 {
			result = gfMul(result, a)
		}
		a = gfMul(a, a)
		exp >>= 1
	}
	return result
}

func gfLagrange(xs, ys []byte) byte {
	result := byte(0)
	for i := range xs {
		num := byte(1)
		den := byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			num = gfMul(num, xs[j])
			den = gfMul(den, xs[i]^xs[j])
		}
		result ^= gfMul(ys[i], gfMul(num, gfInv(den)))
	}
	return result
}
