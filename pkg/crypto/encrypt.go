package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	KeySize   = 32
	NonceSize = 24
)

// GenerateEncryptionKey generates a new X25519 keypair (raw 32-byte scalars).
func GenerateEncryptionKey() (pub, priv [KeySize]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return
	}
	// Clamp per RFC 7748
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pubSlice, e := curve25519.X25519(priv[:], curve25519.Basepoint)
	if e != nil {
		return pub, priv, fmt.Errorf("x25519 pubkey: %w", e)
	}
	copy(pub[:], pubSlice)
	return
}

// ECDH computes the X25519 shared secret.
func ECDH(myPriv [KeySize]byte, theirPub [KeySize]byte) ([KeySize]byte, error) {
	shared, err := curve25519.X25519(myPriv[:], theirPub[:])
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("x25519: %w", err)
	}
	var out [KeySize]byte
	copy(out[:], shared)
	return out, nil
}

// Seal encrypts plaintext with a random nonce using NaCl secretbox.
// Returns nonce+ciphertext.
func Seal(key [KeySize]byte, plaintext []byte) ([]byte, error) {
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	out := make([]byte, NonceSize, NonceSize+len(plaintext)+secretbox.Overhead)
	copy(out, nonce[:])
	return secretbox.Seal(out, plaintext, &nonce, &key), nil
}

// Open decrypts a ciphertext produced by Seal.
func Open(key [KeySize]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+secretbox.Overhead {
		return nil, errors.New("ciphertext too short")
	}
	var nonce [NonceSize]byte
	copy(nonce[:], ciphertext[:NonceSize])
	plain, ok := secretbox.Open(nil, ciphertext[NonceSize:], &nonce, &key)
	if !ok {
		return nil, errors.New("decryption failed")
	}
	return plain, nil
}

// X25519PublicKey derives the public key for an X25519 private scalar.
func X25519PublicKey(priv [KeySize]byte) ([KeySize]byte, error) {
	basepoint := [KeySize]byte{9}
	pub, err := curve25519.X25519(priv[:], basepoint[:])
	if err != nil {
		return [KeySize]byte{}, err
	}
	var out [KeySize]byte
	copy(out[:], pub)
	return out, nil
}
