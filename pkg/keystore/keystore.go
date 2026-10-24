package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	tptcrypto "github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

// Argon2id parameters: GPU-resistant key derivation for identity key material.
const (
	argon2Memory  = 64 * 1024 // 64 MB in KiB
	argon2Time    = 3
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLen       = 32
)

// Keystore holds an Ed25519 signing keypair and an optional X25519 encryption keypair.
type Keystore struct {
	SigningPub  ed25519.PublicKey
	SigningPriv ed25519.PrivateKey
	EncPub      [tptcrypto.KeySize]byte
	EncPriv     [tptcrypto.KeySize]byte
	HasEnc      bool
}

// Generate creates a new Keystore with fresh Ed25519 and X25519 keys.
func Generate() (*Keystore, error) {
	pub, priv, err := tptcrypto.GenerateSigningKey()
	if err != nil {
		return nil, fmt.Errorf("ed25519: %w", err)
	}
	encPub, encPriv, err := tptcrypto.GenerateEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	return &Keystore{
		SigningPub:  pub,
		SigningPriv: priv,
		EncPub:      encPub,
		EncPriv:     encPriv,
		HasEnc:      true,
	}, nil
}

// SaveSigning writes the Ed25519 private key to path, encrypted with passphrase.
// Pass an empty passphrase to store plaintext (development only).
func SaveSigning(ks *Keystore, path, passphrase string) error {
	return savePEM([]byte(ks.SigningPriv), "ED25519 PRIVATE KEY", path, passphrase)
}

// SaveEncryption writes the X25519 private key to path, encrypted with passphrase.
func SaveEncryption(ks *Keystore, path, passphrase string) error {
	return savePEM(ks.EncPriv[:], "X25519 PRIVATE KEY", path, passphrase)
}

// LoadSigning reads an Ed25519 private key written by SaveSigning.
func LoadSigning(path, passphrase string) (*Keystore, error) {
	raw, err := loadPEM(path, passphrase)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 key length")
	}
	priv := ed25519.PrivateKey(raw)
	return &Keystore{
		SigningPriv: priv,
		SigningPub:  priv.Public().(ed25519.PublicKey),
	}, nil
}

// LoadEncryption reads an X25519 private key and attaches it to ks.
func LoadEncryption(ks *Keystore, path, passphrase string) error {
	raw, err := loadPEM(path, passphrase)
	if err != nil {
		return err
	}
	if len(raw) != tptcrypto.KeySize {
		return errors.New("invalid x25519 key length")
	}
	copy(ks.EncPriv[:], raw)
	pub, err := x25519PublicFromPrivate(ks.EncPriv)
	if err != nil {
		return fmt.Errorf("derive x25519 pub: %w", err)
	}
	ks.EncPub = pub
	ks.HasEnc = true
	return nil
}

// x25519PublicFromPrivate derives the X25519 public key from a private scalar.
func x25519PublicFromPrivate(priv [tptcrypto.KeySize]byte) ([tptcrypto.KeySize]byte, error) {
	// curve25519 basepoint is the u-coordinate 9 in little-endian.
	basepoint := [tptcrypto.KeySize]byte{9}
	pub, err := curve25519.X25519(priv[:], basepoint[:])
	if err != nil {
		return [tptcrypto.KeySize]byte{}, err
	}
	var out [tptcrypto.KeySize]byte
	copy(out[:], pub)
	return out, nil
}

func savePEM(key []byte, keyType, path, passphrase string) error {
	var block *pem.Block
	if passphrase == "" {
		block = &pem.Block{Type: keyType, Bytes: key}
	} else {
		ct, salt, nonce, err := encryptKey(key, passphrase)
		if err != nil {
			return err
		}
		block = &pem.Block{
			Type:  keyType,
			Bytes: ct,
			Headers: map[string]string{
				"Proc-Type": "4,ENCRYPTED",
				"Salt":      hex.EncodeToString(salt),
				"Nonce":     hex.EncodeToString(nonce),
			},
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if err := pem.Encode(f, block); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func loadPEM(path, passphrase string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Headers["Proc-Type"] != "4,ENCRYPTED" {
		return block.Bytes, nil
	}
	if passphrase == "" {
		return nil, errors.New("key is encrypted but no passphrase provided")
	}
	salt, err := hex.DecodeString(block.Headers["Salt"])
	if err != nil {
		return nil, fmt.Errorf("salt decode: %w", err)
	}
	nonce, err := hex.DecodeString(block.Headers["Nonce"])
	if err != nil {
		return nil, fmt.Errorf("nonce decode: %w", err)
	}
	return decryptKey(block.Bytes, salt, nonce, passphrase)
}

func encryptKey(key []byte, passphrase string) (ciphertext, salt, nonce []byte, err error) {
	salt = make([]byte, saltLen)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return
	}
	dk := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, e := aes.NewCipher(dk)
	if e != nil {
		err = e
		return
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		err = e
		return
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	ciphertext = gcm.Seal(nil, nonce, key, nil)
	return
}

func decryptKey(ciphertext, salt, nonce []byte, passphrase string) ([]byte, error) {
	dk := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong passphrase or corrupted key")
	}
	return plain, nil
}
