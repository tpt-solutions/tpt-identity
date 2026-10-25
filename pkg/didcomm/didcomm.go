// Package didcomm implements DIDComm v2 message packing and unpacking.
// https://identity.foundation/didcomm-messaging/spec/
//
// Algorithms:
//   - Anoncrypt: ECDH-ES+A256KW+XC20P (ephemeral X25519; sender is hidden)
//   - Authcrypt: ECDH-1PU+A256KW+XC20P (sender key bound; provides authentication)
//
// Key derivation uses Concat KDF (NIST SP 800-56A / RFC 7518 §4.6.2).
// CEK wrapping uses AES-256-KW (RFC 3394).
// Content encryption uses XChaCha20-Poly1305 (XC20P, 192-bit nonce).
package didcomm

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// MediaTypeEncrypted is the Content-Type for DIDComm v2 encrypted messages.
	MediaTypeEncrypted = "application/didcomm-encrypted+json"

	algAnoncrypt = "ECDH-ES+A256KW"
	algAuthcrypt = "ECDH-1PU+A256KW"
	encXC20P     = "XC20P"
)

// Message is a DIDComm v2 plaintext message.
type Message struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	From        string         `json:"from,omitempty"`
	To          []string       `json:"to,omitempty"`
	CreatedTime int64          `json:"created_time,omitempty"`
	ExpiresTime int64          `json:"expires_time,omitempty"`
	Body        map[string]any `json:"body,omitempty"`
	Attachments []Attachment   `json:"attachments,omitempty"`
}

// Attachment is a DIDComm v2 message attachment.
type Attachment struct {
	ID          string         `json:"id,omitempty"`
	Description string         `json:"description,omitempty"`
	MimeType    string         `json:"mime_type,omitempty"`
	Data        AttachmentData `json:"data"`
}

// AttachmentData holds attachment content as base64 or inline JSON.
type AttachmentData struct {
	Base64 string `json:"base64,omitempty"`
	JSON   any    `json:"json,omitempty"`
}

// Recipient is a DIDComm v2 message recipient.
type Recipient struct {
	KID    string   // key ID — e.g. "did:web:example.com#enc-key-1"
	PubKey [32]byte // X25519 public key
}

// Envelope is a DIDComm v2 JWE JSON Serialized encrypted message.
type Envelope struct {
	Protected  string     `json:"protected"`
	Recipients []jweRecip `json:"recipients"`
	IV         string     `json:"iv"`
	Ciphertext string     `json:"ciphertext"`
	Tag        string     `json:"tag"`
}

type jweRecip struct {
	Header       jweRecipHeader `json:"header"`
	EncryptedKey string         `json:"encrypted_key"`
}

type jweRecipHeader struct {
	KID string  `json:"kid"`
	EPK *jwkOKP `json:"epk,omitempty"`
}

// jwkOKP is a JWK for OKP (Octet Key Pair) — X25519 here.
type jwkOKP struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"` // base64url-encoded raw public key
}

// protectedHeader is the JWE shared protected header.
type protectedHeader struct {
	Typ  string `json:"typ"`
	Alg  string `json:"alg"`
	Enc  string `json:"enc"`
	SKID string `json:"skid,omitempty"` // authcrypt: sender key ID
	APU  string `json:"apu,omitempty"`  // base64url(sender_kid bytes); absent for anoncrypt
	APV  string `json:"apv,omitempty"`  // base64url(SHA-256(sorted recipient KIDs joined by "."))
}

// PackAnoncrypt encrypts msg for recipients without revealing the sender identity.
// Uses ECDH-ES+A256KW+XC20P with a per-recipient ephemeral X25519 keypair.
func PackAnoncrypt(msg []byte, recipients []Recipient) ([]byte, error) {
	return packEnvelope(msg, recipients, "", nil)
}

// PackAuthcrypt encrypts msg for recipients and authenticates the sender.
// Uses ECDH-1PU+A256KW+XC20P; recipients can verify the message came from senderKID.
func PackAuthcrypt(msg []byte, recipients []Recipient, senderKID string, senderPriv [32]byte) ([]byte, error) {
	return packEnvelope(msg, recipients, senderKID, &senderPriv)
}

func packEnvelope(msg []byte, recipients []Recipient, senderKID string, senderPriv *[32]byte) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("didcomm: at least one recipient required")
	}
	isAuthcrypt := senderPriv != nil

	// apv = base64url(SHA-256(sorted recipient KIDs joined with "."))
	kids := make([]string, len(recipients))
	for i, r := range recipients {
		kids[i] = r.KID
	}
	sort.Strings(kids)
	apvRaw := computeAPV(kids)
	apvB64 := base64.RawURLEncoding.EncodeToString(apvRaw)

	alg := algAnoncrypt
	hdr := protectedHeader{
		Typ: MediaTypeEncrypted,
		Enc: encXC20P,
		APV: apvB64,
	}
	if isAuthcrypt {
		alg = algAuthcrypt
		hdr.SKID = senderKID
		hdr.APU = base64.RawURLEncoding.EncodeToString([]byte(senderKID))
	}
	hdr.Alg = alg

	protJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, fmt.Errorf("didcomm: marshal header: %w", err)
	}
	protB64 := base64.RawURLEncoding.EncodeToString(protJSON)

	// Random 32-byte CEK for XC20P.
	var cek [32]byte
	if _, err := io.ReadFull(rand.Reader, cek[:]); err != nil {
		return nil, fmt.Errorf("didcomm: gen cek: %w", err)
	}

	// Encrypt the content before wrapping the CEK. ECDH-1PU feeds the content tag into every
	// recipient's KEK, so the tag must exist first.
	aead, err := chacha20poly1305.NewX(cek[:])
	if err != nil {
		return nil, fmt.Errorf("didcomm: xchacha20: %w", err)
	}
	var iv [chacha20poly1305.NonceSizeX]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		return nil, fmt.Errorf("didcomm: gen iv: %w", err)
	}
	// AAD is the base64url-encoded protected header (per JWE spec).
	aad := []byte(protB64)
	sealed := aead.Seal(nil, iv[:], msg, aad)
	tagOff := len(sealed) - aead.Overhead()
	ciphertext, contentTag := sealed[:tagOff], sealed[tagOff:]

	// SuppPrivInfo for ECDH-1PU is the content tag. Anoncrypt has none.
	var suppPriv []byte
	if isAuthcrypt {
		suppPriv = contentTag
	}

	// Per-recipient: generate ephemeral keypair, derive KEK, wrap CEK.
	jweRecipients := make([]jweRecip, len(recipients))
	for i, r := range recipients {
		ephPriv, ephPub, err := generateX25519()
		if err != nil {
			return nil, fmt.Errorf("didcomm: ephem key: %w", err)
		}

		var kek [32]byte
		if isAuthcrypt {
			kek, err = ecdh1PUKEKSender(ephPriv, *senderPriv, r.PubKey, alg, hdr.APU, apvB64, suppPriv)
		} else {
			kek, err = ecdhESKEKSender(ephPriv, r.PubKey, alg, apvB64)
		}
		if err != nil {
			return nil, fmt.Errorf("didcomm: kek for %s: %w", r.KID, err)
		}

		wrapped, err := aesKeyWrap(kek[:], cek[:])
		if err != nil {
			return nil, fmt.Errorf("didcomm: key wrap for %s: %w", r.KID, err)
		}

		jweRecipients[i] = jweRecip{
			Header: jweRecipHeader{
				KID: r.KID,
				EPK: &jwkOKP{
					KTY: "OKP",
					CRV: "X25519",
					X:   base64.RawURLEncoding.EncodeToString(ephPub[:]),
				},
			},
			EncryptedKey: base64.RawURLEncoding.EncodeToString(wrapped),
		}
	}

	return json.Marshal(Envelope{
		Protected:  protB64,
		Recipients: jweRecipients,
		IV:         base64.RawURLEncoding.EncodeToString(iv[:]),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:        base64.RawURLEncoding.EncodeToString(contentTag),
	})
}

// Unpack decrypts a DIDComm v2 JWE envelope.
//
// recipKeyFn returns the X25519 private key for the given recipient key ID.
// Return an error if the key ID is not recognised (Unpack will try the next recipient).
//
// senderPubFn returns the X25519 public key for a sender key ID (from the skid header).
// Only called for authcrypt messages. May be nil; authcrypt then fails with an error.
//
// Returns the plaintext message bytes, the sender key ID (empty for anoncrypt), and any error.
func Unpack(
	envelope []byte,
	recipKeyFn func(kid string) ([32]byte, error),
	senderPubFn func(skid string) ([32]byte, error),
) ([]byte, string, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, "", fmt.Errorf("didcomm: parse envelope: %w", err)
	}

	protJSON, err := base64.RawURLEncoding.DecodeString(env.Protected)
	if err != nil {
		return nil, "", fmt.Errorf("didcomm: decode protected header: %w", err)
	}
	var hdr protectedHeader
	if err := json.Unmarshal(protJSON, &hdr); err != nil {
		return nil, "", fmt.Errorf("didcomm: parse protected header: %w", err)
	}

	// Resolve sender public key once (shared across all recipients for authcrypt).
	var senderPub [32]byte
	if hdr.SKID != "" {
		if senderPubFn == nil {
			return nil, "", errors.New("didcomm: authcrypt envelope requires senderPubFn")
		}
		senderPub, err = senderPubFn(hdr.SKID)
		if err != nil {
			return nil, "", fmt.Errorf("didcomm: resolve sender key %s: %w", hdr.SKID, err)
		}
	}

	// ECDH-1PU derives every KEK from the content tag, so decode it before unwrapping.
	tagBytes, err := base64.RawURLEncoding.DecodeString(env.Tag)
	if err != nil {
		return nil, "", fmt.Errorf("didcomm: decode tag: %w", err)
	}

	// Find a recipient whose key we hold and unwrap the CEK.
	var cek [32]byte
	unwrapped := false
	for _, r := range env.Recipients {
		recipPriv, err := recipKeyFn(r.Header.KID)
		if err != nil {
			continue
		}
		if r.Header.EPK == nil {
			continue
		}
		ephPubBytes, err := base64.RawURLEncoding.DecodeString(r.Header.EPK.X)
		if err != nil || len(ephPubBytes) != 32 {
			continue
		}
		var ephPub [32]byte
		copy(ephPub[:], ephPubBytes)

		var kek [32]byte
		switch hdr.Alg {
		case algAnoncrypt:
			kek, err = ecdhESKEKRecipient(recipPriv, ephPub, hdr.Alg, hdr.APV)
		case algAuthcrypt:
			kek, err = ecdh1PUKEKRecipient(ephPub, recipPriv, senderPub, hdr.Alg, hdr.APU, hdr.APV, tagBytes)
		default:
			continue
		}
		if err != nil {
			continue
		}

		encKey, err := base64.RawURLEncoding.DecodeString(r.EncryptedKey)
		if err != nil {
			continue
		}
		cekSlice, err := aesKeyUnwrap(kek[:], encKey)
		if err != nil {
			continue
		}
		if len(cekSlice) != 32 {
			continue
		}
		copy(cek[:], cekSlice)
		unwrapped = true
		break
	}
	if !unwrapped {
		return nil, "", errors.New("didcomm: no matching recipient key found")
	}

	// Decrypt content.
	ivBytes, err := base64.RawURLEncoding.DecodeString(env.IV)
	if err != nil {
		return nil, "", fmt.Errorf("didcomm: decode iv: %w", err)
	}
	ctBytes, err := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("didcomm: decode ciphertext: %w", err)
	}

	aead, err := chacha20poly1305.NewX(cek[:])
	if err != nil {
		return nil, "", fmt.Errorf("didcomm: init xchacha20: %w", err)
	}
	// Rejoin ciphertext+tag; aead.Open expects them concatenated.
	combined := append(ctBytes, tagBytes...)
	plaintext, err := aead.Open(nil, ivBytes, combined, []byte(env.Protected))
	if err != nil {
		return nil, "", fmt.Errorf("didcomm: decrypt content: %w", err)
	}
	return plaintext, hdr.SKID, nil
}

// --- Key agreement ---

func ecdhESKEKSender(ephPriv [32]byte, recipPub [32]byte, alg, apvB64 string) ([32]byte, error) {
	z, err := curve25519.X25519(ephPriv[:], recipPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	return concatKDF(z, alg, "", apvB64, nil)
}

func ecdhESKEKRecipient(recipPriv [32]byte, ephPub [32]byte, alg, apvB64 string) ([32]byte, error) {
	z, err := curve25519.X25519(recipPriv[:], ephPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	return concatKDF(z, alg, "", apvB64, nil)
}

// ecdh1PUKEKSender derives the ECDH-1PU KEK. contentTag is the content-encryption tag, which goes into
// the KDF as SuppPrivInfo, so the key wrap is bound to the ciphertext.
func ecdh1PUKEKSender(ephPriv, senderPriv [32]byte, recipPub [32]byte, alg, apuB64, apvB64 string, contentTag []byte) ([32]byte, error) {
	ze, err := curve25519.X25519(ephPriv[:], recipPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	zs, err := curve25519.X25519(senderPriv[:], recipPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	return concatKDF(append(ze, zs...), alg, apuB64, apvB64, contentTag)
}

func ecdh1PUKEKRecipient(ephPub, recipPriv, senderPub [32]byte, alg, apuB64, apvB64 string, contentTag []byte) ([32]byte, error) {
	ze, err := curve25519.X25519(recipPriv[:], ephPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	zs, err := curve25519.X25519(recipPriv[:], senderPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	return concatKDF(append(ze, zs...), alg, apuB64, apvB64, contentTag)
}

// --- Concat KDF (NIST SP 800-56A §5.8.1 / RFC 7518 §4.6.2) ---

// concatKDF derives a 256-bit KEK from the shared secret z using one SHA-256 round.
// apuB64 and apvB64 are the base64url-encoded party info values from the JWE header. suppPriv is
// the SuppPrivInfo field: the content tag for ECDH-1PU, nil for ECDH-ES. With nil the output is the
// plain ECDH-ES derivation.
func concatKDF(z []byte, alg, apuB64, apvB64 string, suppPriv []byte) ([32]byte, error) {
	var apu, apv []byte
	if apuB64 != "" {
		var err error
		apu, err = base64.RawURLEncoding.DecodeString(apuB64)
		if err != nil {
			return [32]byte{}, fmt.Errorf("concat-kdf: decode apu: %w", err)
		}
	}
	if apvB64 != "" {
		var err error
		apv, err = base64.RawURLEncoding.DecodeString(apvB64)
		if err != nil {
			return [32]byte{}, fmt.Errorf("concat-kdf: decode apv: %w", err)
		}
	}

	algBytes := []byte(alg)
	var h []byte
	h = binary.BigEndian.AppendUint32(h, 1) // counter = 1
	h = append(h, z...)
	h = binary.BigEndian.AppendUint32(h, uint32(len(algBytes)))
	h = append(h, algBytes...)
	h = binary.BigEndian.AppendUint32(h, uint32(len(apu)))
	h = append(h, apu...)
	h = binary.BigEndian.AppendUint32(h, uint32(len(apv)))
	h = append(h, apv...)
	h = binary.BigEndian.AppendUint32(h, 256) // keydatalen in bits
	h = append(h, suppPriv...)                // SuppPrivInfo: the content tag for ECDH-1PU

	return sha256.Sum256(h), nil
}

// --- AES Key Wrap (RFC 3394) ---

var aesKWDefaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, errors.New("aes-kw: plaintext must be ≥16 bytes and a multiple of 8")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plaintext) / 8
	R := make([]byte, len(plaintext))
	copy(R, plaintext)
	A := aesKWDefaultIV
	buf := make([]byte, 16)
	for j := 0; j <= 5; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], A[:])
			copy(buf[8:], R[i*8:(i+1)*8])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(A[:], binary.BigEndian.Uint64(buf[:8])^t)
			copy(R[i*8:], buf[8:])
		}
	}
	result := make([]byte, 8+len(plaintext))
	copy(result[:8], A[:])
	copy(result[8:], R)
	return result, nil
}

func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, errors.New("aes-kw: ciphertext must be ≥24 bytes and a multiple of 8")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext)/8 - 1
	R := make([]byte, n*8)
	copy(R, ciphertext[8:])
	A := make([]byte, 8)
	copy(A, ciphertext[:8])
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(A)^t)
			copy(buf[8:], R[i*8:(i+1)*8])
			block.Decrypt(buf, buf)
			copy(A, buf[:8])
			copy(R[i*8:], buf[8:])
		}
	}
	if !bytes.Equal(A, aesKWDefaultIV[:]) {
		return nil, errors.New("aes-kw: integrity check failed — wrong key or corrupted ciphertext")
	}
	return R, nil
}

// --- Helpers ---

// computeAPV returns SHA-256(sorted kids joined with ".").
func computeAPV(sortedKIDs []string) []byte {
	var joined string
	for i, k := range sortedKIDs {
		if i > 0 {
			joined += "."
		}
		joined += k
	}
	h := sha256.Sum256([]byte(joined))
	return h[:]
}

// generateX25519 generates a fresh X25519 keypair with RFC 7748 clamping.
func generateX25519() ([32]byte, [32]byte, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	// Clamp per RFC 7748 §5.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	var pubKey [32]byte
	copy(pubKey[:], pub)
	return priv, pubKey, nil
}
