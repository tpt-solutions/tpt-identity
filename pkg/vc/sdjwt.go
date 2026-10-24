package vc

// SD-JWT — Selective Disclosure JWT (draft-ietf-oauth-selective-disclosure-jwt)
//
// Format issued:   <issuer-jwt>~<disc1>~<disc2>~...~
// Format presented: <issuer-jwt>~<disc_a>~<disc_b>~   (subset of disclosures)
// With key binding: <issuer-jwt>~<disc_a>~<kb-jwt>
//
// Each disclosure is base64url([salt, claim_name, claim_value]).
// The issuer JWT carries _sd (hashes of all disclosures) and _sd_alg "sha-256".

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/PhillipC05/tpt-identity/internal/resolver"
	"github.com/PhillipC05/tpt-identity/pkg/schema"
)

// ──────────────────────────────────────────────────────────────────────────────
// Disclosure
// ──────────────────────────────────────────────────────────────────────────────

// Disclosure is a single selectively-disclosable claim: [salt, key, value].
type Disclosure struct {
	Salt  string
	Key   string
	Value any
}

// NewDisclosure creates a Disclosure with a cryptographically random 16-byte salt.
func NewDisclosure(key string, value any) (Disclosure, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: generate salt: %w", err)
	}
	return Disclosure{
		Salt:  base64.RawURLEncoding.EncodeToString(salt),
		Key:   key,
		Value: value,
	}, nil
}

// Encode returns the base64url-encoded JSON array [salt, key, value].
func (d Disclosure) Encode() (string, error) {
	arr := []any{d.Salt, d.Key, d.Value}
	b, err := json.Marshal(arr)
	if err != nil {
		return "", fmt.Errorf("sdjwt: encode disclosure: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Digest returns base64url(sha256(Encode())) — the hash stored in the _sd array.
func (d Disclosure) Digest() (string, error) {
	enc, err := d.Encode()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(enc))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// ParseDisclosure decodes a base64url-encoded disclosure string.
func ParseDisclosure(encoded string) (Disclosure, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: decode disclosure: %w", err)
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: unmarshal disclosure: %w", err)
	}
	if len(arr) != 3 {
		return Disclosure{}, errors.New("sdjwt: disclosure must have 3 elements [salt, key, value]")
	}
	salt, ok := arr[0].(string)
	if !ok {
		return Disclosure{}, errors.New("sdjwt: disclosure salt must be a string")
	}
	key, ok := arr[1].(string)
	if !ok {
		return Disclosure{}, errors.New("sdjwt: disclosure key must be a string")
	}
	return Disclosure{Salt: salt, Key: key, Value: arr[2]}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// SDJWTToken — issued token with all disclosures
// ──────────────────────────────────────────────────────────────────────────────

// SDJWTToken is an issued SD-JWT credential together with its disclosures.
// The holder stores the full token; the issuer only keeps the JWT itself.
type SDJWTToken struct {
	// JWT is the signed issuer JWT: header.payload.signature
	JWT string
	// Disclosures holds every selective-disclosure claim (all possible reveals).
	Disclosures []Disclosure
}

// Serialize returns the full SD-JWT string with all disclosures:
//
//	<jwt>~<disc1>~<disc2>~...~
func (t *SDJWTToken) Serialize() string {
	return t.serializeWith(t.Disclosures)
}

// Present returns a presentation SD-JWT that reveals only the named claims.
// Pass an empty slice to prove the credential is valid without revealing anything.
func (t *SDJWTToken) Present(revealKeys []string) string {
	want := make(map[string]bool, len(revealKeys))
	for _, k := range revealKeys {
		want[k] = true
	}
	var selected []Disclosure
	for _, d := range t.Disclosures {
		if want[d.Key] {
			selected = append(selected, d)
		}
	}
	return t.serializeWith(selected)
}

// PresentWithKeyBinding returns an SD-JWT with a holder-signed KB-JWT appended.
// The KB-JWT proves the holder controls the key referenced in the cnf claim and
// binds the presentation to a specific nonce and audience (anti-replay).
func (t *SDJWTToken) PresentWithKeyBinding(revealKeys []string, holderKey ed25519.PrivateKey, holderKID, nonce, audience string) (string, error) {
	base := t.Present(revealKeys)
	// sd_hash = sha256 of the SD-JWT string without the trailing ~
	forHash := strings.TrimSuffix(base, "~")
	h := sha256.Sum256([]byte(forHash))
	sdHash := base64.RawURLEncoding.EncodeToString(h[:])

	kbClaims := map[string]any{
		"nonce":   nonce,
		"aud":     audience,
		"iat":     time.Now().Unix(),
		"sd_hash": sdHash,
	}
	kbJWT, err := signSDJWT(kbClaims, holderKey, holderKID, "kb+jwt")
	if err != nil {
		return "", fmt.Errorf("sdjwt: sign kb-jwt: %w", err)
	}
	return base + kbJWT, nil
}

func (t *SDJWTToken) serializeWith(discs []Disclosure) string {
	parts := make([]string, 0, 1+len(discs)+1)
	parts = append(parts, t.JWT)
	for _, d := range discs {
		enc, _ := d.Encode()
		parts = append(parts, enc)
	}
	return strings.Join(parts, "~") + "~"
}

// ──────────────────────────────────────────────────────────────────────────────
// Issuance
// ──────────────────────────────────────────────────────────────────────────────

// SDJWTIssueOptions configures SD-JWT credential issuance.
type SDJWTIssueOptions struct {
	IssuerDID            string
	IssuerKey            ed25519.PrivateKey
	VerificationMethodID string
	SubjectDID           string
	// SchemaID is validated against the registered schema taxonomy.
	SchemaID string
	// SelectiveClaims are individually hashed; the holder chooses which to reveal.
	SelectiveClaims map[string]any
	// AlwaysVisibleClaims are embedded directly in the JWT payload (not hashed).
	// Use for claims that must always be visible to any verifier, e.g. credential type,
	// assurance level, or a cnf key-binding claim.
	AlwaysVisibleClaims map[string]any
	ValidFor            time.Duration
}

// IssueSDJWT creates a signed SD-JWT credential.
// Returns an SDJWTToken containing the issuer JWT and all disclosures.
// The holder stores the full token; they present a subset of disclosures per verifier.
func IssueSDJWT(opts SDJWTIssueOptions) (*SDJWTToken, error) {
	if !strings.HasPrefix(opts.IssuerDID, "did:") {
		return nil, ErrIssuerNotDID
	}
	if strings.HasPrefix(opts.IssuerDID, "did:key:") {
		return nil, ErrEphemeralIssuer
	}
	if opts.IssuerDID == "" || opts.IssuerKey == nil {
		return nil, errors.New("sdjwt: issuer DID and key are required")
	}
	if opts.SubjectDID == "" {
		return nil, errors.New("sdjwt: subject DID is required")
	}
	if opts.ValidFor <= 0 {
		opts.ValidFor = 24 * time.Hour
	}
	if opts.SchemaID != "" {
		if _, err := schema.GetSchema(opts.SchemaID); err != nil {
			return nil, fmt.Errorf("sdjwt: unknown schema %q: %w", opts.SchemaID, err)
		}
	}

	// Create one Disclosure per selective claim, collect their sha-256 digests.
	disclosures := make([]Disclosure, 0, len(opts.SelectiveClaims))
	sdDigests := make([]string, 0, len(opts.SelectiveClaims))
	for k, v := range opts.SelectiveClaims {
		d, err := NewDisclosure(k, v)
		if err != nil {
			return nil, err
		}
		digest, err := d.Digest()
		if err != nil {
			return nil, err
		}
		disclosures = append(disclosures, d)
		sdDigests = append(sdDigests, digest)
	}

	now := time.Now()
	payload := map[string]any{
		"iss":     opts.IssuerDID,
		"sub":     opts.SubjectDID,
		"iat":     now.Unix(),
		"exp":     now.Add(opts.ValidFor).Unix(),
		"_sd_alg": "sha-256",
		"_sd":     sdDigests,
	}
	if opts.SchemaID != "" {
		// vct (Verifiable Credential Type) is the SD-JWT analogue of @type in W3C VCs.
		s, _ := schema.GetSchema(opts.SchemaID)
		payload["vct"] = s.VersionedID()
	}
	for k, v := range opts.AlwaysVisibleClaims {
		payload[k] = v
	}

	jwt, err := signSDJWT(payload, opts.IssuerKey, opts.VerificationMethodID, "vc+sd-jwt")
	if err != nil {
		return nil, fmt.Errorf("sdjwt: sign: %w", err)
	}
	return &SDJWTToken{JWT: jwt, Disclosures: disclosures}, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Parsing
// ──────────────────────────────────────────────────────────────────────────────

// ParsedSDJWT holds the separated components of an SD-JWT presentation string.
type ParsedSDJWT struct {
	// JWT is the issuer-signed JWT (header.payload.signature).
	JWT string
	// Disclosures are the raw base64url-encoded disclosure strings the holder chose to reveal.
	Disclosures []string
	// KBToken is the key-binding JWT, present when the holder proved key possession.
	KBToken string
}

// ParseSDJWT splits an SD-JWT presentation string (<jwt>~[disc*][kb-jwt]) into parts.
func ParseSDJWT(token string) (*ParsedSDJWT, error) {
	if token == "" {
		return nil, errors.New("sdjwt: empty token")
	}
	parts := strings.Split(token, "~")
	if len(parts) < 2 {
		return nil, errors.New("sdjwt: not an SD-JWT — missing ~ separator")
	}
	result := &ParsedSDJWT{JWT: parts[0]}
	for _, p := range parts[1:] {
		if p == "" {
			continue
		}
		// KB-JWTs have header.payload.signature (two dots); disclosures have none.
		if strings.Count(p, ".") == 2 {
			result.KBToken = p
		} else {
			result.Disclosures = append(result.Disclosures, p)
		}
	}
	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Verification
// ──────────────────────────────────────────────────────────────────────────────

// SDJWTVerifyResult contains the verified and disclosed claims from a presentation.
type SDJWTVerifyResult struct {
	IssuerDID       string
	SubjectDID      string
	// SchemaID is the vct claim (versioned credential type).
	SchemaID        string
	// DisclosedClaims contains only the claims the holder chose to reveal.
	DisclosedClaims map[string]any
	// AlwaysClaims contains the non-selective claims visible in the JWT payload.
	AlwaysClaims    map[string]any
	IssuedAt        time.Time
	ExpiresAt       time.Time
	// KeyBindingVerified is true when a KB-JWT was present and verified.
	KeyBindingVerified bool
}

// SDJWTVerifier wraps a DID resolver to verify SD-JWT credentials.
// It reuses the same resolver infrastructure as the W3C VC Verifier.
type SDJWTVerifier struct {
	resolver *resolver.Resolver
}

// NewSDJWTVerifier creates an SDJWTVerifier backed by the given DID resolver.
func NewSDJWTVerifier(r *resolver.Resolver) *SDJWTVerifier {
	return &SDJWTVerifier{resolver: r}
}

// Verify verifies an SD-JWT presentation string and returns the disclosed claims.
//
// If expectedNonce or expectedAudience is non-empty, a KB-JWT must be present
// and its nonce/aud claims must match. This prevents replay attacks.
func (v *SDJWTVerifier) Verify(token, expectedNonce, expectedAudience string) (*SDJWTVerifyResult, error) {
	parsed, err := ParseSDJWT(token)
	if err != nil {
		return nil, err
	}

	// Decode the issuer JWT payload without verifying yet (to find the issuer DID).
	rawClaims, err := parseSDJWTPayload(parsed.JWT)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: parse payload: %w", err)
	}
	issuerDID, _ := rawClaims["iss"].(string)
	if issuerDID == "" {
		return nil, errors.New("sdjwt: missing iss claim")
	}

	// Resolve issuer DID → public key.
	pub, err := v.resolveSigningKey(issuerDID)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: resolve issuer key: %w", err)
	}

	// Verify issuer JWT signature.
	if err := verifySDJWTSig(parsed.JWT, pub); err != nil {
		return nil, fmt.Errorf("sdjwt: %w", err)
	}

	// Check expiry.
	if exp, ok := rawClaims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("sdjwt: credential expired")
		}
	}

	// Build a set of _sd digests from the issuer payload.
	sdDigests := make(map[string]bool)
	if arr, ok := rawClaims["_sd"].([]any); ok {
		for _, d := range arr {
			if s, ok := d.(string); ok {
				sdDigests[s] = true
			}
		}
	}

	// Verify each presented disclosure matches a digest in the _sd array.
	disclosedClaims := make(map[string]any)
	for _, enc := range parsed.Disclosures {
		d, err := ParseDisclosure(enc)
		if err != nil {
			return nil, fmt.Errorf("sdjwt: %w", err)
		}
		digest, err := d.Digest()
		if err != nil {
			return nil, err
		}
		if !sdDigests[digest] {
			return nil, fmt.Errorf("sdjwt: disclosure %q not in _sd hashes — possible forgery", d.Key)
		}
		disclosedClaims[d.Key] = d.Value
	}

	// KB-JWT: required when expectedNonce or expectedAudience is set.
	kbVerified := false
	if parsed.KBToken != "" {
		holderPub, err := extractHolderKey(rawClaims)
		if err != nil || holderPub == nil {
			return nil, errors.New("sdjwt: kb-jwt: no cnf holder key in token")
		}
		if err := verifyKBJWT(parsed, holderPub, expectedNonce, expectedAudience); err != nil {
			return nil, fmt.Errorf("sdjwt: kb-jwt: %w", err)
		}
		kbVerified = true
	} else if expectedNonce != "" || expectedAudience != "" {
		return nil, errors.New("sdjwt: key binding JWT required (nonce/audience expected) but not present")
	}

	// Collect always-visible claims (non-selective, directly in payload).
	skip := map[string]bool{
		"iss": true, "sub": true, "iat": true, "exp": true,
		"_sd": true, "_sd_alg": true, "vct": true, "cnf": true,
	}
	alwaysClaims := make(map[string]any)
	for k, v := range rawClaims {
		if !skip[k] {
			alwaysClaims[k] = v
		}
	}

	result := &SDJWTVerifyResult{
		IssuerDID:          issuerDID,
		SubjectDID:         strOrEmpty(rawClaims["sub"]),
		SchemaID:           strOrEmpty(rawClaims["vct"]),
		DisclosedClaims:    disclosedClaims,
		AlwaysClaims:       alwaysClaims,
		KeyBindingVerified: kbVerified,
	}
	if iat, ok := rawClaims["iat"].(float64); ok {
		result.IssuedAt = time.Unix(int64(iat), 0)
	}
	if exp, ok := rawClaims["exp"].(float64); ok {
		result.ExpiresAt = time.Unix(int64(exp), 0)
	}
	return result, nil
}

// resolveSigningKey resolves an issuer DID to its active Ed25519 signing key.
func (v *SDJWTVerifier) resolveSigningKey(issuerDID string) (ed25519.PublicKey, error) {
	doc, err := v.resolver.Resolve(issuerDID)
	if err != nil {
		return nil, fmt.Errorf("resolve DID %q: %w", issuerDID, err)
	}
	for _, vm := range doc.VerificationMethod {
		if vm.Revoked || vm.PublicKeyMultibase == nil {
			continue
		}
		if vm.Type != "Ed25519VerificationKey2020" {
			continue
		}
		return decodeMultibaseEd25519(*vm.PublicKeyMultibase)
	}
	return nil, fmt.Errorf("no active Ed25519 verification method in DID document for %s", issuerDID)
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

// signSDJWT creates a signed JWT using Ed25519 (EdDSA).
// typ is "vc+sd-jwt" for credential tokens, "kb+jwt" for key-binding tokens.
func signSDJWT(claims any, key ed25519.PrivateKey, kid, typ string) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": typ, "kid": kid})
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigInput := header + "." + payloadB64
	sig := ed25519.Sign(key, []byte(sigInput))
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// verifySDJWTSig checks the Ed25519 signature of a JWT.
func verifySDJWTSig(jwt string, pub ed25519.PublicKey) error {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		return errors.New("malformed JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("invalid signature")
	}
	return nil
}

// parseSDJWTPayload decodes the payload of a JWT without verifying its signature.
func parseSDJWTPayload(jwt string) (map[string]any, error) {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	return claims, json.Unmarshal(raw, &claims)
}

// verifyKBJWT verifies a key-binding JWT appended by the holder.
// It checks nonce, audience, sd_hash, and — when holderPub is non-nil — the
// EdDSA signature. KB-JWTs without a cnf key in the issuer JWT are
// structurally verified only (no signature check).
func verifyKBJWT(parsed *ParsedSDJWT, holderPub ed25519.PublicKey, expectedNonce, expectedAud string) error {
	kbClaims, err := parseSDJWTPayload(parsed.KBToken)
	if err != nil {
		return fmt.Errorf("parse kb claims: %w", err)
	}

	if expectedNonce != "" {
		if nonce, _ := kbClaims["nonce"].(string); nonce != expectedNonce {
			return fmt.Errorf("nonce mismatch: got %q, want %q", nonce, expectedNonce)
		}
	}
	if expectedAud != "" {
		if aud, _ := kbClaims["aud"].(string); aud != expectedAud {
			return fmt.Errorf("audience mismatch: got %q, want %q", aud, expectedAud)
		}
	}

	// sd_hash must equal sha256 of the SD-JWT string that the KB-JWT was appended to.
	expectedHash := sdHashOf(parsed)
	if sdHash, _ := kbClaims["sd_hash"].(string); sdHash != expectedHash {
		return errors.New("sd_hash mismatch — presentation was tampered")
	}

	// Verify KB-JWT signature when the issuer embedded the holder's key via cnf.
	if holderPub != nil {
		if err := verifySDJWTSig(parsed.KBToken, holderPub); err != nil {
			return fmt.Errorf("kb-jwt signature: %w", err)
		}
	}
	return nil
}

// sdHashOf computes the sha-256 hash of the SD-JWT without the KB-JWT.
// This is the value that the holder embeds in the sd_hash claim of the KB-JWT.
func sdHashOf(parsed *ParsedSDJWT) string {
	parts := []string{parsed.JWT}
	parts = append(parts, parsed.Disclosures...)
	// The SD-JWT portion ends with a trailing ~.
	forHash := strings.Join(parts, "~") + "~"
	h := sha256.Sum256([]byte(forHash))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// extractHolderKey extracts the Ed25519 public key from the cnf.jwk claim,
// if present. Returns nil when no cnf is set (key binding optional).
func extractHolderKey(claims map[string]any) (ed25519.PublicKey, error) {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil, nil //nolint:nilnil // no cnf — key binding optional
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, nil
	}
	if kty, _ := jwk["kty"].(string); kty != "OKP" {
		return nil, fmt.Errorf("sdjwt: cnf.jwk kty %q unsupported — expected OKP", kty)
	}
	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, errors.New("sdjwt: cnf.jwk missing x coordinate")
	}
	raw, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: decode cnf.jwk x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("sdjwt: cnf.jwk x must be 32 bytes, got %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func strOrEmpty(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
