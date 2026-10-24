package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	tptcrypto "github.com/tpt-solutions/tpt-identity/pkg/crypto"
	"github.com/google/uuid"
)

// ReputationRecord holds the reputation of a domain or DID.
// It is produced by either VerifyReputationVC (preferred) or LookupReputation (legacy DNS).
type ReputationRecord struct {
	// Domain is the subject domain or DID whose reputation this record describes.
	Domain string
	// Score is a 0–100 trust score.
	Score int
	// Tier is a human-readable trust tier: "trusted", "verified", "provisional", "restricted".
	Tier string
	// Since is the date the reputation was established (YYYY-MM-DD).
	Since string
	// Raw is the original DNS TXT record string (populated only for DNS-sourced records).
	Raw string
}

// ----- VC-based reputation (preferred) -----

// ReputationVCType is the VC type claim carried by every reputation credential.
const ReputationVCType = "TptReputationCredential"

// reputationVC is the wire format of a TPT reputation Verifiable Credential.
type reputationVC struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	ValidFrom         string            `json:"validFrom"`
	ValidUntil        string            `json:"validUntil,omitempty"`
	CredentialSubject reputationSubject `json:"credentialSubject"`
	Proof             *reputationProof  `json:"proof,omitempty"`
}

type reputationSubject struct {
	ID    string `json:"id"`
	Score int    `json:"score"`
	Tier  string `json:"tier"`
	Since string `json:"since"`
}

type reputationProof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// IssueReputationVC issues a DataIntegrityProof-signed reputation VC.
// The returned bytes are the JSON-encoded credential ready to publish or store.
// authorityDID is the trust authority issuing the assessment; subjectDID is the
// domain or DID being rated (may be a did:web, did:peer, or plain domain string).
func IssueReputationVC(
	authorityDID string,
	authorityKey ed25519.PrivateKey,
	verificationMethodID string,
	subjectDID string,
	rec ReputationRecord,
	validFor time.Duration,
) ([]byte, error) {
	if rec.Score < 0 || rec.Score > 100 {
		return nil, fmt.Errorf("reputation vc: score %d out of range [0,100]", rec.Score)
	}
	now := time.Now().UTC()
	cred := reputationVC{
		Context:   []string{"https://www.w3.org/ns/credentials/v2", "https://tpt.nz/ns/trust/v1"},
		ID:        "urn:uuid:" + uuid.NewString(),
		Type:      []string{"VerifiableCredential", ReputationVCType},
		Issuer:    authorityDID,
		ValidFrom: now.Format(time.RFC3339),
		CredentialSubject: reputationSubject{
			ID:    subjectDID,
			Score: rec.Score,
			Tier:  rec.Tier,
			Since: rec.Since,
		},
	}
	if validFor != 0 {
		cred.ValidUntil = now.Add(validFor).Format(time.RFC3339)
	}

	proofOptionsBytes, documentBytes, err := reputationSignInput(reputationProof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "eddsa-jcs-2022",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: verificationMethodID,
		ProofPurpose:       "assertionMethod",
	}, cred)
	if err != nil {
		return nil, err
	}

	ph := sha256.Sum256(proofOptionsBytes)
	dh := sha256.Sum256(documentBytes)
	combined := append(ph[:], dh[:]...)
	sig := ed25519.Sign(authorityKey, combined)

	cred.Proof = &reputationProof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "eddsa-jcs-2022",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: verificationMethodID,
		ProofPurpose:       "assertionMethod",
		ProofValue:         base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.Marshal(cred)
}

// VerifyReputationVC parses and verifies a JSON-encoded reputation VC.
// It checks the DataIntegrityProof signature against authorityPub, validates
// expiry, and returns the embedded ReputationRecord on success.
func VerifyReputationVC(credJSON []byte, authorityPub ed25519.PublicKey) (*ReputationRecord, error) {
	var cred reputationVC
	if err := json.Unmarshal(credJSON, &cred); err != nil {
		return nil, fmt.Errorf("reputation vc: unmarshal: %w", err)
	}
	if !sliceContains(cred.Type, ReputationVCType) {
		return nil, errors.New("reputation vc: not a TptReputationCredential")
	}
	if cred.Proof == nil {
		return nil, errors.New("reputation vc: missing proof")
	}
	if cred.ValidUntil != "" {
		exp, err := time.Parse(time.RFC3339, cred.ValidUntil)
		if err != nil {
			return nil, fmt.Errorf("reputation vc: parse validUntil: %w", err)
		}
		if time.Now().After(exp) {
			return nil, errors.New("reputation vc: expired")
		}
	}

	proof := *cred.Proof
	cred.Proof = nil

	proofOptionsBytes, documentBytes, err := reputationSignInput(proof, cred)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(proof.ProofValue)
	if err != nil {
		return nil, fmt.Errorf("reputation vc: decode proof value: %w", err)
	}
	ph := sha256.Sum256(proofOptionsBytes)
	dh := sha256.Sum256(documentBytes)
	combined := append(ph[:], dh[:]...)
	if !ed25519.Verify(authorityPub, combined, sig) {
		return nil, errors.New("reputation vc: invalid signature")
	}

	return &ReputationRecord{
		Domain: cred.CredentialSubject.ID,
		Score:  cred.CredentialSubject.Score,
		Tier:   cred.CredentialSubject.Tier,
		Since:  cred.CredentialSubject.Since,
	}, nil
}

// reputationSignInput returns JCS-canonicalised proof-options bytes and document
// bytes suitable for hashing before signing or verification.
func reputationSignInput(p reputationProof, doc reputationVC) (proofOpts []byte, document []byte, err error) {
	opts := map[string]string{
		"type":               p.Type,
		"cryptosuite":        p.Cryptosuite,
		"created":            p.Created,
		"verificationMethod": p.VerificationMethod,
		"proofPurpose":       p.ProofPurpose,
	}
	proofOpts, err = tptcrypto.JCS(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("reputation vc: jcs proof options: %w", err)
	}
	document, err = tptcrypto.JCS(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("reputation vc: jcs document: %w", err)
	}
	return proofOpts, document, nil
}

func sliceContains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// ----- Trust level classification -----

// TrustLevel classifies a reputation record into a coarse trust level.
type TrustLevel int

const (
	TrustUnknown    TrustLevel = iota // no record or unscored
	TrustRestricted                   // score 0–24
	TrustProvisional                  // score 25–59
	TrustVerified                     // score 60–84
	TrustTrusted                      // score 85–100
)

func (t TrustLevel) String() string {
	switch t {
	case TrustRestricted:
		return "restricted"
	case TrustProvisional:
		return "provisional"
	case TrustVerified:
		return "verified"
	case TrustTrusted:
		return "trusted"
	default:
		return "unknown"
	}
}

// Level derives the TrustLevel from a ReputationRecord. Nil record → TrustUnknown.
func Level(r *ReputationRecord) TrustLevel {
	if r == nil || r.Score < 0 {
		return TrustUnknown
	}
	switch {
	case r.Score >= 85:
		return TrustTrusted
	case r.Score >= 60:
		return TrustVerified
	case r.Score >= 25:
		return TrustProvisional
	default:
		return TrustRestricted
	}
}

// ----- Legacy DNS reputation (deprecated) -----
//
// DNS TXT records are a weak trust anchor: they can be spoofed by DNS hijackers
// and carry no cryptographic proof of the issuer's identity. Prefer VC-based
// reputation for production use. This DNS path is retained for bootstrapping
// and out-of-band discovery only.

// LookupReputation queries DNS TXT records for the TPT reputation of domain.
// The record lives at _tpt-rep.<domain> and must begin with "v=tpt1".
//
// Deprecated: use VC-based reputation instead. DNS TXT provides no cryptographic
// proof of issuer identity and should not be used as a production trust anchor.
func LookupReputation(ctx context.Context, domain string) (*ReputationRecord, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}

	host := "_tpt-rep." + strings.TrimSuffix(domain, ".")
	records, err := net.DefaultResolver.LookupTXT(ctx, host)
	if err != nil {
		if isDNSNoRecord(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reputation: dns lookup %s: %w", host, err)
	}

	for _, r := range records {
		rec := parseReputationTXT(domain, r)
		if rec != nil {
			return rec, nil
		}
	}
	return nil, nil
}

func parseReputationTXT(domain, txt string) *ReputationRecord {
	fields := strings.Fields(txt)
	if len(fields) == 0 || fields[0] != "v=tpt1" {
		return nil
	}
	rec := &ReputationRecord{Domain: domain, Raw: txt, Score: -1}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "score":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
				rec.Score = n
			}
		case "tier":
			rec.Tier = v
		case "since":
			rec.Since = v
		}
	}
	return rec
}

func isDNSNoRecord(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "NXDOMAIN") ||
		strings.Contains(msg, "no answer")
}
