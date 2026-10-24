package store

import (
	"context"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/consent"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// Store is the persistence interface. All upstream code targets this interface only;
// the SQLite implementation is in sqlite.go.
type Store interface {
	// --- Identities ---
	SaveIdentity(ctx context.Context, id *Identity) error
	GetIdentity(ctx context.Context, did string) (*Identity, error)
	ListIdentities(ctx context.Context, limit, offset int) ([]*Identity, int, error)
	UpdateIdentity(ctx context.Context, id *Identity) error

	// --- DID Documents ---
	SaveDocument(ctx context.Context, doc *did.Document) error
	// CreateIdentityWithDocument saves an identity and its DID document atomically.
	CreateIdentityWithDocument(ctx context.Context, id *Identity, doc *did.Document) error
	GetDocument(ctx context.Context, did string) (*did.Document, error)

	// --- Verifiable Credentials ---
	SaveCredential(ctx context.Context, cred *vc.VerifiableCredential) error
	GetCredential(ctx context.Context, id string) (*vc.VerifiableCredential, error)
	ListCredentials(ctx context.Context, subjectDID string) ([]*vc.VerifiableCredential, error)
	DeleteCredential(ctx context.Context, id string) error

	// --- Consent Grants ---
	SaveGrant(ctx context.Context, g *consent.Grant) error
	GetGrant(ctx context.Context, id string) (*consent.Grant, error)
	ListGrants(ctx context.Context, subjectDID string) ([]*consent.Grant, error)
	// RevokeGrant soft-deletes a grant: it sets revoked_at and keeps the row for the audit trail.
	// It returns false if the grant does not exist or is already revoked.
	RevokeGrant(ctx context.Context, id string, at time.Time) (bool, error)

	// --- Consent Receipts ---
	SaveReceipt(ctx context.Context, r *consent.Receipt) error
	ListReceipts(ctx context.Context, subjectDID string) ([]*consent.Receipt, error)

	// --- OIDC Sessions ---
	SaveSession(ctx context.Context, s *OIDCSession) error
	GetSession(ctx context.Context, id string) (*OIDCSession, error)
	GetSessionByCode(ctx context.Context, code string) (*OIDCSession, error)
	ListSessionsBySubject(ctx context.Context, subjectDID string) ([]*OIDCSession, error)
	DeleteSession(ctx context.Context, id string) error
	PurgeExpiredSessions(ctx context.Context) error

	// --- OIDC Clients (RFC 7591 dynamic registration) ---
	SaveClient(ctx context.Context, c *OIDCClient) error
	GetClient(ctx context.Context, clientID string) (*OIDCClient, error)
	ListClients(ctx context.Context) ([]*OIDCClient, error)
	DeleteClient(ctx context.Context, clientID string) error

	// --- Refresh Tokens ---
	SaveRefreshToken(ctx context.Context, t *RefreshToken) error
	GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, hash string) error
	// MarkRefreshTokenUsed atomically sets used_at. It returns false if the token was
	// already used, so exactly one concurrent refresh can win.
	MarkRefreshTokenUsed(ctx context.Context, hash string, at time.Time) (bool, error)
	// DeleteRefreshTokenFamily removes every refresh token issued in one rotation chain.
	DeleteRefreshTokenFamily(ctx context.Context, familyID string) error
	// TakeSessionByCode atomically fetches and deletes the session holding an
	// authorization code, so a code can be redeemed only once.
	TakeSessionByCode(ctx context.Context, code string) (*OIDCSession, error)

	// --- External Provider Links (Identity Bridge) ---
	SaveExternalLink(ctx context.Context, l *ExternalProviderLink) error
	GetExternalLink(ctx context.Context, provider, externalID string) (*ExternalProviderLink, error)
	ListExternalLinks(ctx context.Context, subjectDID string) ([]*ExternalProviderLink, error)
	DeleteExternalLink(ctx context.Context, provider, externalID string) error

	// --- Magic Link Tokens ---
	SaveMagicLinkToken(ctx context.Context, t *MagicLinkToken) error
	GetMagicLinkToken(ctx context.Context, hash string) (*MagicLinkToken, error)
	DeleteMagicLinkToken(ctx context.Context, hash string) error

	// --- WebAuthn Credentials ---
	SaveWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	GetWebAuthnCredential(ctx context.Context, credentialID string) (*WebAuthnCredential, error)
	ListWebAuthnCredentials(ctx context.Context, subjectDID string) ([]*WebAuthnCredential, error)
	UpdateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	DeleteWebAuthnCredential(ctx context.Context, credentialID string) error

	// --- TOTP Credentials ---
	SaveTOTPCredential(ctx context.Context, c *TOTPCredential) error
	GetTOTPCredential(ctx context.Context, subjectDID string) (*TOTPCredential, error)
	DeleteTOTPCredential(ctx context.Context, subjectDID string) error
	// ConsumeTOTPStep atomically records a used time step; it returns false if the step is not newer.
	ConsumeTOTPStep(ctx context.Context, subjectDID string, step int64) (bool, error)

	// --- Webhook Subscriptions ---
	SaveWebhookSubscription(ctx context.Context, s *WebhookSubscription) error
	GetWebhookSubscription(ctx context.Context, id string) (*WebhookSubscription, error)
	ListWebhookSubscriptions(ctx context.Context, eventType string) ([]*WebhookSubscription, error)
	DeleteWebhookSubscription(ctx context.Context, id string) error

	// --- Auth Failures (brute-force lockout) ---
	RecordAuthFailure(ctx context.Context, subjectOrEmail string) error
	GetAuthFailures(ctx context.Context, subjectOrEmail string) (count int, lockedUntil *time.Time, err error)
	ClearAuthFailures(ctx context.Context, subjectOrEmail string) error

	// --- Password Credentials (password bridge) ---
	SavePasswordHash(ctx context.Context, identifier, hash string) error
	GetPasswordHash(ctx context.Context, identifier string) (string, error)
	DeletePasswordHash(ctx context.Context, identifier string) error

	// --- Duress Passphrase ---
	SaveDuressConfig(ctx context.Context, subjectDID, hash string) error
	GetDuressHash(ctx context.Context, subjectDID string) (string, error)
	DeleteDuressConfig(ctx context.Context, subjectDID string) error

	// --- Consent Expiry ---
	ListExpiringGrants(ctx context.Context, within time.Duration) ([]*consent.Grant, error)

	// --- Verifiable Audit Log (hash-chained events) ---
	AppendAuditEvent(ctx context.Context, eventType, payload, prevHash string) (*AuditEvent, error)
	GetAuditHead(ctx context.Context) (*AuditEvent, error)
	ListAuditEvents(ctx context.Context, limit, offset int) ([]*AuditEvent, int, error)

	// --- Guardian Recovery ---
	SaveRecoveryConfig(ctx context.Context, cfg *RecoveryConfig) error
	GetRecoveryConfig(ctx context.Context, subjectDID string) (*RecoveryConfig, error)
	DeleteRecoveryConfig(ctx context.Context, subjectDID string) error
	SaveRecoveryRequest(ctx context.Context, req *RecoveryRequest) error
	GetRecoveryRequest(ctx context.Context, id string) (*RecoveryRequest, error)
	UpdateRecoveryRequest(ctx context.Context, req *RecoveryRequest) error
	SaveRecoveryShare(ctx context.Context, share *RecoveryShare) error
	ListRecoveryShares(ctx context.Context, requestID string) ([]*RecoveryShare, error)

	// --- Pushed Authorization Requests (RFC 9126) ---
	SavePARRequest(ctx context.Context, req *PARRequest) error
	GetPARRequest(ctx context.Context, requestURI string) (*PARRequest, error)
	DeletePARRequest(ctx context.Context, requestURI string) error

	// --- Device Authorization Grant (RFC 8628) ---
	SaveDeviceCode(ctx context.Context, dc *DeviceCode) error
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	UpdateDeviceCode(ctx context.Context, dc *DeviceCode) error
	DeleteDeviceCode(ctx context.Context, deviceCode string) error

	// --- Revoked Access Tokens (RFC 7009) ---
	// RevokeAccessToken records hash (sha256 hex of the token) until expiresAt.
	RevokeAccessToken(ctx context.Context, hash string, expiresAt time.Time) error
	// IsAccessTokenRevoked reports whether hash is on the revocation list.
	IsAccessTokenRevoked(ctx context.Context, hash string) (bool, error)

	// --- Password Reset Tokens ---
	SavePasswordResetToken(ctx context.Context, t *PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, hash string) (*PasswordResetToken, error)
	DeletePasswordResetToken(ctx context.Context, hash string) error
	// ConsumePasswordResetToken atomically fetches and deletes the token, so a reset
	// token can be used once even under concurrent requests. It returns sql.ErrNoRows if absent.
	ConsumePasswordResetToken(ctx context.Context, hash string) (*PasswordResetToken, error)

	// --- Privacy Budget ---
	RecordDisclosure(ctx context.Context, d *PrivacyDisclosure) error
	ListDisclosures(ctx context.Context, subjectDID string, schemaID string) ([]*PrivacyDisclosure, error)
	CountDisclosures(ctx context.Context, subjectDID string, schemaID string) (int, error)

	// --- OID4VCI Credential Offers ---
	SaveCredentialOffer(ctx context.Context, offer *CredentialOffer) error
	GetCredentialOffer(ctx context.Context, id string) (*CredentialOffer, error)
	MarkCredentialOfferUsed(ctx context.Context, id string) error

	// Close releases resources.
	Close() error
}

// Identity records a registered DID and its associated key material.
type Identity struct {
	DID            string    `json:"did"`
	Method         string    `json:"method"` // "web", "key", "peer", "ion"
	SigningKeyPath string    `json:"signingKeyPath,omitempty"`
	EncKeyPath     string    `json:"encKeyPath,omitempty"`
	Role           string    `json:"role"` // "user", "operator", "admin"
	TenantID       string    `json:"tenantId,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// OIDCSession tracks an in-progress or completed OIDC authorization code flow.
type OIDCSession struct {
	ID          string `json:"id"`
	SubjectDID  string `json:"subjectDid"`
	ClientID    string `json:"clientId"`
	RedirectURI string `json:"redirectUri"`
	Scope       string `json:"scope"`
	Nonce       string `json:"nonce,omitempty"`
	State       string `json:"state,omitempty"`
	Code        string `json:"code,omitempty"`
	// PKCE (RFC 7636) — S256 is the only accepted method.
	CodeChallenge       string     `json:"codeChallenge,omitempty"`
	CodeChallengeMethod string     `json:"codeChallengeMethod,omitempty"` // always "S256"
	AccessToken         string     `json:"accessToken,omitempty"`
	RefreshTokenHash    string     `json:"refreshTokenHash,omitempty"`
	UserAgent           string     `json:"userAgent,omitempty"`
	IPAddress           string     `json:"ipAddress,omitempty"`
	LastUsedAt          *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
	ExpiresAt           time.Time  `json:"expiresAt"`
}

// OIDCClient is a registered OIDC/OAuth2 client (RFC 7591).
type OIDCClient struct {
	ClientID                string   `json:"clientId"`
	ClientSecretHash        string   `json:"-"`
	ClientName              string   `json:"clientName"`
	RedirectURIs            []string `json:"redirectUris"`
	TokenEndpointAuthMethod string   `json:"tokenEndpointAuthMethod"`
	GrantTypes              []string `json:"grantTypes"`
	ResponseTypes           []string `json:"responseTypes"`
	Scope                   string   `json:"scope,omitempty"`
	TenantID                string   `json:"tenantId,omitempty"`
	// BackchannelLogoutURI is the OIDC Back-Channel Logout 1.0 URI. Optional.
	BackchannelLogoutURI string `json:"backchannelLogoutUri,omitempty"`
	// PostLogoutRedirectURIs are validated targets for RP-initiated logout (RFC 9596).
	PostLogoutRedirectURIs []string  `json:"postLogoutRedirectUris,omitempty"`
	CreatedAt              time.Time `json:"createdAt"`
}

// RefreshToken stores a hashed refresh token for rotation.
type RefreshToken struct {
	Hash       string     `json:"hash"`     // sha256(raw_token)
	FamilyID   string     `json:"familyId"` // shared by every token in one rotation chain
	SubjectDID string     `json:"subjectDid"`
	ClientID   string     `json:"clientId"`
	Scope      string     `json:"scope"`
	IssuedAt   time.Time  `json:"issuedAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	UsedAt     *time.Time `json:"usedAt,omitempty"` // non-nil = consumed; detect theft during grace window
}

// ExternalProviderLink maps an external identity to a platform DID.
type ExternalProviderLink struct {
	SubjectDID string    `json:"subjectDid"`
	Provider   string    `json:"provider"`   // "google", "github", "magiclink-email", "saml:acme", "ldap", etc.
	ExternalID string    `json:"externalId"` // stable external identifier (sub, NameID, DN, email)
	LinkedAt   time.Time `json:"linkedAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
}

// MagicLinkToken is a one-time-use token for email-based passwordless auth.
type MagicLinkToken struct {
	Hash      string    `json:"hash"`  // sha256(raw_token)
	Email     string    `json:"email"` // normalised email address
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// WebAuthnCredential stores a registered WebAuthn/FIDO2 authenticator.
type WebAuthnCredential struct {
	CredentialID    string     `json:"credentialId"` // base64url-encoded raw ID
	SubjectDID      string     `json:"subjectDid"`
	PublicKeyCBOR   []byte     `json:"publicKeyCbor"` // COSE public key bytes
	AttestationType string     `json:"attestationType"`
	AAGUID          string     `json:"aaguid"`
	SignCount       uint32     `json:"signCount"`
	Name            string     `json:"name,omitempty"`
	Transports      []string   `json:"transports,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	LastUsedAt      *time.Time `json:"lastUsedAt,omitempty"`
}

// TOTPCredential stores an encrypted TOTP secret for a subject.
type TOTPCredential struct {
	SubjectDID      string    `json:"subjectDid"`
	EncryptedSecret string    `json:"encryptedSecret"` // hex(salt) + ":" + hex(nonce) + ":" + hex(ciphertext)
	AccountName     string    `json:"accountName"`
	CreatedAt       time.Time `json:"createdAt"`
	// VerifiedAt is nil until the first code is checked; a pending factor does not count as enrolled.
	VerifiedAt *time.Time `json:"verifiedAt,omitempty"`
	// LastStep is the last accepted 30-second time step (replay protection).
	LastStep int64 `json:"-"`
}

// WebhookSubscription registers a URL to receive platform events.
type WebhookSubscription struct {
	ID         string   `json:"id"`
	URL        string   `json:"url"`
	EventTypes []string `json:"eventTypes"` // e.g. ["credential.issued", "consent.granted"]
	// SigningSecret is the raw HMAC key for delivery payloads. The receiver holds the same
	// value, so it must be stored and cannot be hashed. Never serialised to API callers.
	SigningSecret string    `json:"-"`
	TenantID      string    `json:"tenantId,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}

// AuditEvent is a single entry in the hash-chained verifiable audit log.
type AuditEvent struct {
	Seq       int64     `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	Payload   string    `json:"payload"`   // JSON string
	Hash      string    `json:"hash"`      // SHA-256(prev_hash || event_json)
	PrevHash  string    `json:"prev_hash"` // hash of the previous event; empty for the first
}

// RecoveryConfig stores the guardian configuration for M-of-N key recovery.
type RecoveryConfig struct {
	SubjectDID   string    `json:"subject_did"`
	Threshold    int       `json:"threshold"` // minimum guardians required
	GuardianDIDs []string  `json:"guardian_dids"`
	CreatedAt    time.Time `json:"created_at"`
}

// RecoveryRequest is an in-progress recovery initiated by a subject.
type RecoveryRequest struct {
	ID              string    `json:"id"`
	SubjectDID      string    `json:"subject_did"`
	StartedAt       time.Time `json:"started_at"`
	SharesCollected int       `json:"shares_collected"`
	Completed       bool      `json:"completed"`
	// Commitment is hex(sha256(recovery token)). Completion requires the shares to
	// recombine to a token matching it. Never serialised to API callers.
	Commitment string `json:"-"`
}

// RecoveryShare is a single guardian's contribution to a recovery request.
type RecoveryShare struct {
	RequestID   string    `json:"request_id"`
	GuardianDID string    `json:"guardian_did"`
	ShareHash   string    `json:"share_hash"` // sha256(raw_share) — raw share sent to guardian out-of-band
	CollectedAt time.Time `json:"collected_at"`
}

// PARRequest stores a pushed authorization request (RFC 9126).
type PARRequest struct {
	RequestURI string    `json:"request_uri"` // urn:ietf:params:oauth:request_uri:<random>
	ClientID   string    `json:"client_id"`
	Params     string    `json:"params"` // JSON: all /authorize query params
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// DeviceCode stores a device authorization flow state (RFC 8628).
type DeviceCode struct {
	DeviceCode   string    `json:"device_code"`
	UserCode     string    `json:"user_code"`
	ClientID     string    `json:"client_id"`
	Scope        string    `json:"scope"`
	SubjectDID   string    `json:"subject_did,omitempty"` // set when user approves
	Approved     bool      `json:"approved"`
	Denied       bool      `json:"denied"`
	ExpiresAt    time.Time `json:"expires_at"`
	IntervalSecs int       `json:"interval_secs"`
	CreatedAt    time.Time `json:"created_at"`
}

// PasswordResetToken is a one-time token for password reset (15-min TTL).
type PasswordResetToken struct {
	Hash       string    `json:"hash"`       // sha256(raw_token)
	Identifier string    `json:"identifier"` // email or subject DID
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// PrivacyDisclosure records a single selective-disclosure event for privacy budget tracking.
type PrivacyDisclosure struct {
	ID          string    `json:"id"`
	SubjectDID  string    `json:"subject_did"`
	SchemaID    string    `json:"schema_id"`
	VerifierDID string    `json:"verifier_did"`
	FieldNames  []string  `json:"field_names"` // disclosed field names
	DisclosedAt time.Time `json:"disclosed_at"`
}

// CredentialOffer stores an OID4VCI credential offer (single-use, short-lived).
type CredentialOffer struct {
	ID         string    `json:"id"` // embedded in openid-credential-offer:// URI
	ClientID   string    `json:"client_id,omitempty"`
	SchemaIDs  []string  `json:"schema_ids"` // credential types being offered
	IssuerDID  string    `json:"issuer_did"`
	SubjectDID string    `json:"subject_did,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	Used       bool      `json:"used"`
	CreatedAt  time.Time `json:"created_at"`
}
