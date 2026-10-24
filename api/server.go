package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/tpt-solutions/tpt-identity/internal/authn"
	"github.com/tpt-solutions/tpt-identity/internal/bridge"
	"github.com/tpt-solutions/tpt-identity/internal/events"
	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/internal/store"
	"github.com/tpt-solutions/tpt-identity/oidc"
	"github.com/tpt-solutions/tpt-identity/pkg/marketplace"
)

// Server is the tpt-identity HTTP server.
type Server struct {
	mux            *http.ServeMux
	store          store.Store
	resolver       *resolver.Resolver
	oidc           *oidc.Provider
	apiKey         string
	issuer         string
	// platformDID is the did:web identifier of this server; it is the issuer of every credential.
	platformDID    string
	platformDIDDoc []byte // JSON DID document served at /.well-known/did.json; nil if unavailable
	totpPassphrase string
	logger         *slog.Logger
	magicLinks     MagicLinkSender
	passwordResets PasswordResetSender
	recoveries     *recoveryCollector
	presentations  *presentationRequests
	bridgeKey      []byte // HMAC key for bridge state tokens (independent of api_key)
	limiter        *ipRateLimiter
	// Platform signing key — used for issuing VCs and SD-JWT credentials.
	signingKey   ed25519.PrivateKey
	signingKeyID string // verification method ID, e.g. did:web:example.com#signing-key-1
	// Platform X25519 encryption key — used for DIDComm v2 envelope decryption.
	encKey   [32]byte
	encKeyID string // key agreement method ID, e.g. did:web:example.com#enc-key-1
	// Bridge layer
	bridges *bridge.Manager
	mapper  *bridge.Mapper
	// Lifecycle services
	events  *events.Bus
	lockout *authn.LockoutManager
	// Trusted proxy CIDR ranges; only X-Forwarded-For from these IPs is honoured.
	trustedProxies []*net.IPNet
	// Allowed CORS origins; empty = CORS disabled.
	corsAllowedOrigins []string
	// WebAuthn / Passkeys — nil when not configured.
	webAuthn       *gowebauthn.WebAuthn
	waRegSessions  sync.Map // sessionID → *waSessionEntry (registration flow)
	waAuthSessions sync.Map // sessionID → *waSessionEntry (authentication flow)
	// Credential marketplace — nil when not configured.
	marketplace *marketplace.Registry
	// OID4VP in-process request/response handler.
	oid4vp *oidc.OID4VPHandler
}

// Config holds Server configuration.
type Config struct {
	APIKey         string
	// BridgeSecret keys the HMAC on bridge state tokens. Set it (at least 32 bytes) when
	// running more than one replica or when flows must survive a restart. If empty, a
	// random key is generated at startup and in-flight bridge logins fail after a restart.
	BridgeSecret string
	Issuer       string
	TotpPassphrase string
	// SigningKey is the platform Ed25519 private key used for VC and SD-JWT issuance.
	SigningKey   ed25519.PrivateKey
	SigningKeyID string // verification method ID
	// EncKey is the platform X25519 private key for DIDComm v2 envelope decryption.
	// Both EncKey and EncKeyID must be set to enable the POST /didcomm endpoint.
	EncKey   [32]byte
	EncKeyID string // key agreement method ID, e.g. did:web:example.com#enc-key-1
	Store        store.Store
	Resolver     *resolver.Resolver
	OIDC         *oidc.Provider
	Bridges      *bridge.Manager
	// MagicLinkSender delivers magic-link URLs out of band (e.g. email). Required for
	// POST /auth/magiclink/request to succeed; the link is never returned to the caller.
	MagicLinkSender MagicLinkSender
	// PasswordResetSender delivers reset tokens. Without it, reset requests are accepted
	// but no token is issued.
	PasswordResetSender PasswordResetSender
	// Events is the shared event bus. Subscribers (audit log, marketplace) must be
	// attached to this same bus. If nil, the server creates a private one.
	Events *events.Bus
	Logger *slog.Logger
	// RateLimit is the number of requests per second per IP (0 = disabled).
	RateLimit float64
	// TrustedProxies is a list of CIDR ranges whose X-Forwarded-For header is trusted.
	// When empty, RemoteAddr is always used for rate-limiting and audit logging.
	TrustedProxies []string
	// CORSAllowedOrigins enables CORS for the listed origins. Empty = CORS disabled.
	CORSAllowedOrigins []string
	// WebAuthn / Passkeys — all three must be set to enable WebAuthn endpoints.
	WebAuthnRPID          string   // e.g. "example.com"
	WebAuthnRPDisplayName string   // human-readable relying party name
	WebAuthnRPOrigins     []string // e.g. ["https://example.com"]
	// Marketplace is an optional credential registry; nil = marketplace disabled.
	Marketplace *marketplace.Registry
}

// NewServer wires all routes.
func NewServer(cfg Config) *Server {
	rateLimit := cfg.RateLimit
	if rateLimit == 0 {
		rateLimit = 50 // default: 50 req/s per IP
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	eventBus := cfg.Events
	if eventBus == nil {
		eventBus = events.NewBus(cfg.Store, logger)
	}
	platformDID, platformDIDDoc := "", []byte(nil)
	if cfg.SigningKey != nil {
		if id, doc, err := buildPlatformDIDDocument(cfg.Issuer, cfg.SigningKey.Public().(ed25519.PublicKey), cfg.EncKey); err != nil {
			logger.Warn("platform DID not configured", "error", err)
		} else {
			platformDID, platformDIDDoc = id, doc
		}
	}
	bridgeKey := []byte(cfg.BridgeSecret)
	if len(bridgeKey) == 0 {
		bridgeKey = make([]byte, 32)
		if _, err := rand.Read(bridgeKey); err != nil {
			panic("api: crypto/rand unavailable: " + err.Error())
		}
		logger.Warn("bridge_secret not set; using a random key, in-flight bridge logins will not survive a restart")
	}
	bridges := cfg.Bridges
	if bridges == nil {
		bridges = bridge.NewManager()
	}
	var trustedNets []*net.IPNet
	for _, cidr := range cfg.TrustedProxies {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Warn("invalid trusted_proxy CIDR — skipping", "cidr", cidr, "err", err)
			continue
		}
		trustedNets = append(trustedNets, ipNet)
	}

	s := &Server{
		mux:                http.NewServeMux(),
		store:              cfg.Store,
		resolver:           cfg.Resolver,
		oidc:               cfg.OIDC,
		apiKey:             cfg.APIKey,
		issuer:             cfg.Issuer,
		platformDID:        platformDID,
		platformDIDDoc:     platformDIDDoc,
		totpPassphrase:     cfg.TotpPassphrase,
		signingKey:         cfg.SigningKey,
		signingKeyID:       cfg.SigningKeyID,
		encKey:             cfg.EncKey,
		encKeyID:           cfg.EncKeyID,
		logger:             logger,
		magicLinks:         cfg.MagicLinkSender,
		passwordResets:     cfg.PasswordResetSender,
		recoveries:         newRecoveryCollector(),
		presentations:      newPresentationRequests(),
		bridgeKey:          bridgeKey,
		limiter:            newIPRateLimiter(rateLimit, int(rateLimit*2)),
		bridges:            bridges,
		mapper:             bridge.NewMapper(cfg.Store),
		events:             eventBus,
		lockout:            authn.NewLockoutManager(cfg.Store),
		trustedProxies:     trustedNets,
		corsAllowedOrigins: cfg.CORSAllowedOrigins,
		marketplace:        cfg.Marketplace,
		oid4vp:             oidc.NewOID4VPHandler(cfg.OIDC),
	}

	// Initialise WebAuthn when all required config fields are present.
	if cfg.WebAuthnRPID != "" {
		origins := cfg.WebAuthnRPOrigins
		if len(origins) == 0 {
			origins = []string{cfg.Issuer}
		}
		rpName := cfg.WebAuthnRPDisplayName
		if rpName == "" {
			rpName = cfg.WebAuthnRPID
		}
		wa, waErr := gowebauthn.New(&gowebauthn.Config{
			RPID:          cfg.WebAuthnRPID,
			RPDisplayName: rpName,
			RPOrigins:     origins,
		})
		if waErr != nil {
			logger.Warn("webauthn init failed — passkey endpoints disabled", "err", waErr)
		} else {
			s.webAuthn = wa
		}
	}

	// Periodically evict expired WebAuthn sessions (both registration and auth).
	go func() {
		for range time.Tick(5 * time.Minute) {
			now := time.Now()
			s.waRegSessions.Range(func(k, v any) bool {
				if v.(*waSessionEntry).expiresAt.Before(now) {
					s.waRegSessions.Delete(k)
				}
				return true
			})
			s.waAuthSessions.Range(func(k, v any) bool {
				if v.(*waSessionEntry).expiresAt.Before(now) {
					s.waAuthSessions.Delete(k)
				}
				return true
			})
		}
	}()

	s.events.SetDeliveryHook(func(success bool) {
		result := "success"
		if !success {
			result = "failure"
		}
		WebhookDeliveriesTotal.WithLabelValues(result).Inc()
	})

	// Wire credential bootstrap: auto-issue VCs from bridge claims for new identities.
	if s.signingKey != nil {
		s.mapper.SetBootstrap(s.bootstrapCredentials)
	}

	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) wrap(h http.HandlerFunc) http.HandlerFunc {
	return s.securityHeaders(s.cors(limitBody(h)))
}

// limitBody caps every request body, so JSON and form decoding in any handler is bounded.
func limitBody(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
		}
		h(w, r)
	}
}

func (s *Server) routes() {
	// DIDComm v2 receive endpoint (public — encrypted; no bearer auth required).
	s.mux.HandleFunc("POST /didcomm", s.wrap(s.rateLimit(s.audit(s.handleDIDCommReceive))))

	// Public: OIDC, DID, JWKS, WebFinger
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.wrap(s.audit(s.oidc.DiscoveryHandler)))
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.wrap(s.audit(s.oidc.JWKSHandler)))
	s.mux.HandleFunc("GET /.well-known/did.json", s.wrap(s.audit(s.handleDIDDocument)))
	s.mux.HandleFunc("GET /.well-known/webfinger", s.wrap(s.rateLimit(s.audit(s.oidc.WebFingerHandler))))
	s.mux.HandleFunc("GET /.well-known/openid-credential-issuer", s.wrap(s.audit(s.oidc.CredentialIssuerMetadataHandler)))
	s.mux.HandleFunc("GET /authorize", s.wrap(s.rateLimit(s.audit(s.oidc.AuthorizeHandler))))
	s.mux.HandleFunc("POST /token", s.wrap(s.rateLimit(s.audit(s.oidc.TokenHandler))))
	s.mux.HandleFunc("GET /userinfo", s.wrap(s.rateLimit(s.audit(s.oidc.UserinfoHandler))))
	// Client registration creates trusted relying parties, so it requires the operator key.
	s.mux.HandleFunc("POST /oidc/register", s.wrap(s.rateLimit(s.audit(s.auth(s.oidc.RegisterClientHandler)))))
	s.mux.HandleFunc("POST /oidc/revoke", s.wrap(s.rateLimit(s.audit(s.oidc.RevokeHandler))))
	s.mux.HandleFunc("POST /oauth/introspect", s.wrap(s.rateLimit(s.audit(s.oidc.IntrospectHandler))))
	// RP-initiated logout (OIDC Session Management)
	s.mux.HandleFunc("GET /oidc/logout", s.wrap(s.rateLimit(s.audit(s.oidc.LogoutHandler))))
	// Pushed Authorization Requests (RFC 9126)
	s.mux.HandleFunc("POST /oidc/par", s.wrap(s.rateLimit(s.audit(s.oidc.PARHandler))))
	// Step-up authentication (RFC 9470)
	s.mux.HandleFunc("POST /oidc/stepup", s.wrap(s.rateLimit(s.audit(s.oidc.StepUpHandler))))
	// Device Authorization Grant (RFC 8628)
	s.mux.HandleFunc("POST /device_authorization", s.wrap(s.rateLimit(s.audit(s.oidc.DeviceAuthorizationHandler))))
	s.mux.HandleFunc("GET /device", s.wrap(s.rateLimit(s.audit(s.oidc.DeviceVerifyHandler))))
	s.mux.HandleFunc("POST /device/approve", s.wrap(s.rateLimit(s.audit(s.oidc.DeviceApproveHandler))))
	// OID4VCI
	s.mux.HandleFunc("POST /oid4vci/offers", s.wrap(s.rateLimit(s.audit(s.auth(s.oidc.CreateCredentialOfferHandler(s.signingKey, s.signingKeyID, s.store))))))
	s.mux.HandleFunc("POST /oid4vci/credential", s.wrap(s.rateLimit(s.audit(s.oidc.CredentialHandler(s.signingKey, s.signingKeyID, s.store)))))
	// OID4VP
	s.mux.HandleFunc("POST /oid4vp/requests", s.wrap(s.rateLimit(s.audit(s.auth(s.oid4vp.CreateRequestHandler)))))
	s.mux.HandleFunc("GET /oid4vp/requests/{id}", s.wrap(s.rateLimit(s.audit(s.oid4vp.GetRequestHandler))))
	s.mux.HandleFunc("POST /oid4vp/responses", s.wrap(s.rateLimit(s.audit(s.oid4vp.PostResponseHandler))))
	s.mux.HandleFunc("GET /oid4vp/responses/{id}", s.wrap(s.rateLimit(s.audit(s.oid4vp.GetResponseHandler))))

	// Health (no wrap — lightweight probes)
	s.mux.HandleFunc("GET /healthz", s.handleLiveness)
	s.mux.HandleFunc("GET /readyz", s.handleReadiness)

	// Prometheus metrics — gated by api_key when configured
	s.mux.HandleFunc("GET /metrics", s.wrap(s.auth(MetricsHandler().ServeHTTP)))

	// Status list (public — verifiers fetch without auth)
	s.mux.HandleFunc("GET /api/v1/status/{listId}", s.wrap(s.audit(s.handleStatusList)))

	// ── Identity bridge (public) ───────────────────────────────────────────
	s.mux.HandleFunc("GET /auth/{provider}", s.wrap(s.rateLimit(s.audit(s.handleBridgeStart))))
	s.mux.HandleFunc("GET /auth/{provider}/callback", s.wrap(s.rateLimit(s.audit(s.handleBridgeCallback))))
	// SAML 2.0 SP endpoints (RealMe and any other SAML IdP).
	s.mux.HandleFunc("GET /auth/{provider}/metadata", s.wrap(s.audit(s.handleSAMLMetadata)))
	s.mux.HandleFunc("POST /auth/{provider}/acs", s.wrap(s.rateLimit(s.audit(s.handleSAMLACS))))
	s.mux.HandleFunc("POST /auth/password", s.wrap(s.rateLimit(s.audit(s.handlePasswordAuth))))
	s.mux.HandleFunc("POST /auth/magiclink/request", s.wrap(s.rateLimit(s.audit(s.handleMagicLinkRequest))))
	s.mux.HandleFunc("GET /auth/magiclink/verify", s.wrap(s.rateLimit(s.audit(s.handleMagicLinkVerify))))
	// Password change and reset
	s.mux.HandleFunc("POST /auth/password/change", s.wrap(s.rateLimit(s.audit(s.handlePasswordChange))))
	s.mux.HandleFunc("POST /auth/password/reset/request", s.wrap(s.rateLimit(s.audit(s.handlePasswordResetRequest))))
	s.mux.HandleFunc("POST /auth/password/reset/confirm", s.wrap(s.rateLimit(s.audit(s.handlePasswordResetConfirm))))

	// ── Protected API ──────────────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/v1/identities", s.wrap(s.rateLimit(s.audit(s.auth(s.handleCreateIdentity)))))
	s.mux.HandleFunc("GET /api/v1/identities/{did}", s.wrap(s.rateLimit(s.audit(s.auth(s.handleGetIdentity)))))
	s.mux.HandleFunc("POST /api/v1/credentials", s.wrap(s.rateLimit(s.audit(s.auth(s.handleIssueCredential)))))
	s.mux.HandleFunc("POST /api/v1/credentials/verify", s.wrap(s.rateLimit(s.audit(s.auth(s.handleVerifyCredential)))))
	s.mux.HandleFunc("GET /api/v1/credentials", s.wrap(s.rateLimit(s.audit(s.auth(s.handleListCredentials)))))
	s.mux.HandleFunc("DELETE /api/v1/credentials/{id}", s.wrap(s.rateLimit(s.audit(s.auth(s.handleDeleteCredential)))))
	// SD-JWT selective disclosure
	s.mux.HandleFunc("POST /api/v1/credentials/sd-jwt", s.wrap(s.rateLimit(s.audit(s.auth(s.handleIssueSDJWT)))))
	s.mux.HandleFunc("POST /api/v1/credentials/sd-jwt/verify", s.wrap(s.rateLimit(s.audit(s.auth(s.handleVerifySDJWT)))))
	s.mux.HandleFunc("POST /api/v1/credentials/sd-jwt/present", s.wrap(s.rateLimit(s.audit(s.handleSDJWTPresentWithWatermark))))
	// Batch issuance + freshness oracle
	s.mux.HandleFunc("POST /api/v1/credentials/batch", s.wrap(s.rateLimit(s.audit(s.auth(s.handleBatchIssueCredentials)))))
	s.mux.HandleFunc("GET /api/v1/credentials/{id}/fresh", s.wrap(s.rateLimit(s.audit(s.handleCredentialFreshness))))
	// ZKP — derived age-over proof (issuer-computed, no ZK-SNARK)
	s.mux.HandleFunc("POST /api/v1/credentials/zkp/age", s.wrap(s.rateLimit(s.audit(s.auth(s.handleIssueAgeProof)))))
	s.mux.HandleFunc("GET /api/v1/consents/grants", s.wrap(s.rateLimit(s.audit(s.handleListGrants))))
	s.mux.HandleFunc("POST /api/v1/consents/grants", s.wrap(s.rateLimit(s.audit(s.handleCreateGrant))))
	s.mux.HandleFunc("DELETE /api/v1/consents/grants/{id}", s.wrap(s.rateLimit(s.audit(s.handleRevokeGrant))))
	s.mux.HandleFunc("GET /api/v1/consents/receipts", s.wrap(s.rateLimit(s.audit(s.auth(s.handleListReceipts)))))
	s.mux.HandleFunc("POST /api/v1/consents/receipts", s.wrap(s.rateLimit(s.audit(s.auth(s.handleSubmitReceipt)))))
	s.mux.HandleFunc("DELETE /api/v1/sessions/{id}", s.wrap(s.rateLimit(s.audit(s.auth(s.handleDeleteSession)))))
	s.mux.HandleFunc("GET /api/v1/schemas", s.wrap(s.rateLimit(s.audit(s.auth(s.handleListSchemas)))))

	// ── Me — user self-service (bearer token, not api-key) ─────────────────
	s.mux.HandleFunc("GET /api/v1/me", s.wrap(s.rateLimit(s.audit(s.handleGetMe))))
	s.mux.HandleFunc("GET /api/v1/me/export", s.wrap(s.rateLimit(s.audit(s.handleExportMe))))
	s.mux.HandleFunc("GET /api/v1/me/sessions", s.wrap(s.rateLimit(s.audit(s.handleListMySessions))))
	s.mux.HandleFunc("DELETE /api/v1/me/sessions/{id}", s.wrap(s.rateLimit(s.audit(s.handleRevokeMySession))))
	s.mux.HandleFunc("GET /api/v1/me/links", s.wrap(s.rateLimit(s.audit(s.handleListLinks))))
	s.mux.HandleFunc("DELETE /api/v1/me/links/{provider}", s.wrap(s.rateLimit(s.audit(s.handleUnlink))))
	s.mux.HandleFunc("POST /api/v1/me/totp/enrol", s.wrap(s.rateLimit(s.audit(s.handleTOTPEnrol))))
	s.mux.HandleFunc("POST /api/v1/me/totp/verify", s.wrap(s.rateLimit(s.audit(s.handleTOTPVerify))))
	s.mux.HandleFunc("DELETE /api/v1/me/totp", s.wrap(s.rateLimit(s.audit(s.handleTOTPUnenrol))))
	s.mux.HandleFunc("POST /api/v1/me/duress/enrol", s.wrap(s.rateLimit(s.audit(s.handleDuressEnrol))))
	s.mux.HandleFunc("DELETE /api/v1/me/duress", s.wrap(s.rateLimit(s.audit(s.handleDuressRemove))))
	s.mux.HandleFunc("GET /api/v1/me/privacy-budget", s.wrap(s.rateLimit(s.audit(s.handleGetPrivacyBudget))))
	s.mux.HandleFunc("POST /api/v1/me/privacy-budget/record", s.wrap(s.rateLimit(s.audit(s.handleRecordDisclosure))))

	// ── Webhooks ───────────────────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/v1/webhooks", s.wrap(s.rateLimit(s.audit(s.auth(s.handleRegisterWebhook)))))
	s.mux.HandleFunc("GET /api/v1/webhooks", s.wrap(s.rateLimit(s.audit(s.auth(s.handleListWebhooks)))))
	s.mux.HandleFunc("DELETE /api/v1/webhooks/{id}", s.wrap(s.rateLimit(s.audit(s.auth(s.handleDeleteWebhook)))))
	s.mux.HandleFunc("POST /api/v1/webhooks/{id}/test", s.wrap(s.rateLimit(s.audit(s.auth(s.handleTestWebhook)))))

	// ── Audit log (api_key required) ───────────────────────────────────────
	s.mux.HandleFunc("GET /api/v1/audit-log", s.wrap(s.rateLimit(s.audit(s.auth(s.handleListAuditLog)))))
	s.mux.HandleFunc("GET /api/v1/audit-log/proof/{seq}", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAuditProof)))))

	// ── Marketplace (public) ───────────────────────────────────────────────
	s.mux.HandleFunc("GET /api/v1/marketplace", s.wrap(s.rateLimit(s.audit(s.handleListMarketplace))))

	// ── Guardian recovery ──────────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/v1/me/recovery/enrol", s.wrap(s.rateLimit(s.audit(s.handleRecoveryEnrol))))
	s.mux.HandleFunc("GET /api/v1/me/recovery", s.wrap(s.rateLimit(s.audit(s.handleGetRecoveryConfig))))
	s.mux.HandleFunc("POST /api/v1/recovery/{id}/approve", s.wrap(s.rateLimit(s.audit(s.handleRecoveryApprove))))
	s.mux.HandleFunc("POST /api/v1/recovery/initiate", s.wrap(s.rateLimit(s.audit(s.auth(s.handleRecoveryInitiate)))))
	s.mux.HandleFunc("GET /api/v1/recovery/{id}", s.wrap(s.rateLimit(s.audit(s.auth(s.handleGetRecovery)))))

	// ── Presentation Exchange ──────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/v1/presentations/request", s.wrap(s.rateLimit(s.audit(s.auth(s.handleCreatePresentationRequest)))))
	s.mux.HandleFunc("POST /api/v1/presentations/submit", s.wrap(s.rateLimit(s.audit(s.auth(s.handleSubmitPresentation)))))

	// ── Admin API (api_key required) ──────────────────────────────────────────
	s.mux.HandleFunc("GET /admin/v1/identities", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAdminListIdentities)))))
	s.mux.HandleFunc("POST /admin/v1/identities/{did}/suspend", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAdminSuspendIdentity)))))
	s.mux.HandleFunc("POST /admin/v1/identities/{did}/unsuspend", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAdminUnsuspendIdentity)))))
	s.mux.HandleFunc("DELETE /admin/v1/identities/{did}", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAdminDeleteIdentity)))))
	s.mux.HandleFunc("GET /admin/v1/clients", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAdminListClients)))))
	s.mux.HandleFunc("DELETE /admin/v1/clients/{id}", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAdminDeleteClient)))))
	s.mux.HandleFunc("POST /admin/v1/lockout/{subject}/clear", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAdminClearLockout)))))
	s.mux.HandleFunc("GET /admin/v1/stats", s.wrap(s.rateLimit(s.audit(s.auth(s.handleAdminStats)))))

	// ── WebAuthn / Passkeys ────────────────────────────────────────────────
	// Registration uses OIDC bearer auth (user must already have a session).
	s.mux.HandleFunc("POST /api/v1/me/webauthn/register/begin", s.wrap(s.rateLimit(s.audit(s.handleWebAuthnRegisterBegin))))
	s.mux.HandleFunc("POST /api/v1/me/webauthn/register/finish", s.wrap(s.rateLimit(s.audit(s.handleWebAuthnRegisterFinish))))
	// Login is public — credential discovery happens during the ceremony.
	s.mux.HandleFunc("POST /api/v1/webauthn/login/begin", s.wrap(s.rateLimit(s.audit(s.handleWebAuthnLoginBegin))))
	s.mux.HandleFunc("POST /api/v1/webauthn/login/finish", s.wrap(s.rateLimit(s.audit(s.handleWebAuthnLoginFinish))))
	// Credential management requires OIDC bearer auth.
	s.mux.HandleFunc("GET /api/v1/me/webauthn/credentials", s.wrap(s.rateLimit(s.audit(s.handleListWebAuthnCredentials))))
	s.mux.HandleFunc("DELETE /api/v1/me/webauthn/credentials/{id}", s.wrap(s.rateLimit(s.audit(s.handleDeleteWebAuthnCredential))))
}

// --- Middleware ---

// audit logs every request as a structured audit event: method, path, remote IP, status.
// It also records Prometheus HTTP metrics.
func (s *Server) audit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rw, r)
		elapsed := time.Since(start)
		s.logger.Info("audit",
			"method", r.Method,
			"path", r.URL.Path,
			"ip", s.clientIP(r),
			"status", rw.status,
			"duration_ms", elapsed.Milliseconds(),
			"user_agent", r.UserAgent(),
		)
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(rw.status)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(elapsed.Seconds())
	}
}

// rateLimit rejects requests from IPs that exceed the configured token-bucket rate.
func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		if !s.limiter.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// auth middleware checks the Bearer API key.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Fail closed: an unconfigured key must never grant access.
		if s.apiKey == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(bearer), []byte(s.apiKey)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// parsePagination reads limit and offset from query params with safe defaults.
func parsePagination(r *http.Request, defaultLimit, maxLimit int) (limit, offset int) {
	limit = defaultLimit
	offset = 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// writeJSONError writes a consistent JSON error body understood by all API clients.
// maxJSONBody caps request bodies decoded with json.NewDecoder.
const maxJSONBody = 1 << 20 // 1 MiB

// randomHex returns n cryptographically random bytes encoded as hex (2n characters).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSONError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// --- Handlers ---

func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}


// --- responseRecorder captures the status code for audit logging ---

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *responseRecorder) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// --- Rate limiter (token bucket, per IP) ---

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	capacity int     // max burst
}

func newIPRateLimiter(rate float64, capacity int) *ipRateLimiter {
	l := &ipRateLimiter{buckets: make(map[string]*bucket), rate: rate, capacity: capacity}
	// Periodically evict stale entries.
	go func() {
		for range time.Tick(5 * time.Minute) {
			l.evict()
		}
	}()
	return l
}

func (l *ipRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(l.capacity), lastSeen: time.Now()}
		l.buckets[ip] = b
	}
	now := time.Now()
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.capacity) {
		b.tokens = float64(l.capacity)
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *ipRateLimiter) evict() {
	cutoff := time.Now().Add(-10 * time.Minute)
	l.mu.Lock()
	for ip, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
	l.mu.Unlock()
}

// clientIP returns the real client IP. X-Forwarded-For is only trusted when
// the direct connection comes from a configured trusted proxy CIDR.
func (s *Server) clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	if len(s.trustedProxies) > 0 {
		remoteIP := net.ParseIP(remoteHost)
		isTrusted := false
		if remoteIP != nil {
			for _, cidr := range s.trustedProxies {
				if cidr.Contains(remoteIP) {
					isTrusted = true
					break
				}
			}
		}
		if isTrusted {
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				parts := strings.SplitN(fwd, ",", 2)
				if ip := strings.TrimSpace(parts[0]); ip != "" {
					return ip
				}
			}
		}
	}
	return remoteHost
}

// securityHeaders sets security-relevant response headers on every request.
func (s *Server) securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if strings.HasPrefix(s.issuer, "https://") {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next(w, r)
	}
}

// cors adds CORS headers when the request Origin matches a configured allowed origin.
func (s *Server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && len(s.corsAllowedOrigins) > 0 {
			for _, allowed := range s.corsAllowedOrigins {
				if allowed == "*" || allowed == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
					w.Header().Set("Access-Control-Max-Age", "600")
					break
				}
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

