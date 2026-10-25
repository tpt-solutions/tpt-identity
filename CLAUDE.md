# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build ./cmd/tpt-identity/...

# Build with optional features
go build -tags "ion,saml,ldap" ./cmd/tpt-identity/...

# Run all tests
go test ./...

# Run tests in one package
go test -v ./pkg/vc/...
go test -v ./oidc/...

# Run a single test function
go test -v -run TestIssueVerifyRoundTrip ./pkg/vc/...
go test -v -run TestPKCEVerification ./oidc/...

# Test with coverage
go test -cover ./...

# Run the server
go run ./cmd/tpt-identity serve --config config.yaml

# Key management
go run ./cmd/tpt-identity keygen --method web --domain example.com \
  --out-sign keys/ed25519.pem --out-enc keys/x25519.pem --passphrase ""

# Database migrations
go run ./cmd/tpt-identity migrate up
go run ./cmd/tpt-identity migrate version

# Issue a credential
go run ./cmd/tpt-identity issue-vc \
  --issuer did:web:example.com --key ed25519.pem \
  --subject did:peer:xyz --schema identity.legal-name \
  --claim givenNames=Alice --claim familyName=Smith --valid-for 8760h

# Resolve a DID
go run ./cmd/tpt-identity resolve "did:web:example.com"
```

## Architecture

### Module

`github.com/tpt-solutions/tpt-identity` — Go 1.25, pure-Go SQLite (`modernc.org/sqlite`, no CGo).

### Request flow

```
HTTP request
  → api/server.go (rateLimit → audit → auth middleware)
  → handler (api/*.go)
  → oidc/ or pkg/ for domain logic
  → internal/store/ for persistence
```

The `api.Server` struct carries all runtime dependencies: `store.Store`, `oidc.Provider`, `bridge.Manager`, `bridge.Mapper`, `events.Bus`, `authn.LockoutManager`. These are wired in `cmd/tpt-identity/cmd/serve.go`.

### Cryptography invariants

- **Ed25519** for all signing (credentials, JWTs, consent receipts).
- **X25519 + NaCl secretbox** for encryption at rest and DIDComm.
- **Argon2id** (64 MB / 3 iterations / 4 threads) for every key derivation from a passphrase — this is the same constant in both `pkg/keystore/keystore.go` and `internal/authn/totp.go`; keep them in sync.
- **`did:key` may never be an issuer** of persistent credentials — `pkg/vc/issue.go` returns `ErrEphemeralIssuer` if you try. Bridge-created identities use `did:key` only as a stable identifier; auth is via the external provider.
- Proof algorithm: **DataIntegrityProof / eddsa-jcs-2022**. `pkg/crypto/hash.go` provides JCS canonicalization. The signing pipeline is `JCS(proofOptions) ‖ JCS(document) → SHA-256 → Ed25519.Sign`.

### DID methods

Registered at `init()` time via `pkg/did/method.go`'s global registry. The four methods (`web`, `key`, `peer`, and optionally `ion` under build tag, experimental: its Create is not implemented) each live in their own file. `did:web` resolution fetches `https://{domain}/.well-known/did.json` with SSRF hardening (RFC-1918 blocked, 5 s timeout, max 1 redirect). The `internal/resolver` package wraps DID resolution with a TTL cache.

### SD-JWT selective disclosure

`pkg/vc/sdjwt.go` implements SD-JWT (draft-ietf-oauth-selective-disclosure-jwt) as a second credential format alongside the W3C DataIntegrityProof VCs:

- `IssueSDJWT(opts)` → `*SDJWTToken` — produces a JWT (`vc+sd-jwt` typ) where each selective claim is replaced by its SHA-256 hash in the `_sd` array. The `SDJWTToken` holds the JWT and all `Disclosure` values.
- `token.Present(keys)` → string — holder picks which claims to reveal; returns `<jwt>~<selected_discs>~`
- `token.PresentWithKeyBinding(keys, holderKey, kid, nonce, aud)` → string — appends a `kb+jwt` that binds the presentation to a verifier nonce (anti-replay)
- `SDJWTVerifier.Verify(token, nonce, aud)` — resolves the issuer DID, verifies the JWT signature, checks each presented disclosure hash against `_sd`, and validates the KB-JWT if present

**Key constraints:**
- `_sd_alg` is always `sha-256`; `cnf` is optional (used for KB-JWT holder key binding)
- `did:key` is blocked as issuer (same `ErrEphemeralIssuer` as W3C VCs)
- `AlwaysVisibleClaims` go directly into the JWT payload; `SelectiveClaims` are hashed
- The `vct` claim carries the versioned schema ID (analogous to `@type` in W3C VCs)
- `api.Server` needs `signingKey`+`signingKeyID` populated (via `Config.SigningKey`) — both credential handlers (`handleIssueCredential` and `handleIssueSDJWT`) use the platform signing key, not caller-provided keys

### Credential schemas

`pkg/schema/registry.go` holds the in-memory registry. All 50+ schemas are registered by the `init()` calls in `pkg/schema/core/*.go` — the serve command blank-imports this package (`_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"`). Tests that need schemas must do the same. Schema IDs are versioned: `healthcare.nhi-credential-v1`; the registry can look up by base ID (`healthcare.nhi-credential`) to find the latest version.

Schemas marked `ExtraSensitive: true` (mental-health, addiction, criminal-record, etc.) require a separate, individually confirmed consent grant even when a category grant is active — enforced in `api/consents.go` and `pkg/consent/policy.go`.

### OIDC provider

`oidc.Provider` is the OIDC server. Every authorize call requires both `state` (CSRF) and `code_challenge` (PKCE S256). Client registration (`POST /oidc/register`, RFC 7591) is required before a `client_id` is accepted — `AuthorizeHandler` validates against the store. Tokens are EdDSA-signed JWTs; the JWKS (`GET /.well-known/jwks.json`) exposes the public key for downstream verification. Refresh tokens are stored by `sha256(raw_token)`, rotated on every use, with a consumed-token grace window to detect theft.

### Identity bridge

`internal/bridge/bridge.go` defines the `Bridge` interface. Providers (OIDC RP, magic link, password, SAML†, LDAP†; the LDAP bridge has no HTTP login route yet, so it is not reachable) authenticate and return an `ExternalIdentity{Provider, ExternalID, Claims}`. `internal/bridge/mapper.go` finds or creates the corresponding platform DID in the store; each external identity maps to exactly one DID. Account linking (`POST /api/v1/me/links`) attaches additional providers to an existing DID. The bridge HTTP handlers in `api/bridge.go` use a HMAC-signed state token to carry OIDC flow parameters across the external provider redirect without a server-side state table.

†Require build tags: `-tags saml` / `-tags ldap`.

### Persistence

`internal/store/store.go` defines the `Store` interface. `internal/store/sqlite.go` and `internal/store/postgres.go` both implement it through the same query code (`dialect.go`). Migrations live in `internal/store/migrations/`: the top-level `*.sql` files are SQLite, and `pg/*.sql` are PostgreSQL. `migrations.UpFor(db, dialect)` applies the set for the dialect, and records each version in `schema_migrations`. `OpenSQLite` runs the SQLite set on open, and `tpt-identity migrate up` runs it for either database. PostgreSQL migrations take an advisory lock, and the record table is created under that lock. Only `migrate down` is SQLite-only. For SQLite, migration 004 is the complete schema, and its Go hook (`reconcileColumns`) adds columns that older shapes lack. Migrations 001-003 are history. The readiness probe fails when the applied version is behind. Add a PostgreSQL change as a new `pg/NNN_*.sql` file and, if SQLite needs it too, a matching top-level file. All list/get operations use the context for cancellation. `OIDCSession` stores PKCE challenge, state, user-agent, IP, and refresh token hash alongside the auth code.

### Consent and receipts

Grants are soft-deleted (`RevokedAt` set, never `DELETE`d) for NZ Privacy Act 2020 audit trail compliance. Receipts are append-only and cryptographically signed. The `pkg/consent/policy.go` enforcer checks grant expiry, category vs. schema level, and extra-sensitive overrides before allowing credential access.

### Webhook events

`internal/events/events.go` provides a typed event bus. `events.Bus.Publish` fans out to subscribers from the store, delivers via HTTP POST with `X-TPT-Signature-256: sha256=<hmac>`, and retries up to 3 times with exponential backoff. Published on: `credential.issued`, `credential.revoked`, `consent.granted`, `consent.revoked`, `identity.created`, `session.created`, `session.revoked`, `session.duress`, `consent.expiring_soon`, `recovery.initiated`, `recovery.approved`.

The bus also supports in-process `LocalSubscriber` callbacks via `events.Bus.Subscribe(fn)` — used by the audit logger and marketplace registry.

### Duress code

`internal/authn/duress.go` — `DuressManager` stores an Argon2id hash of a secondary passphrase. When the password bridge authenticates with the duress passphrase, the session is created normally (so a coercer sees success) and a `session.duress` event fires silently. Enrol via `POST /api/v1/me/duress/enrol`; remove via `DELETE /api/v1/me/duress`.

### Back-channel logout

`oidc/backchannel.go` — `Provider.SendBackChannelLogout(ctx, clientID, subjectDID)` builds a signed `logout_token` JWT and POSTs it to the client's `backchannel_logout_uri`. Called on session revocation. Clients register their logout URI via `POST /oidc/register`. Advertised in the OIDC discovery document as `backchannel_logout_supported: true`.

### Client credentials grant

`POST /token` with `grant_type=client_credentials` — M2M authentication for downstream services. Only allowed for clients with `token_endpoint_auth_method: client_secret_basic` or `client_secret_post`. Issues an access token with `sub=client_id`; no refresh token.

### Magic link

TTL is **15 minutes** (hardcoded in `internal/bridge/providers/magiclink.go`). Tokens are single-use.

### Verifiable audit log

`internal/auditlog/auditlog.go` — subscribes to all `events.Bus` events and appends each to an `audit_log` table as a hash-chained row. New rows are hash version 2: `SHA-256(prev_hash ‖ {version, event_type, payload, prev_hash, recorded_at})`, so the recorded time is covered. Rows from before versioning are version 1, which omits the time. `store.VerifyAuditChain` checks a run of events under either version. `GET /api/v1/audit-log` returns events in sequence order. `GET /api/v1/audit-log/proof/{seq}` returns the hash chain from `seq` to head for third-party verification.

### Guardian recovery

`pkg/recovery/recovery.go` — GF(256) Shamir secret sharing. `Split(secret, threshold, n)` → `[]Share`; `Combine(shares)` → secret. The API enrols guardians via `POST /api/v1/me/recovery/enrol`, initiates recovery via `POST /api/v1/recovery/initiate`, and guardians approve via `POST /api/v1/recovery/{id}/approve`.

### Credential marketplace

`pkg/marketplace/registry.go` — in-memory registry updated on every `credential.issued` event. `GET /api/v1/marketplace` returns `[{issuer_did, schema_id, schema_name, issued_count}]`. Enabled by `marketplace.advertise: true` in config.

### Prometheus metrics

`GET /metrics` (gated by `api_key` if set) exposes:
- `tpt_http_requests_total{method,path,status}` — counter
- `tpt_http_request_duration_seconds{method,path}` — histogram
- `tpt_credentials_issued_total{format}` — counter
- `tpt_webhook_deliveries_total{result}` — counter

### DIDComm v2 messaging

`pkg/didcomm/didcomm.go` implements DIDComm v2 JWE JSON Serialized envelopes (https://identity.foundation/didcomm-messaging/spec/):

- **`PackAnoncrypt(msg, recipients)`** — ECDH-ES+A256KW+XC20P; per-recipient ephemeral X25519 keypair; sender is hidden.
- **`PackAuthcrypt(msg, recipients, senderKID, senderPriv)`** — ECDH-1PU+A256KW+XC20P; sender's static X25519 key is bound into each recipient's KEK.
- **`Unpack(envelope, recipKeyFn, senderPubFn)`** — decodes protected header, tries each recipient until one succeeds; `senderPubFn` is called only for authcrypt to verify the sender key (may be nil for anoncrypt-only servers).

**Key derivation**: Concat KDF (NIST SP 800-56A / RFC 7518 §4.6.2) — `SHA-256(counter || Z || algID || PartyUInfo || PartyVInfo || keydatalen || SuppPrivInfo)`. For authcrypt: `Z = Ze || Zs` where `Ze = ECDH(ephem, recip)` and `Zs = ECDH(sender_static, recip)`, and `SuppPrivInfo` is the content-encryption tag (the content is encrypted before the CEK is wrapped). Anoncrypt has no SuppPrivInfo.

**`apv`**: `base64url(SHA-256(sorted recipient KIDs joined with "."))` — included in all envelopes; used in the KDF.

**`POST /didcomm`** (public, rate-limited): receives a JWE envelope, decrypts with the platform X25519 key, parses the `Message`, logs it, and returns 202 with `{message_id, type}`. Requires `identity.enc_key` and `identity.enc_key_id` config fields (or auto-derives `<issuer>#enc-key-1`).

**Config**: add `identity.enc_key` (path to X25519 PEM) and optionally `identity.enc_key_id` to `config.yaml` to enable DIDComm receive. Use `keygen --method web` which already writes both Ed25519 and X25519 key files.

**Key constraints**:
- Per-recipient ephemeral X25519 keypair — each recipient gets a different Z, different KEK, same CEK.
- `apv` is shared across recipients (in the protected header), computed over all recipient KIDs sorted lexicographically.
- AES-256-KW integrity check detects wrong KEK (RFC 3394 default IV `0xA6A6A6A6A6A6A6A6`).
- `api/didcomm.go:decodeX25519Multibase` handles both standard `z`+base58btc multibase and the `z`+base64url fallback encoding from `did:peer`.
- **did:peer X25519 keys are base64url under the `u` prefix.** The decoder checks the x25519-pub codec on each candidate, because a `z` prefix over base64url text can base58-decode to other bytes (`api/didcomm.go`, `pkg/did/peer.go`). Keep that check if the decoder changes.

### Trusted proxies / CORS

`server.trusted_proxies` (CIDR list): `X-Forwarded-For` is only trusted when the direct connection IP is in this list; otherwise `RemoteAddr` is used for rate limiting.

`cors.allowed_origins` (string list): enables CORS with the given origins. Empty list = CORS disabled.

## Key constraints and non-obvious rules

- **`did:key` cannot issue persistent VCs** — `ErrEphemeralIssuer` enforced in `vc.Issue`.
- **PKCE + state are mandatory** on every `/authorize` call — no opt-out.
- **Client registration required** — `AuthorizeHandler` rejects unknown `client_id` values; downstream TPT modules must call `POST /oidc/register` first.
- **Extra-sensitive schemas need individual grants** — category grants alone are insufficient for mental-health, sexual-health, reproductive-health, addiction, criminal-record schemas.
- **LDAP requires `ldaps://`** — plaintext `ldap://` returns an error at bridge construction, not at runtime.
- **Argon2id is slow by design** — don't call it in tests without a deterministic fixture or it will dominate test time.
- **Schema `init()` must be imported** — tests touching schema validation need `_ "github.com/tpt-solutions/tpt-identity/pkg/schema/core"`.
- **SQLite is single-writer** — `db.SetMaxOpenConns(1)` is intentional; don't remove it.
- **`did:peer` uses base64url multibase prefix `u`** — the multicodec key bytes are base64url-encoded with prefix `u`, not base58btc (`z`). The VC verifier has a fallback for `u`-prefixed keys.
- **Webhook `handleListWebhooks` passes `""` as eventType** — `ListWebhookSubscriptions("", ...)` returns all subscriptions regardless of event type; non-empty values filter by event type. Do not change this to `"*"`.
- **`SetWebResolverConfig` writes directly to `methods["web"]`** — it does not call `RegisterMethod` (which panics on re-registration). Keep this pattern for test helpers that reconfigure the web resolver.
- **Tenant keys are refused by default** — `auth(scope, ...)` refuses a tenant-bound scoped key with 403. Only routes wrapped in `authTenant` accept one, and their handlers must check the caller with `callerOwns`. Admin is never granted to a tenant key.
- **Deactivation is permanent** — `identity.role = "deactivated"` cannot be suspended or unsuspended, and the DID resolves with no keys (`api/deactivate.go`).
- **`private_key_jwt` assertions use the seen-message table** — the jti is recorded in `didcomm_seen` under sender `client_assertion:<client_id>`.
- **SD-JWT payload claims are issuer-owned** — `iss`, `sub`, `iat`, `exp`, `nbf`, `_sd`, `_sd_alg`, `vct`, `jti` and `status` cannot be set by the caller (`pkg/vc/sdjwt.go`, `issuerOwnedClaims`).
- **Consent is recorded per client and scope** — a grant covers one client and one scope (`oidc:<scope>`), and a first-party client (`first_party`, operator registration only) skips the step. A revoked grant asks again. Consent is not asked for the device flow, where the approval is the consent.
- **The login page is the only browser sign-in** — `/authorize` redirects a session-less browser to `/login` only after the request passes every check (client, redirect URI, state, PKCE). The login transaction is the signed bridge state, bound to the starting browser by `tpt_login_binding`. Form steps need the `tpt_login_csrf` token; the passkey step also needs the `X-CSRF-Token` header. The magic link is not bound to the browser (it is opened on other devices), so PKCE is what protects that code. Pages are served with a CSP that forbids inline script and framing (`api/login.go`).
- **The DIDComm inbox is not an action queue** — messages are kept only when their type is in `didcomm.accepted_types`. Nothing consumes them automatically.
- **`ValidFor < 0` in `vc.Issue` / `IssueReputationVC`** — negative values set an already-expired `ValidUntil` (useful for tests). Zero means no expiry. Both `vc.Issue` and `trust.IssueReputationVC` handle this identically.

## Configuration

To try the platform locally without configuration, run `serve --demo`. It creates `./tpt-demo` on first run, listens on 127.0.0.1:8080 only, prints sign-in emails to the console instead of sending them, and serves a built-in relying party at `/demo` (`cmd/tpt-identity/cmd/demo.go`). Demo mode is not for production.

Copy `config.yaml.example` to `config.yaml`. Key fields: `issuer` (canonical HTTPS URL, used as OIDC issuer and `did:web` base), `identity.signing_key` (path to Ed25519 PEM), `identity.passphrase` (Argon2id key derivation), `api_key` (Bearer token for protected admin endpoints). Bridge providers are configured under `bridges.oidc[]`. TOTP uses `totp_passphrase` (defaults to `identity.passphrase`). Environment variable override prefix: `TPT_IDENTITY_`.

New fields: `server.trusted_proxies` (CIDR list for `X-Forwarded-For` trust), `cors.allowed_origins` (CORS opt-in), `consent.expiry_warning_days` (default 7), `marketplace.advertise` (bool, enables `GET /api/v1/marketplace`), `log.level`, `log.format`.
