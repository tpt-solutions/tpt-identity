# tpt-identity

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8.svg)](https://go.dev)

[![CI](https://github.com/tpt-solutions/tpt-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/tpt-solutions/tpt-identity/actions/workflows/ci.yml)
Sovereign identity backbone for the TPT open-source ecosystem. Every person gets one DID that works across email, healthcare, payments, and civic systems — authenticated however makes sense for them.

## What it does

- **DID management** — create and resolve `did:web`, `did:key`, `did:peer` identifiers (optional: `did:ion` via build tag)
- **Verifiable Credentials** — issue and verify W3C VC Data Model 2.0 with DataIntegrityProof (eddsa-jcs-2022) and SD-JWT selective disclosure
- **Consent receipts** — cryptographically signed records of who accessed what, under what legal basis (NZ Privacy Act 2020 compliant)
- **OIDC Provider** — authorization code flow with mandatory PKCE, dynamic client registration (RFC 7591), token introspection (RFC 7662), back-channel logout (OIDC BCL 1.0), client credentials grant (RFC 6749 §4.4), refresh token rotation
- **Identity bridges** — accept Google, GitHub, Azure AD, SAML 2.0, LDAP/AD, magic link, password, and passkey (WebAuthn) auth; each maps to a platform DID
- **Account linking** — one DID, multiple external auth providers
- **MFA** — TOTP (RFC 6238) with AES-256-GCM encrypted secrets; brute-force lockout
- **Duress code** — secondary passphrase that creates a normal session but fires a silent `session.duress` alert
- **Guardian recovery** — M-of-N Shamir secret sharing so trusted guardians can recover a lost identity key
- **Verifiable audit log** — every event is appended to a SHA-256 hash-chained log; tampering is detectable
- **Credential marketplace** — discoverable registry of which issuers offer which credential schemas
- **Webhook events** — push `credential.issued`, `consent.granted`, `session.duress` etc. to subscribers with HMAC-SHA256 signatures
- **Presentation Exchange** — DIF PE v2 request/submit flow for structured credential requests
- **Inter-service trust** — short-lived Ed25519-signed permits and federated reputation via DNS TXT or VC

## Docker quickstart

```bash
# 1. Generate signing keys
mkdir -p keys
go run ./cmd/tpt-identity keygen --method web --domain example.com \
  --out-sign keys/ed25519.pem --out-enc keys/x25519.pem --passphrase ""

# 2. Copy and edit config
cp config.yaml.example config.yaml
# Set issuer, db_path, api_key, identity.signing_key, etc.

# 3. Build and start
docker compose up --build

# Server is now at http://localhost:8080
```

## Binary quickstart

```bash
# Install
go install github.com/tpt-solutions/tpt-identity/cmd/tpt-identity@latest

# 1. Generate keys
tpt-identity keygen --method web --domain example.com \
  --out-sign keys/ed25519.pem --out-enc keys/x25519.pem --passphrase ""

# 2. Edit config
cp config.yaml.example config.yaml

# 3. Run migrations
tpt-identity migrate up

# 4. Start server
tpt-identity serve --config config.yaml
```

### Optional build tags

```bash
go build -tags "ion"           # include did:ion (Bitcoin/Sidetree)
go build -tags "saml"          # include SAML 2.0 identity bridge
go build -tags "ldap"          # include LDAP/Active Directory bridge
go build -tags "ion,saml,ldap" # all optional features
```

## Integration guide (OIDC)

Register your application, then follow the standard PKCE authorization code flow:

```bash
# Step 1: Register a client (once)
curl -s -X POST https://identity.example.com/oidc/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "token_endpoint_auth_method": "none"
  }' | tee client.json

CLIENT_ID=$(jq -r .client_id client.json)

# Step 2: Generate PKCE verifier + challenge
VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | head -c 43)
CHALLENGE=$(echo -n "$VERIFIER" | sha256sum -b | xxd -r -p | base64 -w 0 | tr '+/' '-_' | tr -d '=')

# Step 3: Redirect user to /authorize
echo "https://identity.example.com/authorize?response_type=code\
&client_id=$CLIENT_ID\
&redirect_uri=https://myapp.example.com/callback\
&scope=openid\
&state=$(openssl rand -hex 16)\
&code_challenge=$CHALLENGE\
&code_challenge_method=S256"

# Step 4: Exchange code for tokens
curl -s -X POST https://identity.example.com/token \
  -d "grant_type=authorization_code" \
  -d "code=<code_from_callback>" \
  -d "redirect_uri=https://myapp.example.com/callback" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$VERIFIER"
```

## Webhook verification

Every webhook delivery includes an `X-TPT-Signature-256` header:

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "net/http"
)

func verifyWebhook(r *http.Request, signingSecret string) bool {
    sig := r.Header.Get("X-TPT-Signature-256")
    body, _ := io.ReadAll(r.Body)
    mac := hmac.New(sha256.New, []byte(signingSecret))
    mac.Write(body)
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(sig), []byte(expected))
}
```

## Configuration

Copy `config.yaml.example` to `config.yaml`. All keys can be overridden via environment variables prefixed `TPT_IDENTITY_` (e.g. `TPT_IDENTITY_API_KEY`).

| Key | Description |
|-----|-------------|
| `issuer` | Canonical HTTPS URL — used as OIDC issuer and `did:web` base _(required)_ |
| `listen_addr` | HTTP bind address (default `:8080`) |
| `db_path` | SQLite database file path |
| `api_key` | Bearer token for admin/service endpoints |
| `identity.signing_key` | Path to Ed25519 private key PEM |
| `identity.passphrase` | Argon2id passphrase for key decryption |
| `totp_passphrase` | Passphrase for TOTP secret encryption (defaults to `identity.passphrase`) |
| `rate_limit` | Requests per second per IP (default `50`) |
| `server.trusted_proxies` | CIDR list of trusted reverse proxies for `X-Forwarded-For` |
| `cors.allowed_origins` | Allowed CORS origins (empty = CORS disabled) |
| `bridges.oidc[]` | OIDC relying-party bridges — `name`, `issuer`, `client_id`, `client_secret`, `scopes` |
| `bridges.password.enabled` | Enable legacy password bridge (default `false`) |
| `consent.expiry_warning_days` | Fire `consent.expiring_soon` events N days before expiry (default `7`) |
| `marketplace.advertise` | Enable the credential marketplace registry (default `false`) |
| `log.level` | `debug`, `info`, `warn`, `error` (default `info`) |
| `log.format` | `json` or `text` (default `json`) |

## Deployment notes

### HTTPS (required)

Run behind Caddy or nginx. Caddy example:

```
identity.example.com {
    reverse_proxy localhost:8080
}
```

### SQLite WAL mode

The server enables WAL mode automatically. For best performance, mount the database on a local filesystem (not NFS). The store uses a single writer connection intentionally — do not set `SetMaxOpenConns` higher than 1.

### Key file permissions

```bash
chmod 600 keys/ed25519.pem keys/x25519.pem
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           tpt-identity                               │
│                                                                      │
│  ┌──────────────────── Identity Bridge ───────────────────────────┐  │
│  │ OIDC RP (Google/GitHub/Azure) │ Magic Link │ SAML† │ LDAP/AD† │  │
│  │ Password (opt-in) │ WebAuthn/Passkeys │ TOTP MFA                │  │
│  └────────────────────────────┬───────────────────────────────────┘  │
│                               │ ExternalIdentity → platform DID      │
│  ┌─────────┐  ┌────────────┐  ┌───────────┐  ┌──────────────────┐   │
│  │   DID   │  │  VC + SD-  │  │  Consent  │  │  OIDC Provider   │   │
│  │  layer  │  │    JWT     │  │ grants +  │  │ PKCE · RFC 7591  │   │
│  │ w/k/p/i │  │ issue/vrfy │  │ receipts  │  │ introspect · BCL │   │
│  └────┬────┘  └─────┬──────┘  └─────┬─────┘  └────────┬─────────┘   │
│       │              │               │                  │             │
│  ┌────┴──────────────┴───────────────┴──────────────────┴──────────┐  │
│  │              SQLite store (PostgreSQL-compatible schema)         │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │  REST API · rate limit · audit log · webhook events · metrics  │   │
│  └───────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │  Duress alerts   │  │ Guardian recovery│  │  Credential market  │  │
│  └──────────────────┘  └─────────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
 † requires build tag
```

## API endpoints

The full API is described in [`api/openapi.yaml`](api/openapi.yaml) (OpenAPI 3.1). The running server serves the same document at `GET /openapi.yaml`. Use it to generate clients, for example `progenitor` for Rust or `openapi-generator` for other languages. A test fails if a route is added to `api/server.go` without a matching entry in the spec.

The tables below are a summary.

### Public — no auth required

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/openid-configuration` | OIDC discovery document |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |
| GET | `/.well-known/did.json` | Platform DID document |
| GET | `/authorize` | OIDC authorization (PKCE + state required) |
| POST | `/token` | Token exchange, refresh, client credentials |
| POST | `/oauth/introspect` | RFC 7662 token introspection |
| GET | `/userinfo` | Subject DID + AMR claims |
| POST | `/oidc/register` | RFC 7591 dynamic client registration |
| POST | `/oidc/revoke` | RFC 7009 token revocation |
| GET | `/healthz` | Liveness probe |
| GET | `/readyz` | Readiness probe (DB check) |
| GET | `/api/v1/status/{listId}` | BitstringStatusList credential |
| GET | `/api/v1/marketplace` | Credential marketplace (issuers + schemas) |

### Identity bridge — public

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/{provider}` | Start redirect-based bridge flow |
| GET | `/auth/{provider}/callback` | OAuth2/OIDC callback |
| POST | `/auth/magiclink/request` | Request a magic link |
| GET | `/auth/magiclink/verify` | Verify magic link token |
| POST | `/auth/password` | Password authentication |
| POST | `/auth/webauthn/register/begin` | Start passkey registration |
| POST | `/auth/webauthn/register/finish` | Complete passkey registration |
| POST | `/auth/webauthn/login/begin` | Start passkey login |
| POST | `/auth/webauthn/login/finish` | Complete passkey login |

### Self-service — bearer token (user's own access token)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/me/sessions` | List active sessions |
| DELETE | `/api/v1/me/sessions/{id}` | Revoke a session |
| GET | `/api/v1/me/links` | List linked external providers |
| DELETE | `/api/v1/me/links/{provider}` | Unlink a provider |
| POST | `/api/v1/me/totp/enrol` | Enrol TOTP — returns `otpauth://` URI |
| POST | `/api/v1/me/totp/verify` | Verify a TOTP code |
| DELETE | `/api/v1/me/totp` | Remove TOTP enrolment |
| POST | `/api/v1/me/duress/enrol` | Set duress passphrase |
| DELETE | `/api/v1/me/duress` | Remove duress passphrase |
| POST | `/api/v1/me/recovery/enrol` | Configure guardian recovery (M-of-N) |
| GET | `/api/v1/me/recovery` | Get recovery configuration |

### Protected — Bearer `api_key`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities` | Register a DID |
| GET | `/api/v1/identities/{did}` | Resolve identity |
| POST | `/api/v1/credentials` | Issue a W3C VC |
| POST | `/api/v1/credentials/verify` | Verify a W3C VC |
| GET | `/api/v1/credentials` | List credentials for a subject |
| DELETE | `/api/v1/credentials/{id}` | Delete a credential |
| POST | `/api/v1/credentials/sd-jwt` | Issue an SD-JWT credential |
| POST | `/api/v1/credentials/sd-jwt/verify` | Verify an SD-JWT presentation |
| GET/POST/DELETE | `/api/v1/consents/grants` | Consent grant management |
| GET | `/api/v1/consents/receipts` | Consent receipt audit trail |
| GET | `/api/v1/schemas` | Full schema taxonomy |
| POST/GET/DELETE | `/api/v1/webhooks` | Webhook subscription management |
| POST | `/api/v1/presentations/request` | DIF PE v2 presentation request |
| POST | `/api/v1/presentations/submit` | Submit a VP |
| DELETE | `/api/v1/sessions/{id}` | Admin session revocation |
| GET | `/api/v1/audit-log` | Paginated verifiable audit log |
| GET | `/api/v1/audit-log/proof/{seq}` | Hash-chain proof from seq to head |
| POST | `/api/v1/recovery/{id}/approve` | Guardian approves a recovery request |
| GET | `/api/v1/recovery/{id}` | Get recovery request status |
| POST | `/api/v1/recovery/initiate` | Initiate M-of-N recovery |
| GET | `/metrics` | Prometheus metrics (api_key gated) |

## Security notes

- **PKCE** (S256) and **state** are mandatory on every authorization code flow
- **Dynamic client registration** is required — unregistered `client_id` values are rejected
- **Refresh tokens** are single-use, stored by `sha256(raw)`, with stolen-token detection via grace window
- **did:key** is blocked as a VC issuer DID — use `did:web` or `did:peer`
- **did:web** resolution enforces RFC-1918 blocking and 5-second timeout (SSRF hardening)
- **Webhook URLs** are validated at registration time; loopback/RFC-1918 targets are rejected
- **Argon2id** (64 MB / 3 iterations / 4 threads) for all passphrase-based key derivation
- **LDAP bridge** requires `ldaps://` — plaintext `ldap://` is refused at startup
- **Duress passphrase** creates a normal-looking session while triggering a silent `session.duress` event
- Extra-sensitive schemas (mental-health, addiction, criminal-record, etc.) require individual explicit grants
- Consent revocations set `revokedAt` — records are never deleted (NZ Privacy Act 2020 audit trail)
- Audit log events are SHA-256 hash-chained; any tampering breaks the chain

## Credential schema taxonomy

50+ schemas across 11 categories. See [SCHEMA.md](SCHEMA.md) for the full reference.

Categories: `identity` · `healthcare` · `finance` · `professional` · `education` · `legal` · `property` · `civic` · `social` · `travel` · `insurance`

## PWA / Mobile

tpt-identity exposes a pure REST + OIDC API. The recommended mobile integration is a **Progressive Web App** that communicates directly with the API — no native SDK or app-store distribution required.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual licensed as above, without any additional terms or conditions.
