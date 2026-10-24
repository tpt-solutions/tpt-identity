# tpt-identity — Build Checklist

## Phase 1 — Crypto & Key Foundation
- [x] `pkg/crypto/sign.go` — Ed25519 sign / verify
- [x] `pkg/crypto/encrypt.go` — X25519 ECDH + NaCl secretbox
- [x] `pkg/crypto/hash.go` — canonical hashing utilities
- [x] `pkg/keystore/keystore.go` — AES-256-GCM encrypted PEM, Argon2id (64 MB / 3 iter / 4 threads), Ed25519 + X25519

## Phase 2 — DID Layer
- [x] `pkg/did/method.go` — `DIDMethod` interface + `RegisterMethod()` registry
- [x] `pkg/did/document.go` — W3C DID Document types
- [x] `pkg/did/web.go` — did:web: create, resolve via HTTPS `/.well-known/did.json`
- [x] `pkg/did/key.go` — did:key: derive DID from Ed25519 pubkey, offline resolve; reject as issuer for persistent VCs
- [x] `pkg/did/peer.go` — did:peer: pairwise DIDs
- [x] `pkg/did/ion.go` — did:ion: Bitcoin/Sidetree (build tag `ion`, optional)
- [x] `internal/resolver/resolver.go` — DID resolver with TTL caching, SSRF hardening (RFC-1918 block, 5 s timeout, max 1 redirect)

## Phase 3 — Credential Schema Taxonomy
- [x] `pkg/schema/registry.go` — `RegisterSchema()`, `RegisterCategory()`, versioned IDs (e.g. `nhi-credential-v1`)
- [x] `pkg/schema/core/` — 50+ schemas across 11 categories (identity, healthcare, finance, professional, education, legal, property, civic, social, travel, insurance); extra-sensitive flags on 7 schemas
- [x] `pkg/schema/validate.go` — validate VC claims against schema definitions
- [x] `pkg/schema/validate.go` — rewrite using `github.com/santhosh-tekuri/jsonschema/v6`; schemas compiled from ClaimDefinitions at runtime, format assertions enabled, compiled schemas cached

## Phase 4 — Verifiable Credentials
- [x] `pkg/vc/credential.go` — W3C VC Data Model 2.0 types
- [x] `pkg/vc/issue.go` — DataIntegrityProof + eddsa-jcs-2022; JCS inline; `ErrEphemeralIssuer` guard for did:key
- [x] `pkg/vc/verify.go` — resolve issuer DID, verify DataIntegrityProof, check expiry, check `credentialStatus`
- [x] `pkg/vc/presentation.go` — Verifiable Presentations with `challenge` + `domain` anti-replay
- [x] `pkg/vc/status.go` — BitstringStatusList: revoke/unrevoke bits, issued VCs carry `credentialStatus` pointer

## Phase 5 — Consent & Trust
- [x] `pkg/consent/policy.go` — schema-level + category grants; extra-sensitive exclusions; `ExpiresAt` / `RevokedAt` (soft-delete for NZ Privacy Act 2020)
- [x] `pkg/consent/receipt.go` — cryptographically signed consent receipts (who, schema, when, legal basis)
- [x] `pkg/trust/permit.go` — Ed25519-signed JWT permits (short-lived, audience-scoped, action-scoped)
- [x] `pkg/trust/reputation.go` — federated reputation via DNS TXT `_tpt-rep.<domain>`

## Phase 6 — Storage
- [x] `internal/store/store.go` — `Store` interface
- [x] `internal/store/sqlite.go` — SQLite implementation (pure-Go modernc, PostgreSQL-compatible schema); tables: identities, DID docs, credentials, consent grants/receipts, OIDC sessions/clients/refresh tokens, external provider links, magic link tokens, WebAuthn credentials, TOTP credentials, webhook subscriptions, auth failures
- [x] `internal/store/migrations/` — embedded SQL migration runner; `migrate up` / `migrate down` / `migrate version` CLI subcommands

## Phase 7 — OIDC Provider
- [x] `oidc/discovery.go` — `GET /.well-known/openid-configuration`; method on `Provider` (includes `jwks_uri`, `registration_endpoint`)
- [x] `oidc/jwks.go` — `GET /.well-known/jwks.json` — exposes Ed25519 public key as JWK (OKP/Ed25519); supports multi-key for rotation
- [x] `oidc/jwt.go` — ID token + access token (EdDSA, `kid` in header, `amr`/`token_type` claims)
- [x] `oidc/provider.go` — auth code flow: PKCE (S256) mandatory, `state` required; refresh token rotation with replay detection; client validation against registration
- [x] `oidc/registration.go` — `POST /oidc/register` RFC 7591 Dynamic Client Registration
- [x] `oidc/revocation.go` — `POST /oidc/revoke` RFC 7009; refresh tokens deleted, access tokens blacklisted in-memory until expiry

## Phase 8 — REST API
- [x] `api/server.go` — route wiring; structured audit logging middleware; token-bucket rate limiting per IP; `bridge.Manager`, `events.Bus`, `authn.LockoutManager` wired
- [x] `api/health.go` — `GET /healthz` (liveness), `GET /readyz` (DB connectivity probe)
- [x] `api/status.go` — `GET /api/v1/status/{listId}` — serve BitstringStatusList VCs
- [x] `api/identity.go` — `POST /api/v1/identities`, `GET /api/v1/identities/{did}`
- [x] `api/credentials.go` — `POST /api/v1/credentials`, verify, list, delete
- [x] `api/consents.go` — grants CRUD, receipts list, schema list
- [x] `api/sessions.go` — `GET /api/v1/me/sessions`, `DELETE /api/v1/me/sessions/{id}` (user self-service, bearer token auth)
- [x] `api/mfa.go` — `POST /api/v1/me/totp/enrol`, `/verify`, `DELETE /api/v1/me/totp`
- [x] `api/webhooks.go` — `POST/GET/DELETE /api/v1/webhooks` — webhook subscription management
- [x] `api/presentations.go` — `POST /api/v1/presentations/request|submit` (DIF Presentation Exchange v2)
- [x] `api/` — HTTP handler integration tests (`api/server_test.go`): health, OIDC discovery, JWKS, auth middleware, identity CRUD, webhooks CRUD, consent grants, rate-limit enforcement

## Phase 9 — CLI & Server Binary
- [x] `cmd/tpt-identity/cmd/serve.go` — start server; wires OIDC RP bridges from config, magic link bridge, optional password bridge
- [x] `cmd/tpt-identity/cmd/keygen.go` — generate Ed25519 + X25519 keypair, derive and print DID
- [x] `cmd/tpt-identity/cmd/resolve.go` — resolve any DID string
- [x] `cmd/tpt-identity/cmd/issue_vc.go` — issue a VC from the CLI
- [x] `cmd/tpt-identity/cmd/verify_vc.go` — verify a VC from the CLI
- [x] `cmd/tpt-identity/cmd/migrate.go` — `migrate up / down / version`
- [x] `config.yaml.example` — annotated config (issuer, keys, OIDC TTLs, bridge providers, rate limit, TOTP passphrase)

## Phase 10 — Identity Bridge & Auth Layer
- [x] `internal/bridge/bridge.go` — `Bridge` interface + `Manager` registry; `ExternalIdentity` type
- [x] `internal/bridge/mapper.go` — `FindOrCreate` (external identity → platform DID); `LinkIdentity` / `UnlinkIdentity`; creates `did:key` identities for bridge users
- [x] `internal/bridge/providers/oidc_rp.go` — OIDC relying-party bridge; upstream `id_token` verification via JWKS (RSA, ECDSA, Ed25519); signed state token for CSRF-safe redirect round-trip
- [x] `internal/bridge/providers/magiclink.go` — single-use email token (SHA-256 hash stored, 15-min TTL)
- [x] `internal/bridge/providers/password.go` — Argon2id password bridge (opt-in, `bridges.password.enabled`)
- [x] `internal/bridge/providers/saml.go` — SAML 2.0 SP bridge (build tag `saml`); attribute mapping, AD group extraction
- [x] `internal/bridge/providers/ldap.go` — LDAP/AD bind bridge (build tag `ldap`); `ldaps://` required; service-account search + user bind
- [x] `api/bridge.go` — `GET /auth/{provider}`, `GET /auth/{provider}/callback`, `POST /auth/magiclink/request`, `GET /auth/magiclink/verify`, `GET/DELETE /api/v1/me/links`
- [x] `internal/authn/totp.go` — TOTP (RFC 6238, HMAC-SHA1, ±1-window); AES-256-GCM encrypted secrets (Argon2id key derivation)
- [x] `internal/authn/lockout.go` — brute-force lockout: 5 failures → 5 min; 10 → 30 min; 20 → permanent (admin reset)
- [x] `internal/events/events.go` — typed event bus; HMAC-SHA256 signed HTTP webhook delivery; 3-attempt exponential backoff; events: `credential.issued/revoked`, `consent.granted/revoked`, `identity.created`, `session.created/revoked`
- [x] `pkg/pe/definition.go` — DIF Presentation Exchange v2 types (`PresentationDefinition`, `InputDescriptor`, `Constraints`, `Filter`)
- [x] `pkg/pe/submission.go` — `Evaluate(def, submission, vp)` — checks each `InputDescriptor` against presented VCs; JSON path resolution; filter evaluation

## Phase 11 — Tests
- [x] `pkg/crypto/` — sign/verify round-trip, tamper detection, JCS determinism, ECDH, Seal/Open
- [x] `pkg/did/` — all DID methods; SSRF prevention for did:web
- [x] `pkg/vc/` — issue → verify → revoke → re-verify; anti-replay presentation; DataIntegrityProof compliance; BitstringStatusList encode/decode
- [x] `pkg/consent/` — expiry, withdrawal/revocation, extra-sensitive exclusion, category grant confirmation
- [x] `pkg/schema/` — registry versioning, versioned ID resolution, validation
- [x] `oidc/` — JWT issue/verify, PKCE S256, token revocation, AMR/token_type, refresh rotation
- [x] `pkg/trust/` — permit issue/verify/expiry/audience; reputation level classification
- [x] `api/` — HTTP handler integration tests

## Phase 12 — Documentation
- [x] `README.md`
- [x] `PROTOCOL.md` — DID methods spec, VC profiles, OIDC flows, consent model, inter-service trust
- [x] `SCHEMA.md` — full credential taxonomy (50+ schemas across 11 categories)
- [x] `CLAUDE.md` — guidance for Claude Code

## Future (post-MVP)
- [x] `pkg/schema/validate.go` — full JSON Schema validation via `github.com/santhosh-tekuri/jsonschema/v6`
- [x] `api/` — HTTP handler integration tests
- [x] WebAuthn / Passkeys (`github.com/go-webauthn/webauthn`) — register/login endpoints, authenticator public key anchored in DID Document
- [ ] Credential bootstrap from bridge claims — auto-issue VCs from claims provided by external providers (email → `social.verified-contacts`, AD groups → professional schemas)
- [ ] Multi-tenancy — `TenantID` on identities/sessions/clients; per-tenant signing keys and `did:web` namespaces
- [ ] Admin API — `/admin/v1/` (privileged); list/suspend identities, manage clients, view audit log
- [ ] DIDComm v2 messaging — `anoncrypt`/`authcrypt` envelopes using existing X25519 keys; `POST /didcomm` endpoint
- [x] `pkg/trust/reputation.go` — redesign DNS reputation as VC-based before production (DNS TXT is a weak trust anchor)
- [ ] Prometheus metrics endpoint
- [ ] `POST /api/v1/consents/receipts` — relying party submits a receipt after access
- [x] `pkg/vc/sdjwt.go` — SD-JWT selective disclosure (draft-ietf-oauth-selective-disclosure-jwt): `IssueSDJWT`, `Disclosure`, `SDJWTToken.Present(keys)`, `SDJWTToken.PresentWithKeyBinding(keys, holderKey, nonce, aud)`, `ParseSDJWT`, `SDJWTVerifier.Verify`; `cnf` key binding; KB-JWT nonce/aud/sd_hash anti-replay
- [x] `api/sdjwt.go` — `POST /api/v1/credentials/sd-jwt` (issue), `POST /api/v1/credentials/sd-jwt/verify` (verify presentation, optional KB-JWT check)
- [ ] BBS+ — only if ZK proofs become a hard requirement (not SD-JWT's scope)
- [ ] did:ion production hardening (Sidetree node, IPFS anchoring)
- [ ] Mobile SDK (Swift / Kotlin) wrapping the REST API
- [x] NZ government integrations: RealMe bridge, Te Whatu Ora FHIR identity, ACC API auth
  - `internal/bridge/providers/realme.go` — RealMe SAML 2.0 (build tag: saml); FLT stable ID, LOA1/LOA2 verified identity
  - `internal/bridge/providers/te_whatu_ora.go` — SMART on FHIR; NHI (patient) and HPI (practitioner) via FHIR R4 API
  - `internal/bridge/providers/acc.go` — ACC OAuth2; client number as stable ID, acc:claims.read scope
  - Schemas added: `identity.realme-verified`, `identity.hpi-practitioner`, `healthcare.acc-authorisation`, `healthcare.nhi-patient`
  - Routes added: `GET /auth/{provider}/metadata`, `POST /auth/{provider}/acs`
  - Registration: RealMe → DIA; Te Whatu Ora / ACC → developer portals at respective .govt.nz domains
- [ ] tpt-email migration — swap `internal/identity`, `internal/keystore`, `pkg/tfep/` for tpt-identity imports
