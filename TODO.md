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
- [x] Credential bootstrap from bridge claims — auto-issue VCs from claims provided by external providers (email → `social.verified-contacts`, AD groups → professional schemas)
- [ ] Multi-tenancy — `TenantID` on identities/sessions/clients; per-tenant signing keys and `did:web` namespaces
- [x] Admin API — `/admin/v1/` (privileged); list/suspend identities, manage clients, view audit log
- [x] DIDComm v2 messaging — `anoncrypt`/`authcrypt` envelopes using existing X25519 keys; `POST /didcomm` endpoint
- [x] `pkg/trust/reputation.go` — redesign DNS reputation as VC-based before production (DNS TXT is a weak trust anchor)
- [x] Prometheus metrics endpoint
- [x] `POST /api/v1/consents/receipts` — relying party submits a receipt after access
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

## Phase 13 — Review Findings (2026-10-25)
Source: platform review. Reproduce each item before fixing. Several `[x]` items above are only partially wired in code (see 13.4 and 13.7 "Reconcile docs").

### 13.0 Build blockers
- [x] `oidc/oid4vci.go:256-257` — `CredentialSubject` is a struct, not a map; use `.Claims` / `.ID`
- [x] `api/batch.go:119` — same `CredentialSubject["id"]` indexing error
- [x] Re-run `go build ./... && go vet ./... && go test ./...` and fix any errors hidden behind the above (hidden error fixed: `randomHex` undefined in `api`, now defined in `api/server.go`)
- [x] Dockerfile `golang:1.22-alpine` vs `go.mod` `go 1.25.0`; align Dockerfile, README badge, CLAUDE.md
- [ ] Housekeeping: license is done (LICENSE-MIT and LICENSE-APACHE, dual-licensed; `LICENSE` was renamed in c9f2793). Still open: delete `docs/TODO backup copy.md`, `history/`, stray TODO copies — rename and deletions of `docs/` and `TODO 1260613.md` done; `history/` (two stale TODO copies) still present, awaiting confirmation to delete

### 13.1 Security — critical (account takeover / open endpoints)
- [x] `/authorize` trusts client-supplied `X-Subject-DID` (`oidc/provider.go:76`); require authenticated session (now requires a verified bearer token; 401 otherwise; regression test `TestAuthorizeRejectsForgedSubjectHeader`)
- [x] `POST /device/approve` unauthenticated, subject from form; `math/rand` user codes; no `slow_down` polling throttle (`oidc/device.go`)
- [x] Magic link returns live token in response (`api/bridge.go:373`); deliver by email (pluggable sender), return 202
- [x] Bridge flows skip `client_id`/`redirect_uri` registry validation and state-to-browser binding (`api/bridge.go`)
- [x] Bridge state HMAC keyed by `api_key` (may be empty); use dedicated random secret
- [x] `auth` middleware fails open when `api_key` empty; non-constant-time compare; refuse startup without key; separate admin credential; scoped keys — fail-closed, constant-time compare, startup refusal, separate admin credential and scoped keys (`api/auth_scope_test.go`) all done.
- [x] OID4VCI: any bearer token can mint platform-signed VCs; require `credential:*` scope bound to offer, validate proof + `c_nonce`, issuer must be a DID, wire pre-authorized code into `TokenHandler`
- [x] Guardian recovery (`api/recovery.go`): unauthenticated initiate/get, shares published to event bus/audit log, approve unchecked, never completes
- [x] Lockout never enforced (`CheckLocked` has no callers); duress passphrase unreachable (normal password checked first)
- [x] Two event buses (`serve.go` vs `api/server.go:134`) — audit log and marketplace receive nothing; inject shared bus via `Config`

### 13.2 Security — high
- [x] Access-token verify: check `iss`, `aud`, `token_type`; reject ID tokens at `/me/*` and `/userinfo`; persist revocation list (DB) and consult it everywhere
- [x] Token-minting oracles: `stepup.go`, `oid4vp.go:497-504`, `token_exchange.go` (client auth, reject ID token as subject token, fail on bad actor token)
- [ ] OID4VP response endpoint: validate `state`, verify VP + nonce, bound/evict maps, persist — persistence is now done (store-backed, one response per request by constraint); JWT-format VPs are still open
- [x] Dynamic client registration: auth/rate class, redirect URI validation, enforce `grant_types` + scope, SSRF-guard `backchannel_logout_uri`, call `SendBackChannelLogout`, support post-logout URIs
- [x] Atomic auth-code redemption and refresh rotation; revoke token family on replay
- [x] Webhooks: connect-time IP-check dialer, no redirects, https only; fix HMAC signing (currently keyed by hash of secret); don't fan out `webhook.ping`
- [x] Never publish secrets on event bus (password-reset token, recovery shares)
- [x] Password change/reset always 500 (interface mismatch `api/password.go:17`); key by email; atomic reset; revoke sessions on reset
- [x] IDOR: `DELETE /api/v1/me/links/{provider}` doesn't check link ownership
- [x] Revocation end-to-end: `credentialStatus` on issue, persisted status list, revoke/suspend endpoints, `StatusChecker` in verify, emit `credential.revoked`, build list URL from configured issuer not `r.Host`; freshness oracle must not return `fresh:true` for `status_list_check_required` — done: every issued credential gets a status entry; POST /api/v1/credentials/{id}/revoke sets it and republishes the signed list; verify and the freshness oracle check the stored bits and fail closed for lists this issuer does not host. Suspend purpose stays open (see the SD-JWT status-list item)
- [x] Enforce suspended/deleted roles in token + `/me` paths; admin delete purges refresh tokens/passwords/links
- [x] Platform issuer must be a DID; implement `/.well-known/did.json` (`api/server.go:439` returns 404); `did_web` config not read: the platform DID is derived from `issuer` (see api/platform_did.go)
- [x] `POST /api/v1/identities` discards generated private keys; make SaveIdentity+SaveDocument atomic
- [ ] VP / SD-JWT: holder==subject check, enforce KB when `cnf` present, honour `kid`, require `exp`, verify signatures in `pkg/pe` + `api/presentations.go` — presentation submit now verifies the holder signature, nonce, domain, enclosed credentials and holder==subject against a stored single-use request; SD-JWT KB/exp/kid checks still open — the issuer JWT kid now selects the verification key; the other sub-items are still open
- [x] `http.MaxBytesReader` on all JSON bodies; server timeouts (`ReadHeaderTimeout` etc.) + graceful shutdown
- [x] TOTP: require old factor to re-enrol/unenrol; replay protection; pending state before first verify
- [x] Consent: grant ID/subject from server not body; call `validateGrant`; unknown scope must not bypass extra-sensitive; revoke/delete check subject; `CanAccess` still has no callers (the policy engine is not yet wired into credential access)

### 13.3 Security — medium
- [x] `remoteIP` in `oidc/provider.go` trusts XFF unconditionally; parse XFF right-to-left skipping trusted hops
- [x] `/me/export` leaks `Code`, `CodeChallenge`, `AccessToken` of sessions
- [x] Upstream OIDC RP: verify `iss`/`aud`/`nonce`/`email_verified`; timeouts; Ed25519 key length check; bootstrap VC only for verified email
- [x] Metrics: label by route pattern, not raw `r.URL.Path` (cardinality)
- [ ] `did:web`: dial resolved IP (DNS rebinding), check doc `id`, `%3A` ports, bounded resolver cache + Purge — the dial now uses the checked address (DNS rebinding); the document id, port and cache items are still open
- [ ] DIDComm: anoncrypt returns spoofable sender; add replay/`exp` handling; ECDH-1PU tag in KDF; handle received messages — sender checks, expiry, clock and replay are done (api/didcomm.go). Still open: the ECDH-1PU content tag in the KDF (a wire-format change) and handling of received messages beyond logging
- [ ] WebAuthn login finish must issue a session; check `CloneWarning`; anchored key visible in DID resolution — passkey login now returns a session token and refuses cloned authenticators; the anchored key in DID resolution is still open
- [ ] Audit log: atomic append (head read + insert), timestamp in hash, surface append errors — atomic append and error logging are done; timestamp in the hash needs a versioned hash format first
- [ ] Mapper: concurrent first-login creates duplicate identities; `isNotFound` string matching — the in-process race is fixed, and isNotFound now matches store.ErrNotFound only. Still open: cross-replica uniqueness of the external link
- [x] Admin: role filter applied after pagination; admin actions not audited — role filter applies before pagination; admin actions are written to the audit chain
- [ ] URL-encode `state`/`acr_values`/redirect params (`logout.go`, `provider.go:135`, `bridge.go:561`, `stepup.go`); PAR `client_id` binding; CORS `*` reflection — redirect and CORS fixes done; PAR `client_id` binding still open
- [ ] `vc.Issue`: tie `IssuerDID` to `VerificationMethodID`; `CheckStatus` panics on negative index; schema `additionalProperties` — IssuerDID is tied to the verification method and CheckStatus no longer panics; the schema additionalProperties check is still open
- [x] `recovery.Combine` reject duplicate/zero share indices; `RecordAuthFailure` atomic with decay; `/oauth/introspect` client auth (see the commits adding those tests)
- [x] SQLite `MaxOpenConns(1)`: audit for nested queries inside open `rows` (deadlock) — audited by reading: none of the 13 row loops query inside the loop, every loop defers rows.Close(), and the scan helpers make no database calls. A runtime check is still worth adding


### 13.4 Wiring gaps (documented but not functional)
- [x] WebAuthn config (`WebAuthnRPID` etc.) never set in `serve.go`; add `webauthn` section to config + example
- [ ] SAML / LDAP bridges never constructed in `serve.go` — constructed in `serve.go` now; LDAP has no HTTP login route yet
- [x] `oidc.*_ttl` config values not read
- [x] `did_web` config block not read (block removed from example; DID is derived from `issuer`)
- [x] Re-check credential bootstrap (`maybeIssueBootstrapVC`) after issuer-DID fix
- [ ] `did:ion` Create not implemented (`pkg/did/ion.go:35`)
- [ ] Multi-key JWKS / key rotation (`publicJWKS()` returns one key); earlier claim in this file is inaccurate — retired keys now verify by kid and are published in the JWKS (identity.previous_keys). Generating a rotated key and its rotation CLI are still open
- [ ] Config validation (issuer required + https, TTL parsing, unknown keys) — issuer and TTL validation done; unknown-key checks open — `config validate` is in place; the unknown-key check is still open
- [ ] Readiness probe should check keys loaded + migrations applied — signing-key check added. The migration check is blocked: OpenSQLite creates tables inline and never writes schema_migrations, which only `migrate up` does, so a check would mark a normal start as degraded. Unify the two schema paths first
- [x] Graceful shutdown and context cancellation for background goroutines (consent warning, rate-limiter eviction, webhook delivery) — consent reminders, rate-limiter, WebAuthn eviction and webhook deliveries all stop or drain on shutdown


### 13.5 Standards / production readiness
- [ ] Key rotation: multi-key JWKS with `kid` history, rotation CLI; RS256/ES256 for RP compatibility — the verification side is done (retired keys by kid, in the JWKS). Still open: the rotation CLI, RS256/ES256, and the DID-document side
- [ ] DID document update / key rotation / deactivation API
- [x] Persist OID4VP state and access-token revocation (replica-safe) — done: OID4VP requests and responses are in the store, and access-token revocation was already persistent. Replica-safe for both
- [ ] PostgreSQL store; multi-tenancy via existing `TenantID` fields
- [ ] Scoped API keys / RBAC; admin credential separate from API key — scoped API keys and a separate admin credential are done; per-user roles (RBAC) are still open
- [x] Complete OIDC discovery metadata; serve `/.well-known/oauth-authorization-server` (RFC 8414) — discovery now advertises S256, response modes, auth methods and the request-parameter flags; RFC 8414 is served (`api/discovery_test.go`)
- [ ] `private_key_jwt` client auth, DPoP (RFC 9449), JAR (RFC 9101), RFC 9068 `at+jwt`, RFC 9207 `iss` param
- [ ] OID4VCI: `dc+sd-jwt` format, authorization_code flow, deferred issuance, enforce `tx_code` — the PIN (`tx_code`) is now enforced; the other sub-items are still open
- [ ] OID4VP: signed request objects, `client_id_scheme`, DCQL, `direct_post.jwt`
- [ ] Email delivery interface (SMTP) for magic link / password reset / recovery — magic-link and password-reset delivery over SMTP is done (`internal/mail`); guardian-recovery notifications are still open
- [ ] Token status list for SD-JWT VC; suspend purpose

### 13.6 Test coverage
- [ ] Tests for `internal/authn`, `internal/bridge` (+providers), `internal/events`, `internal/store`, `internal/auditlog`, `internal/resolver` — lockout, OIDC RP, netguard client IP done; the rest open
- [x] Tests for `pkg/recovery`, `pkg/keystore`, `pkg/pe`, `pkg/marketplace` and `cmd/` (config validate, version)
- [ ] Regression test per security fix (forged `X-Subject-DID` → 401; empty `api_key` → startup fails; magic-link response has no token) — the named cases exist: forged X-Subject-DID, empty api_key, magic-link without a token. Other fixes still lack a regression test
- [x] `go test -race ./...` in CI

### 13.7 Adoption & developer experience
- [x] `tpt-identity init` wizard — `init` writes keys, a config with fresh secrets, and the migrated database; prod encrypts keys with TPT_IDENTITY_PASSPHRASE
- [ ] `tpt-identity doctor` / `config validate` / `version` with actionable errors — `config validate` and `version` are done; `doctor` is still open
- [ ] `tpt-identity serve --demo` sandbox mode (seeded issuers, schemas, fake wallet)
- [x] Remove enabled-by-default placeholder Google bridge from `config.yaml.example`; add missing keys (cors, trusted_proxies, consent, marketplace, webauthn)
- [ ] Published image on GHCR via goreleaser + GitHub Actions; compose with auto-init entrypoint (no Go needed for keygen)
- [ ] README "5-minute demo" (issue + verify via curl); fix wrong WebAuthn paths; document OID4VC/VP, device, PAR, DIDComm, admin, privacy routes; add CI badge
- [ ] `examples/`: RP app (Go + Node, OIDC+PKCE), age-over-18 SD-JWT verifier, webhook receiver, custom-schema registration (`Source: community`, v1→v2), extra-sensitive consent demo
- [ ] Issuer starter profiles: university (education.*), clinic/pharmacy (healthcare.*), bank KYC (finance.* + identity.*), employer (professional.employment)
- [ ] Embedded minimal HTML pages (login, consent, device approval, wallet/admin) via `embed`
- [x] OpenAPI spec (`api/openapi.yaml`, served at `/openapi.yaml`, route-drift test)
- [ ] Postman/Bruno collection; generated TS + Go client SDKs
- [ ] CLI: `schemas list|show|validate|scaffold`, client registration command, `--output json|yaml`, shell completion docs — `schemas list` and `schemas show` are done; validate, scaffold, client registration, `--output` and completion docs are still open
- [x] `.github/` (CI build/vet/test/lint, Dependabot, issue templates; no PR template because contributions are issues only), Makefile, `.golangci.yml`
- [x] CONTRIBUTING.md (issues only), CHANGELOG.md, CODE_OF_CONDUCT.md
- [ ] Tag v0.x release
- [ ] Helm chart / k8s manifests
- [ ] Docs: schema-authoring guide, ops guide (backup, key rotation, upgrades), FAQ/troubleshooting, comparison with Keycloak/Authentik, roadmap link
- [ ] Reconcile docs with reality (README/CLAUDE.md/TODO.md claims on status lists, WebAuthn, audit log, marketplace, JWKS rotation, SAML/LDAP, back-channel logout)

### 13.8 Innovation ideas
- [ ] Policy-as-code for verifiers (declarative accept rules → Presentation Definitions; single yes/no verifier SDK)
- [ ] Real ZK age/range proofs (BBS+ predicates) replacing issuer-computed `api/zkp.go`
- [ ] Trust registries / signed issuer allow-lists; public marketplace directory
- [ ] User-facing consent timeline + privacy dashboard from audit log; "who accessed what" notifications
- [ ] Credential lifecycle automation: expiry reminders, auto-reissue via deferred issuance, CSV/SCIM import from HR/SIS
- [ ] Audit-log head-hash anchoring to external transparency log
- [ ] Wallet-less verification QR flow (OID4VP + redirect)
- [ ] NZ health/gov starter pack (RealMe / Te Whatu Ora / ACC bridges + schemas + templates)