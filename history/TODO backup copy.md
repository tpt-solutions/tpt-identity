# tpt-identity — Build Checklist

## Phase 1 — Crypto & Key Foundation
- [ ] `go.mod` — initialise module `github.com/PhillipC05/tpt-identity`
- [ ] `pkg/crypto/sign.go` — Ed25519 sign / verify
- [ ] `pkg/crypto/encrypt.go` — X25519 ECDH + NaCl secretbox
- [ ] `pkg/crypto/hash.go` — canonical hashing utilities
- [ ] `pkg/keystore/keystore.go` — AES-256-GCM encrypted PEM, PBKDF2, Ed25519 + X25519

## Phase 2 — DID Layer
- [ ] `pkg/did/method.go` — `DIDMethod` interface + `RegisterMethod()` registry
- [ ] `pkg/did/document.go` — W3C DID Document types (verification methods, services, context)
- [ ] `pkg/did/web.go` — did:web: create, resolve via HTTPS `/.well-known/did.json`
- [ ] `pkg/did/key.go` — did:key: derive DID from Ed25519 pubkey, offline resolve
- [ ] `pkg/did/peer.go` — did:peer: pairwise DIDs, no public resolution
- [ ] `pkg/did/ion.go` — did:ion: Bitcoin/Sidetree (build tag `ion`, optional)
- [ ] `internal/resolver/resolver.go` — DID resolver with TTL caching, routes by prefix

## Phase 3 — Credential Schema Taxonomy
- [ ] `pkg/schema/registry.go` — `RegisterSchema()`, `RegisterCategory()`, lookup helpers
- [ ] `pkg/schema/core/identity.go` — schemas: legal-name, dob, address, passport, drivers-licence, nhi, ird-number
- [ ] `pkg/schema/core/healthcare.go` — schemas: gp-records, specialist, pharmacy, allergies, immunisation, radiology, pathology, dental, acc-injury, disability + extra-sensitive: mental-health, sexual-health, reproductive-health, addiction
- [ ] `pkg/schema/core/finance.go` — schemas: bank-account, income, tax-records, credit-history, benefits, insurance-policies, investments, property-ownership
- [ ] `pkg/schema/core/professional.go` — schemas: qualifications, registrations, employment, practising-certificates
- [ ] `pkg/schema/core/education.go` — schemas: enrolments, transcripts, qualifications, nzqa
- [ ] `pkg/schema/core/legal.go` — schemas: court-orders, poa, will-estate, immigration-status + extra-sensitive: criminal-record
- [ ] `pkg/schema/core/property.go` — schemas: real-estate, vehicles, assets
- [ ] `pkg/schema/core/civic.go` — schemas: electoral-roll, benefits-entitlements, tax-filing, business-registration
- [ ] `pkg/schema/core/social.go` — schemas: verified-contacts, social-graph, reputation
- [ ] `pkg/schema/core/travel.go` — schemas: passport, visas, vaccination-certs, travel-insurance
- [ ] `pkg/schema/core/insurance.go` — schemas: health, life, vehicle, home, business
- [ ] `pkg/schema/validate.go` — validate VC claims against schema definitions

## Phase 4 — Verifiable Credentials
- [ ] `pkg/vc/credential.go` — W3C VC Data Model 2.0 types (VerifiableCredential, VerifiablePresentation)
- [ ] `pkg/vc/issue.go` — sign a VC with issuer DID (Ed25519Signature2020)
- [ ] `pkg/vc/verify.go` — resolve issuer DID, verify signature, check expiry
- [ ] `pkg/vc/presentation.go` — Verifiable Presentations (holder proves possession)

## Phase 5 — Consent & Trust
- [ ] `pkg/consent/policy.go` — sharing policy: schema-level grants, category grants (extra confirmation), extra-sensitive exclusions
- [ ] `pkg/consent/receipt.go` — cryptographically signed consent receipts (who, schema, when, legal basis)
- [ ] `pkg/trust/permit.go` — JWT permits (Ed25519-signed, short-lived) — ported from tpt-email
- [ ] `pkg/trust/reputation.go` — federated reputation DNS queries — ported from tpt-email

## Phase 6 — Storage
- [ ] `internal/store/store.go` — `Store` interface defining all operations (identities, VCs, consent grants, consent receipts, OIDC sessions, schema registry); all upstream code targets this interface only
- [ ] `internal/store/sqlite.go` — SQLite implementation of `Store` using `modernc.org/sqlite` (pure-Go, no CGo); schema designed to be PostgreSQL-compatible for future migration

## Phase 7 — OIDC Provider
- [ ] add `github.com/ory/fosite` to go.mod — use as OIDC/OAuth2 framework (spec compliance, PKCE, timing-safe token comparison); do NOT roll token validation logic by hand
- [ ] `oidc/provider.go` — fosite `OAuth2Provider` configuration: storage adapter, DID-aware client registry, Ed25519 token strategy
- [ ] `oidc/handlers.go` — HTTP handlers for `/authorize`, `/token`, `/userinfo`, `/introspect` wired to fosite
- [ ] `oidc/discovery.go` — `GET /.well-known/openid-configuration` (fosite metadata + DID-specific claims)
- [ ] `oidc/token.go` — Ed25519-signed ID token strategy implementing fosite's `OpenIDConnectTokenStrategy`; DID as `sub`, schema claims as custom claims

## Phase 8 — REST API
- [ ] `api/server.go` — wire routes, middleware (auth, logging, metrics)
- [ ] `api/identity.go` — `POST /api/v1/identities`, `GET /api/v1/identities/:did`
- [ ] `api/credentials.go` — `POST /api/v1/credentials`, `POST /api/v1/credentials/verify`
- [ ] `api/consents.go` — `GET/POST/DELETE /api/v1/consents`
- [ ] `api/sessions.go` — `DELETE /api/v1/sessions/:id`
- [ ] `api/wellknown.go` — `GET /.well-known/did.json` (DID document hosting)

## Phase 9 — CLI & Server Binary
- [ ] `cmd/tpt-identity/main.go` — cobra root + subcommands
- [ ] `cmd/tpt-identity/cmd/serve.go` — start HTTP server
- [ ] `cmd/tpt-identity/cmd/keygen.go` — generate keypair, output DID
- [ ] `cmd/tpt-identity/cmd/resolve.go` — resolve any DID
- [ ] `cmd/tpt-identity/cmd/issue_vc.go` — issue a VC from CLI
- [ ] `cmd/tpt-identity/cmd/verify_vc.go` — verify a VC from CLI
- [ ] `config.yaml.example` — annotated example config

## Phase 10 — Tests
- [ ] `pkg/crypto/` — unit tests
- [ ] `pkg/did/` — unit tests for all four methods
- [ ] `pkg/vc/` — issue + verify round-trip tests
- [ ] `pkg/consent/` — policy enforcement tests (extra-sensitive exclusion, category grant confirmation)
- [ ] `pkg/schema/` — registry and validation tests
- [ ] `oidc/` — authorization code flow integration test
- [ ] `api/` — HTTP handler tests

## Phase 11 — Documentation
- [ ] `README.md` — overview, quickstart, architecture diagram
- [ ] `PROTOCOL.md` — DID methods spec, VC profiles, OIDC flows, consent model
- [ ] `SCHEMA.md` — full credential taxonomy reference

## Future (post-MVP)
- [ ] tpt-email migration — swap `internal/identity`, `internal/keystore`, `pkg/tfep/` for tpt-identity imports
- [ ] did:ion production hardening (Sidetree node connection, IPFS anchoring)
- [ ] Selective disclosure: evaluate SD-JWT (`draft-ietf-oauth-selective-disclosure-jwt`) first — achieves selective disclosure without ZK proofs, solid Go support, wider real-world deployment than BBS+; only proceed to BBS+ if ZK proofs are a hard requirement
- [ ] BBS+ (if required): Go ecosystem is thin; implement via WASM compiled from Rust `bbs` crate rather than a pure-Go implementation
- [ ] Mobile SDK (Swift / Kotlin) wrapping the REST API
- [ ] NZ government integration: RealMe bridge, Te Whatu Ora FHIR identity, ACC API auth
