# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/) once it reaches v1.0.

## [Unreleased]

### Added

- PostgreSQL store: set `db_path` to a `postgres://` URL. The same query code runs on SQLite and PostgreSQL; the PostgreSQL schema is created on start, and the transactions that read a row and then write it take advisory locks so concurrent requests cannot fork the audit chain or lose auth-failure counts. The store contract tests run on both when `TPT_TEST_POSTGRES_DSN` is set, and CI runs them against a PostgreSQL service.
- `tpt-identity doctor` checks the config, the database (including that a PostgreSQL server answers), the DIDComm key file and the listen address.
- GitHub Actions CI: build, vet, race-enabled tests, and golangci-lint on every push to `master` and every pull request.
- Dependabot updates for Go modules and GitHub Actions.
- Issue templates for bug reports and feature requests. Pull requests are not accepted; see CONTRIBUTING.md.
- `Makefile` with `build`, `vet`, `test`, `race`, `lint`, `fmt`, and `check` targets.
- `.golangci.yml` lint configuration.

- `tpt-identity rotate-key` generates a new signing key and prints the config change. The outgoing key stays in the platform DID document and in `identity.previous_keys`.
- Tenant-bound scoped keys (`scoped_api_keys[].tenant_id`) see and create only their own identities, and see only their own credentials and consent receipts. A tenant key is refused everywhere else.
- Client authentication with `private_key_jwt` (RFC 7523): clients register Ed25519 keys through `jwks`.
- OID4VP accepts JWT-format presentations (a compact JWS signed by the holder, bound to the request by `aud`, `nonce` and `exp`).
- SD-JWT credentials carry a `status` claim and a `jti`. They are revocable by id (`POST /api/v1/credentials/sd-jwt/{id}/revoke`), and their status is published as an IETF Token Status List (`GET /api/v1/token-status/{listId}`).
- Permanent DID deactivation: `POST /admin/v1/identities/{did}/deactivate`. The DID then resolves with no keys.
- DIDComm inbox: received messages whose type is in `didcomm.accepted_types` are kept for the operator (`GET /admin/v1/didcomm/inbox`). Only basic messages are accepted by default.
- Guardian recovery notices: a guardian with an address (`guardian_emails` at enrolment) is told when a recovery starts. The notice carries no token or share.
- Passkeys appear in the resolved DID document, and deleting a passkey removes its key.
- Audit log hash version 2 covers the recorded time. Rows written before this change still verify.
- `pe.Evaluate` requires a credential verifier. A credential that fails verification never matches.
- `examples/rp-go`: a relying party that runs the PKCE flow with private_key_jwt, checks the ID token, and reads userinfo. It has integration tests against a live in-process platform.

### Changed

- **Breaking:** authcrypt DIDComm envelopes bind the content tag into the key derivation (ECDH-1PU `SuppPrivInfo`). Envelopes produced before this change no longer unpack. Anoncrypt envelopes are unchanged.
- The PAR front-channel call must name the client that pushed the request. Without a matching `client_id` it is refused.
- Identities hosted here resolve from the store, uncached, so updates show at once.
- SQLite schema: the server builds its schema from the embedded migrations, not inline. Migration 004 is the complete schema. Existing databases upgrade on the next start, and `tpt-identity migrate up` applies the same migrations. `/readyz` reports degraded when the schema version is behind this build. PostgreSQL still builds its schema inline and keeps no version record.

### Security

- A caller could supply `iss`, `sub`, `exp` or other issuer-owned claims as always-visible SD-JWT claims, and the platform signed them. Those claims are now refused.
- A PAR `request_uri` could be burned by a client other than the one that pushed it. The check now runs before the request is consumed.

### Fixed

- `tpt-identity migrate` opened `database.path`, a key the server never reads, so it inspected a different file from the one the server used. It now uses `db_path`.
- `tpt-identity version` and `config` were registered twice on the root command.
- did:web: a resolved document must name the requested DID; a percent-encoded port is accepted; the allowlist matches the host without the port.
- The resolver cache is bounded (10 000 entries); expired entries are evicted first, pinned entries never.
- Unchecked errors on encoder writes, JSON parsing, and key file writes are now handled. The key file write now reports `Close` failures.
- `did:peer` presentation IDs are generated from `crypto/rand` rather than `math/rand`.
- OIDC RP provider: a malformed JWT header now returns an error instead of being silently ignored.
- Bridge state cookie clearing sets the same `Secure` and `SameSite` attributes as the cookie it clears.
