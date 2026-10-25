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

### Fixed

- `tpt-identity migrate` opened `database.path`, a key the server never reads, so it inspected a different file from the one the server used. It now uses `db_path`.
- `tpt-identity version` and `config` were registered twice on the root command.
- did:web: a resolved document must name the requested DID; a percent-encoded port is accepted; the allowlist matches the host without the port.
- The resolver cache is bounded (10 000 entries); expired entries are evicted first, pinned entries never.
- Unchecked errors on encoder writes, JSON parsing, and key file writes are now handled. The key file write now reports `Close` failures.
- `did:peer` presentation IDs are generated from `crypto/rand` rather than `math/rand`.
- OIDC RP provider: a malformed JWT header now returns an error instead of being silently ignored.
- Bridge state cookie clearing sets the same `Secure` and `SameSite` attributes as the cookie it clears.
