# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/) once it reaches v1.0.

## [Unreleased]

### Added

- GitHub Actions CI: build, vet, race-enabled tests, and golangci-lint on every push to `master` and every pull request.
- Dependabot updates for Go modules and GitHub Actions.
- Issue templates for bug reports and feature requests. Pull requests are not accepted; see CONTRIBUTING.md.
- `Makefile` with `build`, `vet`, `test`, `race`, `lint`, `fmt`, and `check` targets.
- `.golangci.yml` lint configuration.

### Fixed

- Unchecked errors on encoder writes, JSON parsing, and key file writes are now handled. The key file write now reports `Close` failures.
- `did:peer` presentation IDs are generated from `crypto/rand` rather than `math/rand`.
- OIDC RP provider: a malformed JWT header now returns an error instead of being silently ignored.
- Bridge state cookie clearing sets the same `Secure` and `SameSite` attributes as the cookie it clears.
