# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | Yes |

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Report security issues privately via [GitHub Security Advisories](https://github.com/tpt-solutions/tpt-identity/security/advisories/new).

Include:
- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept if possible)
- Affected component(s) and version/commit
- Your assessment of severity (CVSS score welcome but not required)

### Response SLA

| Milestone | Target |
|-----------|--------|
| Acknowledgement | 48 hours |
| Triage & severity assessment | 5 business days |
| Patch for Critical/High | 14 days |
| Patch for Medium | 30 days |
| Patch for Low | Next regular release |

You will be credited in the release notes unless you prefer to remain anonymous.

## Scope

In scope:
- Authentication bypass (bridge callbacks, OIDC flows, passkey verification)
- Authorisation bypass (consent policy enforcement, credential access control)
- Cryptographic weaknesses (key derivation, signing pipeline, SD-JWT verification)
- Injection vulnerabilities in API handlers (SQLi, path traversal, SSRF)
- Sensitive data exposure (credential claims, TOTP secrets, duress config)
- PKCE/state bypass or CSRF in the OIDC authorization flow

Out of scope:
- Denial-of-service without authentication (rate limiting is best-effort)
- Issues in third-party dependencies that have no patch upstream
- Social engineering of maintainers
- Physical attacks

## Known Deferred Risks

- **SQLite single-writer**: The store uses `SetMaxOpenConns(1)` intentionally. Under high write concurrency this can queue writes. A PostgreSQL migration is planned.
- **did:peer in-process only**: Peer DID documents are stored in memory; a production deployment with multiple server replicas should use the SQLite store for peer DID resolution.
- **Magic link TTL**: 15 minutes. Tokens are single-use but a compromised email account within the TTL window can log in.
- **Webhook delivery secrets**: Signing secrets are shown once at registration. If a secret is lost, the webhook must be deleted and re-registered.

## Cryptographic Design

- **Ed25519** for all signing (VCs, JWTs, consent receipts, audit log events)
- **X25519 + NaCl secretbox** for encryption at rest and DIDComm
- **Argon2id** (64 MB / 3 iterations / 4 threads) for all key derivation from passphrases
- **SHA-256** for HMAC webhook signatures, token storage, and audit log hash chain
- Proofs use **DataIntegrityProof / eddsa-jcs-2022** with JCS canonicalisation
