-- Migration 001: initial schema
-- This is the canonical schema; the inline migrate() in sqlite.go bootstraps
-- new databases. These files are the source-of-truth for version tracking and
-- incremental upgrades on existing databases.


CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
    did             TEXT PRIMARY KEY,
    method          TEXT NOT NULL,
    signing_key_path TEXT,
    enc_key_path    TEXT,
    role            TEXT NOT NULL DEFAULT 'user',
    tenant_id       TEXT,
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS did_documents (
    did         TEXT PRIMARY KEY,
    document    JSON NOT NULL,
    cached_at   DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id          TEXT PRIMARY KEY,
    subject_did TEXT NOT NULL,
    issuer_did  TEXT NOT NULL,
    schema_id   TEXT NOT NULL,
    valid_from  DATETIME NOT NULL,
    valid_until DATETIME,
    credential  JSON NOT NULL,
    created_at  DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_subject ON credentials(subject_did);
CREATE INDEX IF NOT EXISTS idx_credentials_schema  ON credentials(schema_id);

CREATE TABLE IF NOT EXISTS consent_grants (
    id                   TEXT PRIMARY KEY,
    subject_did          TEXT NOT NULL,
    relying_did          TEXT NOT NULL,
    level                TEXT NOT NULL,
    scope_id             TEXT NOT NULL,
    granted_at           DATETIME NOT NULL,
    expires_at           DATETIME,
    revoked_at           DATETIME,
    explicitly_confirmed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_grants_subject ON consent_grants(subject_did);

CREATE TABLE IF NOT EXISTS consent_receipts (
    id          TEXT PRIMARY KEY,
    subject_did TEXT NOT NULL,
    relying_did TEXT NOT NULL,
    schema_id   TEXT NOT NULL,
    accessed_at DATETIME NOT NULL,
    expires_at  DATETIME,
    revoked_at  DATETIME,
    legal_basis TEXT NOT NULL,
    purpose     TEXT,
    signed_by   TEXT,
    signature   TEXT
);
CREATE INDEX IF NOT EXISTS idx_receipts_subject ON consent_receipts(subject_did);

CREATE TABLE IF NOT EXISTS oidc_sessions (
    id                   TEXT PRIMARY KEY,
    subject_did          TEXT NOT NULL,
    client_id            TEXT NOT NULL,
    redirect_uri         TEXT NOT NULL,
    scope                TEXT,
    nonce                TEXT,
    state                TEXT,
    code                 TEXT,
    code_challenge       TEXT,
    code_challenge_method TEXT,
    access_token         TEXT,
    refresh_token_hash   TEXT,
    user_agent           TEXT,
    ip_address           TEXT,
    last_used_at         DATETIME,
    created_at           DATETIME NOT NULL,
    expires_at           DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON oidc_sessions(subject_did);
CREATE INDEX IF NOT EXISTS idx_sessions_code    ON oidc_sessions(code);

CREATE TABLE IF NOT EXISTS oidc_clients (
    client_id                  TEXT PRIMARY KEY,
    client_secret_hash         TEXT,
    client_name                TEXT NOT NULL,
    redirect_uris              JSON NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL,
    grant_types                JSON NOT NULL,
    response_types             JSON NOT NULL,
    scope                      TEXT,
    tenant_id                  TEXT,
    created_at                 DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    hash        TEXT PRIMARY KEY,
    subject_did TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    scope       TEXT,
    issued_at   DATETIME NOT NULL,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME
);
CREATE INDEX IF NOT EXISTS idx_refresh_subject ON refresh_tokens(subject_did);

CREATE TABLE IF NOT EXISTS external_provider_links (
    subject_did TEXT NOT NULL,
    provider    TEXT NOT NULL,
    external_id TEXT NOT NULL,
    linked_at   DATETIME NOT NULL,
    last_used_at DATETIME NOT NULL,
    PRIMARY KEY (provider, external_id)
);
CREATE INDEX IF NOT EXISTS idx_links_subject ON external_provider_links(subject_did);

CREATE TABLE IF NOT EXISTS magic_link_tokens (
    hash       TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id    TEXT PRIMARY KEY,
    subject_did      TEXT NOT NULL,
    public_key_cbor  BLOB NOT NULL,
    attestation_type TEXT,
    aaguid           TEXT,
    sign_count       INTEGER NOT NULL DEFAULT 0,
    name             TEXT,
    transports       JSON,
    created_at       DATETIME NOT NULL,
    last_used_at     DATETIME
);
CREATE INDEX IF NOT EXISTS idx_webauthn_subject ON webauthn_credentials(subject_did);

CREATE TABLE IF NOT EXISTS totp_credentials (
    subject_did      TEXT PRIMARY KEY,
    encrypted_secret TEXT NOT NULL,
    account_name     TEXT,
    created_at       DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id          TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    event_types JSON NOT NULL,
    secret_hash TEXT,
    tenant_id   TEXT,
    created_at  DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_failures (
    subject_or_email TEXT PRIMARY KEY,
    count            INTEGER NOT NULL DEFAULT 0,
    last_failure_at  DATETIME NOT NULL,
    locked_until     DATETIME
);
