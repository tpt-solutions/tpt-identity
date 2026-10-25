-- 004: the schema the server uses, as one migration.
--
-- Migrations 001-003 were written before the server built its schema inline, so they differ from it:
-- some tables lack columns, and some tables the server uses are missing. This migration creates every
-- table and index the server needs. The CREATE statements are idempotent, so a database that already has
-- a table keeps it. Columns that an older shape lacks are added by the Go hook registered for version 4
-- (see migrate.go), which checks PRAGMA table_info first.

CREATE TABLE IF NOT EXISTS identities (
	did TEXT PRIMARY KEY,
	method TEXT NOT NULL,
	signing_key_path TEXT,
	enc_key_path TEXT,
	role TEXT NOT NULL DEFAULT 'user',
	tenant_id TEXT,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS did_documents (
	did TEXT PRIMARY KEY,
	document JSON NOT NULL,
	cached_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
	id TEXT PRIMARY KEY,
	subject_did TEXT NOT NULL,
	issuer_did TEXT NOT NULL,
	schema_id TEXT NOT NULL,
	valid_from DATETIME NOT NULL,
	valid_until DATETIME,
	credential JSON NOT NULL,
	created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_subject ON credentials(subject_did);
CREATE INDEX IF NOT EXISTS idx_credentials_schema ON credentials(schema_id);

CREATE TABLE IF NOT EXISTS consent_grants (
	id TEXT PRIMARY KEY,
	subject_did TEXT NOT NULL,
	relying_did TEXT NOT NULL,
	level TEXT NOT NULL,
	scope_id TEXT NOT NULL,
	granted_at DATETIME NOT NULL,
	expires_at DATETIME,
	explicitly_confirmed INTEGER NOT NULL DEFAULT 0,
	revoked_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_grants_subject ON consent_grants(subject_did);

CREATE TABLE IF NOT EXISTS consent_receipts (
	id TEXT PRIMARY KEY,
	subject_did TEXT NOT NULL,
	relying_did TEXT NOT NULL,
	schema_id TEXT NOT NULL,
	accessed_at DATETIME NOT NULL,
	legal_basis TEXT NOT NULL,
	purpose TEXT,
	signed_by TEXT,
	signature TEXT
);
CREATE INDEX IF NOT EXISTS idx_receipts_subject ON consent_receipts(subject_did);

CREATE TABLE IF NOT EXISTS oidc_sessions (
	id TEXT PRIMARY KEY,
	subject_did TEXT NOT NULL,
	client_id TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	scope TEXT,
	nonce TEXT,
	state TEXT,
	code TEXT,
	code_challenge TEXT,
	code_challenge_method TEXT,
	access_token TEXT,
	refresh_token_hash TEXT,
	user_agent TEXT,
	ip_address TEXT,
	last_used_at DATETIME,
	created_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON oidc_sessions(subject_did);
CREATE INDEX IF NOT EXISTS idx_sessions_code ON oidc_sessions(code);

CREATE TABLE IF NOT EXISTS oidc_clients (
	client_id TEXT PRIMARY KEY,
	client_secret_hash TEXT,
	client_name TEXT NOT NULL,
	redirect_uris JSON NOT NULL,
	token_endpoint_auth_method TEXT NOT NULL,
	grant_types JSON NOT NULL,
	response_types JSON NOT NULL,
	scope TEXT,
	tenant_id TEXT,
	created_at DATETIME NOT NULL,
	backchannel_logout_uri TEXT,
	post_logout_redirect_uris JSON,
	jwks TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	hash TEXT PRIMARY KEY,
	family_id TEXT NOT NULL DEFAULT '',
	subject_did TEXT NOT NULL,
	client_id TEXT NOT NULL,
	scope TEXT,
	issued_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	used_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_refresh_subject ON refresh_tokens(subject_did);

CREATE TABLE IF NOT EXISTS external_provider_links (
	subject_did TEXT NOT NULL,
	provider TEXT NOT NULL,
	external_id TEXT NOT NULL,
	linked_at DATETIME NOT NULL,
	last_used_at DATETIME NOT NULL,
	PRIMARY KEY (provider, external_id)
);
CREATE INDEX IF NOT EXISTS idx_links_subject ON external_provider_links(subject_did);

CREATE TABLE IF NOT EXISTS magic_link_tokens (
	hash TEXT PRIMARY KEY,
	email TEXT NOT NULL,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
	credential_id TEXT PRIMARY KEY,
	subject_did TEXT NOT NULL,
	public_key_cbor BLOB NOT NULL,
	attestation_type TEXT,
	aaguid TEXT,
	sign_count INTEGER NOT NULL DEFAULT 0,
	name TEXT,
	transports JSON,
	created_at DATETIME NOT NULL,
	last_used_at DATETIME
);
CREATE INDEX IF NOT EXISTS idx_webauthn_subject ON webauthn_credentials(subject_did);

CREATE TABLE IF NOT EXISTS totp_credentials (
	subject_did TEXT PRIMARY KEY,
	encrypted_secret TEXT NOT NULL,
	account_name TEXT,
	created_at DATETIME NOT NULL,
	verified_at DATETIME,
	last_step INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
	id TEXT PRIMARY KEY,
	url TEXT NOT NULL,
	event_types JSON NOT NULL,
	secret_hash TEXT,
	signing_secret TEXT NOT NULL DEFAULT '',
	tenant_id TEXT,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_failures (
	subject_or_email TEXT PRIMARY KEY,
	count INTEGER NOT NULL DEFAULT 0,
	last_failure_at DATETIME NOT NULL,
	locked_until DATETIME
);

CREATE TABLE IF NOT EXISTS passwords (
	identifier TEXT PRIMARY KEY,
	hash       TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS duress_configs (
	subject_did TEXT PRIMARY KEY,
	hash        TEXT NOT NULL,
	created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
	seq        INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	event_type TEXT NOT NULL,
	payload    TEXT NOT NULL,
	hash       TEXT NOT NULL,
	prev_hash  TEXT NOT NULL DEFAULT '',
	hash_version INTEGER NOT NULL DEFAULT 1,
	recorded_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS recovery_configs (
	subject_did   TEXT PRIMARY KEY,
	threshold     INTEGER NOT NULL,
	guardian_dids TEXT NOT NULL,
	guardian_emails TEXT NOT NULL DEFAULT '{}',
	created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS recovery_requests (
	id               TEXT PRIMARY KEY,
	subject_did      TEXT NOT NULL,
	started_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	shares_collected INTEGER NOT NULL DEFAULT 0,
	completed        INTEGER NOT NULL DEFAULT 0,
	commitment       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS recovery_shares (
	request_id   TEXT NOT NULL,
	guardian_did TEXT NOT NULL,
	share_hash   TEXT NOT NULL,
	collected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (request_id, guardian_did)
);

CREATE TABLE IF NOT EXISTS revoked_access_tokens (
	hash       TEXT PRIMARY KEY,
	expires_at DATETIME NOT NULL
);

-- Pushed Authorization Requests (RFC 9126)
CREATE TABLE IF NOT EXISTS par_requests (
	request_uri  TEXT PRIMARY KEY,
	client_id    TEXT NOT NULL,
	params       TEXT NOT NULL,
	expires_at   DATETIME NOT NULL,
	created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Device Authorization Grant codes (RFC 8628)
CREATE TABLE IF NOT EXISTS device_codes (
	device_code   TEXT PRIMARY KEY,
	user_code     TEXT NOT NULL UNIQUE,
	client_id     TEXT NOT NULL,
	scope         TEXT NOT NULL DEFAULT '',
	subject_did   TEXT,
	approved      INTEGER NOT NULL DEFAULT 0,
	denied        INTEGER NOT NULL DEFAULT 0,
	expires_at    DATETIME NOT NULL,
	interval_secs INTEGER NOT NULL DEFAULT 5,
	created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
	hash       TEXT PRIMARY KEY,
	identifier TEXT NOT NULL,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Privacy budget: per-subject, per-schema disclosure counter
CREATE TABLE IF NOT EXISTS privacy_disclosures (
	id            TEXT PRIMARY KEY,
	subject_did   TEXT NOT NULL,
	schema_id     TEXT NOT NULL,
	verifier_did  TEXT NOT NULL,
	field_names   TEXT NOT NULL,
	disclosed_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_privacy_disclosures_subject ON privacy_disclosures(subject_did);
CREATE INDEX IF NOT EXISTS idx_privacy_disclosures_schema  ON privacy_disclosures(subject_did, schema_id);

-- OID4VCI credential offers
CREATE TABLE IF NOT EXISTS credential_offers (
	id          TEXT PRIMARY KEY,
	client_id   TEXT,
	schema_ids  TEXT NOT NULL,
	issuer_did  TEXT NOT NULL,
	subject_did TEXT,
	expires_at  DATETIME NOT NULL,
	used        INTEGER NOT NULL DEFAULT 0,
	created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	tx_code_hash TEXT NOT NULL DEFAULT ''
);

-- Bitstring status lists (revocation)
CREATE TABLE IF NOT EXISTS status_lists (
	id          TEXT PRIMARY KEY,
	issuer_did  TEXT NOT NULL,
	size_bits   INTEGER NOT NULL,
	next_index  INTEGER NOT NULL DEFAULT 0,
	bits        BLOB NOT NULL,
	updated_at  DATETIME NOT NULL,
	created_at  DATETIME
);
CREATE INDEX IF NOT EXISTS idx_status_lists_issuer ON status_lists(issuer_did);

-- OID4VP presentation state
CREATE TABLE IF NOT EXISTS oid4vp_requests (
	id          TEXT PRIMARY KEY,
	data        TEXT NOT NULL,
	expires_at  DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS oid4vp_responses (
	request_id  TEXT PRIMARY KEY,
	data        TEXT NOT NULL,
	received_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oid4vp_requests_expiry ON oid4vp_requests(expires_at);

-- DIDComm: seen message ids (replay guard, also used for client assertion ids) and the operator inbox
CREATE TABLE IF NOT EXISTS didcomm_seen (
	sender     TEXT NOT NULL,
	message_id TEXT NOT NULL,
	seen_until DATETIME NOT NULL,
	PRIMARY KEY (sender, message_id)
);
CREATE INDEX IF NOT EXISTS idx_didcomm_seen_until ON didcomm_seen(seen_until);
CREATE TABLE IF NOT EXISTS didcomm_inbox (
	sender      TEXT NOT NULL,
	message_id  TEXT NOT NULL,
	type        TEXT NOT NULL,
	received_at DATETIME NOT NULL,
	body        TEXT NOT NULL,
	PRIMARY KEY (sender, message_id)
);

-- SD-JWT credentials this server issued, so each can be revoked by id
CREATE TABLE IF NOT EXISTS sdjwt_issued (
	id           TEXT PRIMARY KEY,
	subject_did  TEXT NOT NULL,
	status_list  TEXT NOT NULL,
	status_index INTEGER NOT NULL,
	issued_at    DATETIME NOT NULL,
	expires_at   DATETIME NOT NULL
);
