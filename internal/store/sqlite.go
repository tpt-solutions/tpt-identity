package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tpt-solutions/tpt-identity/pkg/consent"
	"github.com/tpt-solutions/tpt-identity/pkg/did"
	"github.com/tpt-solutions/tpt-identity/pkg/vc"
	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using SQLite via modernc (pure-Go, no CGo).
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens (or creates) a SQLite database at path and runs migrations.
func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// migrate creates or updates tables. Schema is designed to be PostgreSQL-compatible.
func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
	PRAGMA journal_mode=WAL;

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
		created_at DATETIME NOT NULL
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
		prev_hash  TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS recovery_configs (
		subject_did   TEXT PRIMARY KEY,
		threshold     INTEGER NOT NULL,
		guardian_dids TEXT NOT NULL,
		created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS recovery_requests (
		id               TEXT PRIMARY KEY,
		subject_did      TEXT NOT NULL,
		started_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		shares_collected INTEGER NOT NULL DEFAULT 0,
		completed        INTEGER NOT NULL DEFAULT 0
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
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	`)
	if err != nil {
		return err
	}
	// Idempotent column additions — errors are ignored.
	_, _ = s.db.Exec(`ALTER TABLE oidc_clients ADD COLUMN backchannel_logout_uri TEXT`)
	_, _ = s.db.Exec(`ALTER TABLE oidc_clients ADD COLUMN post_logout_redirect_uris JSON`)
	_, _ = s.db.Exec(`ALTER TABLE recovery_requests ADD COLUMN commitment TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE webhook_subscriptions ADD COLUMN signing_secret TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE totp_credentials ADD COLUMN verified_at DATETIME`)
	_, _ = s.db.Exec(`ALTER TABLE totp_credentials ADD COLUMN last_step INTEGER NOT NULL DEFAULT 0`)
	_, _ = s.db.Exec(`ALTER TABLE consent_grants ADD COLUMN revoked_at DATETIME`)
	// SHA-256 of the offer PIN (tx_code). Offers from before this column have no hash and are refused.
	_, _ = s.db.Exec(`ALTER TABLE credential_offers ADD COLUMN tx_code_hash TEXT NOT NULL DEFAULT ''`)
	if err := s.migrateStatusLists(); err != nil {
		return err
	}
	if err := s.migrateOID4VP(); err != nil {
		return err
	}
	return nil
}

// --- Identities ---

// execer is satisfied by *sql.DB and *sql.Tx, so the same statements can run in or out of a transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (s *SQLiteStore) SaveIdentity(ctx context.Context, id *Identity) error {
	return saveIdentity(ctx, s.db, id)
}

func saveIdentity(ctx context.Context, ex execer, id *Identity) error {
	role := id.Role
	if role == "" {
		role = "user"
	}
	_, err := ex.ExecContext(ctx, `
		INSERT INTO identities (did, method, signing_key_path, enc_key_path, role, tenant_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(did) DO UPDATE SET
			signing_key_path=excluded.signing_key_path,
			enc_key_path=excluded.enc_key_path,
			role=excluded.role,
			tenant_id=excluded.tenant_id,
			updated_at=excluded.updated_at`,
		id.DID, id.Method, id.SigningKeyPath, id.EncKeyPath, role, id.TenantID, id.CreatedAt, id.UpdatedAt)
	return err
}

// CreateIdentityWithDocument stores an identity and its DID document in one transaction,
// so a failure cannot leave one without the other.
func (s *SQLiteStore) CreateIdentityWithDocument(ctx context.Context, id *Identity, doc *did.Document) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveIdentity(ctx, tx, id); err != nil {
		return err
	}
	if err := saveDocument(ctx, tx, doc); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetIdentity(ctx context.Context, did string) (*Identity, error) {
	row := s.db.QueryRowContext(ctx, `SELECT did, method, signing_key_path, enc_key_path, role, tenant_id, created_at, updated_at FROM identities WHERE did=?`, did)
	var id Identity
	if err := row.Scan(&id.DID, &id.Method, &id.SigningKeyPath, &id.EncKeyPath, &id.Role, &id.TenantID, &id.CreatedAt, &id.UpdatedAt); err != nil {
		return nil, fmt.Errorf("get identity: %w", err)
	}
	return &id, nil
}

func (s *SQLiteStore) ListIdentities(ctx context.Context, limit, offset int) ([]*Identity, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identities`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("list identities count: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT did, method, signing_key_path, enc_key_path, role, tenant_id, created_at, updated_at FROM identities ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list identities: %w", err)
	}
	defer rows.Close()
	var ids []*Identity
	for rows.Next() {
		var id Identity
		if err := rows.Scan(&id.DID, &id.Method, &id.SigningKeyPath, &id.EncKeyPath, &id.Role, &id.TenantID, &id.CreatedAt, &id.UpdatedAt); err != nil {
			return nil, 0, err
		}
		ids = append(ids, &id)
	}
	return ids, total, rows.Err()
}

func (s *SQLiteStore) UpdateIdentity(ctx context.Context, id *Identity) error {
	_, err := s.db.ExecContext(ctx, `UPDATE identities SET role=?, tenant_id=?, updated_at=? WHERE did=?`,
		id.Role, id.TenantID, id.UpdatedAt, id.DID)
	return err
}

// --- DID Documents ---

func (s *SQLiteStore) SaveDocument(ctx context.Context, doc *did.Document) error {
	return saveDocument(ctx, s.db, doc)
}

func saveDocument(ctx context.Context, ex execer, doc *did.Document) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = ex.ExecContext(ctx, `INSERT INTO did_documents (did, document, cached_at) VALUES (?,?,?) ON CONFLICT(did) DO UPDATE SET document=excluded.document, cached_at=excluded.cached_at`,
		doc.ID, string(b), time.Now())
	return err
}

func (s *SQLiteStore) GetDocument(ctx context.Context, id string) (*did.Document, error) {
	row := s.db.QueryRowContext(ctx, `SELECT document FROM did_documents WHERE did=?`, id)
	var raw string
	if err := row.Scan(&raw); err != nil {
		return nil, fmt.Errorf("get document: %w", err)
	}
	var doc did.Document
	return &doc, json.Unmarshal([]byte(raw), &doc)
}

// --- Verifiable Credentials ---

func (s *SQLiteStore) SaveCredential(ctx context.Context, cred *vc.VerifiableCredential) error {
	b, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	schemaID := ""
	if cred.CredentialSchema != nil {
		schemaID = cred.CredentialSchema.ID
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO credentials (id, subject_did, issuer_did, schema_id, valid_from, valid_until, credential, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		cred.ID, cred.CredentialSubject.ID, cred.Issuer, schemaID, cred.ValidFrom, cred.ValidUntil, string(b), time.Now())
	return err
}

func (s *SQLiteStore) GetCredential(ctx context.Context, id string) (*vc.VerifiableCredential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT credential FROM credentials WHERE id=?`, id)
	var raw string
	if err := row.Scan(&raw); err != nil {
		return nil, fmt.Errorf("get credential: %w", err)
	}
	var cred vc.VerifiableCredential
	return &cred, json.Unmarshal([]byte(raw), &cred)
}

func (s *SQLiteStore) ListCredentials(ctx context.Context, subjectDID string) ([]*vc.VerifiableCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT credential FROM credentials WHERE subject_did=? ORDER BY valid_from DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCredentials(rows)
}

func (s *SQLiteStore) DeleteCredential(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE id=?`, id)
	return err
}

// --- Consent Grants ---

func (s *SQLiteStore) SaveGrant(ctx context.Context, g *consent.Grant) error {
	confirmed := 0
	if g.ExplicitlyConfirmed {
		confirmed = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO consent_grants (id, subject_did, relying_did, level, scope_id, granted_at, expires_at, explicitly_confirmed) VALUES (?,?,?,?,?,?,?,?)`,
		g.ID, g.SubjectDID, g.RelyingDID, string(g.Level), g.ScopeID, g.GrantedAt, g.ExpiresAt, confirmed)
	return err
}

func (s *SQLiteStore) GetGrant(ctx context.Context, id string) (*consent.Grant, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, subject_did, relying_did, level, scope_id, granted_at, expires_at, explicitly_confirmed, revoked_at FROM consent_grants WHERE id=?`, id)
	var g consent.Grant
	var confirmed int
	var revokedAt sql.NullTime
	if err := row.Scan(&g.ID, &g.SubjectDID, &g.RelyingDID, &g.Level, &g.ScopeID, &g.GrantedAt, &g.ExpiresAt, &confirmed, &revokedAt); err != nil {
		return nil, fmt.Errorf("get grant: %w", err)
	}
	g.ExplicitlyConfirmed = confirmed == 1
	if revokedAt.Valid {
		g.RevokedAt = &revokedAt.Time
	}
	return &g, nil
}

func (s *SQLiteStore) ListGrants(ctx context.Context, subjectDID string) ([]*consent.Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, subject_did, relying_did, level, scope_id, granted_at, expires_at, explicitly_confirmed, revoked_at FROM consent_grants WHERE subject_did=? ORDER BY granted_at DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*consent.Grant
	for rows.Next() {
		var g consent.Grant
		var confirmed int
		var revokedAt sql.NullTime
		if err := rows.Scan(&g.ID, &g.SubjectDID, &g.RelyingDID, &g.Level, &g.ScopeID, &g.GrantedAt, &g.ExpiresAt, &confirmed, &revokedAt); err != nil {
			return nil, err
		}
		g.ExplicitlyConfirmed = confirmed == 1
		if revokedAt.Valid {
			g.RevokedAt = &revokedAt.Time
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) RevokeGrant(ctx context.Context, id string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE consent_grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, at.UTC(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// --- Consent Receipts ---

func (s *SQLiteStore) SaveReceipt(ctx context.Context, r *consent.Receipt) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO consent_receipts (id, subject_did, relying_did, schema_id, accessed_at, legal_basis, purpose, signed_by, signature) VALUES (?,?,?,?,?,?,?,?,?)`,
		r.ID, r.SubjectDID, r.RelyingDID, r.SchemaID, r.AccessedAt, string(r.LegalBasis), r.Purpose, r.SignedBy, r.Signature)
	return err
}

func (s *SQLiteStore) ListReceipts(ctx context.Context, subjectDID string) ([]*consent.Receipt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, subject_did, relying_did, schema_id, accessed_at, legal_basis, purpose, signed_by, signature FROM consent_receipts WHERE subject_did=? ORDER BY accessed_at DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*consent.Receipt
	for rows.Next() {
		var r consent.Receipt
		if err := rows.Scan(&r.ID, &r.SubjectDID, &r.RelyingDID, &r.SchemaID, &r.AccessedAt, &r.LegalBasis, &r.Purpose, &r.SignedBy, &r.Signature); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// --- OIDC Sessions ---

const sessionCols = `id, subject_did, client_id, redirect_uri, scope, nonce, state, code, code_challenge, code_challenge_method, access_token, refresh_token_hash, user_agent, ip_address, last_used_at, created_at, expires_at`

func (s *SQLiteStore) SaveSession(ctx context.Context, sess *OIDCSession) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_sessions (`+sessionCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			state=excluded.state,
			code=excluded.code,
			code_challenge=excluded.code_challenge,
			code_challenge_method=excluded.code_challenge_method,
			access_token=excluded.access_token,
			refresh_token_hash=excluded.refresh_token_hash,
			last_used_at=excluded.last_used_at,
			expires_at=excluded.expires_at`,
		sess.ID, sess.SubjectDID, sess.ClientID, sess.RedirectURI, sess.Scope, sess.Nonce,
		sess.State, sess.Code, sess.CodeChallenge, sess.CodeChallengeMethod,
		sess.AccessToken, sess.RefreshTokenHash, sess.UserAgent, sess.IPAddress,
		sess.LastUsedAt, sess.CreatedAt, sess.ExpiresAt)
	return err
}

func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*OIDCSession, error) {
	return s.scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM oidc_sessions WHERE id=?`, id))
}

func (s *SQLiteStore) GetSessionByCode(ctx context.Context, code string) (*OIDCSession, error) {
	return s.scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM oidc_sessions WHERE code=?`, code))
}

func (s *SQLiteStore) ListSessionsBySubject(ctx context.Context, subjectDID string) ([]*OIDCSession, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sessionCols+` FROM oidc_sessions WHERE subject_did=? AND expires_at > ? ORDER BY created_at DESC`, subjectDID, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OIDCSession
	for rows.Next() {
		sess, err := s.scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE expires_at < ?`, time.Now())
	return err
}

func (s *SQLiteStore) scanSession(row *sql.Row) (*OIDCSession, error) {
	var sess OIDCSession
	var lastUsedAt sql.NullTime
	if err := row.Scan(
		&sess.ID, &sess.SubjectDID, &sess.ClientID, &sess.RedirectURI, &sess.Scope, &sess.Nonce,
		&sess.State, &sess.Code, &sess.CodeChallenge, &sess.CodeChallengeMethod,
		&sess.AccessToken, &sess.RefreshTokenHash, &sess.UserAgent, &sess.IPAddress,
		&lastUsedAt, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	if lastUsedAt.Valid {
		sess.LastUsedAt = &lastUsedAt.Time
	}
	return &sess, nil
}

func (s *SQLiteStore) scanSessionRow(rows *sql.Rows) (*OIDCSession, error) {
	var sess OIDCSession
	var lastUsedAt sql.NullTime
	if err := rows.Scan(
		&sess.ID, &sess.SubjectDID, &sess.ClientID, &sess.RedirectURI, &sess.Scope, &sess.Nonce,
		&sess.State, &sess.Code, &sess.CodeChallenge, &sess.CodeChallengeMethod,
		&sess.AccessToken, &sess.RefreshTokenHash, &sess.UserAgent, &sess.IPAddress,
		&lastUsedAt, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
		return nil, err
	}
	if lastUsedAt.Valid {
		sess.LastUsedAt = &lastUsedAt.Time
	}
	return &sess, nil
}

// --- OIDC Clients ---

func (s *SQLiteStore) SaveClient(ctx context.Context, c *OIDCClient) error {
	redirectURIs, _ := json.Marshal(c.RedirectURIs)
	grantTypes, _ := json.Marshal(c.GrantTypes)
	responseTypes, _ := json.Marshal(c.ResponseTypes)
	postLogoutURIs, _ := json.Marshal(c.PostLogoutRedirectURIs)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_clients
		  (client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method,
		   grant_types, response_types, scope, tenant_id, backchannel_logout_uri, post_logout_redirect_uris, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(client_id) DO UPDATE SET
			client_secret_hash=excluded.client_secret_hash,
			client_name=excluded.client_name,
			redirect_uris=excluded.redirect_uris,
			token_endpoint_auth_method=excluded.token_endpoint_auth_method,
			grant_types=excluded.grant_types,
			response_types=excluded.response_types,
			scope=excluded.scope,
			backchannel_logout_uri=excluded.backchannel_logout_uri,
			post_logout_redirect_uris=excluded.post_logout_redirect_uris`,
		c.ClientID, c.ClientSecretHash, c.ClientName, string(redirectURIs),
		c.TokenEndpointAuthMethod, string(grantTypes), string(responseTypes),
		c.Scope, c.TenantID, c.BackchannelLogoutURI, string(postLogoutURIs), c.CreatedAt)
	return err
}

const clientSelectCols = `client_id, client_secret_hash, client_name, redirect_uris,
	token_endpoint_auth_method, grant_types, response_types, scope, tenant_id,
	COALESCE(backchannel_logout_uri,''), COALESCE(post_logout_redirect_uris,'[]'), created_at`

func (s *SQLiteStore) GetClient(ctx context.Context, clientID string) (*OIDCClient, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+clientSelectCols+` FROM oidc_clients WHERE client_id=?`, clientID)
	return s.scanClient(row)
}

func (s *SQLiteStore) ListClients(ctx context.Context) ([]*OIDCClient, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+clientSelectCols+` FROM oidc_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OIDCClient
	for rows.Next() {
		c, err := s.scanClientRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteClient(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_clients WHERE client_id=?`, clientID)
	return err
}

func (s *SQLiteStore) scanClient(row *sql.Row) (*OIDCClient, error) {
	var c OIDCClient
	var redirectURIs, grantTypes, responseTypes, postLogoutURIs string
	if err := row.Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientName, &redirectURIs,
		&c.TokenEndpointAuthMethod, &grantTypes, &responseTypes, &c.Scope, &c.TenantID,
		&c.BackchannelLogoutURI, &postLogoutURIs, &c.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan client: %w", err)
	}
	_ = unmarshalField(redirectURIs, &c.RedirectURIs)
	_ = unmarshalField(grantTypes, &c.GrantTypes)
	_ = unmarshalField(responseTypes, &c.ResponseTypes)
	_ = unmarshalField(postLogoutURIs, &c.PostLogoutRedirectURIs)
	return &c, nil
}

func (s *SQLiteStore) scanClientRow(rows *sql.Rows) (*OIDCClient, error) {
	var c OIDCClient
	var redirectURIs, grantTypes, responseTypes, postLogoutURIs string
	if err := rows.Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientName, &redirectURIs,
		&c.TokenEndpointAuthMethod, &grantTypes, &responseTypes, &c.Scope, &c.TenantID,
		&c.BackchannelLogoutURI, &postLogoutURIs, &c.CreatedAt); err != nil {
		return nil, err
	}
	_ = unmarshalField(redirectURIs, &c.RedirectURIs)
	_ = unmarshalField(grantTypes, &c.GrantTypes)
	_ = unmarshalField(responseTypes, &c.ResponseTypes)
	_ = unmarshalField(postLogoutURIs, &c.PostLogoutRedirectURIs)
	return &c, nil
}

// --- Refresh Tokens ---

func (s *SQLiteStore) SaveRefreshToken(ctx context.Context, t *RefreshToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (hash, family_id, subject_did, client_id, scope, issued_at, expires_at, used_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(hash) DO UPDATE SET used_at=excluded.used_at`,
		t.Hash, t.FamilyID, t.SubjectDID, t.ClientID, t.Scope, t.IssuedAt, t.ExpiresAt, t.UsedAt)
	return err
}

func (s *SQLiteStore) GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash, family_id, subject_did, client_id, scope, issued_at, expires_at, used_at FROM refresh_tokens WHERE hash=?`, hash)
	var t RefreshToken
	var usedAt sql.NullTime
	if err := row.Scan(&t.Hash, &t.FamilyID, &t.SubjectDID, &t.ClientID, &t.Scope, &t.IssuedAt, &t.ExpiresAt, &usedAt); err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	if usedAt.Valid {
		t.UsedAt = &usedAt.Time
	}
	return &t, nil
}

func (s *SQLiteStore) DeleteRefreshToken(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE hash=?`, hash)
	return err
}

func (s *SQLiteStore) MarkRefreshTokenUsed(ctx context.Context, hash string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET used_at=? WHERE hash=? AND used_at IS NULL`, at.UTC(), hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *SQLiteStore) DeleteRefreshTokenFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE family_id=?`, familyID)
	return err
}

func (s *SQLiteStore) TakeSessionByCode(ctx context.Context, code string) (*OIDCSession, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	sess, err := s.scanSession(tx.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM oidc_sessions WHERE code=?`, code))
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE id=? AND code=?`, sess.ID, code)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return sess, nil
}

// --- External Provider Links ---

func (s *SQLiteStore) SaveExternalLink(ctx context.Context, l *ExternalProviderLink) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO external_provider_links (subject_did, provider, external_id, linked_at, last_used_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(provider, external_id) DO UPDATE SET
			subject_did=excluded.subject_did,
			last_used_at=excluded.last_used_at`,
		l.SubjectDID, l.Provider, l.ExternalID, l.LinkedAt, l.LastUsedAt)
	return err
}

func (s *SQLiteStore) GetExternalLink(ctx context.Context, provider, externalID string) (*ExternalProviderLink, error) {
	row := s.db.QueryRowContext(ctx, `SELECT subject_did, provider, external_id, linked_at, last_used_at FROM external_provider_links WHERE provider=? AND external_id=?`, provider, externalID)
	var l ExternalProviderLink
	if err := row.Scan(&l.SubjectDID, &l.Provider, &l.ExternalID, &l.LinkedAt, &l.LastUsedAt); err != nil {
		return nil, fmt.Errorf("get external link: %w", err)
	}
	return &l, nil
}

func (s *SQLiteStore) ListExternalLinks(ctx context.Context, subjectDID string) ([]*ExternalProviderLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject_did, provider, external_id, linked_at, last_used_at FROM external_provider_links WHERE subject_did=? ORDER BY linked_at DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ExternalProviderLink
	for rows.Next() {
		var l ExternalProviderLink
		if err := rows.Scan(&l.SubjectDID, &l.Provider, &l.ExternalID, &l.LinkedAt, &l.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteExternalLink(ctx context.Context, provider, externalID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM external_provider_links WHERE provider=? AND external_id=?`, provider, externalID)
	return err
}

// --- Magic Link Tokens ---

func (s *SQLiteStore) SaveMagicLinkToken(ctx context.Context, t *MagicLinkToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO magic_link_tokens (hash, email, expires_at, created_at) VALUES (?,?,?,?)`,
		t.Hash, t.Email, t.ExpiresAt, t.CreatedAt)
	return err
}

func (s *SQLiteStore) GetMagicLinkToken(ctx context.Context, hash string) (*MagicLinkToken, error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash, email, expires_at, created_at FROM magic_link_tokens WHERE hash=?`, hash)
	var t MagicLinkToken
	if err := row.Scan(&t.Hash, &t.Email, &t.ExpiresAt, &t.CreatedAt); err != nil {
		return nil, fmt.Errorf("get magic link token: %w", err)
	}
	return &t, nil
}

func (s *SQLiteStore) DeleteMagicLinkToken(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM magic_link_tokens WHERE hash=?`, hash)
	return err
}

// --- WebAuthn Credentials ---

func (s *SQLiteStore) SaveWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	transports, _ := json.Marshal(c.Transports)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (credential_id, subject_did, public_key_cbor, attestation_type, aaguid, sign_count, name, transports, created_at, last_used_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(credential_id) DO UPDATE SET sign_count=excluded.sign_count, name=excluded.name, last_used_at=excluded.last_used_at`,
		c.CredentialID, c.SubjectDID, c.PublicKeyCBOR, c.AttestationType, c.AAGUID,
		c.SignCount, c.Name, string(transports), c.CreatedAt, c.LastUsedAt)
	return err
}

func (s *SQLiteStore) GetWebAuthnCredential(ctx context.Context, credentialID string) (*WebAuthnCredential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT credential_id, subject_did, public_key_cbor, attestation_type, aaguid, sign_count, name, transports, created_at, last_used_at FROM webauthn_credentials WHERE credential_id=?`, credentialID)
	return s.scanWebAuthnCredential(row)
}

func (s *SQLiteStore) ListWebAuthnCredentials(ctx context.Context, subjectDID string) ([]*WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT credential_id, subject_did, public_key_cbor, attestation_type, aaguid, sign_count, name, transports, created_at, last_used_at FROM webauthn_credentials WHERE subject_did=? ORDER BY created_at DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebAuthnCredential
	for rows.Next() {
		c, err := s.scanWebAuthnRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpdateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count=?, last_used_at=?, name=? WHERE credential_id=?`,
		c.SignCount, c.LastUsedAt, c.Name, c.CredentialID)
	return err
}

func (s *SQLiteStore) DeleteWebAuthnCredential(ctx context.Context, credentialID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE credential_id=?`, credentialID)
	return err
}

func (s *SQLiteStore) scanWebAuthnCredential(row *sql.Row) (*WebAuthnCredential, error) {
	var c WebAuthnCredential
	var transports string
	var lastUsedAt sql.NullTime
	if err := row.Scan(&c.CredentialID, &c.SubjectDID, &c.PublicKeyCBOR, &c.AttestationType, &c.AAGUID,
		&c.SignCount, &c.Name, &transports, &c.CreatedAt, &lastUsedAt); err != nil {
		return nil, fmt.Errorf("scan webauthn credential: %w", err)
	}
	if err := unmarshalField(transports, &c.Transports); err != nil {
		slog.Warn("store: webauthn transports unmarshal", "cred_id", c.CredentialID, "err", err)
	}
	if lastUsedAt.Valid {
		c.LastUsedAt = &lastUsedAt.Time
	}
	return &c, nil
}

func (s *SQLiteStore) scanWebAuthnRow(rows *sql.Rows) (*WebAuthnCredential, error) {
	var c WebAuthnCredential
	var transports string
	var lastUsedAt sql.NullTime
	if err := rows.Scan(&c.CredentialID, &c.SubjectDID, &c.PublicKeyCBOR, &c.AttestationType, &c.AAGUID,
		&c.SignCount, &c.Name, &transports, &c.CreatedAt, &lastUsedAt); err != nil {
		return nil, err
	}
	if err := unmarshalField(transports, &c.Transports); err != nil {
		slog.Warn("store: webauthn transports unmarshal", "cred_id", c.CredentialID, "err", err)
	}
	if lastUsedAt.Valid {
		c.LastUsedAt = &lastUsedAt.Time
	}
	return &c, nil
}

// --- TOTP Credentials ---

// SaveTOTPCredential stores a new (pending) factor. A new secret always starts unverified
// and with no replay history.
func (s *SQLiteStore) SaveTOTPCredential(ctx context.Context, c *TOTPCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_credentials (subject_did, encrypted_secret, account_name, created_at, verified_at, last_step)
		VALUES (?,?,?,?,NULL,0)
		ON CONFLICT(subject_did) DO UPDATE SET encrypted_secret=excluded.encrypted_secret,
			account_name=excluded.account_name, created_at=excluded.created_at, verified_at=NULL, last_step=0`,
		c.SubjectDID, c.EncryptedSecret, c.AccountName, c.CreatedAt)
	return err
}

func (s *SQLiteStore) GetTOTPCredential(ctx context.Context, subjectDID string) (*TOTPCredential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT subject_did, encrypted_secret, account_name, created_at, verified_at, last_step FROM totp_credentials WHERE subject_did=?`, subjectDID)
	var c TOTPCredential
	var verifiedAt sql.NullTime
	if err := row.Scan(&c.SubjectDID, &c.EncryptedSecret, &c.AccountName, &c.CreatedAt, &verifiedAt, &c.LastStep); err != nil {
		return nil, fmt.Errorf("get totp credential: %w", err)
	}
	if verifiedAt.Valid {
		c.VerifiedAt = &verifiedAt.Time
	}
	return &c, nil
}

// ConsumeTOTPStep records that time step was used. It succeeds only for a step newer than
// the last one used, which stops a code from being replayed inside its validity window. The
// first success also marks the factor verified.
func (s *SQLiteStore) ConsumeTOTPStep(ctx context.Context, subjectDID string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE totp_credentials
		SET last_step=?, verified_at=COALESCE(verified_at, ?)
		WHERE subject_did=? AND last_step < ?`,
		step, time.Now().UTC(), subjectDID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *SQLiteStore) DeleteTOTPCredential(ctx context.Context, subjectDID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp_credentials WHERE subject_did=?`, subjectDID)
	return err
}

// --- Webhook Subscriptions ---

func (s *SQLiteStore) SaveWebhookSubscription(ctx context.Context, sub *WebhookSubscription) error {
	eventTypes, _ := json.Marshal(sub.EventTypes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_subscriptions (id, url, event_types, signing_secret, tenant_id, created_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET url=excluded.url, event_types=excluded.event_types`,
		sub.ID, sub.URL, string(eventTypes), sub.SigningSecret, sub.TenantID, sub.CreatedAt)
	return err
}

func (s *SQLiteStore) GetWebhookSubscription(ctx context.Context, id string) (*WebhookSubscription, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, url, event_types, signing_secret, tenant_id, created_at FROM webhook_subscriptions WHERE id=?`, id)
	return s.scanWebhookSub(row)
}

func (s *SQLiteStore) ListWebhookSubscriptions(ctx context.Context, eventType string) ([]*WebhookSubscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, url, event_types, signing_secret, tenant_id, created_at FROM webhook_subscriptions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebhookSubscription
	for rows.Next() {
		sub, err := s.scanWebhookSubRow(rows)
		if err != nil {
			return nil, err
		}
		// Empty eventType = return all (used by admin list endpoint).
		if eventType == "" {
			out = append(out, sub)
			continue
		}
		// Otherwise filter by event type match or wildcard subscription.
		for _, et := range sub.EventTypes {
			if et == "*" || et == eventType {
				out = append(out, sub)
				break
			}
		}
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteWebhookSubscription(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webhook_subscriptions WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) scanWebhookSub(row *sql.Row) (*WebhookSubscription, error) {
	var sub WebhookSubscription
	var eventTypes string
	if err := row.Scan(&sub.ID, &sub.URL, &eventTypes, &sub.SigningSecret, &sub.TenantID, &sub.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan webhook subscription: %w", err)
	}
	if err := unmarshalField(eventTypes, &sub.EventTypes); err != nil {
		slog.Warn("store: webhook event_types unmarshal", "id", sub.ID, "err", err)
	}
	return &sub, nil
}

func (s *SQLiteStore) scanWebhookSubRow(rows *sql.Rows) (*WebhookSubscription, error) {
	var sub WebhookSubscription
	var eventTypes string
	if err := rows.Scan(&sub.ID, &sub.URL, &eventTypes, &sub.SigningSecret, &sub.TenantID, &sub.CreatedAt); err != nil {
		return nil, err
	}
	if err := unmarshalField(eventTypes, &sub.EventTypes); err != nil {
		slog.Warn("store: webhook event_types unmarshal", "id", sub.ID, "err", err)
	}
	return &sub, nil
}

// unmarshalField is a helper that decodes a JSON string column into dest.
func unmarshalField(s string, dest any) error {
	if s == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), dest)
}

// --- Auth Failures ---

const (
	lockThreshold1 = 5
	lockDuration1  = 5 * time.Minute
	lockThreshold2 = 10
	lockDuration2  = 30 * time.Minute
	lockThreshold3 = 20 // permanent (admin reset required)
)

// authFailureDecay is how long a quiet period resets the failure counter. A lock already in force
// is never shortened by a later failure.
const authFailureDecay = 24 * time.Hour

// RecordAuthFailure increments the failure counter for subjectOrEmail and sets the lockout window.
// The read and the write run in one transaction, so concurrent failures are all counted.
func (s *SQLiteStore) RecordAuthFailure(ctx context.Context, subjectOrEmail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	var count int
	var lastFailure, existingLock sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT count, last_failure_at, locked_until FROM auth_failures WHERE subject_or_email=?`, subjectOrEmail).
		Scan(&count, &lastFailure, &existingLock)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if lastFailure.Valid && now.Sub(lastFailure.Time) > authFailureDecay {
		count = 0
	}
	count++

	var lockedUntil *time.Time
	switch {
	case count >= lockThreshold3:
		// permanent lock — set far future
		t := now.Add(100 * 365 * 24 * time.Hour)
		lockedUntil = &t
	case count >= lockThreshold2:
		t := now.Add(lockDuration2)
		lockedUntil = &t
	case count >= lockThreshold1:
		t := now.Add(lockDuration1)
		lockedUntil = &t
	}
	if existingLock.Valid && existingLock.Time.After(now) && (lockedUntil == nil || existingLock.Time.After(*lockedUntil)) {
		t := existingLock.Time
		lockedUntil = &t
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO auth_failures (subject_or_email, count, last_failure_at, locked_until) VALUES (?,?,?,?)
		ON CONFLICT(subject_or_email) DO UPDATE SET count=excluded.count, last_failure_at=excluded.last_failure_at, locked_until=excluded.locked_until`,
		subjectOrEmail, count, now, lockedUntil); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetAuthFailures(ctx context.Context, subjectOrEmail string) (int, *time.Time, error) {
	row := s.db.QueryRowContext(ctx, `SELECT count, locked_until FROM auth_failures WHERE subject_or_email=?`, subjectOrEmail)
	var count int
	var lockedUntil sql.NullTime
	if err := row.Scan(&count, &lockedUntil); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	var lu *time.Time
	if lockedUntil.Valid {
		lu = &lockedUntil.Time
	}
	return count, lu, nil
}

func (s *SQLiteStore) ClearAuthFailures(ctx context.Context, subjectOrEmail string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_failures WHERE subject_or_email=?`, subjectOrEmail)
	return err
}

// --- Duress Configs ---

func (s *SQLiteStore) SaveDuressConfig(ctx context.Context, subjectDID, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO duress_configs (subject_did, hash) VALUES (?,?)
		 ON CONFLICT(subject_did) DO UPDATE SET hash=excluded.hash, created_at=CURRENT_TIMESTAMP`,
		subjectDID, hash)
	return err
}

func (s *SQLiteStore) GetDuressHash(ctx context.Context, subjectDID string) (string, error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash FROM duress_configs WHERE subject_did=?`, subjectDID)
	var hash string
	if err := row.Scan(&hash); err != nil {
		return "", err
	}
	return hash, nil
}

func (s *SQLiteStore) DeleteDuressConfig(ctx context.Context, subjectDID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM duress_configs WHERE subject_did=?`, subjectDID)
	return err
}

// --- Consent Expiry ---

func (s *SQLiteStore) ListExpiringGrants(ctx context.Context, within time.Duration) ([]*consent.Grant, error) {
	cutoff := time.Now().Add(within)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, subject_did, relying_did, level, scope_id, granted_at, expires_at, explicitly_confirmed
		 FROM consent_grants
		 WHERE expires_at IS NOT NULL AND expires_at <= ? AND revoked_at IS NULL
		 ORDER BY expires_at ASC`,
		cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*consent.Grant
	for rows.Next() {
		var g consent.Grant
		var confirmed int
		if err := rows.Scan(&g.ID, &g.SubjectDID, &g.RelyingDID, &g.Level, &g.ScopeID, &g.GrantedAt, &g.ExpiresAt, &confirmed); err != nil {
			return nil, err
		}
		g.ExplicitlyConfirmed = confirmed == 1
		out = append(out, &g)
	}
	return out, rows.Err()
}

// --- Verifiable Audit Log ---

func (s *SQLiteStore) AppendAuditEvent(ctx context.Context, eventType, payload string) (*AuditEvent, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// The head is read in the same transaction that writes the new row.
	prevHash := ""
	var head string
	switch err := tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&head); {
	case err == nil:
		prevHash = head
	case errors.Is(err, sql.ErrNoRows):
		// Empty chain: the first event links to the empty string.
	default:
		return nil, fmt.Errorf("audit: read chain head: %w", err)
	}

	raw, _ := json.Marshal(map[string]string{"event_type": eventType, "payload": payload, "prev_hash": prevHash})
	sum := sha256.Sum256(append([]byte(prevHash), raw...))
	hash := hex.EncodeToString(sum[:])
	res, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log (event_type, payload, hash, prev_hash) VALUES (?,?,?,?)`,
		eventType, payload, hash, prevHash)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("audit: commit: %w", err)
	}
	id, _ := res.LastInsertId()
	return &AuditEvent{
		Seq:       id,
		Timestamp: time.Now(),
		EventType: eventType,
		Payload:   payload,
		Hash:      hash,
		PrevHash:  prevHash,
	}, nil
}

func (s *SQLiteStore) GetAuditHead(ctx context.Context) (*AuditEvent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT seq, timestamp, event_type, payload, hash, prev_hash FROM audit_log ORDER BY seq DESC LIMIT 1`)
	return scanAuditRow(row)
}

func (s *SQLiteStore) ListAuditEvents(ctx context.Context, limit, offset int) ([]*AuditEvent, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, timestamp, event_type, payload, hash, prev_hash FROM audit_log ORDER BY seq ASC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var events []*AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.Seq, &e.Timestamp, &e.EventType, &e.Payload, &e.Hash, &e.PrevHash); err != nil {
			return nil, 0, err
		}
		events = append(events, &e)
	}
	return events, total, rows.Err()
}

func scanAuditRow(row *sql.Row) (*AuditEvent, error) {
	var e AuditEvent
	if err := row.Scan(&e.Seq, &e.Timestamp, &e.EventType, &e.Payload, &e.Hash, &e.PrevHash); err != nil {
		return nil, err
	}
	return &e, nil
}

// --- Guardian Recovery ---

func (s *SQLiteStore) SaveRecoveryConfig(ctx context.Context, cfg *RecoveryConfig) error {
	gdids, _ := json.Marshal(cfg.GuardianDIDs)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO recovery_configs (subject_did, threshold, guardian_dids) VALUES (?,?,?)
		 ON CONFLICT(subject_did) DO UPDATE SET threshold=excluded.threshold, guardian_dids=excluded.guardian_dids, created_at=CURRENT_TIMESTAMP`,
		cfg.SubjectDID, cfg.Threshold, string(gdids))
	return err
}

func (s *SQLiteStore) GetRecoveryConfig(ctx context.Context, subjectDID string) (*RecoveryConfig, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT subject_did, threshold, guardian_dids, created_at FROM recovery_configs WHERE subject_did=?`, subjectDID)
	var cfg RecoveryConfig
	var gdids string
	if err := row.Scan(&cfg.SubjectDID, &cfg.Threshold, &gdids, &cfg.CreatedAt); err != nil {
		return nil, err
	}
	if err := unmarshalField(gdids, &cfg.GuardianDIDs); err != nil {
		slog.Warn("store: recovery guardian_dids unmarshal", "subject", cfg.SubjectDID, "err", err)
	}
	return &cfg, nil
}

func (s *SQLiteStore) DeleteRecoveryConfig(ctx context.Context, subjectDID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM recovery_configs WHERE subject_did=?`, subjectDID)
	return err
}

func (s *SQLiteStore) SaveRecoveryRequest(ctx context.Context, req *RecoveryRequest) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO recovery_requests (id, subject_did, shares_collected, completed, commitment) VALUES (?,?,?,?,?)`,
		req.ID, req.SubjectDID, req.SharesCollected, boolToInt(req.Completed), req.Commitment)
	return err
}

func (s *SQLiteStore) GetRecoveryRequest(ctx context.Context, id string) (*RecoveryRequest, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, subject_did, started_at, shares_collected, completed, commitment FROM recovery_requests WHERE id=?`, id)
	var req RecoveryRequest
	var completed int
	if err := row.Scan(&req.ID, &req.SubjectDID, &req.StartedAt, &req.SharesCollected, &completed, &req.Commitment); err != nil {
		return nil, err
	}
	req.Completed = completed != 0
	return &req, nil
}

func (s *SQLiteStore) UpdateRecoveryRequest(ctx context.Context, req *RecoveryRequest) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE recovery_requests SET shares_collected=?, completed=? WHERE id=?`,
		req.SharesCollected, boolToInt(req.Completed), req.ID)
	return err
}

func (s *SQLiteStore) SaveRecoveryShare(ctx context.Context, share *RecoveryShare) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO recovery_shares (request_id, guardian_did, share_hash) VALUES (?,?,?)
		 ON CONFLICT(request_id, guardian_did) DO NOTHING`,
		share.RequestID, share.GuardianDID, share.ShareHash)
	return err
}

func (s *SQLiteStore) ListRecoveryShares(ctx context.Context, requestID string) ([]*RecoveryShare, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT request_id, guardian_did, share_hash, collected_at FROM recovery_shares WHERE request_id=?`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var shares []*RecoveryShare
	for rows.Next() {
		var sh RecoveryShare
		if err := rows.Scan(&sh.RequestID, &sh.GuardianDID, &sh.ShareHash, &sh.CollectedAt); err != nil {
			return nil, err
		}
		shares = append(shares, &sh)
	}
	return shares, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- Password Credentials ---

func (s *SQLiteStore) SavePasswordHash(ctx context.Context, identifier, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO passwords (identifier, hash) VALUES (?,?)
		 ON CONFLICT(identifier) DO UPDATE SET hash=excluded.hash, created_at=CURRENT_TIMESTAMP`,
		identifier, hash)
	return err
}

func (s *SQLiteStore) GetPasswordHash(ctx context.Context, identifier string) (string, error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash FROM passwords WHERE identifier=?`, identifier)
	var hash string
	if err := row.Scan(&hash); err != nil {
		return "", fmt.Errorf("get password hash: %w", err)
	}
	return hash, nil
}

func (s *SQLiteStore) DeletePasswordHash(ctx context.Context, identifier string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM passwords WHERE identifier=?`, identifier)
	return err
}

// --- helpers ---

func scanCredentials(rows *sql.Rows) ([]*vc.VerifiableCredential, error) {
	var out []*vc.VerifiableCredential
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var cred vc.VerifiableCredential
		if err := json.Unmarshal([]byte(raw), &cred); err != nil {
			return nil, err
		}
		out = append(out, &cred)
	}
	return out, rows.Err()
}

// --- Pushed Authorization Requests (RFC 9126) ---

func (s *SQLiteStore) SavePARRequest(ctx context.Context, req *PARRequest) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO par_requests (request_uri, client_id, params, expires_at, created_at) VALUES (?,?,?,?,?)`,
		req.RequestURI, req.ClientID, req.Params, req.ExpiresAt, req.CreatedAt)
	return err
}

func (s *SQLiteStore) GetPARRequest(ctx context.Context, requestURI string) (*PARRequest, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT request_uri, client_id, params, expires_at, created_at FROM par_requests WHERE request_uri=?`, requestURI)
	var r PARRequest
	if err := row.Scan(&r.RequestURI, &r.ClientID, &r.Params, &r.ExpiresAt, &r.CreatedAt); err != nil {
		return nil, fmt.Errorf("get par request: %w", err)
	}
	return &r, nil
}

func (s *SQLiteStore) DeletePARRequest(ctx context.Context, requestURI string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM par_requests WHERE request_uri=?`, requestURI)
	return err
}

// --- Device Authorization Grant (RFC 8628) ---

func (s *SQLiteStore) SaveDeviceCode(ctx context.Context, dc *DeviceCode) error {
	approved, denied := boolToInt(dc.Approved), boolToInt(dc.Denied)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO device_codes (device_code, user_code, client_id, scope, subject_did, approved, denied, expires_at, interval_secs, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(device_code) DO UPDATE SET subject_did=excluded.subject_did, approved=excluded.approved, denied=excluded.denied`,
		dc.DeviceCode, dc.UserCode, dc.ClientID, dc.Scope, dc.SubjectDID,
		approved, denied, dc.ExpiresAt, dc.IntervalSecs, dc.CreatedAt)
	return err
}

func (s *SQLiteStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT device_code, user_code, client_id, scope, subject_did, approved, denied, expires_at, interval_secs, created_at
		 FROM device_codes WHERE device_code=?`, deviceCode)
	return scanDeviceCode(row)
}

func (s *SQLiteStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT device_code, user_code, client_id, scope, subject_did, approved, denied, expires_at, interval_secs, created_at
		 FROM device_codes WHERE user_code=?`, userCode)
	return scanDeviceCode(row)
}

func (s *SQLiteStore) UpdateDeviceCode(ctx context.Context, dc *DeviceCode) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_codes SET subject_did=?, approved=?, denied=? WHERE device_code=?`,
		dc.SubjectDID, boolToInt(dc.Approved), boolToInt(dc.Denied), dc.DeviceCode)
	return err
}

func (s *SQLiteStore) RevokeAccessToken(ctx context.Context, hash string, expiresAt time.Time) error {
	// Entries past their expiry can never match a valid token; drop them as we go.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM revoked_access_tokens WHERE expires_at < ?`, time.Now().UTC())
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO revoked_access_tokens (hash, expires_at) VALUES (?,?)
		 ON CONFLICT(hash) DO UPDATE SET expires_at=excluded.expires_at`,
		hash, expiresAt.UTC())
	return err
}

func (s *SQLiteStore) IsAccessTokenRevoked(ctx context.Context, hash string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM revoked_access_tokens WHERE hash=? AND expires_at > ?`,
		hash, time.Now().UTC()).Scan(&n)
	return n > 0, err
}

func (s *SQLiteStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM device_codes WHERE device_code=?`, deviceCode)
	return err
}

func scanDeviceCode(row *sql.Row) (*DeviceCode, error) {
	var dc DeviceCode
	var approved, denied int
	var subjectDID sql.NullString
	if err := row.Scan(&dc.DeviceCode, &dc.UserCode, &dc.ClientID, &dc.Scope,
		&subjectDID, &approved, &denied, &dc.ExpiresAt, &dc.IntervalSecs, &dc.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan device code: %w", err)
	}
	dc.SubjectDID = subjectDID.String
	dc.Approved = approved != 0
	dc.Denied = denied != 0
	return &dc, nil
}

// --- Password Reset Tokens ---

func (s *SQLiteStore) SavePasswordResetToken(ctx context.Context, t *PasswordResetToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO password_reset_tokens (hash, identifier, expires_at, created_at) VALUES (?,?,?,?)`,
		t.Hash, t.Identifier, t.ExpiresAt, t.CreatedAt)
	return err
}

func (s *SQLiteStore) GetPasswordResetToken(ctx context.Context, hash string) (*PasswordResetToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT hash, identifier, expires_at, created_at FROM password_reset_tokens WHERE hash=?`, hash)
	var t PasswordResetToken
	if err := row.Scan(&t.Hash, &t.Identifier, &t.ExpiresAt, &t.CreatedAt); err != nil {
		return nil, fmt.Errorf("get password reset token: %w", err)
	}
	return &t, nil
}

func (s *SQLiteStore) DeletePasswordResetToken(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE hash=?`, hash)
	return err
}

func (s *SQLiteStore) ConsumePasswordResetToken(ctx context.Context, hash string) (*PasswordResetToken, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var t PasswordResetToken
	err = tx.QueryRowContext(ctx,
		`SELECT hash, identifier, expires_at, created_at FROM password_reset_tokens WHERE hash=?`, hash,
	).Scan(&t.Hash, &t.Identifier, &t.ExpiresAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE hash=?`, hash)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &t, nil
}

// --- Privacy Budget ---

func (s *SQLiteStore) RecordDisclosure(ctx context.Context, d *PrivacyDisclosure) error {
	fields, _ := json.Marshal(d.FieldNames)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO privacy_disclosures (id, subject_did, schema_id, verifier_did, field_names, disclosed_at)
		 VALUES (?,?,?,?,?,?)`,
		d.ID, d.SubjectDID, d.SchemaID, d.VerifierDID, string(fields), d.DisclosedAt)
	return err
}

func (s *SQLiteStore) ListDisclosures(ctx context.Context, subjectDID, schemaID string) ([]*PrivacyDisclosure, error) {
	q := `SELECT id, subject_did, schema_id, verifier_did, field_names, disclosed_at FROM privacy_disclosures WHERE subject_did=?`
	args := []any{subjectDID}
	if schemaID != "" {
		q += ` AND schema_id=?`
		args = append(args, schemaID)
	}
	q += ` ORDER BY disclosed_at DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PrivacyDisclosure
	for rows.Next() {
		var d PrivacyDisclosure
		var fields string
		if err := rows.Scan(&d.ID, &d.SubjectDID, &d.SchemaID, &d.VerifierDID, &fields, &d.DisclosedAt); err != nil {
			return nil, err
		}
		_ = unmarshalField(fields, &d.FieldNames)
		out = append(out, &d)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) CountDisclosures(ctx context.Context, subjectDID, schemaID string) (int, error) {
	q := `SELECT COUNT(*) FROM privacy_disclosures WHERE subject_did=?`
	args := []any{subjectDID}
	if schemaID != "" {
		q += ` AND schema_id=?`
		args = append(args, schemaID)
	}
	var n int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// --- OID4VCI Credential Offers ---

func (s *SQLiteStore) SaveCredentialOffer(ctx context.Context, offer *CredentialOffer) error {
	schemas, _ := json.Marshal(offer.SchemaIDs)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO credential_offers (id, client_id, schema_ids, issuer_did, subject_did, expires_at, used, created_at, tx_code_hash)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		offer.ID, offer.ClientID, string(schemas), offer.IssuerDID, offer.SubjectDID,
		offer.ExpiresAt, boolToInt(offer.Used), offer.CreatedAt, offer.TxCodeHash)
	return err
}

func (s *SQLiteStore) GetCredentialOffer(ctx context.Context, id string) (*CredentialOffer, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, schema_ids, issuer_did, subject_did, expires_at, used, created_at, tx_code_hash
		 FROM credential_offers WHERE id=?`, id)
	var o CredentialOffer
	var schemas string
	var used int
	var clientID, subjectDID sql.NullString
	if err := row.Scan(&o.ID, &clientID, &schemas, &o.IssuerDID, &subjectDID, &o.ExpiresAt, &used, &o.CreatedAt, &o.TxCodeHash); err != nil {
		return nil, fmt.Errorf("get credential offer: %w", err)
	}
	o.ClientID = clientID.String
	o.SubjectDID = subjectDID.String
	o.Used = used != 0
	_ = unmarshalField(schemas, &o.SchemaIDs)
	return &o, nil
}

// MarkCredentialOfferUsed claims an offer. The update applies only while the offer is unused, so two
// redemptions cannot both succeed; the loser gets ErrOfferUsed.
func (s *SQLiteStore) MarkCredentialOfferUsed(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE credential_offers SET used=1 WHERE id=? AND used=0`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrOfferUsed
	}
	return nil
}
