package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/tpt-solutions/tpt-identity/internal/store/migrations"
)

// IsPostgresDSN reports whether dsn names a PostgreSQL database rather than a SQLite file.
func IsPostgresDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// OpenPostgres connects to the PostgreSQL database named by dsn (a postgres:// URL) and creates the
// schema if it is missing. Unlike SQLite, PostgreSQL runs transactions concurrently, so the pool is
// sized for parallel requests; the read-then-write transactions take advisory locks (see sqlTx.lock).
func OpenPostgres(dsn string) (*SQLStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	s := &SQLStore{db: sqlDB{DB: db, d: dialectPostgres}}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// migratePostgres brings the database to the current schema by running the PostgreSQL migrations (pg/). The
// runner takes an advisory lock per migration, so replicas that start together apply each one once.
func (s *SQLStore) migratePostgres() error {
	return migrations.UpFor(s.db.DB, migrations.Postgres)
}
