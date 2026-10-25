package store

import (
	"context"
	"errors"

	"github.com/tpt-solutions/tpt-identity/internal/store/migrations"
)

// ErrSchemaVersionUnsupported means the backend does not record a schema version. PostgreSQL builds its schema
// inline and keeps no version record yet.
var ErrSchemaVersionUnsupported = errors.New("schema version is not tracked by this database")

// SchemaVersion returns the migration version the database has applied.
func (s *SQLStore) SchemaVersion(ctx context.Context) (int, error) {
	if s.db.d == dialectPostgres {
		return 0, ErrSchemaVersionUnsupported
	}
	return migrations.Version(s.db.DB)
}

// LatestSchemaVersion returns the version this build expects the database to have applied.
func LatestSchemaVersion() (int, error) {
	return migrations.Latest()
}
