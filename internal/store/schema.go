package store

import (
	"context"

	"github.com/tpt-solutions/tpt-identity/internal/store/migrations"
)

// SchemaVersion returns the migration version the database has applied, and the version this build expects it
// to have. The two differ when the server has been upgraded but the migrations have not yet run.
func (s *SQLStore) SchemaVersion(ctx context.Context) (applied, latest int, err error) {
	d := migrations.SQLite
	if s.db.d == dialectPostgres {
		d = migrations.Postgres
	}
	applied, err = migrations.VersionFor(s.db.DB, d)
	if err != nil {
		return 0, 0, err
	}
	latest, err = migrations.LatestFor(d)
	return applied, latest, err
}
