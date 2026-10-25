package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// dialect selects the SQL flavour the shared query code runs against. The store methods are
// written once with ? placeholders; the dialect decides how they are sent and how transactions
// that read a row and then write it are serialised.
type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

// rebind rewrites ? placeholders to PostgreSQL's $1, $2, … form. Question marks inside single-quoted
// SQL literals are left alone. SQLite takes ? natively, so its queries pass through unchanged.
func (d dialect) rebind(q string) string {
	if d != dialectPostgres || !strings.Contains(q, "?") {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n := 0
	inLiteral := false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '\'':
			inLiteral = !inLiteral
			b.WriteByte(c)
		case c == '?' && !inLiteral:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// sqlDB is the store's connection pool. It applies the dialect to every query it runs, so the
// methods of SQLStore never handle placeholders themselves.
type sqlDB struct {
	*sql.DB
	d dialect
}

func (db sqlDB) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return db.DB.ExecContext(ctx, db.d.rebind(q), args...)
}

func (db sqlDB) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return db.DB.QueryContext(ctx, db.d.rebind(q), args...)
}

func (db sqlDB) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return db.DB.QueryRowContext(ctx, db.d.rebind(q), args...)
}

// BeginTx starts a transaction whose statements are rewritten the same way.
func (db sqlDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (sqlTx, error) {
	tx, err := db.DB.BeginTx(ctx, opts)
	if err != nil {
		return sqlTx{}, err
	}
	return sqlTx{Tx: tx, d: db.d}, nil
}

// sqlTx is a transaction on the store's pool.
type sqlTx struct {
	*sql.Tx
	d dialect
}

func (t sqlTx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, t.d.rebind(q), args...)
}

func (t sqlTx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, t.d.rebind(q), args...)
}

func (t sqlTx) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, t.d.rebind(q), args...)
}

// lock serialises transactions that read a row and then write it. SQLite runs one writer at a time
// (the pool has a single connection), so it needs nothing. PostgreSQL runs transactions concurrently,
// so key is taken as a transaction-scoped advisory lock: the lock is released at commit or rollback.
// Two transactions with the same key cannot both read the old state and both write.
func (t sqlTx) lock(ctx context.Context, key string) error {
	if t.d != dialectPostgres {
		return nil
	}
	_, err := t.Tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
	return err
}
