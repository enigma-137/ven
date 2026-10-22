// Package storage owns the SQLite database: connection setup, versioned
// migrations and the row-level queries used by the application services.
package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var (
	// ErrNotFound is returned when a row does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a uniqueness constraint is violated.
	ErrConflict = errors.New("already exists")
)

// Querier is satisfied by *sql.DB and *sql.Tx.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// DB wraps the SQLite connection pool.
type DB struct {
	*sql.DB
	Path string
}

// Open opens (creating if needed) the vault database at path and applies
// pending migrations. The parent directory is created with 0700 permissions.
func Open(path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	// Create the file with restrictive permissions before SQLite touches it.
	if f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		f.Close()
	} else {
		return nil, fmt.Errorf("open vault file: %w", err)
	}

	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "secure_delete(1)")
	// BEGIN IMMEDIATE takes the write lock up front, so concurrent CLI and
	// dashboard writers wait on busy_timeout instead of failing mid-transaction.
	q.Set("_txlock", "immediate")
	dsn := "file:" + filepath.ToSlash(abs) + "?" + q.Encode()

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(4)
	db := &DB{DB: sqlDB, Path: abs}
	if err := db.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.migrate(context.Background()); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

// WithTx runs fn inside a transaction, committing on success and rolling
// back on error or panic.
func (db *DB) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		prefix, _, ok := strings.Cut(name, "_")
		if !ok || !strings.HasSuffix(name, ".sql") {
			return nil, fmt.Errorf("invalid migration file name %q", name)
		}
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid migration version in %q", name)
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: name, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// SchemaVersion returns the highest applied migration version.
func (db *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

func (db *DB) migrate(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		err := db.WithTx(ctx, func(tx *sql.Tx) error {
			var exists int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&exists); err != nil {
				return err
			}
			if exists > 0 {
				return nil
			}
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, FormatTime(time.Now()))
			return err
		})
		if err != nil {
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
	}
	return nil
}

// NewID returns a random 128-bit hex identifier.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return hex.EncodeToString(b)
}

// Now returns the current UTC time truncated to milliseconds, matching storage precision.
func Now() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// FormatTime formats t for storage.
func FormatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ParseTime parses a stored timestamp.
func ParseTime(s string) time.Time {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339Nano, s)
	}
	return t
}

// mapErr converts driver errors into package sentinel errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}
