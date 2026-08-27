// Package db owns the PostgreSQL connection pool and schema migrations.
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Pool is the application's database handle.
type Pool = pgxpool.Pool

// Options configures a connection pool.
type Options struct {
	URL          string
	MaxConns     int32
	MinConns     int32
	ConnLifetime time.Duration
}

// Connect opens a pool and verifies it can actually reach the database, so a
// misconfigured URL fails at startup rather than on the first request.
func Connect(ctx context.Context, opts Options) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("db: parsing connection URL: %w", err)
	}

	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	}
	if opts.ConnLifetime > 0 {
		cfg.MaxConnLifetime = opts.ConnLifetime
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: creating pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: connecting: %w", err)
	}

	return pool, nil
}

// migration is one numbered SQL file.
type migration struct {
	version int
	name    string
	sql     string
}

// Migrate applies every migration that has not yet been recorded.
//
// Each migration runs inside its own transaction together with the row that
// records it, so a failure leaves the schema exactly where it started rather
// than half-applied.
func Migrate(ctx context.Context, pool *Pool, log *slog.Logger) error {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INT PRIMARY KEY,
			name        TEXT NOT NULL,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("db: creating schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	var ran int
	for _, m := range migrations {
		if applied[m.version] {
			continue
		}

		start := time.Now()
		if err := applyOne(ctx, pool, m); err != nil {
			return err
		}
		ran++

		if log != nil {
			log.Info("applied migration",
				"version", m.version,
				"name", m.name,
				"duration", time.Since(start).Round(time.Millisecond))
		}
	}

	if log != nil && ran == 0 {
		log.Debug("schema up to date", "version", maxVersion(migrations))
	}
	return nil
}

func applyOne(ctx context.Context, pool *Pool, m migration) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: beginning migration %d: %w", m.version, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx, m.sql); err != nil {
		return fmt.Errorf("db: applying migration %d (%s): %w", m.version, m.name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`,
		m.version, m.name); err != nil {
		return fmt.Errorf("db: recording migration %d: %w", m.version, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: committing migration %d: %w", m.version, err)
	}
	return nil
}

func appliedVersions(ctx context.Context, pool *Pool) (map[int]bool, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("db: reading applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("db: scanning migration version: %w", err)
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// loadMigrations reads and orders the embedded migration files. Filenames must
// be "<version>_<name>.sql", e.g. "0001_initial_schema.sql".
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("db: reading migrations directory: %w", err)
	}

	out := make([]migration, 0, len(entries))
	seen := make(map[int]string)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}

		version, name, err := parseMigrationName(e.Name())
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("db: duplicate migration version %d (%s and %s)", version, prev, e.Name())
		}
		seen[version] = e.Name()

		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("db: reading %s: %w", e.Name(), err)
		}

		out = append(out, migration{version: version, name: name, sql: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

func parseMigrationName(filename string) (int, string, error) {
	base := strings.TrimSuffix(filename, ".sql")
	prefix, name, found := strings.Cut(base, "_")
	if !found {
		return 0, "", fmt.Errorf("db: migration %q must be named <version>_<name>.sql", filename)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, "", fmt.Errorf("db: migration %q has a non-numeric version prefix", filename)
	}
	return version, name, nil
}

func maxVersion(ms []migration) int {
	if len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].version
}
