// Package dbtest provides isolated PostgreSQL databases for integration tests.
//
// Go runs different test packages in parallel. Sharing one database between
// them means one package's schema reset races another package's queries, which
// surfaces as deadlocks and "relation does not exist" errors that look like
// product bugs but are not. Each caller gets its own freshly created,
// fully migrated database instead, and it is dropped when the test finishes.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
)

// EnvVar names the connection string pointing at a PostgreSQL server the tests
// may create and drop databases on.
const EnvVar = "SKM_TEST_DATABASE_URL"

// New returns a pool connected to a brand-new migrated database.
//
// The test is skipped when EnvVar is unset, so `go test ./...` still works on a
// machine without Docker.
func New(t *testing.T) *db.Pool {
	t.Helper()
	pool, _ := NewWithURL(t)
	return pool
}

// NewWithURL is New, additionally returning the connection URL — needed by
// tests that start a second component against the same database.
func NewWithURL(t *testing.T) (*db.Pool, string) {
	t.Helper()

	adminURL := envOrSkip(t)
	name := "skm_test_" + randomSuffix(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := db.Connect(ctx, db.Options{URL: adminURL, MaxConns: 2, MinConns: 1})
	if err != nil {
		t.Skipf("cannot reach the test PostgreSQL server: %v", err)
	}

	// Identifiers cannot be parameterised, so the name is generated here rather
	// than taken from input; it is hex and a fixed prefix by construction.
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		admin.Close()
		t.Fatalf("creating test database %s: %v", name, err)
	}
	admin.Close()

	testURL := withDatabase(t, adminURL, name)

	pool, err := db.Connect(ctx, db.Options{URL: testURL, MaxConns: 8, MinConns: 1})
	if err != nil {
		dropDatabase(adminURL, name)
		t.Fatalf("connecting to test database %s: %v", name, err)
	}

	if err := db.Migrate(ctx, pool, nil); err != nil {
		pool.Close()
		dropDatabase(adminURL, name)
		t.Fatalf("migrating test database %s: %v", name, err)
	}

	t.Cleanup(func() {
		pool.Close()
		dropDatabase(adminURL, name)
	})

	return pool, testURL
}

// dropDatabase removes a test database, terminating any lingering connections
// first so the drop cannot fail on a connection the pool has not yet released.
func dropDatabase(adminURL, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	admin, err := db.Connect(ctx, db.Options{URL: adminURL, MaxConns: 2, MinConns: 1})
	if err != nil {
		return
	}
	defer admin.Close()

	_, _ = admin.Exec(ctx,
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
		name)
	_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name))
}

func envOrSkip(t *testing.T) string {
	t.Helper()

	url := getenv(EnvVar)
	if url == "" {
		t.Skipf("%s not set; skipping database integration test", EnvVar)
	}
	return url
}

// withDatabase rewrites a connection URL to point at a different database.
func withDatabase(t *testing.T, raw, name string) string {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", EnvVar, err)
	}
	u.Path = "/" + name
	return u.String()
}

func randomSuffix(t *testing.T) string {
	t.Helper()

	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating a database name: %v", err)
	}
	return hex.EncodeToString(buf)
}

// quoteIdent renders a SQL identifier safely.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
