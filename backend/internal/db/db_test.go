package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"
)

// testPool creates a database private to this test and returns a pool for it.
//
// This package cannot use internal/dbtest: that helper runs migrations itself,
// and these tests need to observe an unmigrated database. It creates and drops
// its own instead.
func testPool(t *testing.T) *Pool {
	t.Helper()

	adminURL := os.Getenv("SKM_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("SKM_TEST_DATABASE_URL not set; skipping database integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating a database name: %v", err)
	}
	name := "skm_dbtest_" + hex.EncodeToString(buf)

	admin, err := Connect(ctx, Options{URL: adminURL, MaxConns: 2, MinConns: 1})
	if err != nil {
		t.Skipf("cannot reach the test PostgreSQL server: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		admin.Close()
		t.Fatalf("creating test database: %v", err)
	}
	admin.Close()

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("parsing SKM_TEST_DATABASE_URL: %v", err)
	}
	u.Path = "/" + name

	pool, err := Connect(ctx, Options{URL: u.String(), MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Fatalf("connecting to test database: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if admin, err := Connect(cleanupCtx, Options{URL: adminURL, MaxConns: 2, MinConns: 1}); err == nil {
			defer admin.Close()
			_, _ = admin.Exec(cleanupCtx, `DROP DATABASE IF EXISTS "`+name+`"`)
		}
	})

	return pool
}

// resetSchema drops everything so a test can observe migration from empty.
func resetSchema(t *testing.T, pool *Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("resetting schema: %v", err)
	}
}

func TestMigrateAppliesSchema(t *testing.T) {
	pool := testPool(t)
	resetSchema(t, pool)
	ctx := context.Background()

	if err := Migrate(ctx, pool, nil); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var tables int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables); err != nil {
		t.Fatalf("counting tables: %v", err)
	}
	// 28 schema tables plus schema_migrations.
	if tables < 29 {
		t.Errorf("got %d tables after migration, want at least 29", tables)
	}

	// The default tenant must exist; the single-tenant path depends on it.
	var tenants int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&tenants); err != nil {
		t.Fatalf("counting tenants: %v", err)
	}
	if tenants != 1 {
		t.Errorf("got %d tenants, want 1", tenants)
	}
}

// Migrate runs on every boot, so running it twice must be a no-op rather than
// an error about duplicate objects.
func TestMigrateIsIdempotent(t *testing.T) {
	pool := testPool(t)
	resetSchema(t, pool)
	ctx := context.Background()

	if err := Migrate(ctx, pool, nil); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := Migrate(ctx, pool, nil); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatalf("counting migrations: %v", err)
	}
	if want := len(mustLoad(t)); applied != want {
		t.Errorf("schema_migrations has %d rows, want %d", applied, want)
	}
}

// The audit trail is only meaningful if the database itself refuses to rewrite
// it, so that guarantee is asserted rather than assumed.
func TestAuditEventsAreAppendOnly(t *testing.T) {
	pool := testPool(t)
	resetSchema(t, pool)
	ctx := context.Background()

	if err := Migrate(ctx, pool, nil); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const tenant = "00000000-0000-0000-0000-000000000001"
	var seq int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO audit_events (tenant_id, action, hash) VALUES ($1,'test.event','h0') RETURNING seq`,
		tenant).Scan(&seq); err != nil {
		t.Fatalf("inserting audit event: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE audit_events SET action='tampered' WHERE seq=$1`, seq); err == nil {
		t.Error("UPDATE on audit_events succeeded; the append-only trigger is not protecting the table")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE seq=$1`, seq); err == nil {
		t.Error("DELETE on audit_events succeeded; the append-only trigger is not protecting the table")
	}

	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&remaining); err != nil {
		t.Fatalf("counting audit events: %v", err)
	}
	if remaining != 1 {
		t.Errorf("audit_events has %d rows after tamper attempts, want 1", remaining)
	}
}

func TestLoadMigrationsIsOrderedAndWellFormed(t *testing.T) {
	ms := mustLoad(t)
	if len(ms) == 0 {
		t.Fatal("no migrations were embedded")
	}
	for i, m := range ms {
		if m.version < 1 {
			t.Errorf("migration %d has version %d, want >= 1", i, m.version)
		}
		if m.name == "" {
			t.Errorf("migration %d has an empty name", i)
		}
		if m.sql == "" {
			t.Errorf("migration %d (%s) is empty", m.version, m.name)
		}
		if i > 0 && ms[i-1].version >= m.version {
			t.Errorf("migrations out of order: %d then %d", ms[i-1].version, m.version)
		}
	}
}

func TestParseMigrationName(t *testing.T) {
	tests := []struct {
		filename    string
		wantVersion int
		wantName    string
		wantErr     bool
	}{
		{"0001_initial_schema.sql", 1, "initial_schema", false},
		{"0042_add_widgets.sql", 42, "add_widgets", false},
		{"12_x.sql", 12, "x", false},
		{"noversion.sql", 0, "", true},
		{"abc_thing.sql", 0, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.filename, func(t *testing.T) {
			version, name, err := parseMigrationName(tc.filename)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMigrationName(%q) succeeded, want an error", tc.filename)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMigrationName(%q): %v", tc.filename, err)
			}
			if version != tc.wantVersion || name != tc.wantName {
				t.Errorf("got (%d, %q), want (%d, %q)", version, name, tc.wantVersion, tc.wantName)
			}
		})
	}
}

func mustLoad(t *testing.T) []migration {
	t.Helper()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	return ms
}
