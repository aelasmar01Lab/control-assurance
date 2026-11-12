// Package testdb gives a test its own migrated database schema.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/aelasmar01Lab/control-assurance/internal/db"
)

// EnvVar names the environment variable holding the test database URL.
const EnvVar = "CCA_TEST_DATABASE_URL"

// New creates an empty schema in the test database, applies every migration
// to it, and returns a URL that connects to that schema. The schema is
// dropped when the test ends. The test is skipped when EnvVar is not set,
// unless CI is set, where a missing database is a failure.
func New(t *testing.T) string {
	t.Helper()
	base := os.Getenv(EnvVar)
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is not set; database tests must run in CI", EnvVar)
		}
		t.Skipf("%s is not set; skipping database test", EnvVar)
	}
	ctx := context.Background()

	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "test_" + hex.EncodeToString(suffix[:])

	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	_ = conn.Close(ctx)
	t.Cleanup(func() {
		conn, err := pgx.Connect(ctx, base)
		if err != nil {
			return
		}
		_, _ = conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		_ = conn.Close(ctx)
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %s: %v", EnvVar, err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scoped := u.String()

	if _, err := db.MigrateUp(ctx, scoped); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return scoped
}
