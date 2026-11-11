// Package db holds database access shared by the application's commands.
package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"

	"github.com/aelasmar01Lab/control-assurance/migrations"
)

// MigrationStatus describes one migration file and whether it has been applied.
type MigrationStatus struct {
	Version int64
	Source  string
	Applied bool
}

func provider(databaseURL string) (*goose.Provider, *sql.DB, error) {
	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, conn, migrations.FS)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("load migrations: %w", err)
	}
	return p, conn, nil
}

// MigrateUp applies every pending migration and returns the versions applied.
func MigrateUp(ctx context.Context, databaseURL string) ([]int64, error) {
	p, conn, err := provider(databaseURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	results, err := p.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	applied := make([]int64, 0, len(results))
	for _, r := range results {
		applied = append(applied, r.Source.Version)
	}
	return applied, nil
}

// MigrateStatus reports every known migration and whether it is applied.
func MigrateStatus(ctx context.Context, databaseURL string) ([]MigrationStatus, error) {
	p, conn, err := provider(databaseURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	statuses, err := p.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("read migration status: %w", err)
	}
	out := make([]MigrationStatus, 0, len(statuses))
	for _, s := range statuses {
		out = append(out, MigrationStatus{
			Version: s.Source.Version,
			Source:  s.Source.Path,
			Applied: s.State == goose.StateApplied,
		})
	}
	return out, nil
}
