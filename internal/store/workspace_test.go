package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/aelasmar01Lab/control-assurance/internal/testdb"
)

// Every table that holds what the organization collected or decided carries
// a workspace. Frameworks, check versions, accounts and the list of
// workspaces itself are shared.
func TestEveryOrganizationTableHasAWorkspace(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testdb.New(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	shared := map[string]bool{
		"workspaces": true, "framework_versions": true, "requirements": true, "check_versions": true,
		"users": true, "sessions": true, "goose_db_version": true, "control_revisions": true,
	}
	rows, err := conn.Query(ctx, `
		SELECT t.table_name, EXISTS (
			SELECT 1 FROM information_schema.columns c
			WHERE c.table_schema = t.table_schema AND c.table_name = t.table_name AND c.column_name = 'workspace_id')
		FROM information_schema.tables t
		WHERE t.table_schema = current_schema() AND t.table_type = 'BASE TABLE'
		ORDER BY t.table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name string
		var has bool
		if err := rows.Scan(&name, &has); err != nil {
			t.Fatal(err)
		}
		seen++
		if has == shared[name] {
			t.Errorf("table %s: workspace_id present = %v, but shared = %v", name, has, shared[name])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen < 15 {
		t.Fatalf("only %d tables found", seen)
	}
}

// The same external resource can be tracked in two workspaces, and only
// once in each.
func TestResourceIsUniquePerWorkspace(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testdb.New(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var second int64
	if err := conn.QueryRow(ctx,
		`INSERT INTO workspaces (key, name) VALUES ('unit-b', 'Unit B') RETURNING id`).Scan(&second); err != nil {
		t.Fatal(err)
	}
	const insert = `INSERT INTO resources (workspace_id, provider, kind, external_id, scope, decided_by)
		VALUES ($1, 'github', 'repository', 'org/repo', 'in_scope', 'test')`
	if _, err := conn.Exec(ctx, insert, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, insert, second); err != nil {
		t.Fatalf("the same resource in a second workspace was refused: %v", err)
	}
	if _, err := conn.Exec(ctx, insert, second); err == nil {
		t.Fatal("the same resource was accepted twice in one workspace")
	}
}
