package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

type migrationScope string

const (
	migrationScopeBoth   migrationScope = "both"
	migrationScopeServer migrationScope = "server"
	migrationScopeCLI    migrationScope = "cli"
)

type migration struct {
	ID    int
	Name  string
	Scope migrationScope
	SQL   string
}

var migrations = []migration{
	{
		ID:    1,
		Name:  "create_server_entries_table",
		Scope: migrationScopeServer,
		SQL: `
create table entries (
	server_id integer primary key autoincrement,
	client_id text not null unique,
	name text not null,
	device_name text not null,
	created_at text not null
)
`,
	},
	{
		ID:    2,
		Name:  "create_sessions_table",
		Scope: migrationScopeServer,
		SQL: `
create table sessions (
	token_hash text not null unique,
	created_at text not null,
	expires_at text not null
)
`,
	},
	{
		ID:    3,
		Name:  "create_api_tokens_table",
		Scope: migrationScopeServer,
		SQL: `
create table api_tokens (
	id integer primary key autoincrement,
	label text not null,
	token_hash text not null unique,
	created_at text not null,
	last_used_at text,
	revoked_at text
)
`,
	},
	{
		ID:    4,
		Name:  "create_cli_entries_table",
		Scope: migrationScopeCLI,
		SQL: `
create table entries (
	local_id integer primary key autoincrement,
	client_id text not null unique,
	server_id integer unique,
	name text not null,
	device_name text not null,
	created_at text not null,
	needs_push integer not null default 1
)
`,
	},
	{
		ID:    5,
		Name:  "create_cli_sync_state_table",
		Scope: migrationScopeCLI,
		SQL: `
create table sync_state (
	id integer primary key check (id = 1),
	last_pushed_local_id integer not null default 0,
	last_pulled_server_id integer not null default 0
);

insert into sync_state (id, last_pushed_local_id, last_pulled_server_id)
values (1, 0, 0);
`,
	},
}

func runMigrations(ctx context.Context, db *sql.DB, target Target) error {
	slog.InfoContext(ctx, "starting database migrations", slog.String("target", string(target)))

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, `
create table if not exists schema_migrations (
	id integer primary key,
	name text not null,
	scope text not null,
	applied_at text not null default current_timestamp
)
`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	appliedCount := 0

	for _, migration := range migrations {
		if !shouldRunMigration(migration.Scope, target) {
			continue
		}

		applied, checkErr := isMigrationApplied(ctx, tx, migration.ID)
		if checkErr != nil {
			return checkErr
		}
		if applied {
			continue
		}

		slog.InfoContext(ctx, "applying migration", slog.Int("id", migration.ID), slog.String("name", migration.Name), slog.String("scope", string(migration.Scope)))

		if _, err = tx.ExecContext(ctx, migration.SQL); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", migration.ID, migration.Name, err)
		}

		if _, err = tx.ExecContext(ctx, `insert into schema_migrations (id, name, scope) values (?, ?, ?)`, migration.ID, migration.Name, migration.Scope); err != nil {
			return fmt.Errorf("record migration %d (%s): %w", migration.ID, migration.Name, err)
		}

		appliedCount++
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations transaction: %w", err)
	}

	slog.InfoContext(ctx, "database migrations finished", slog.Int("applied", appliedCount), slog.Int("total", len(migrations)), slog.String("target", string(target)))

	return nil
}

func shouldRunMigration(scope migrationScope, target Target) bool {
	if scope == migrationScopeBoth {
		return true
	}

	return string(scope) == string(target)
}

func isMigrationApplied(ctx context.Context, tx *sql.Tx, id int) (bool, error) {
	var exists int
	if err := tx.QueryRowContext(ctx, `select 1 from schema_migrations where id = ? limit 1`, id).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}

		return false, fmt.Errorf("query migration %d: %w", id, err)
	}

	return true, nil
}
