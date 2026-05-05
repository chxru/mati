package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

type migration struct {
	ID   int
	Name string
	SQL  string
}

var migrations = []migration{
	{
		ID:   1,
		Name: "create_entries_table",
		SQL: `
create table entries (
	client_id text not null unique,
	server_id integer primary key autoincrement,
	name text not null,
	device_name text not null,
	created_at text not null
)
`,
	},
	{
		ID:   2,
		Name: "create_sessions_table",
		SQL: `
create table sessions (
	token_hash text not null unique,
	created_at text not null,
	expires_at text not null
)
`,
	},
	{
		ID:   3,
		Name: "create_api_tokens_table",
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
}

func runMigrations(ctx context.Context, db *sql.DB) error {
	slog.InfoContext(ctx, "starting database migrations")

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
	applied_at text not null default current_timestamp
)
`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	var lastAppliedID int
	if err = tx.QueryRowContext(ctx, `select coalesce(max(id), 0) from schema_migrations`).Scan(&lastAppliedID); err != nil {
		return fmt.Errorf("query last migration id: %w", err)
	}
	slog.InfoContext(ctx, "loaded last applied migration", slog.Int("last_id", lastAppliedID))

	appliedCount := 0

	for _, migration := range migrations {
		if migration.ID <= lastAppliedID {
			continue
		}

		slog.InfoContext(ctx, "applying migration", slog.Int("id", migration.ID), slog.String("name", migration.Name))

		if _, err = tx.ExecContext(ctx, migration.SQL); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", migration.ID, migration.Name, err)
		}

		if _, err = tx.ExecContext(ctx, `insert into schema_migrations (id, name) values (?, ?)`, migration.ID, migration.Name); err != nil {
			return fmt.Errorf("record migration %d (%s): %w", migration.ID, migration.Name, err)
		}

		appliedCount++
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations transaction: %w", err)
	}

	slog.InfoContext(ctx, "database migrations finished", slog.Int("applied", appliedCount), slog.Int("total", len(migrations)))

	return nil
}
