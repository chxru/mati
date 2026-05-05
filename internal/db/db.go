package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func Init(ctx context.Context) error {
	if db != nil {
		slog.DebugContext(ctx, "database already initialized")
		return nil
	}

	dbPath, err := resolveDBPath()
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	slog.DebugContext(ctx, "resolved database path", slog.String("path", dbPath))

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite db: %w", err)
	}
	slog.DebugContext(ctx, "opened sqlite connection")

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return fmt.Errorf("ping sqlite db: %w", err)
	}
	slog.InfoContext(ctx, "sqlite connection ping succeeded")

	if err := runMigrations(ctx, conn); err != nil {
		_ = conn.Close()
		return fmt.Errorf("run migrations: %w", err)
	}

	db = conn
	return nil
}

func DB() *sql.DB {
	return db
}

func Close() error {
	if db == nil {
		return nil
	}

	slog.Info("closing database connection")
	err := db.Close()
	db = nil
	if err == nil {
		slog.Info("database connection closed")
	}
	return err
}

func resolveDBPath() (string, error) {
	if envPath := os.Getenv("MARK_TIME_DB_PATH"); envPath != "" {
		envPath = strings.TrimSpace(envPath)
		if envPath == "" {
			return "", errors.New("MARK_TIME_DB_PATH is empty")
		}

		resolved := filepath.Clean(envPath)
		if err := validateDBFilePath(resolved); err != nil {
			return "", err
		}

		if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
			return "", err
		}

		return resolved, nil
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	defaultPath := filepath.Join(configDir, "mark-time", "db.sqlite")
	if err := os.MkdirAll(filepath.Dir(defaultPath), 0o755); err != nil {
		return "", err
	}

	return defaultPath, nil
}

func validateDBFilePath(dbPath string) error {
	fileInfo, err := os.Stat(dbPath)
	if err == nil && fileInfo.IsDir() {
		return fmt.Errorf("db path points to a directory: %s", dbPath)
	}

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}
