package http

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/chxru/mark-time/internal/db"
	"github.com/google/uuid"
	"html/template"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

type entryRow struct {
	ClientID   string
	Name       string
	DeviceName string
	CreatedAt  string
}

type createEntryRequest struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	DeviceName string `json:"device_name"`
	CreatedAt  string `json:"created_at"`
}

type pageData struct {
	Entries []entryRow
}

var pageTemplates = template.Must(template.ParseFiles(
	filepath.Join("web", "templates", "index.html"),
	filepath.Join("web", "templates", "marks_list.html"),
))

func initiateEndpoints(router *http.ServeMux) {
	router.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join("web", "static")))))

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		slog.InfoContext(r.Context(), "rendering index page")

		entries, err := listEntries(r.Context())
		if err != nil {
			slog.ErrorContext(r.Context(), "failed loading entries for index", slog.Any("error", err))
			http.Error(w, "failed to load entries", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pageTemplates.ExecuteTemplate(w, "index.html", pageData{Entries: entries}); err != nil {
			slog.ErrorContext(r.Context(), "failed rendering index template", slog.Any("error", err))
			http.Error(w, "failed to render page", http.StatusInternalServerError)
			return
		}
	})

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	router.HandleFunc("/entries", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}

		newEntry := entryRow{
			ClientID:   uuid.NewString(),
			Name:       name,
			DeviceName: "browser",
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		}

		if err := insertEntries(r.Context(), []entryRow{newEntry}); err != nil {
			slog.ErrorContext(r.Context(), "failed creating entry from web form", slog.Any("error", err))
			http.Error(w, "failed to create entry", http.StatusInternalServerError)
			return
		}

		entries, err := listEntries(r.Context())
		if err != nil {
			slog.ErrorContext(r.Context(), "failed loading entries after create", slog.Any("error", err))
			http.Error(w, "failed to load entries", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pageTemplates.ExecuteTemplate(w, "marks_list", pageData{Entries: entries}); err != nil {
			slog.ErrorContext(r.Context(), "failed rendering marks list", slog.Any("error", err))
			http.Error(w, "failed to render entries", http.StatusInternalServerError)
			return
		}
	})

	router.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "received create request", slog.String("method", r.Method), slog.String("path", r.URL.Path))

		if r.Method != http.MethodPost {
			slog.WarnContext(r.Context(), "method not allowed for create", slog.String("method", r.Method))
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload []createEntryRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			slog.WarnContext(r.Context(), "invalid create payload json", slog.Any("error", err))
			http.Error(w, "invalid json payload", http.StatusBadRequest)
			return
		}

		if len(payload) == 0 {
			slog.WarnContext(r.Context(), "empty create payload")
			http.Error(w, "payload must contain at least one entry", http.StatusBadRequest)
			return
		}

		for idx, entry := range payload {
			if _, err := uuid.Parse(entry.ID); err != nil {
				slog.WarnContext(r.Context(), "invalid uuid in create payload", slog.Int("index", idx), slog.String("id", entry.ID))
				http.Error(w, "id must be a valid uuid", http.StatusBadRequest)
				return
			}

			if strings.TrimSpace(entry.Name) == "" {
				slog.WarnContext(r.Context(), "missing name in create payload", slog.Int("index", idx))
				http.Error(w, "name is required", http.StatusBadRequest)
				return
			}

			if strings.TrimSpace(entry.DeviceName) == "" {
				slog.WarnContext(r.Context(), "missing device_name in create payload", slog.Int("index", idx))
				http.Error(w, "device_name is required", http.StatusBadRequest)
				return
			}

			if _, err := time.Parse(time.RFC3339, entry.CreatedAt); err != nil {
				slog.WarnContext(r.Context(), "invalid created_at in create payload", slog.Int("index", idx), slog.String("created_at", entry.CreatedAt))
				http.Error(w, "created_at must be a valid RFC3339 timestamp", http.StatusBadRequest)
				return
			}
		}

		slog.InfoContext(r.Context(), "validated create payload", slog.Int("entries", len(payload)))

		entriesToInsert := make([]entryRow, 0, len(payload))
		for _, entry := range payload {
			entriesToInsert = append(entriesToInsert, entryRow{
				ClientID:   entry.ID,
				Name:       entry.Name,
				DeviceName: entry.DeviceName,
				CreatedAt:  entry.CreatedAt,
			})
		}

		if err := insertEntries(r.Context(), entriesToInsert); err != nil {
			if isUniqueConstraintError(err) {
				slog.WarnContext(r.Context(), "duplicate client_id on create", slog.Any("error", err))
				http.Error(w, "client_id must be unique", http.StatusConflict)
				return
			}

			slog.ErrorContext(r.Context(), "failed inserting create entries", slog.Any("error", err))
			http.Error(w, "failed to insert entries", http.StatusInternalServerError)
			return
		}

		slog.InfoContext(r.Context(), "create entries succeeded", slog.Int("inserted", len(payload)))
		w.WriteHeader(http.StatusCreated)
	})
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(strings.ToLower(err.Error()), "unique")
}

func insertEntries(ctx context.Context, entries []entryRow) error {
	database := db.DB()
	if database == nil {
		return fmt.Errorf("database is not initialized")
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	for _, entry := range entries {
		_, err = tx.ExecContext(
			ctx,
			`insert into entries (client_id, name, device_name, created_at) values (?, ?, ?, ?)`,
			entry.ClientID,
			entry.Name,
			entry.DeviceName,
			entry.CreatedAt,
		)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func listEntries(ctx context.Context) ([]entryRow, error) {
	database := db.DB()
	if database == nil {
		return nil, fmt.Errorf("database is not initialized")
	}

	rows, err := database.QueryContext(ctx, `
		select client_id, name, device_name, created_at
		from entries
		order by created_at desc, server_id desc
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]entryRow, 0)
	for rows.Next() {
		var entry entryRow
		if err := rows.Scan(&entry.ClientID, &entry.Name, &entry.DeviceName, &entry.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}
