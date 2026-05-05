package http

import (
	"encoding/json"
	"fmt"
	"github.com/chxru/mark-time/internal/db"
	"github.com/google/uuid"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type createEntryRequest struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	DeviceName string `json:"device_name"`
	CreatedAt  string `json:"created_at"`
}

func initiateEndpoints(router *http.ServeMux) {
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
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

		database := db.DB()
		if database == nil {
			slog.ErrorContext(r.Context(), "database unavailable for create")
			http.Error(w, "database is not initialized", http.StatusInternalServerError)
			return
		}

		tx, err := database.BeginTx(r.Context(), nil)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to begin create transaction", slog.Any("error", err))
			http.Error(w, "failed to start transaction", http.StatusInternalServerError)
			return
		}

		for _, entry := range payload {
			_, err = tx.ExecContext(
				r.Context(),
				`insert into entries (client_id, name, device_name, created_at) values (?, ?, ?, ?)`,
				entry.ID,
				entry.Name,
				entry.DeviceName,
				entry.CreatedAt,
			)
			if err != nil {
				_ = tx.Rollback()
				if isUniqueConstraintError(err) {
					slog.WarnContext(r.Context(), "duplicate client_id on create", slog.String("client_id", entry.ID), slog.Any("error", err))
					http.Error(w, "client_id must be unique", http.StatusConflict)
					return
				}
				slog.ErrorContext(r.Context(), "failed inserting create entry", slog.String("client_id", entry.ID), slog.Any("error", err))
				http.Error(w, "failed to insert entries", http.StatusInternalServerError)
				return
			}
		}

		if err = tx.Commit(); err != nil {
			slog.ErrorContext(r.Context(), "failed to commit create transaction", slog.Any("error", err))
			http.Error(w, "failed to commit transaction", http.StatusInternalServerError)
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
