package http

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chxru/mati/internal/db"
	"github.com/google/uuid"
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

type syncRequest struct {
	LastPulledServerID int64                `json:"last_pulled_server_id"`
	Entries            []createEntryRequest `json:"entries"`
}

type syncEntryResponse struct {
	ServerID   int64  `json:"server_id"`
	ClientID   string `json:"client_id"`
	Name       string `json:"name"`
	DeviceName string `json:"device_name"`
	CreatedAt  string `json:"created_at"`
}

type syncResponse struct {
	Entries      []syncEntryResponse `json:"entries"`
	NextServerID int64               `json:"next_server_id"`
}

type pageData struct {
	Entries        []entryRow
	APITokens      []apiTokenRow
	CreatedToken   string
	CreatedServer  string
	CreatedConnect string
}

var pageTemplates = template.Must(template.ParseFiles(
	filepath.Join("web", "templates", "index.html"),
	filepath.Join("web", "templates", "marks_list.html"),
	filepath.Join("web", "templates", "login.html"),
	filepath.Join("web", "templates", "token.html"),
))

func initiateEndpoints(router *http.ServeMux) {
	router.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join("web", "static")))))

	router.Handle("/", requireSessionAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})))

	router.Handle("/token", requireSessionAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tokens, err := listAPITokens(r.Context())
		if err != nil {
			slog.ErrorContext(r.Context(), "failed loading api tokens", slog.Any("error", err))
			http.Error(w, "failed to load tokens", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pageTemplates.ExecuteTemplate(w, "token.html", pageData{APITokens: tokens}); err != nil {
			http.Error(w, "failed to render token page", http.StatusInternalServerError)
		}
	})))

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := pageTemplates.ExecuteTemplate(w, "login.html", nil); err != nil {
				http.Error(w, "failed to render login", http.StatusInternalServerError)
			}
		case http.MethodPost:
			username := strings.TrimSpace(r.FormValue("username"))
			password := r.FormValue("password")
			if !verifyOwnerCredentials(ownerConfig, username, password) {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
				return
			}

			token, err := createSession(r.Context(), 30*24*time.Hour)
			if err != nil {
				slog.ErrorContext(r.Context(), "failed creating session", slog.Any("error", err))
				http.Error(w, "failed to login", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Secure:   r.TLS != nil,
				MaxAge:   int((30 * 24 * time.Hour).Seconds()),
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	router.Handle("/logout", requireSessionAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		state := getAuthState(r.Context())
		if err := deleteSession(r.Context(), state.SessionTokenHash); err != nil {
			slog.ErrorContext(r.Context(), "failed deleting session", slog.Any("error", err))
		}

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
			MaxAge:   -1,
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})))

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	router.Handle("/auth/validate", requireAccessAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})))

	router.Handle("/entries", requireAccessAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})))

	router.Handle("/tokens", requireSessionAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		label := strings.TrimSpace(r.FormValue("label"))
		if label == "" {
			http.Error(w, "label is required", http.StatusBadRequest)
			return
		}

		token, err := createAPIToken(r.Context(), label)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed creating api token", slog.Any("error", err))
			http.Error(w, "failed creating token", http.StatusInternalServerError)
			return
		}

		serverURL := requestServerURL(r)
		connectString := buildCLIConnectString(serverURL, token)

		tokens, err := listAPITokens(r.Context())
		if err != nil {
			http.Error(w, "failed to load tokens", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pageTemplates.ExecuteTemplate(w, "token.html", pageData{APITokens: tokens, CreatedToken: token, CreatedServer: serverURL, CreatedConnect: connectString}); err != nil {
			http.Error(w, "failed to render page", http.StatusInternalServerError)
		}
	})))

	router.Handle("/tokens/revoke", requireSessionAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		idStr := strings.TrimSpace(r.FormValue("id"))
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			http.Error(w, "invalid token id", http.StatusBadRequest)
			return
		}

		if err := revokeAPIToken(r.Context(), id); err != nil {
			http.Error(w, "failed to revoke token", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/token", http.StatusSeeOther)
	})))

	router.Handle("/create", requireAccessAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})))

	router.Handle("/sync", requireAccessAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload syncRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid json payload", http.StatusBadRequest)
			return
		}

		if payload.LastPulledServerID < 0 {
			http.Error(w, "last_pulled_server_id must be >= 0", http.StatusBadRequest)
			return
		}

		for idx, entry := range payload.Entries {
			if _, err := uuid.Parse(entry.ID); err != nil {
				http.Error(w, fmt.Sprintf("entries[%d].id must be a valid uuid", idx), http.StatusBadRequest)
				return
			}

			if strings.TrimSpace(entry.Name) == "" {
				http.Error(w, fmt.Sprintf("entries[%d].name is required", idx), http.StatusBadRequest)
				return
			}

			if strings.TrimSpace(entry.DeviceName) == "" {
				http.Error(w, fmt.Sprintf("entries[%d].device_name is required", idx), http.StatusBadRequest)
				return
			}

			if _, err := time.Parse(time.RFC3339, entry.CreatedAt); err != nil {
				http.Error(w, fmt.Sprintf("entries[%d].created_at must be RFC3339", idx), http.StatusBadRequest)
				return
			}
		}

		rowsToInsert := make([]entryRow, 0, len(payload.Entries))
		for _, entry := range payload.Entries {
			rowsToInsert = append(rowsToInsert, entryRow{ClientID: entry.ID, Name: entry.Name, DeviceName: entry.DeviceName, CreatedAt: entry.CreatedAt})
		}

		if err := insertEntriesIgnoreDuplicates(r.Context(), rowsToInsert); err != nil {
			http.Error(w, "failed to insert entries", http.StatusInternalServerError)
			return
		}

		entries, nextServerID, err := listEntriesAfterServerID(r.Context(), payload.LastPulledServerID)
		if err != nil {
			http.Error(w, "failed to load sync entries", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(syncResponse{Entries: entries, NextServerID: nextServerID}); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})))
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

func insertEntriesIgnoreDuplicates(ctx context.Context, entries []entryRow) error {
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
			`insert into entries (client_id, name, device_name, created_at) values (?, ?, ?, ?) on conflict(client_id) do nothing`,
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

func listEntriesAfterServerID(ctx context.Context, lastPulledServerID int64) ([]syncEntryResponse, int64, error) {
	database := db.DB()
	if database == nil {
		return nil, 0, fmt.Errorf("database is not initialized")
	}

	rows, err := database.QueryContext(ctx, `
		select server_id, client_id, name, device_name, created_at
		from entries
		where server_id > ?
		order by server_id asc
	`, lastPulledServerID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries := make([]syncEntryResponse, 0)
	nextServerID := lastPulledServerID
	for rows.Next() {
		var entry syncEntryResponse
		if err := rows.Scan(&entry.ServerID, &entry.ClientID, &entry.Name, &entry.DeviceName, &entry.CreatedAt); err != nil {
			return nil, 0, err
		}
		if entry.ServerID > nextServerID {
			nextServerID = entry.ServerID
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return entries, nextServerID, nil
}

func requestServerURL(r *http.Request) string {
	scheme := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}

	host := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0])
	if host == "" {
		host = r.Host
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func buildCLIConnectString(serverURL, token string) string {
	return fmt.Sprintf("marktime://auth?server=%s&token=%s", url.QueryEscape(serverURL), url.QueryEscape(token))
}
