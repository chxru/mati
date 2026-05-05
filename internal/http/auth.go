package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chxru/mark-time/internal/db"
	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "mark_time_session"

type ownerAuthConfig struct {
	Username     string
	PasswordHash string
}

type authContextKey string

const authKey authContextKey = "auth"

type authState struct {
	SessionTokenHash string
	HasSession       bool
	HasAccess        bool
}

type apiTokenRow struct {
	ID         int64
	Label      string
	CreatedAt  string
	LastUsedAt sql.NullString
	RevokedAt  sql.NullString
}

func loadOwnerAuthConfig() (ownerAuthConfig, error) {
	username := strings.TrimSpace(os.Getenv("MARK_TIME_OWNER_USERNAME"))
	if username == "" {
		return ownerAuthConfig{}, errors.New("MARK_TIME_OWNER_USERNAME is required")
	}

	passwordHash := strings.TrimSpace(os.Getenv("MARK_TIME_OWNER_PASSWORD_HASH"))
	if passwordHash == "" {
		return ownerAuthConfig{}, errors.New("MARK_TIME_OWNER_PASSWORD_HASH is required")
	}

	if _, err := bcrypt.Cost([]byte(passwordHash)); err != nil {
		return ownerAuthConfig{}, fmt.Errorf("MARK_TIME_OWNER_PASSWORD_HASH is not a valid bcrypt hash: %w", err)
	}

	return ownerAuthConfig{Username: username, PasswordHash: passwordHash}, nil
}

func verifyOwnerCredentials(cfg ownerAuthConfig, username, password string) bool {
	if strings.TrimSpace(username) != cfg.Username {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(password)) == nil
}

func loadAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := authState{}

		if c, err := r.Cookie(sessionCookieName); err == nil {
			hash := tokenHash(c.Value)
			ok, err := isValidSession(r.Context(), hash)
			if err == nil && ok {
				state.SessionTokenHash = hash
				state.HasSession = true
				state.HasAccess = true
			}
		}

		if !state.HasAccess {
			bearer := extractBearerToken(r.Header.Get("Authorization"))
			if bearer != "" {
				hash := tokenHash(bearer)
				ok, err := useValidAPIToken(r.Context(), hash)
				if err == nil && ok {
					state.HasAccess = true
				}
			}
		}

		ctx := context.WithValue(r.Context(), authKey, state)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireSessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := getAuthState(r.Context())
		if !state.HasSession {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func requireAccessAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := getAuthState(r.Context())
		if !state.HasAccess {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getAuthState(ctx context.Context) authState {
	v := ctx.Value(authKey)
	state, ok := v.(authState)
	if !ok {
		return authState{}
	}

	return state
}

func extractBearerToken(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func createSession(ctx context.Context, ttl time.Duration) (string, error) {
	database := db.DB()
	if database == nil {
		return "", errors.New("database is not initialized")
	}

	token, err := newRandomToken()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	_, err = database.ExecContext(
		ctx,
		`insert into sessions (token_hash, created_at, expires_at) values (?, ?, ?)`,
		tokenHash(token),
		now.Format(time.RFC3339),
		expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		return "", err
	}

	return token, nil
}

func deleteSession(ctx context.Context, sessionHash string) error {
	if sessionHash == "" {
		return nil
	}

	database := db.DB()
	if database == nil {
		return errors.New("database is not initialized")
	}

	_, err := database.ExecContext(ctx, `delete from sessions where token_hash = ?`, sessionHash)
	return err
}

func isValidSession(ctx context.Context, sessionHash string) (bool, error) {
	if sessionHash == "" {
		return false, nil
	}

	database := db.DB()
	if database == nil {
		return false, errors.New("database is not initialized")
	}

	var expiresAt string
	err := database.QueryRowContext(ctx, `select expires_at from sessions where token_hash = ?`, sessionHash).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return false, err
	}

	if time.Now().UTC().After(expiry) {
		_, _ = database.ExecContext(ctx, `delete from sessions where token_hash = ?`, sessionHash)
		return false, nil
	}

	return true, nil
}

func createAPIToken(ctx context.Context, label string) (string, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return "", errors.New("label is required")
	}

	database := db.DB()
	if database == nil {
		return "", errors.New("database is not initialized")
	}

	token, err := newRandomToken()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = database.ExecContext(ctx, `insert into api_tokens (label, token_hash, created_at) values (?, ?, ?)`, label, tokenHash(token), now)
	if err != nil {
		return "", err
	}

	return token, nil
}

func revokeAPIToken(ctx context.Context, id int64) error {
	database := db.DB()
	if database == nil {
		return errors.New("database is not initialized")
	}

	_, err := database.ExecContext(ctx, `update api_tokens set revoked_at = ? where id = ?`, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func listAPITokens(ctx context.Context) ([]apiTokenRow, error) {
	database := db.DB()
	if database == nil {
		return nil, errors.New("database is not initialized")
	}

	rows, err := database.QueryContext(ctx, `
		select id, label, created_at, last_used_at, revoked_at
		from api_tokens
		order by created_at desc, id desc
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]apiTokenRow, 0)
	for rows.Next() {
		var row apiTokenRow
		if err := rows.Scan(&row.ID, &row.Label, &row.CreatedAt, &row.LastUsedAt, &row.RevokedAt); err != nil {
			return nil, err
		}
		result = append(result, row)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func useValidAPIToken(ctx context.Context, hash string) (bool, error) {
	if hash == "" {
		return false, nil
	}

	database := db.DB()
	if database == nil {
		return false, errors.New("database is not initialized")
	}

	var id int64
	err := database.QueryRowContext(ctx, `
		select id
		from api_tokens
		where token_hash = ? and revoked_at is null
	`, hash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	_, _ = database.ExecContext(ctx, `update api_tokens set last_used_at = ? where id = ?`, time.Now().UTC().Format(time.RFC3339), id)
	return true, nil
}
