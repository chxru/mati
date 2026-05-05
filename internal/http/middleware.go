package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

type Middleware func(http.Handler) http.Handler

func createMiddlewareStack(mws ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		// to set the first middleware as the top of stack,
		// we loop in reverse
		for i := len(mws) - 1; i >= 0; i-- {
			middleware := mws[i]
			next = middleware(next)
		}

		return next
	}
}

type ctxKey string

const requestIdKey ctxKey = "requestId"

func requestIdMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqId := r.Header.Get("X-Request-Id")
		if reqId == "" {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				slog.Error("Failed to generate a request id", slog.Any("error", err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			reqId = hex.EncodeToString(b[:])
		}

		ctx := context.WithValue(r.Context(), requestIdKey, reqId)
		w.Header().Set("X-Request-Id", reqId)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type wrappedWriter struct {
	http.ResponseWriter
	statusCode int
}

// [http.ResponseWriter] has a method to write headers but do not
// expose header property to outside like `w.Header.statusCode`
// Therefore, we wrap the WriteHeader method and extract the status code
func (w *wrappedWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
	w.statusCode = statusCode
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &wrappedWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // defaults to ok
		}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		status := wrapped.statusCode

		if status < http.StatusInternalServerError {
			slog.InfoContext(r.Context(), "request",
				slog.Int("statusCode", wrapped.statusCode),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Duration("duration", duration))
		} else {
			slog.ErrorContext(r.Context(), "request",
				slog.Int("statusCode", wrapped.statusCode),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Duration("duration", duration))
		}
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigins := map[string]bool{
			"http://localhost:3000": true,
		}

		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
