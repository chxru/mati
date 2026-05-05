package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

type HttpServer struct {
	Addr string
}

var ownerConfig ownerAuthConfig

func (s *HttpServer) Start(ctx context.Context) error {
	if s.Addr == "" {
		return errors.New("addr is empty")
	}

	logHandler := &slogContextHandler{Handler: slog.Default().Handler()}
	slog.SetDefault(slog.New(logHandler))

	cfg, err := loadOwnerAuthConfig()
	if err != nil {
		return fmt.Errorf("load owner auth config: %w", err)
	}
	ownerConfig = cfg

	router := http.NewServeMux()
	middlewares := createMiddlewareStack(corsMiddleware, requestIdMiddleware, loggingMiddleware, loadAuthMiddleware)
	initiateEndpoints(router)

	server := http.Server{
		Addr:    s.Addr,
		Handler: middlewares(router),
	}

	slog.InfoContext(ctx, fmt.Sprintf("starting server at %s", s.Addr))

	return server.ListenAndServe()
}
