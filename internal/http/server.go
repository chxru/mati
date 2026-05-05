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

func (s *HttpServer) Start(ctx context.Context) error {
	if s.Addr == "" {
		return errors.New("addr is empty")
	}

	logHandler := &slogContextHandler{Handler: slog.Default().Handler()}
	slog.SetDefault(slog.New(logHandler))

	router := http.NewServeMux()
	middlewares := createMiddlewareStack(corsMiddleware, requestIdMiddleware, loggingMiddleware)
	initiateEndpoints(router)

	server := http.Server{
		Addr:    s.Addr,
		Handler: middlewares(router),
	}

	slog.InfoContext(ctx, fmt.Sprintf("starting server at %s", s.Addr))

	return server.ListenAndServe()
}
