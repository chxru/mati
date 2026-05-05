package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/chxru/mark-time/internal/db"
	"github.com/chxru/mark-time/internal/http"
)

func main() {
	ctx := context.Background()

	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, Level: slog.LevelInfo})
	slog.SetDefault(slog.New(logHandler))

	slog.InfoContext(ctx, "initializing database")
	if err := db.Init(ctx); err != nil {
		panic(err)
	}
	defer func() {
		slog.InfoContext(ctx, "closing database")
		if err := db.Close(); err != nil {
			panic(err)
		}
	}()

	server := http.HttpServer{
		Addr: ":8080",
	}

	panic(server.Start(ctx))
}
