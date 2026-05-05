package http

import (
	"context"
	"log/slog"
)

type slogContextHandler struct {
	slog.Handler
}

func (s *slogContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if reqId, ok := ctx.Value(requestIdKey).(string); ok {
		r.AddAttrs(slog.String("request_id", reqId))
	}

	return s.Handler.Handle(ctx, r)
}
