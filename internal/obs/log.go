package obs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// NewLogger собирает журнал по настройкам уровня и формата.
//
// Формат json выбран по умолчанию: логи разбираются машиной, а поля с именами
// типов ПД и счётчиками удобно агрегировать. Значения ПД в журнал не попадают
// ни при каком уровне — их просто нет среди передаваемых полей.
func NewLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "info", "":
		lv = slog.LevelInfo
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("logging.level: неизвестный уровень %q", level)
	}
	opts := &slog.HandlerOptions{Level: lv}

	var h slog.Handler
	switch strings.ToLower(format) {
	case "json", "":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("logging.format: неизвестный формат %q (доступны: json, text)", format)
	}
	return slog.New(h), nil
}

type ctxKey struct{}

// WithLogger кладёт журнал в контекст запроса.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// LoggerFrom достаёт журнал из контекста. При отсутствии возвращается журнал
// по умолчанию, чтобы вызывающий код не проверял nil.
func LoggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}
