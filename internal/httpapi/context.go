package httpapi

import "context"

type ridKey struct{}

func withRequestID(ctx context.Context, rid string) context.Context {
	return context.WithValue(ctx, ridKey{}, rid)
}

// requestID возвращает идентификатор запроса из контекста.
func requestID(ctx context.Context) string {
	if v, ok := ctx.Value(ridKey{}).(string); ok {
		return v
	}
	return ""
}
