package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"ai-gateway/internal/obs"
)

// Аудит отказов доступа (P4-9 раунда 4 жюри).
//
// Отказ 401 и 403 — событие безопасности, а не ошибка формата: раньше он не
// попадал в журнал вовсе, а в метриках смешивался с bad_request. Теперь каждый
// отказ пишется строкой журнала «доступ отклонён» и учитывается исходом
// unauthorized или forbidden.
//
// Ключ в запись не попадает ни целиком, ни префиксом, ни длиной, ни хешем:
// короткий хеш публичного словаря ключей обращается перебором, а префикс
// сужает перебор. Записывается только сам факт — предъявлен ключ или нет, — а
// для 403 ещё и потребитель, которому ключ принадлежит: он уже прошёл
// аутентификацию и назван идентификатором из конфигурации.

// Сообщения об отказе доступа — постоянные строки.
const (
	msgDenied        = "доступ отклонён"
	reasonNoKey      = "no_key"
	reasonUnknownKey = "key_not_accepted"
)

// unauthorized отвечает 401 и фиксирует отказ в журнале и метриках.
//
// Неизвестный ключ и ключ отключённого потребителя неразличимы и здесь
// (REQ-500): причина различает только «ключа нет» и «ключ не принят».
func (s *Server) unauthorized(w http.ResponseWriter, r *http.Request, log *slog.Logger,
	e obs.Endpoint, op obs.Op, started time.Time) {

	reason := reasonUnknownKey
	if apiKey(r) == "" {
		reason = reasonNoKey
	}
	// Эндпоинт уже назван в атрибутах log: повтор дал бы в JSON-журнале
	// два одинаковых ключа.
	log.Warn(msgDenied,
		"status", http.StatusUnauthorized,
		"reason", reason,
		logKeyOutcome, obs.OutcomeUnauthorized.String())
	s.deps.Metrics.Request(e, op, obs.OutcomeUnauthorized, time.Since(started).Seconds())
	s.deps.Metrics.ConsumerRequest(obs.ConsumerAnonymous, e, obs.OutcomeUnauthorized)
	writeError(w, http.StatusUnauthorized, msgNoKey)
}

// denial — отказ 403: где, кому и почему.
type denial struct {
	endpoint   obs.Endpoint
	op         obs.Op
	consumerID string
	// reason — перечислимая причина из кода сервиса, а не текст запроса.
	reason string
	// msg — постоянное сообщение клиенту.
	msg     string
	started time.Time
}

// forbidden отвечает 403 на действие, которое политика потребителя не
// разрешает, и фиксирует отказ в журнале и метриках.
func (s *Server) forbidden(w http.ResponseWriter, log *slog.Logger, d *denial) {
	log.Warn(msgDenied,
		logKeyConsumer, d.consumerID,
		"status", http.StatusForbidden,
		"reason", d.reason,
		logKeyOutcome, obs.OutcomeForbidden.String())
	s.deps.Metrics.Request(d.endpoint, d.op, obs.OutcomeForbidden, time.Since(d.started).Seconds())
	s.deps.Metrics.ConsumerRequest(d.consumerID, d.endpoint, obs.OutcomeForbidden)
	writeError(w, http.StatusForbidden, d.msg)
}
