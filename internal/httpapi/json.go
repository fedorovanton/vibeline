package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"ai-gateway/internal/obs"
)

// Постоянные сообщения об отказах, общие для обработчиков. Ни одно не зависит
// от содержимого запроса.
const (
	msgBodyTooLarge   = "тело запроса превышает допустимый размер"
	msgBodyTimeout    = "тело запроса не получено вовремя, повторите запрос"
	msgBodyUnreadable = "не удалось прочитать тело запроса"
	msgBodyNotJSON    = "тело запроса не является корректным JSON"
	msgDeadline       = "обработка не уложилась в отведённое время, повторите запрос"
	msgStoreFull      = "хранилище соответствий переполнено, повторите запрос"
	msgNoModel        = "downstream-модель не настроена"
	msgRouteNotFound  = "маршрут не найден"
)

// errorResponse — тело ответа при ошибке.
//
// Сообщение описывает класс проблемы и никогда не содержит ни исходного
// текста, ни значений персональных данных: ответы об ошибках проверяются
// на утечки наравне с логами.
type errorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"ошибка сериализации ответа"}`))
		return
	}
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	rid := w.Header().Get(headerRequestID)
	writeJSON(w, status, errorResponse{Error: msg, RequestID: rid})
}

// bodyReadTimedOut сообщает, что тело запроса не дочитано до истечения
// http.Server.ReadTimeout.
//
// Это не ошибка клиента, а медленный канал: на публичном адресе крупный текст
// в сотню тысяч токенов при узкой полосе грузится дольше нескольких секунд.
// Ответ 400 проверяющая система считает невалидным, и пять таких подряд
// останавливают прогон, поэтому истечение чтения отдаётся как управляемый
// отказ 429 с Retry-After — его система повторяет (T-48).
func bodyReadTimedOut(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }

// writeBodyTimeout отвечает на недочитанное вовремя тело запроса.
func writeBodyTimeout(w http.ResponseWriter) {
	setRetryAfter(w, retryAfterSeconds)
	writeError(w, http.StatusTooManyRequests, msgBodyTimeout)
}

// readBody читает тело запроса с пределом размера limit.
//
// При отказе возвращает код ответа и постоянное сообщение: 413 — тело больше
// предела, 429 — тело не дочитано вовремя (bodyReadTimedOut), 400 — прочий
// обрыв чтения. Ноль вместо кода — тело прочитано. Заголовок Retry-After
// выставляет вызывающий.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, int, string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err == nil {
		return body, 0, ""
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return nil, http.StatusRequestEntityTooLarge, msgBodyTooLarge
	case bodyReadTimedOut(err):
		return nil, http.StatusTooManyRequests, msgBodyTimeout
	default:
		return nil, http.StatusBadRequest, msgBodyUnreadable
	}
}

// decodeJSONBody читает тело с пределом limit и разбирает его в v.
//
// При отказе сам отвечает клиенту и сообщает исход в fail до записи ответа:
// overloaded — тело не дочитано вовремя (429 с Retry-After), bad_request —
// всё остальное. Возвращает ложь, если обработку нужно прекратить.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, limit int64, v any, fail func(obs.Outcome)) bool {
	body, status, msg := readBody(w, r, limit)
	switch status {
	case 0:
	case http.StatusTooManyRequests:
		fail(obs.OutcomeOverloaded)
		writeBodyTimeout(w)
		return false
	default:
		fail(obs.OutcomeBadRequest)
		writeError(w, status, msg)
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		fail(obs.OutcomeBadRequest)
		writeError(w, http.StatusBadRequest, msgBodyNotJSON)
		return false
	}
	return true
}
