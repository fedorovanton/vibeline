package httpapi

import (
	"net/http"
	"strconv"
)

// Пути маршрутов сервиса. Таблица одна на регистрацию в ServeMux,
// methodGuard и перечислимые метки метрик: расхождение пути в одном из мест
// превратилось бы в 404 или в чужую метку.
const (
	pathRoot         = "/"
	pathProcess      = "/process"
	pathHealth       = "/healthz"
	pathReady        = "/readyz"
	pathMetrics      = "/metrics"
	pathPresentation = "/presentation"
	pathChat         = "/v1/chat/completions"
	pathMask         = "/api/v1/mask"
	pathUnmask       = "/api/v1/unmask"
	pathAnalyze      = "/api/v1/analyze"
	pathUIConsumers  = "/api/v1/ui/consumers"
	pathUIHistory    = "/api/v1/ui/history"
	pathUITrace      = "/api/v1/ui/trace"
	pathUIJournal    = "/api/v1/ui/journal"
)

// Префиксы шаблонов ServeMux: метод, пробел, путь.
const (
	routeGET  = http.MethodGet + " "
	routePOST = http.MethodPost + " "
)

// Заголовки и их постоянные значения.
const (
	headerRetryAfter    = "Retry-After"
	headerCacheControl  = "Cache-Control"
	headerAllow         = "Allow"
	headerContentType   = "Content-Type"
	headerRequestID     = "X-Request-Id"
	headerCSP           = "Content-Security-Policy"
	headerAPIKey        = "X-API-Key"
	headerAuthorization = "Authorization"

	cacheNoStore    = "no-store"
	contentTypeJSON = "application/json; charset=utf-8"
)

// Ключи атрибутов журнала, общие для обработчиков. Значения ПД под эти ключи
// не попадают: идентификаторы, перечислимые метки и тексты ошибок ядра.
const (
	logKeyRequestID = "request_id"
	logKeyEndpoint  = "endpoint"
	logKeyOwner     = "owner"
	logKeyPayloadID = "payload_id"
	logKeyConsumer  = "consumer"
	logKeyOutcome   = "outcome"
	logKeyError     = "error"
	logKeyLimit     = "limit"

	// Итог обработки запроса: найденные и замаскированные типы, счётчики
	// замен, размер входа и длительности этапов.
	logKeyDetectedTypes = "detected_types"
	logKeyMaskedTypes   = "masked_types"
	logKeyMaskedCount   = "masked_count"
	logKeyRestoredCount = "restored_count"
	logKeyBytesIn       = "bytes_in"
	logKeyDurationMS    = "duration_ms"
	logKeyDurationUS    = "duration_us"
	logKeyDetectUS      = "detect_us"
	logKeyPolicyUS      = "policy_us"
	logKeyMaskUS        = "mask_us"
)

// setRetryAfter выставляет Retry-After в секундах.
func setRetryAfter(w http.ResponseWriter, seconds int) {
	w.Header().Set(headerRetryAfter, strconv.Itoa(seconds))
}

// noStore запрещает кэширование ответа.
func noStore(w http.ResponseWriter) {
	w.Header().Set(headerCacheControl, cacheNoStore)
}
