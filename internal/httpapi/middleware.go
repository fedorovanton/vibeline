package httpapi

import (
	"ai-gateway/internal/obs"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// retryAfterSeconds — пауза, рекомендуемая клиенту при перегрузке.
//
// Проверяющая система учитывает Retry-After и повторяет запрос; 429 не
// считается невалидным ответом и не приближает остановку прогона.
const retryAfterSeconds = 1

var requestSeq atomic.Uint64

// wrap навешивает общие для всех рабочих эндпоинтов middleware:
// ограничение одновременной обработки, идентификатор запроса и перехват паники.
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()

		// Идентификатор запроса и журнал готовятся до проверки предела
		// одновременной обработки: отказ по перегрузке — такой же наблюдаемый
		// исход, как и успех. Иначе backpressure не виден ни оператору в
		// журнале, ни в метриках, ни клиенту в заголовке ответа, и растущая
		// нагрузка выглядит как тишина.
		rid := sanitizeRequestID(r.Header.Get(headerRequestID))
		if rid == "" {
			rid = "r" + strconv.FormatUint(requestSeq.Add(1), 36)
		}
		w.Header().Set(headerRequestID, rid)
		log := s.deps.Logger.With(logKeyRequestID, rid)

		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			// Очередь не копим: предсказуемый отказ под нагрузкой лучше
			// растущей латентности и последующих таймаутов.
			// Эндпоинт называется перечислимой меткой, а не сырым путём:
			// путь приходит от клиента и в долгоживущий буфер журнала
			// попадать не должен.
			log.Warn("запрос отклонён по пределу одновременной обработки",
				logKeyEndpoint, endpointOf(r.URL.Path).String(), "path", r.URL.Path, logKeyLimit, cap(s.sem))
			s.deps.Metrics.Request(endpointOf(r.URL.Path), obs.OpMask, obs.OutcomeOverloaded,
				time.Since(started).Seconds())
			// Аутентификация до этой точки не дошла: у контракта /process
			// потребитель один и известен заранее, остальные — анонимны.
			who := obs.ConsumerAnonymous
			if endpointOf(r.URL.Path) == obs.EndpointProcess {
				who = s.deps.Config.Current().Consumers.Default().ID
			}
			s.deps.Metrics.ConsumerRequest(who, endpointOf(r.URL.Path), obs.OutcomeOverloaded)
			setRetryAfter(w, retryAfterSeconds)
			writeError(w, http.StatusTooManyRequests, "сервис перегружен, повторите запрос")
			return
		}

		defer func() {
			if rec := recover(); rec != nil {
				// Сообщение об ошибке не содержит ни payload, ни значений ПД.
				log.Error("паника при обработке запроса", "panic", rec,
					logKeyEndpoint, endpointOf(r.URL.Path).String(), "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "внутренняя ошибка обработки")
			}
		}()

		next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), rid)))
	})
}

// maxRequestIDBytes — предел длины идентификатора запроса, принятого от клиента.
const maxRequestIDBytes = 64

// sanitizeRequestID приводит присланный клиентом X-Request-Id к безопасному виду.
//
// Идентификатор — единственное строковое поле запроса, которое сервис кладёт
// в заголовок ответа, в журнал и теперь в долгоживущий кольцевой буфер
// истории. Без нормализации клиент мог бы записать туда произвольный текст,
// в том числе персональные данные, и инвариант «в истории нет значений ПД»
// держался бы только на его добросовестности. Поэтому пропускаются лишь
// символы, из которых составляют идентификаторы, а длина ограничена; любой
// другой символ приводит к выдаче собственного идентификатора.
func sanitizeRequestID(v string) string {
	if v == "" || len(v) > maxRequestIDBytes {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == ':'
		if !ok {
			return ""
		}
	}
	return v
}

// endpointOf сопоставляет путь перечислимой метке метрики.
//
// Метка обязана оставаться перечислимой: класть в неё сырой путь значило бы
// открыть неограниченную кардинальность, которую запрещает REQ-703.
func endpointOf(path string) obs.Endpoint {
	switch path {
	case pathChat:
		return obs.EndpointChat
	case pathMask:
		return obs.EndpointMask
	case pathUnmask:
		return obs.EndpointUnmask
	case pathAnalyze:
		return obs.EndpointAnalyze
	default:
		return obs.EndpointProcess
	}
}
