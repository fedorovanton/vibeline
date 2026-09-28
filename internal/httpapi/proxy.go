package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/llm"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
)

// proxyHandler — продуктовый контур /v1/*.
//
// Обработчик держит клиента модели: транспорт с пулом соединений обязан
// переживать отдельные запросы, иначе каждое обращение начиналось бы с
// рукопожатия TLS. Клиент пересобирается только при изменении настроек —
// после SIGHUP-перезагрузки конфигурации.
type proxyHandler struct {
	srv *Server

	mu   sync.Mutex
	key  clientKey
	chat llm.Chatter
}

// clientKey — настройки, при изменении которых клиента нужно пересобрать.
type clientKey struct {
	mode      string
	baseURL   string
	model     string
	timeout   time.Duration
	apiKeyEnv string
}

// newProxyHandler собирает обработчик продуктового контура.
func (s *Server) newProxyHandler() *proxyHandler { return &proxyHandler{srv: s} }

// registerProxyRoutes регистрирует маршруты продуктового контура.
//
// Регистрация вынесена в отдельный метод, чтобы добавление контура сводилось
// к одной строке в NewServer и не конфликтовало с параллельными правками
// маршрутизации.
func (s *Server) registerProxyRoutes(mux *http.ServeMux) {
	h := s.newProxyHandler()
	mux.Handle(routePOST+pathChat, s.wrap(http.HandlerFunc(h.handleChat)))
}

// handleChat реализует POST /v1/chat/completions.
//
// Эндпоинт OpenAI-совместим: потребитель шлёт обычный chat-completion, а
// защита остаётся для него прозрачной. Маскируются поля content всех
// сообщений; ответ возвращается в формате модели с обработанным content.
func (h *proxyHandler) handleChat(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	deps := h.srv.deps
	snap := deps.Config.Current()
	rid := requestID(r.Context())
	log := deps.Logger.With(logKeyRequestID, rid, logKeyEndpoint, "chat_completions")
	tr := obs.NewTracer(deps.Recorder.Enabled(), started)

	// REQ-500: неизвестный ключ и ключ отключённого потребителя неразличимы
	// для клиента. Сообщение не уточняет, какая проверка не прошла.
	consumer, ok := snap.Consumers.ByKey(apiKey(r))
	if !ok {
		h.srv.unauthorized(w, r, log, obs.EndpointChat, obs.OpProxy, started)
		return
	}
	// owner — владелец записи для изоляции потока журнала. Проставляется сразу
	// после аутентификации, чтобы ни одна последующая строка не оказалась
	// служебной по недосмотру и не досталась чужому ключу.
	log = log.With(logKeyOwner, consumer.ID)
	// Лимит частоты обращений к модели — до чтения тела: отклонённый запрос
	// не должен стоить ни разбора, ни детекции (P4-8).
	if !h.srv.allowModel(w, r, log, snap, consumer.ID, obs.EndpointChat, started) {
		return
	}

	req, ok := h.readChat(w, r, snap.Server.MaxBodyBytes.Int64(), consumer.ID, started)
	if !ok {
		return
	}

	model, err := h.client(snap)
	if err != nil {
		// Клиент не собран — это отказ до выпуска наружу. Текст ошибки
		// называет переменную окружения, но никогда её значение.
		log.Error("клиент модели не настроен", logKeyError, err.Error())
		h.finish(consumer.ID, obs.OutcomeFailClosed, started, 0)
		writeError(w, http.StatusInternalServerError, msgNoModel)
		return
	}

	accepted := time.Now()
	tr.Mark(obs.StageAccept, started, accepted)

	// Предел на весь запрос: локальная обработка (маскирование запроса и
	// восстановление ответа) получает бюджет request_timeout на обе фазы
	// вместе, ожидание модели — llm.timeout. Без предела квадратичный на
	// каком-то входе разбор шёл бы сколько угодно, а запрос потом всё равно
	// уходил бы в модель. Истечение до выпуска — fail-closed: наружу ничего.
	ctx, cancel := context.WithTimeout(r.Context(),
		snap.Server.RequestTimeout.Duration()+snap.LLM.Timeout.Duration())
	defer cancel()

	res, err := deps.Gateway.Proxy(ctx, model, gateway.ProxyRequest{
		ID:     rid,
		Chat:   req,
		Budget: snap.Server.RequestTimeout.Duration(),
	}, consumer)
	finished := time.Now()
	markProxyTrace(&tr, accepted, finished, &res)

	llmSeconds := res.LLM.Seconds()
	if res.Sent {
		out := obs.OutcomeOK
		if err != nil && errors.Is(err, gateway.ErrUpstream) {
			out = obs.OutcomeUpstreamError
		}
		deps.Metrics.LLM(out, llmSeconds)
	}

	if err != nil {
		out := h.chatFailed(w, log, snap.Server.RequestTimeout.String(), consumer.ID, started, &res, err)
		h.record(rid, consumer.ID, out, started, finished, &res, &tr)
		return
	}

	deps.Metrics.PII(&res.DetectedCounts, &res.MaskedCounts)
	// ПД, найденные в ответе модели, учитываются тем же счётчиком: они и
	// найдены, и замаскированы — но уже на обратном пути.
	deps.Metrics.PII(&res.ResponseMaskedCounts, &res.ResponseMaskedCounts)
	deps.Metrics.Traffic(res.BytesIn, res.BytesOut)
	h.finish(consumer.ID, obs.OutcomeOK, started, llmSeconds)

	log.Info("запрос проксирован",
		logKeyConsumer, consumer.ID,
		"op", obs.OpProxy.String(),
		logKeyDetectedTypes, res.Detected.Keys(),
		logKeyMaskedTypes, res.Masked.Keys(),
		logKeyMaskedCount, res.Replaced,
		logKeyRestoredCount, res.Restored,
		"response_masked_count", res.ResponseMasked,
		logKeyBytesIn, res.BytesIn,
		"llm_ms", res.LLM.Milliseconds(),
		logKeyDurationMS, time.Since(started).Milliseconds(),
		// Этапы защиты — в микросекундах, как в журнале /process (T-54).
		logKeyDetectUS, res.DetectNs/1000,
		logKeyPolicyUS, res.PolicyNs/1000,
		logKeyMaskUS, res.MaskNs/1000,
		"store_us", res.StoreNs/1000,
		"restore_us", res.RestoreNs/1000,
		logKeyOutcome, obs.OutcomeOK.String(),
	)
	writeJSON(w, http.StatusOK, res.Response)
	h.record(rid, consumer.ID, obs.OutcomeOK, started, finished, &res, &tr)
}

// readChat читает и проверяет тело chat-completion. При отказе сам отвечает
// клиенту, фиксирует метрики и возвращает ложь.
func (h *proxyHandler) readChat(w http.ResponseWriter, r *http.Request, limit int64, consumerID string,
	started time.Time) (llm.Request, bool) {

	var req llm.Request
	fail := func(out obs.Outcome) { h.finish(consumerID, out, started, 0) }
	if !decodeJSONBody(w, r, limit, &req, fail) {
		return req, false
	}
	if len(req.Messages) == 0 {
		fail(obs.OutcomeBadRequest)
		writeError(w, http.StatusBadRequest, "поле messages обязательно и не может быть пустым")
		return req, false
	}
	if req.Stream {
		// Потоковый ответ пришлось бы буферизовать целиком: демаскирование и
		// повторное сканирование выполняются по всему тексту.
		fail(obs.OutcomeBadRequest)
		writeError(w, http.StatusBadRequest, "потоковый режим не поддерживается, укажите stream: false")
		return req, false
	}
	return req, true
}

// chatFailed переводит ошибку ядра продуктового контура в ответ, строку
// журнала и метрики и возвращает исход для записи в историю. limit — предел
// обработки из конфигурации, только для журнала.
func (h *proxyHandler) chatFailed(w http.ResponseWriter, log *slog.Logger, limit, consumerID string,
	started time.Time, res *gateway.ProxyResult, err error) obs.Outcome {

	llmSeconds := res.LLM.Seconds()
	switch {
	case !res.Sent && errors.Is(err, gateway.ErrSpanLimit):
		// Значений больше предела замен: частичная маска выпустила бы
		// остаток открытым. Наружу ничего не ушло; повтор даст тот же отказ,
		// поэтому 413, как у /api/v1/mask, а не 5XX (T-52).
		log.Warn("значений к маскированию больше предела замен", logKeyConsumer, consumerID,
			logKeyOutcome, obs.OutcomeFailClosed.String())
		h.finish(consumerID, obs.OutcomeFailClosed, started, llmSeconds)
		writeError(w, http.StatusRequestEntityTooLarge, "значений к маскированию больше предела замен, разбейте текст на части")
		return obs.OutcomeFailClosed
	case !res.Sent && errors.Is(err, context.DeadlineExceeded):
		// Защита не уложилась в request_timeout до выпуска: в модель ничего
		// не ушло. Управляемый отказ с Retry-After, как на /process.
		log.Warn("защита запроса не уложилась в предел", logKeyConsumer, consumerID,
			logKeyLimit, limit)
		h.finish(consumerID, obs.OutcomeOverloaded, started, llmSeconds)
		setRetryAfter(w, retryAfterSeconds)
		writeError(w, http.StatusTooManyRequests, msgDeadline)
		return obs.OutcomeOverloaded
	case errors.Is(err, gateway.ErrFailClosed):
		// Инвариант fail-closed: наружу не ушло ничего, клиент получает 500
		// без персональных данных в теле.
		log.Error("запрос в модель не отправлен", logKeyError, err.Error(),
			logKeyConsumer, consumerID, logKeyOutcome, obs.OutcomeFailClosed.String())
		h.finish(consumerID, obs.OutcomeFailClosed, started, llmSeconds)
		writeError(w, http.StatusInternalServerError, "защита запроса не завершена, запрос в модель не отправлен")
		return obs.OutcomeFailClosed
	case errors.Is(err, gateway.ErrUpstream):
		// Класс и код выведены отдельными полями, хотя оба входят и в текст
		// ошибки: по тексту нельзя ни отобрать записи, ни построить сводку,
		// а разбирать отказы приходится именно так.
		log.Warn("модель не ответила", logKeyError, err.Error(),
			"upstream_class", res.UpstreamClass, "upstream_status", res.UpstreamStatus,
			logKeyConsumer, consumerID, logKeyOutcome, obs.OutcomeUpstreamError.String())
		h.finish(consumerID, obs.OutcomeUpstreamError, started, llmSeconds)
		writeError(w, http.StatusBadGateway, "downstream-модель недоступна")
		return obs.OutcomeUpstreamError
	default:
		// Ответ модели не проверен повторно — отдавать его нельзя.
		log.Error("ответ модели не обработан", logKeyError, err.Error(),
			logKeyConsumer, consumerID, logKeyOutcome, obs.OutcomeFailClosed.String())
		h.finish(consumerID, obs.OutcomeFailClosed, started, llmSeconds)
		writeError(w, http.StatusInternalServerError, "ответ модели не обработан")
		return obs.OutcomeFailClosed
	}
}

// markProxyTrace раскладывает этапы продуктового контура на шкалу трассировки.
//
// Ядро возвращает длительности этапов, а моменты известны только транспорту,
// поэтому раскладка делается здесь. Защита, ожидание модели и восстановление
// идут встык: это три непересекающихся участка одного вызова ядра, и порядок
// их выполнения жёстко задан инвариантом fail-closed.
func markProxyTrace(tr *obs.Tracer, accepted, finished time.Time, res *gateway.ProxyResult) {
	if !tr.On() {
		return
	}
	at := accepted.Sub(tr.Base()).Nanoseconds()
	llmNs := res.LLM.Nanoseconds()

	// Время защиты получается вычитанием: отдельного замера вокруг неё нет,
	// а ошибка вычитания здесь меньше цены ещё одного обращения к часам.
	protectNs := finished.Sub(accepted).Nanoseconds() - llmNs - res.RestoreNs
	if protectNs < 0 {
		protectNs = 0
	}
	tr.MarkNs(obs.StageProtect, at, protectNs)
	markProtectStages(tr, accepted, res.DetectNs, res.PolicyNs, res.MaskNs, res.StoreNs)
	tr.MarkNs(obs.StageLLM, at+protectNs, llmNs)
	tr.MarkNs(obs.StageRestore, at+protectNs+llmNs, res.RestoreNs)
}

// record кладёт запись продуктового контура в историю.
//
// Владелец записи — потребитель, предъявивший ключ: по нему и работает
// изоляция. Значений персональных данных в записи нет — только типы,
// счётчики, длительности и исход.
func (h *proxyHandler) record(rid, caller string, out obs.Outcome, started, finished time.Time,
	res *gateway.ProxyResult, tr *obs.Tracer) {

	rec := h.srv.deps.Recorder
	if !rec.Enabled() {
		return
	}
	service := time.Since(started) - res.LLM
	if service < 0 {
		service = 0
	}
	// Запись ответа — всё, что происходит после возврата ядра: учёт метрик,
	// строка журнала и собственно отправка тела. Отрезок нулевой длины на
	// шкале выглядел бы как пропущенный этап, поэтому измеряется честно.
	tr.MarkDur(obs.StageRespond, finished, time.Since(finished))

	entry := obs.Record{
		At:             started,
		RequestID:      rid,
		Caller:         caller,
		Consumer:       caller,
		Endpoint:       obs.EndpointChat,
		Op:             obs.OpProxy,
		Outcome:        out,
		Detected:       res.Detected,
		Masked:         res.Masked,
		DetectedCounts: res.DetectedCounts,
		MaskedCounts:   res.MaskedCounts,
		BytesIn:        int32(res.BytesIn),
		BytesOut:       int32(res.BytesOut),
		Service:        service,
		LLM:            res.LLM,
		Trace:          tr.Trace(),
	}
	// ПД, найденные в ответе модели, учитываются в тех же счётчиках: они и
	// найдены, и замаскированы, но уже на обратном пути.
	for t := 1; t < pii.Count; t++ {
		entry.MaskedCounts[t] += res.ResponseMaskedCounts[t]
	}
	rec.Record(&entry)
}

// finish фиксирует метрики запроса продуктового контура.
//
// Время ожидания модели вычитается: организаторы измеряют время сервиса, и
// чужая задержка в него входить не должна. Отдельно оно учтено метрикой
// Metrics.LLM.
func (h *proxyHandler) finish(consumer string, out obs.Outcome, started time.Time, llmSeconds float64) {
	service := time.Since(started).Seconds() - llmSeconds
	if service < 0 {
		service = 0
	}
	h.srv.deps.Metrics.Request(obs.EndpointChat, obs.OpProxy, out, service)
	h.srv.deps.Metrics.ConsumerRequest(consumer, obs.EndpointChat, out)
}

// client возвращает клиента модели для текущего снимка конфигурации.
func (h *proxyHandler) client(snap *config.Snapshot) (llm.Chatter, error) {
	key := clientKey{
		mode:      snap.LLM.Mode,
		baseURL:   snap.LLM.BaseURL,
		model:     snap.LLM.Model,
		timeout:   snap.LLM.Timeout.Duration(),
		apiKeyEnv: snap.LLM.APIKeyEnv,
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.chat != nil && h.key == key {
		return h.chat, nil
	}

	var chat llm.Chatter
	switch key.mode {
	case llm.ModeStub:
		chat = llm.Stub{Model: key.model}
	default:
		// Ключ читается из окружения в момент сборки клиента и остаётся в
		// памяти процесса: ни в конфигурацию, ни в логи он не попадает.
		secret := os.Getenv(key.apiKeyEnv)
		if secret == "" {
			return nil, fmt.Errorf("переменная окружения %s не задана", key.apiKeyEnv)
		}
		cli, err := llm.New(llm.Options{
			BaseURL: key.baseURL,
			Model:   key.model,
			APIKey:  secret,
			Timeout: key.timeout,
		})
		if err != nil {
			return nil, err
		}
		chat = cli
	}

	h.key = key
	h.chat = chat
	return chat, nil
}

// apiKey извлекает ключ доступа потребителя из запроса.
//
// Поддерживаются оба принятых способа: X-API-Key и Authorization с префиксом
// Bearer. Префикс необязателен — это заголовок нашего сервиса, а не AlfaGen,
// где ключ передаётся без префикса.
func apiKey(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get(headerAPIKey)); k != "" {
		return k
	}
	h := strings.TrimSpace(r.Header.Get(headerAuthorization))
	if len(h) >= 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return h
}
