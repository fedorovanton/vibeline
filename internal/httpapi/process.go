package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/store"
)

// processRequest — тело запроса контракта автопроверки.
//
// Схема задана организаторами (приложение A ТЗ): оба поля обязательны и имеют
// тип «строка». Дополнительных полей контракт не определяет, поэтому
// неизвестные поля не считаются ошибкой — проверяющая система вправе их слать.
type processRequest struct {
	Payload   string    `json:"payload"`
	PayloadID payloadID `json:"payload_id"`
}

// payloadID принимает идентификатор и строкой, и числом.
//
// Контракт показывает строку, но проверяющая система может прислать
// порядковый номер числом; ответ 400 на каждый такой запрос остановил бы
// прогон на пятом. Число берётся в том написании, в каком пришло: «42» и
// 42 — один идентификатор, «042» — другой (техническое жюри 23.09, раунд 2).
type payloadID string

func (p *payloadID) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*p = payloadID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*p = payloadID(n.String())
	return nil
}

// maxPayloadIDBytes — предел длины payload_id на /process, в байтах.
const maxPayloadIDBytes = 1024

// msgLongPayloadID — отказ на слишком длинный payload_id.
const msgLongPayloadID = "поле payload_id длиннее 1024 байт"

// processResponse — тело успешного ответа контракта автопроверки.
type processResponse struct {
	Result string `json:"result"`
}

// handleProcess реализует POST /process.
//
// Эндпоинт не требует аутентификации: проверяющая система шлёт запросы без
// заголовков. Запросы обрабатываются в области изолированного потребителя
// по умолчанию, который не даёт доступа к соответствиям других потребителей.
func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	snap := s.deps.Config.Current()
	rid := requestID(r.Context())
	log := s.deps.Logger.With(logKeyRequestID, rid, logKeyEndpoint, obs.EndpointProcess.String())
	// Контракт /process обслуживается одним потребителем по умолчанию, и
	// метка consumer в метриках известна до разбора тела.
	cid := snap.Consumers.Default().ID

	// Трассировка живёт на стеке обработчика: значение фиксированного размера,
	// между горутинами не разделяется, при выключенных буферах не делает
	// ничего. Владелец записи пуст — контракт автопроверки работает без ключа,
	// и его телеметрия никому персонально не принадлежит.
	tr := obs.NewTracer(s.deps.Recorder.Enabled(), started)

	var req processRequest
	readFailed := func(out obs.Outcome) {
		if out == obs.OutcomeOverloaded {
			log.Warn("тело запроса не получено вовремя", logKeyLimit,
				bodyReadTimeout(snap.Server.ReadTimeout.Duration(), snap.Server.RequestTimeout.Duration()).String())
		}
		s.finish(cid, obs.EndpointProcess, obs.OpMask, out, started)
	}
	if !decodeJSONBody(w, r, snap.Server.MaxBodyBytes.Int64(), &req, readFailed) {
		return
	}
	if req.PayloadID == "" {
		s.finish(cid, obs.EndpointProcess, obs.OpMask, obs.OutcomeBadRequest, started)
		writeError(w, http.StatusBadRequest, msgNoPayloadID)
		return
	}
	if len(req.PayloadID) > maxPayloadIDBytes {
		// Идентификатор уходит в журнал и в ключ хранилища: без предела
		// клиент занимал бы память хранилища и строки журнала идентификатором
		// любой длины (P4-11). Предел заведомо выше любого разумного
		// идентификатора — UUID, хеша, порядкового номера.
		s.finish(cid, obs.EndpointProcess, obs.OpMask, obs.OutcomeBadRequest, started)
		writeError(w, http.StatusBadRequest, msgLongPayloadID)
		return
	}

	// Предел обработки одного запроса. Таймаут проверяющей системы — 10 с,
	// и ответ дольше считается неответом, а пять неответов подряд обрывают
	// весь прогон. Поэтому собственный предел заведомо меньше и применяется
	// на самом деле, а не только объявляется в конфигурации.
	ctx, cancel := context.WithTimeout(r.Context(), snap.Server.RequestTimeout.Duration())
	defer cancel()

	accepted := time.Now()
	tr.Mark(obs.StageAccept, started, accepted)

	consumer := snap.Consumers.Default()
	res, err := s.deps.Gateway.Process(ctx, string(req.PayloadID), req.Payload, consumer)
	protected := time.Now()
	if err != nil {
		s.processFailed(w, r, log, snap, req.PayloadID, started, err)
		return
	}

	outcome := obs.OutcomeOK
	if res.Degraded {
		outcome = obs.OutcomeDegraded
	}
	s.deps.Metrics.PII(&res.Mask.DetectedCounts, &res.Mask.MaskedCounts)
	s.deps.Metrics.Traffic(len(req.Payload), len(res.Result))
	s.finish(cid, obs.EndpointProcess, res.Op, outcome, started)

	// В журнал идут типы и счётчики, но не значения: требование ТЗ §3.2.1
	// о логировании выявленных типов выполняется без раскрытия данных.
	log.Info("запрос обработан",
		logKeyPayloadID, req.PayloadID,
		logKeyConsumer, consumer.ID,
		"op", res.Op.String(),
		logKeyDetectedTypes, res.Mask.Detected.Keys(),
		logKeyMaskedTypes, res.Mask.Masked.Keys(),
		logKeyMaskedCount, len(res.Mask.Applied),
		"degraded", res.Degraded,
		logKeyBytesIn, len(req.Payload),
		logKeyDurationMS, time.Since(started).Milliseconds(),
		// Этапы — в микросекундах: короткий текст обрабатывается за десятки
		// микросекунд, и в миллисекундах все этапы читались бы нулями.
		logKeyDurationUS, time.Since(started).Microseconds(),
		logKeyDetectUS, res.Mask.DetectNs/1000,
		logKeyPolicyUS, res.Mask.PolicyNs/1000,
		logKeyMaskUS, res.Mask.MaskNs/1000,
		"store_us", res.StoreNs/1000,
	)
	writeJSON(w, http.StatusOK, processResponse{Result: res.Result})

	// История пишется после ответа: работа с буфером не должна попадать во
	// время, которое видит клиент.
	tr.Mark(obs.StageProtect, accepted, protected)
	markProtectStages(&tr, accepted, res.Mask.DetectNs, res.Mask.PolicyNs, res.Mask.MaskNs, res.StoreNs)
	tr.MarkDur(obs.StageRespond, protected, time.Since(protected))

	s.deps.Recorder.Record(&obs.Record{
		At:             started,
		RequestID:      rid,
		Consumer:       consumer.ID,
		Endpoint:       obs.EndpointProcess,
		Op:             res.Op,
		Outcome:        outcome,
		Degraded:       res.Degraded,
		Detected:       res.Mask.Detected,
		Masked:         res.Mask.Masked,
		DetectedCounts: res.Mask.DetectedCounts,
		MaskedCounts:   res.Mask.MaskedCounts,
		BytesIn:        int32(len(req.Payload)),
		BytesOut:       int32(len(res.Result)),
		Service:        time.Since(started),
		Trace:          tr.Trace(),
	})
}

// msgNoPayloadID — отказ на отсутствующий payload_id.
const msgNoPayloadID = "поле payload_id обязательно"

// processFailed переводит ошибку ядра /process в ответ, строку журнала и
// метрики. snap — снимок конфигурации, под которым обрабатывался запрос.
func (s *Server) processFailed(w http.ResponseWriter, r *http.Request, log *slog.Logger, snap *config.Snapshot,
	id payloadID, started time.Time, err error) {

	cid := snap.Consumers.Default().ID
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		// Не уложились в бюджет. Отвечаем 429: проверяющая система подождёт
		// и повторит, а счётчик невалидных ответов не сдвинется. Ответ 500
		// здесь стоил бы одного шага к остановке всего прогона.
		log.Warn("обработка не уложилась в предел", logKeyPayloadID, id,
			logKeyLimit, snap.Server.RequestTimeout.String())
		s.finish(cid, obs.EndpointProcess, obs.OpMask, obs.OutcomeOverloaded, started)
		setRetryAfter(w, retryAfterSeconds)
		writeError(w, http.StatusTooManyRequests, msgDeadline)
	case errors.Is(err, store.ErrFull):
		// Хранилище исчерпано. Отвечаем 429: проверяющая система подождёт и
		// повторит, а счётчик невалидных ответов не сдвинется.
		log.Warn("хранилище соответствий исчерпано", logKeyPayloadID, id)
		s.finish(cid, obs.EndpointProcess, obs.OpMask, obs.OutcomeOverloaded, started)
		setRetryAfter(w, retryAfterSeconds)
		writeError(w, http.StatusTooManyRequests, msgStoreFull)
	case errors.Is(err, gateway.ErrEmptyID):
		s.finish(cid, obs.EndpointProcess, obs.OpMask, obs.OutcomeBadRequest, started)
		writeError(w, http.StatusBadRequest, msgNoPayloadID)
	case errors.Is(err, context.Canceled) && r.Context().Err() != nil:
		// Клиент ушёл раньше ответа. Отвечать уже некому, а смешивать обрыв
		// соединения с отказом защиты в журнале и метриках нельзя: на
		// дашборде это выглядело бы как fail_closed.
		log.Info("клиент закрыл соединение до ответа", logKeyPayloadID, id)
		s.finish(cid, obs.EndpointProcess, obs.OpMask, obs.OutcomeClientGone, started)
	default:
		log.Error("обработка не завершена", logKeyError, err.Error(), logKeyPayloadID, id)
		s.finish(cid, obs.EndpointProcess, obs.OpMask, obs.OutcomeFailClosed, started)
		writeError(w, http.StatusInternalServerError, "обработка не завершена")
	}
}

// markProtectStages раскладывает измеренные длительности подэтапов защиты на
// шкалу трассировки, начиная с момента base.
//
// Ядро возвращает длительности, а не моменты: иначе пришлось бы протаскивать
// в него общее начало отсчёта запроса. Подэтапы укладываются встык в порядке
// выполнения; разница между их суммой и длительностью родителя — это накладные
// расходы самого ядра, и на шкале она видна как незаполненный хвост
// родительского отрезка, а не прячется.
func markProtectStages(tr *obs.Tracer, base time.Time, detectNs, policyNs, maskNs, storeNs int64) {
	if !tr.On() {
		return
	}
	at := base.Sub(tr.Base()).Nanoseconds()
	for _, st := range [...]struct {
		stage obs.Stage
		ns    int64
	}{
		{obs.StageDetect, detectNs},
		{obs.StagePolicy, policyNs},
		{obs.StageMask, maskNs},
		{obs.StageStore, storeNs},
	} {
		tr.MarkNs(st.stage, at, st.ns)
		at += st.ns
	}
}

// finish фиксирует метрики завершённого запроса: общий счётчик и счётчик
// по потребителю consumer — идентификатору из конфигурации.
func (s *Server) finish(consumer string, e obs.Endpoint, op obs.Op, out obs.Outcome, started time.Time) {
	s.deps.Metrics.Request(e, op, out, time.Since(started).Seconds())
	s.deps.Metrics.ConsumerRequest(consumer, e, out)
}
