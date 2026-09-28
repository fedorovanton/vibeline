package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"hash/maphash"
	"net/http"
	"strconv"
	"sync"
	"time"

	"ai-gateway/internal/gateway"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
	"ai-gateway/internal/store"
)

// Явный продуктовый API: маскирование без обращения к модели и
// восстановление отдельным вызовом позже.
//
// Оба эндпоинта требуют ключ потребителя и применяют его политику. Ядро
// обработки то же, что у /process и /v1/chat/completions, — gateway.Mask;
// здесь только разбор запроса, область хранения и перевод исходов в коды.

// apiStorePrefix отделяет соответствия явного API от записей /process и
// продуктового прокси. Ключ ядра начинается с идентификатора потребителя из
// конфигурации, а этот — с управляющего байта: совпасть они не могут, и
// идентификатор, выбранный клиентом здесь, не затрёт запись автопроверки.
const apiStorePrefix = "\x02api\x00"

// apiStoreKey строит ключ хранилища в области потребителя.
//
// Область входит в ключ, а не проверяется после чтения: чужой идентификатор
// ищется в собственной области вызывающего и поэтому неотличим от
// неизвестного — по построению, а не по аккуратности проверки.
//
// Перед идентификатором потребителя стоит его длина, как в ключе /process
// (gateway.scopedKey): склейка через разделитель неинъективна, если байт
// разделителя окажется в идентификаторе (дефект D-6 из T-19).
func apiStoreKey(consumerID, id string) string {
	return apiStorePrefix + strconv.Itoa(len(consumerID)) + ":" + consumerID + id
}

// apiIDLocks сериализуют «проверить и записать» по одному ключу хранилища.
//
// Интерфейс Store не даёт атомарной записи «если отсутствует», а два
// одновременных маскирования разных текстов под одним идентификатором без
// замка оставили бы первому клиенту маску, соответствие которой уже затёрто.
// Замки полосатые: критическая секция — чтение и запись в памяти, и общий
// замок на весь эндпоинт здесь не нужен.
var (
	apiIDLocks [64]sync.Mutex
	apiIDSeed  = maphash.MakeSeed()
)

func apiIDLock(key string) *sync.Mutex {
	return &apiIDLocks[maphash.String(apiIDSeed, key)%uint64(len(apiIDLocks))]
}

// maskAPIRequest — тело POST /api/v1/mask.
type maskAPIRequest struct {
	// Text — исходный текст. Указатель отличает отсутствующее поле от пустой
	// строки: пустой текст допустим, забытое поле — ошибка клиента.
	Text *string `json:"text"`
	// ID — необязательный идентификатор корреляции. Пустой — сервис выдаёт свой.
	ID string `json:"id"`
}

// maskAPIResponse — ответ POST /api/v1/mask.
//
// Значений ПД в ответе нет: только защищённый текст, типы и счётчики.
type maskAPIResponse struct {
	Masked string         `json:"masked"`
	ID     string         `json:"id"`
	Types  []string       `json:"types"`
	Counts map[string]int `json:"counts"`
}

// unmaskAPIRequest — тело POST /api/v1/unmask.
type unmaskAPIRequest struct {
	Masked *string `json:"masked"`
	ID     string  `json:"id"`
}

// unmaskAPIResponse — ответ POST /api/v1/unmask.
type unmaskAPIResponse struct {
	Text string `json:"text"`
}

// Сообщения об ошибках — постоянные строки. Ни одно из них не зависит от
// содержимого хранилища сверх того, что вызывающий уже знает сам.
const (
	msgNoKey       = "требуется действующий ключ доступа"
	msgBadID       = "поле id: допустимы латинские буквы, цифры и символы - _ . : длиной до 64 байт"
	msgNoDemask    = "потребителю не разрешено обратное преобразование"
	msgNotFound    = "соответствие не найдено: неизвестный идентификатор или истёк срок хранения"
	msgIDTaken     = "идентификатор уже связан с другим текстом: передайте другой id или не передавайте его"
	msgStalePolicy = "соответствие создано под прежней политикой: восстанавливается только неизменённая маска"
)

// registerAPIRoutes регистрирует маршруты явного API.
func (s *Server) registerAPIRoutes(mux *http.ServeMux) {
	mux.Handle(routePOST+pathMask, s.wrap(http.HandlerFunc(s.handleAPIMask)))
	mux.Handle(routePOST+pathUnmask, s.wrap(http.HandlerFunc(s.handleAPIUnmask)))
}

// handleAPIMask реализует POST /api/v1/mask.
//
// Порядок шагов задан инвариантами: защита завершена полностью, соответствие
// записано — и только потом клиент получает маску. Безопасного отката на
// маскирование всей строки здесь нет, как и на продуктовом прокси: клиент
// явного API отправит маску дальше сам, и частично обработанный текст
// недопустим, а отказ ему понятен и дёшев.
func (s *Server) handleAPIMask(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	snap := s.deps.Config.Current()
	rid := requestID(r.Context())
	log := s.deps.Logger.With(logKeyRequestID, rid, logKeyEndpoint, obs.EndpointMask.String())
	tr := obs.NewTracer(s.deps.Recorder.Enabled(), started)

	// REQ-500: неизвестный ключ и ключ отключённого потребителя неразличимы.
	consumer, ok := snap.Consumers.ByKey(apiKey(r))
	if !ok {
		s.unauthorized(w, r, log, obs.EndpointMask, obs.OpMask, started)
		return
	}
	log = log.With(logKeyOwner, consumer.ID)
	fail := func(status int, op obs.Op, out obs.Outcome, msg string) {
		s.finish(consumer.ID, obs.EndpointMask, op, out, started)
		if status == http.StatusTooManyRequests {
			setRetryAfter(w, retryAfterSeconds)
		}
		writeError(w, status, msg)
	}

	var req maskAPIRequest
	if status, msg := readAPIBody(w, r, snap.Server.MaxBodyBytes.Int64(), &req); status != 0 {
		fail(status, obs.OpMask, obs.OutcomeBadRequest, msg)
		return
	}
	if req.Text == nil {
		fail(http.StatusBadRequest, obs.OpMask, obs.OutcomeBadRequest, "поле text обязательно")
		return
	}
	text := *req.Text
	id := req.ID
	if id == "" {
		// 26 символов base32 из криптографического источника: угадать чужой
		// идентификатор незачем — он всё равно ищется в своей области, — но
		// и случайно совпасть со своим прежним он не должен.
		id = rand.Text()
	} else if sanitizeRequestID(id) == "" {
		// Идентификатор попадает в журнал и в ответ, поэтому произвольный
		// текст в нём недопустим — ровно как для X-Request-Id.
		fail(http.StatusBadRequest, obs.OpMask, obs.OutcomeBadRequest, msgBadID)
		return
	}

	// Предел обработки — тот же, что у /process.
	ctx, cancel := context.WithTimeout(r.Context(), snap.Server.RequestTimeout.Duration())
	defer cancel()

	accepted := time.Now()
	tr.Mark(obs.StageAccept, started, accepted)

	// Номера, чья замена уже буквально написана во входе, не выдаются —
	// как на прокси к модели (С-6, T-56): иначе unmask изменённой маски
	// подставил бы значение на место буквального «[ФИО_1]».
	res, err := s.deps.Gateway.MaskReserved(ctx, text, consumer)
	if err == nil {
		err = gateway.VerifyReplaced(text, res)
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		log.Warn("маскирование не уложилось в предел", logKeyPayloadID, id,
			logKeyLimit, snap.Server.RequestTimeout.String())
		fail(http.StatusTooManyRequests, obs.OpMask, obs.OutcomeOverloaded, msgDeadline)
		return
	case errors.Is(err, gateway.ErrSpanLimit):
		// Значений больше предела замен: частичная маска оставила бы остаток
		// открытым (T-52). Отказ — fail-closed, без маски и без записи
		// соответствия. Код 413, а не 500: это ограничение входа, как предел
		// размера тела (REQ-600), — повтор того же текста даст тот же отказ,
		// и клиенту нужно разбить текст, а не повторять запрос.
		log.Warn("значений больше предела замен, маска не выдана", logKeyPayloadID, id,
			logKeyConsumer, consumer.ID, "max_spans", consumer.MaxSpans,
			logKeyOutcome, obs.OutcomeFailClosed.String())
		fail(http.StatusRequestEntityTooLarge, obs.OpMask, obs.OutcomeFailClosed, spanLimitMessage(consumer.MaxSpans))
		return
	case err != nil:
		// Инвариант fail-closed: ни исходный, ни частично обработанный текст
		// клиенту не выдаётся. Текст ошибки ядра значений не содержит.
		log.Error("маскирование не завершено", logKeyError, err.Error(), logKeyPayloadID, id,
			logKeyConsumer, consumer.ID, logKeyOutcome, obs.OutcomeFailClosed.String())
		fail(http.StatusInternalServerError, obs.OpMask, obs.OutcomeFailClosed,
			"защита текста не завершена, маска не выдана")
		return
	}

	// Соответствие записывается до ответа: иначе клиент получил бы маску,
	// которую нечем восстановить.
	storeStart := time.Now()
	op, err := s.storeAPIRecord(apiStoreKey(consumer.ID, id), store.Record{
		Original:  text,
		Masked:    res.Text,
		Types:     res.Masked,
		Consumer:  consumer.ID,
		CreatedAt: time.Now(),
	})
	storeNs := time.Since(storeStart).Nanoseconds()
	switch {
	case errors.Is(err, errIDTaken):
		fail(http.StatusConflict, obs.OpMaskConflict, obs.OutcomeBadRequest, msgIDTaken)
		return
	case errors.Is(err, store.ErrFull):
		log.Warn("хранилище соответствий исчерпано", logKeyPayloadID, id)
		fail(http.StatusTooManyRequests, obs.OpMask, obs.OutcomeOverloaded, msgStoreFull)
		return
	case err != nil:
		log.Error("соответствие не сохранено", logKeyError, err.Error(), logKeyPayloadID, id,
			logKeyConsumer, consumer.ID, logKeyOutcome, obs.OutcomeFailClosed.String())
		fail(http.StatusInternalServerError, obs.OpMask, obs.OutcomeFailClosed,
			"соответствие не сохранено, маска не выдана")
		return
	}
	protected := time.Now()

	if op == obs.OpMask {
		s.deps.Metrics.PII(&res.DetectedCounts, &res.MaskedCounts)
	}
	s.deps.Metrics.Traffic(len(text), len(res.Text))
	s.finish(consumer.ID, obs.EndpointMask, op, obs.OutcomeOK, started)

	log.Info("текст замаскирован",
		logKeyPayloadID, id,
		logKeyConsumer, consumer.ID,
		"op", op.String(),
		logKeyDetectedTypes, res.Detected.Keys(),
		logKeyMaskedTypes, res.Masked.Keys(),
		logKeyMaskedCount, len(res.Applied),
		logKeyBytesIn, len(text),
		logKeyDurationMS, time.Since(started).Milliseconds(),
		logKeyDurationUS, time.Since(started).Microseconds(),
		logKeyDetectUS, res.DetectNs/1000,
		logKeyPolicyUS, res.PolicyNs/1000,
		logKeyMaskUS, res.MaskNs/1000,
	)
	writeJSON(w, http.StatusOK, maskAPIResponse{
		Masked: res.Text,
		ID:     id,
		Types:  res.Masked.Keys(),
		Counts: countsOf(res.Masked, &res.MaskedCounts),
	})

	tr.Mark(obs.StageProtect, accepted, protected)
	markProtectStages(&tr, accepted, res.DetectNs, res.PolicyNs, res.MaskNs, storeNs)
	tr.MarkDur(obs.StageRespond, protected, time.Since(protected))
	s.recordAPI(&apiRecord{
		endpoint: obs.EndpointMask, op: op, rid: rid, consumer: consumer.ID, started: started,
		res: &res, bytesIn: len(text), bytesOut: len(res.Text),
	}, &tr)
}

// handleAPIUnmask реализует POST /api/v1/unmask.
//
// Восстанавливается только соответствие из собственной области потребителя и
// только при праве demask. Два режима:
//
//   - маска совпадает с выданной — возвращается сохранённый оригинал,
//     побайтово;
//   - маска изменена (например, это ответ модели) — восстанавливаются
//     плейсхолдеры, выданные для этого идентификатора; чужие, подделанные и
//     неоднозначные остаются как есть и ничего не раскрывают.
func (s *Server) handleAPIUnmask(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	snap := s.deps.Config.Current()
	rid := requestID(r.Context())
	log := s.deps.Logger.With(logKeyRequestID, rid, logKeyEndpoint, obs.EndpointUnmask.String())
	tr := obs.NewTracer(s.deps.Recorder.Enabled(), started)

	consumer, ok := snap.Consumers.ByKey(apiKey(r))
	if !ok {
		s.unauthorized(w, r, log, obs.EndpointUnmask, obs.OpUnmask, started)
		return
	}
	log = log.With(logKeyOwner, consumer.ID)
	fail := func(status int, out obs.Outcome, msg string) {
		s.finish(consumer.ID, obs.EndpointUnmask, obs.OpUnmask, out, started)
		if status == http.StatusTooManyRequests {
			setRetryAfter(w, retryAfterSeconds)
		}
		writeError(w, status, msg)
	}

	var req unmaskAPIRequest
	if status, msg := readAPIBody(w, r, snap.Server.MaxBodyBytes.Int64(), &req); status != 0 {
		fail(status, obs.OutcomeBadRequest, msg)
		return
	}
	if req.Masked == nil {
		fail(http.StatusBadRequest, obs.OutcomeBadRequest, "поле masked обязательно")
		return
	}
	if req.ID == "" {
		fail(http.StatusBadRequest, obs.OutcomeBadRequest, "поле id обязательно")
		return
	}
	if sanitizeRequestID(req.ID) == "" {
		fail(http.StatusBadRequest, obs.OutcomeBadRequest, msgBadID)
		return
	}
	// Право проверяется до обращения к хранилищу: ответ без права одинаков
	// для любого идентификатора и не служит оракулом существования записи.
	if !consumer.Demask {
		s.forbidden(w, log, &denial{
			endpoint: obs.EndpointUnmask, op: obs.OpUnmask, consumerID: consumer.ID,
			reason: "demask_not_allowed", msg: msgNoDemask, started: started,
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), snap.Server.RequestTimeout.Duration())
	defer cancel()

	accepted := time.Now()
	tr.Mark(obs.StageAccept, started, accepted)

	masked := *req.Masked
	rec, found := s.deps.Gateway.Store().Get(apiStoreKey(consumer.ID, req.ID))
	if !found || rec.Consumer != consumer.ID {
		// Чужой и неизвестный идентификаторы дают один и тот же ответ.
		fail(http.StatusNotFound, obs.OutcomeBadRequest, msgNotFound)
		return
	}

	text, restored, err := s.restoreAPI(ctx, masked, rec, consumer)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		log.Warn("восстановление не уложилось в предел", logKeyPayloadID, req.ID,
			logKeyLimit, snap.Server.RequestTimeout.String())
		fail(http.StatusTooManyRequests, obs.OutcomeOverloaded, msgDeadline)
		return
	case errors.Is(err, errStalePolicy):
		fail(http.StatusConflict, obs.OutcomeBadRequest, msgStalePolicy)
		return
	case err != nil:
		log.Error("восстановление не завершено", logKeyError, err.Error(), logKeyPayloadID, req.ID,
			logKeyConsumer, consumer.ID, logKeyOutcome, obs.OutcomeFailClosed.String())
		fail(http.StatusInternalServerError, obs.OutcomeFailClosed, "восстановление не завершено")
		return
	}
	finished := time.Now()

	s.deps.Metrics.Traffic(len(masked), len(text))
	s.finish(consumer.ID, obs.EndpointUnmask, obs.OpUnmask, obs.OutcomeOK, started)
	log.Info("текст восстановлен",
		logKeyPayloadID, req.ID,
		logKeyConsumer, consumer.ID,
		"op", obs.OpUnmask.String(),
		"exact", masked == rec.Masked,
		logKeyRestoredCount, restored,
		"types", rec.Types.Keys(),
		logKeyBytesIn, len(masked),
		logKeyDurationMS, time.Since(started).Milliseconds(),
		logKeyDurationUS, time.Since(started).Microseconds(),
	)
	writeJSON(w, http.StatusOK, unmaskAPIResponse{Text: text})

	tr.Mark(obs.StageRestore, accepted, finished)
	tr.MarkDur(obs.StageRespond, finished, time.Since(finished))
	s.recordAPI(&apiRecord{
		endpoint: obs.EndpointUnmask, op: obs.OpUnmask, rid: rid, consumer: consumer.ID, started: started,
		bytesIn: len(masked), bytesOut: len(text),
	}, &tr)
}

// errIDTaken — идентификатор в области потребителя уже связан с другим текстом.
var errIDTaken = errors.New("httpapi: идентификатор уже использован")

// errStalePolicy — маска изменена, а текущая политика даёт для сохранённого
// оригинала другую маску: сопоставить плейсхолдеры со значениями нельзя.
var errStalePolicy = errors.New("httpapi: соответствие создано под прежней политикой")

// storeAPIRecord сохраняет соответствие, если идентификатор свободен.
//
// Повтор с тем же текстом и той же маской — идемпотентный повтор прямого шага:
// запись не переписывается. Любое другое совпадение идентификатора — отказ:
// перезапись оставила бы прежнюю маску без восстановления.
func (s *Server) storeAPIRecord(key string, rec store.Record) (obs.Op, error) {
	st := s.deps.Gateway.Store()
	mu := apiIDLock(key)
	mu.Lock()
	defer mu.Unlock()

	if prev, ok := st.Get(key); ok {
		if prev.Consumer == rec.Consumer && prev.Original == rec.Original && prev.Masked == rec.Masked {
			return obs.OpMaskRetry, nil
		}
		return obs.OpMaskConflict, errIDTaken
	}
	if err := st.Put(key, rec); err != nil {
		return obs.OpMask, err
	}
	return obs.OpMask, nil
}

// restoreAPI возвращает исходный текст для маски из записи rec.
//
// Неизменённая маска восстанавливается возвратом сохранённого оригинала — так
// круговой путь точен побайтово при любой стратегии. Для изменённой маски
// замены получаются повторным маскированием сохранённого оригинала: маскирование
// — чистая функция от текста и политики, и совпадение результата с
// сохранённой маской доказывает, что замены те же, что были выданы.
// Подстановка — та же, что у ответа модели на прокси (gateway.RestoreIssued):
// одна реализация на оба контура (С-6, T-56).
func (s *Server) restoreAPI(ctx context.Context, masked string, rec store.Record, c *policy.Consumer) (string, int, error) {
	if masked == rec.Masked {
		return rec.Original, 0, nil
	}
	res, err := s.deps.Gateway.MaskReserved(ctx, rec.Original, c)
	if errors.Is(err, gateway.ErrSpanLimit) {
		// Запись создана под прежним, более высоким пределом замен: текущая
		// политика ту же маску не выдаёт.
		return "", 0, errStalePolicy
	}
	if err != nil {
		return "", 0, err
	}
	if res.Text != rec.Masked {
		return "", 0, errStalePolicy
	}
	text, n := gateway.RestoreIssued(masked, rec.Original, res.Applied, c)
	return text, n, nil
}

// readAPIBody читает и разбирает JSON-тело с пределом размера.
//
// Возвращает ноль при успехе, иначе код ответа и постоянное сообщение.
func readAPIBody(w http.ResponseWriter, r *http.Request, limit int64, v any) (int, string) {
	body, status, msg := readBody(w, r, limit)
	if status == http.StatusTooManyRequests {
		setRetryAfter(w, retryAfterSeconds)
	}
	if status != 0 {
		return status, msg
	}
	if err := json.Unmarshal(body, v); err != nil {
		return http.StatusBadRequest, msgBodyNotJSON
	}
	return 0, ""
}

// spanLimitMessage — текст отказа при превышении предела замен.
//
// Называет только предел из конфигурации: ни значений, ни их числа в тексте
// запроса в сообщении нет.
func spanLimitMessage(limit int) string {
	return "текст содержит больше значений персональных данных, чем допускает предел замен на один запрос (" +
		strconv.Itoa(limit) + "): маска не выдана, разбейте текст на части"
}

// countsOf собирает счётчики замаскированных значений по машинным ключам типов.
func countsOf(set pii.Set, counts *[pii.Count]uint16) map[string]int {
	out := make(map[string]int, set.Len())
	for _, t := range set.Types() {
		out[t.Key()] = int(counts[t])
	}
	return out
}

// apiRecord — сведения об успешном запросе явного API для истории стенда.
type apiRecord struct {
	endpoint obs.Endpoint
	op       obs.Op
	rid      string
	// consumer — потребитель, предъявивший ключ: он же владелец записи.
	consumer string
	started  time.Time
	// res — результат маскирования; nil у восстановления.
	res      *gateway.MaskResult
	bytesIn  int
	bytesOut int
}

// recordAPI кладёт запись явного API в историю стенда.
//
// Владелец записи — потребитель, предъявивший ключ. Значений ПД в записи нет:
// только типы, счётчики, длительности и исход.
func (s *Server) recordAPI(a *apiRecord, tr *obs.Tracer) {
	if !s.deps.Recorder.Enabled() {
		return
	}
	entry := obs.Record{
		At:        a.started,
		RequestID: a.rid,
		Caller:    a.consumer,
		Consumer:  a.consumer,
		Endpoint:  a.endpoint,
		Op:        a.op,
		Outcome:   obs.OutcomeOK,
		BytesIn:   int32(a.bytesIn),
		BytesOut:  int32(a.bytesOut),
		Service:   time.Since(a.started),
		Trace:     tr.Trace(),
	}
	if res := a.res; res != nil {
		entry.Detected = res.Detected
		entry.Masked = res.Masked
		entry.DetectedCounts = res.DetectedCounts
		entry.MaskedCounts = res.MaskedCounts
	}
	s.deps.Recorder.Record(&entry)
}
