package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/llm"
	"ai-gateway/internal/mask"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
	"ai-gateway/web"
)

// uiHandler — демонстрационный стенд.
//
// Стенд существует ради одного утверждения: наружу уходит маска, а не
// исходный текст, и это видно своими глазами. Поэтому тело запроса к модели
// не пересобирается для показа, а записывается на границе выпуска наружу —
// ровно то значение, которое получил клиент модели.
type uiHandler struct {
	srv *Server
	// proxy — отдельный экземпляр обработчика продуктового контура, нужный
	// только ради кэша клиента модели: транспорт с пулом соединений обязан
	// переживать отдельные запросы стенда. Маршруты /v1/* он здесь не
	// обслуживает — их регистрирует registerProxyRoutes.
	proxy *proxyHandler
}

// registerUIRoutes регистрирует маршруты демонстрационного стенда.
//
// Регистрация вынесена в отдельный метод по образцу registerProxyRoutes:
// добавление контура сводится к одной строке в NewServer и не конфликтует с
// параллельными правками маршрутизации.
func (s *Server) registerUIRoutes(mux *http.ServeMux) {
	h := &uiHandler{srv: s, proxy: s.newProxyHandler()}
	mux.Handle(routeGET+pathRoot, http.HandlerFunc(h.handlePage))
	mux.Handle(routeGET+pathPresentation, http.HandlerFunc(h.handlePresentation))
	mux.Handle(routeGET+pathUIConsumers, http.HandlerFunc(h.handleConsumers))
	mux.Handle(routePOST+pathAnalyze, s.wrap(http.HandlerFunc(h.handleAnalyze)))

	// Наблюдаемость стенда. Эндпоинты только читают буферы, поэтому предел
	// одновременной обработки на них не навешен: опрос страницы не должен
	// занимать слоты, отведённые боевым запросам, и не должен сам порождать
	// записи в журнале и истории. Ключ обязателен — проверка внутри каждого
	// обработчика, как на /api/v1/analyze.
	mux.Handle(routeGET+pathUIHistory, http.HandlerFunc(h.handleHistory))
	mux.Handle(routeGET+pathUITrace, http.HandlerFunc(h.handleTrace))
	mux.Handle(routeGET+pathUIJournal, http.HandlerFunc(h.handleJournal))
}

// contentSecurityPolicy запрещает странице всё, кроме обращений к этому же
// сервису. Утверждение «стенд не ходит наружу» проверяется браузером, а не
// обещанием: default-src 'none' и connect-src 'self' не оставляют выбора.
// img-src data: разрешает только картинки, встроенные в сам документ
// (логотип команды в презентации): сетевого запроса у них нет.
const contentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; " +
	"script-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'none'; " +
	"base-uri 'none'; frame-ancestors 'none'"

// handlePage отдаёт страницу стенда.
//
// Ключ не требуется: страница — статический документ и сама по себе ничего не
// раскрывает. Всё содержательное лежит за POST /api/v1/analyze, который без
// ключа отвечает 401.
func (h *uiHandler) handlePage(w http.ResponseWriter, r *http.Request) {
	// Шаблон "GET /" в ServeMux покрывает всё дерево путей, поэтому сюда
	// попадает и то, что не совпало ни с одним маршрутом.
	if r.URL.Path != pathRoot {
		writeError(w, http.StatusNotFound, msgRouteNotFound)
		return
	}
	writeStaticPage(w, web.Page())
}

// handlePresentation отдаёт слайды о решении. Ключ не нужен по той же
// причине, что и у страницы стенда: это статический документ.
func (h *uiHandler) handlePresentation(w http.ResponseWriter, _ *http.Request) {
	writeStaticPage(w, web.Presentation())
}

// writeStaticPage отдаёт встроенную HTML-страницу под политикой безопасности
// стенда: страница не может ни загрузить внешний ресурс, ни обратиться наружу.
func writeStaticPage(w http.ResponseWriter, body []byte) {
	w.Header().Set(headerContentType, "text/html; charset=utf-8")
	w.Header().Set(headerCSP, contentSecurityPolicy)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	noStore(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// consumersResponse — список систем-потребителей для выпадающего списка стенда.
type consumersResponse struct {
	Consumers []consumerBrief `json:"consumers"`
	// LLMMode перечислим (alfagen|stub) и секретом не является: он показывает
	// жюри, идёт ли демонстрация с обращением в сеть.
	LLMMode string `json:"llm_mode"`
	// PIITypes — реестр типов ПД. Метрики отдают машинные ключи типов, и без
	// реестра дашборд стенда показывал бы жюри «passport_number» вместо
	// «Серия и номер паспорта» или держал бы второй словарь в JS.
	PIITypes []piiTypeBrief `json:"pii_types"`
}

type consumerBrief struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// piiTypeBrief — тип ПД из реестра internal/pii. Реестр публичен: он же
// описан в README и зашит в плейсхолдеры, которые видит любой вызывающий.
type piiTypeBrief struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	// Required — тип входит в обязательное покрытие ТЗ.
	Required bool `json:"required"`
}

// handleConsumers отдаёт идентификаторы потребителей, режим работы с моделью
// и реестр типов ПД.
//
// Ключ не требуется, но и раскрывать нечего: наружу идут те же сведения, что
// уже отдаёт /readyz, плюс общий для всех реестр типов. Ключи доступа и
// политики потребителей — какие типы кто маскирует и какой стратегией — сюда
// не попадают: их возвращает только аутентифицированный /api/v1/analyze.
func (h *uiHandler) handleConsumers(w http.ResponseWriter, _ *http.Request) {
	snap := h.srv.deps.Config.Current()
	all := snap.Consumers.All()
	types := pii.All()
	out := consumersResponse{
		Consumers: make([]consumerBrief, 0, len(all)),
		LLMMode:   snap.LLM.Mode,
		PIITypes:  make([]piiTypeBrief, 0, len(types)),
	}
	for _, c := range all {
		out.Consumers = append(out.Consumers, consumerBrief{ID: c.ID, Enabled: c.Enabled})
	}
	for _, t := range types {
		out.PIITypes = append(out.PIITypes, piiTypeBrief{
			Key: t.Key(), Label: t.Label(), Placeholder: t.Placeholder(), Required: t.Required(),
		})
	}
	noStore(w)
	writeJSON(w, http.StatusOK, out)
}

// analyzeRequest — тело запроса стенда.
type analyzeRequest struct {
	// Text — текст, который ввело жюри.
	Text string `json:"text"`
	// Consumer — чья политика применяется. Пусто — политика владельца ключа.
	Consumer string `json:"consumer"`
}

// analyzeResponse — разбор одного прогона по шагам.
//
// Значения персональных данных в ответе есть только там, где они и так
// принадлежат вызывающему: это его собственный текст и восстановленный для
// него ответ. Спаны передаются смещениями, а не значениями.
type analyzeResponse struct {
	RequestID string       `json:"request_id"`
	Consumer  consumerView `json:"consumer"`
	Model     modelView    `json:"model"`
	// Spans — всё, что нашла детекция, в порядке появления.
	Spans []spanView `json:"spans"`
	// Summary — счётчики по типам.
	Summary []summaryRow `json:"summary"`
	// MaskedText — текст после маскирования, полученный диагностическим
	// прогоном тех же этапов.
	MaskedText string `json:"masked_text"`
	// SentToModel — что фактически ушло в модель.
	SentToModel sentView `json:"sent_to_model"`
	// LeakCheck — поиск каждого замаскированного значения в отправленном теле.
	LeakCheck leakView `json:"leak_check"`
	// ModelResponseRaw — ответ модели до восстановления.
	ModelResponseRaw string `json:"model_response_raw"`
	// ModelResponseRestored — ответ, который получил бы потребитель.
	ModelResponseRestored string      `json:"model_response_restored"`
	Timings               timingsView `json:"timings_ms"`
	// ChainStatus: ok | fail_closed | upstream_error | response_error.
	ChainStatus string   `json:"chain_status"`
	ChainNote   string   `json:"chain_note,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

type consumerView struct {
	ID              string `json:"id"`
	Profile         string `json:"profile"`
	DefaultStrategy string `json:"default_strategy"`
	Demask          bool   `json:"demask"`
	MaskedTypes     int    `json:"masked_types"`
}

type modelView struct {
	Mode string `json:"mode"`
	Name string `json:"name"`
}

type spanView struct {
	// Start и End — смещения в байтах UTF-8 в исходном тексте.
	Start int    `json:"start"`
	End   int    `json:"end"`
	Type  string `json:"type"`
	Label string `json:"label"`
	// Confidence — уровень уверенности: certain, strong или weak.
	Confidence string `json:"confidence"`
	// Rule — имя сработавшего правила: решение объяснимо конкретным правилом.
	Rule string `json:"rule"`
	// Masked сообщает, дошёл ли спан до замены после правил политики.
	Masked      bool   `json:"masked"`
	Replacement string `json:"replacement,omitempty"`
}

type summaryRow struct {
	Type     string `json:"type"`
	Label    string `json:"label"`
	Detected int    `json:"detected"`
	Masked   int    `json:"masked"`
	Strategy string `json:"strategy"`
}

type sentView struct {
	// Performed сообщает, был ли вообще выпуск наружу.
	Performed bool `json:"performed"`
	// Body — тело запроса к модели, записанное на границе выпуска.
	Body string `json:"body,omitempty"`
	// Messages — содержимое сообщений отдельно, для чтения человеком.
	Messages []llm.Message `json:"messages,omitempty"`
}

type leakView struct {
	// Checked — сколько различных замаскированных значений проверено.
	Checked int `json:"checked"`
	// Found — сколько из них найдено в отправленном теле. Ожидается ноль.
	Found int `json:"found"`
}

// timingsView — длительности этапов в миллисекундах.
type timingsView struct {
	Detect  float64 `json:"detect"`
	Mask    float64 `json:"mask"`
	Protect float64 `json:"protect"`
	// LLM — ожидание модели. Во время сервиса не входит.
	LLM     float64 `json:"llm"`
	Restore float64 `json:"restore"`
	// Service — время сервиса: защита плюс восстановление, без модели.
	Service float64 `json:"service"`
}

// handleAnalyze реализует POST /api/v1/analyze.
//
// Обработчик проводит текст по двум дорожкам. Первая — диагностический прогон
// тех же этапов по отдельности: он даёт спаны для подсветки и разделяет время
// детекции и маскирования. Вторая — боевой путь через gateway.Proxy: именно он
// выпускает данные наружу, и именно его результат показывается в блоке «что
// фактически ушло в модель».
func (h *uiHandler) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	deps := h.srv.deps
	snap := deps.Config.Current()
	rid := requestID(r.Context())

	// Предел обработки действует и на стенде: демонстрация не должна вести себя
	// иначе, чем боевой путь. Ожидание модели в этот бюджет не входит и
	// ограничено своим таймаутом клиента, поэтому боевой путь получает не
	// этот контекст, а остаток предела в ProxyRequest.Budget: дедлайн общего
	// контекста оборвал бы и ожидание модели.
	ctx, cancel := context.WithTimeout(r.Context(), snap.Server.RequestTimeout.Duration())
	defer cancel()
	log := deps.Logger.With(logKeyRequestID, rid, logKeyEndpoint, "analyze")

	// Стенд — продуктовый эндпоинт: ключ обязателен, как и на /v1/*.
	caller, ok := snap.Consumers.ByKey(apiKey(r))
	if !ok {
		h.srv.unauthorized(w, r, log, obs.EndpointAnalyze, obs.OpProxy, started)
		return
	}
	// owner — предъявитель ключа, а не выбранный в списке потребитель: прогон
	// под чужой политикой принадлежит жюри, а не владельцу этой политики.
	log = log.With(logKeyOwner, caller.ID)
	// Лимит считается по предъявителю ключа, а не по выбранной политике:
	// квоту расходует ключ, какую бы политику жюри ни выбрало (P4-8).
	if !h.srv.allowModel(w, r, log, snap, caller.ID, obs.EndpointAnalyze, started) {
		return
	}

	req, ok := h.readAnalyze(w, r, snap.Server.MaxBodyBytes.Int64(), caller.ID, started)
	if !ok {
		return
	}

	consumer, err := h.pickConsumer(snap.Consumers, caller, req.Consumer)
	if err != nil {
		h.srv.forbidden(w, log, &denial{
			endpoint: obs.EndpointAnalyze, op: obs.OpProxy, consumerID: caller.ID,
			reason: "policy_not_available", msg: err.Error(), started: started,
		})
		return
	}

	model, err := h.proxy.client(snap)
	if err != nil {
		// Клиент не собран — до выпуска наружу дело не дошло. Текст ошибки
		// называет переменную окружения, но никогда её значение.
		log.Error("клиент модели не настроен", logKeyError, err.Error())
		h.finish(caller.ID, obs.OutcomeFailClosed, started, 0)
		writeError(w, http.StatusInternalServerError, msgNoModel)
		return
	}

	res := h.diagnose(ctx, req.Text, consumer)
	res.RequestID = rid
	res.Model = modelView{Mode: snap.LLM.Mode, Name: snap.LLM.Model}

	// Предел исчерпан уже диагностическим прогоном — боевой путь не
	// запускается: защита не успела бы завершиться, а ответ 429 с
	// Retry-After, как на /process и /api/v1/mask (REQ-604), клиенту понятен.
	deadline, _ := ctx.Deadline()
	if ctx.Err() != nil {
		h.overloaded(w, log, caller.ID, started, snap.Server.RequestTimeout.String())
		return
	}

	// Боевой путь. Модель задаётся явно, чтобы записанное тело совпадало с
	// тем, что сериализует клиент: он подставляет модель сам, если поле пусто.
	rec := &recordingChatter{next: model}
	chat := llm.Request{
		Model:    snap.LLM.Model,
		Messages: []llm.Message{{Role: "user", Content: req.Text}},
	}

	proxyStart := time.Now()
	out, perr := deps.Gateway.Proxy(r.Context(), rec, gateway.ProxyRequest{
		ID:     rid,
		Chat:   chat,
		Budget: time.Until(deadline),
	}, consumer)
	proxyEnd := time.Now()

	if !out.Sent && errors.Is(perr, context.DeadlineExceeded) {
		// Защита не уложилась в остаток предела — запрос в модель не
		// отправлялся. Управляемый отказ, а не 500.
		h.overloaded(w, log, caller.ID, started, snap.Server.RequestTimeout.String())
		return
	}
	// Значений больше предела замен: боевой путь отказал без выпуска
	// (fail-closed), и стенд отвечает тем же кодом, что и /api/v1/mask.
	spanLimit := !out.Sent && errors.Is(perr, gateway.ErrSpanLimit)

	// Приём на стенде включает диагностический прогон: именно он даёт спаны
	// для подсветки. Боевой путь начинается с proxyStart, и всё, что правее
	// на шкале, измерено на нём.
	tr := obs.NewTracer(deps.Recorder.Enabled(), started)
	tr.Mark(obs.StageAccept, started, proxyStart)
	markProxyTrace(&tr, proxyStart, proxyEnd, &out)

	h.fillChain(&res, req.Text, rec, out, perr, proxyStart, proxyEnd)

	outcome := h.reportAnalyze(log, caller.ID, consumer.ID, started, &res, &out, perr)
	if spanLimit {
		// Частичный разбор не показывается: подсветка 20 000 спанов из
		// 20 050 выглядела бы как успешная защита. Запись в историю ниже
		// остаётся — отказ виден на стенде с исходом fail_closed.
		log.Warn("стенд: значений больше предела замен, запрос в модель не отправлен",
			logKeyConsumer, consumer.ID, "max_spans", consumer.MaxSpans,
			logKeyOutcome, obs.OutcomeFailClosed.String())
		writeError(w, http.StatusRequestEntityTooLarge, spanLimitMessage(consumer.MaxSpans))
	} else {
		writeJSON(w, http.StatusOK, res)
	}

	// Владелец записи — предъявивший ключ, а не выбранный в списке
	// потребитель: иначе прогон под чужой политикой исчезал бы из собственной
	// истории жюри, а владелец этой политики видел бы чужое обращение.
	service := time.Since(started) - out.LLM
	if service < 0 {
		service = 0
	}
	// Запись ответа: разбор в JSON, строка журнала и отправка тела.
	tr.MarkDur(obs.StageRespond, proxyEnd, time.Since(proxyEnd))
	entry := obs.Record{
		At:             started,
		RequestID:      rid,
		Caller:         caller.ID,
		Consumer:       consumer.ID,
		Endpoint:       obs.EndpointAnalyze,
		Op:             obs.OpProxy,
		Outcome:        outcome,
		Detected:       out.Detected,
		Masked:         out.Masked,
		DetectedCounts: out.DetectedCounts,
		MaskedCounts:   out.MaskedCounts,
		BytesIn:        int32(out.BytesIn),
		BytesOut:       int32(out.BytesOut),
		Service:        service,
		LLM:            out.LLM,
		Trace:          tr.Trace(),
	}
	for t := 1; t < pii.Count; t++ {
		entry.MaskedCounts[t] += out.ResponseMaskedCounts[t]
	}
	deps.Recorder.Record(&entry)
}

// readAnalyze читает и проверяет тело запроса стенда. При отказе сам отвечает
// клиенту, фиксирует метрики и возвращает ложь.
func (h *uiHandler) readAnalyze(w http.ResponseWriter, r *http.Request, limit int64, callerID string,
	started time.Time) (analyzeRequest, bool) {

	var req analyzeRequest
	fail := func(out obs.Outcome) { h.finish(callerID, out, started, 0) }
	if !decodeJSONBody(w, r, limit, &req, fail) {
		return req, false
	}
	if strings.TrimSpace(req.Text) == "" {
		fail(obs.OutcomeBadRequest)
		writeError(w, http.StatusBadRequest, "поле text обязательно и не может быть пустым")
		return req, false
	}
	return req, true
}

// reportAnalyze фиксирует метрики и строку журнала завершённого прогона
// стенда и возвращает его исход.
//
// В журнал идут типы, счётчики и длительности, но не текст и не значения.
func (h *uiHandler) reportAnalyze(log *slog.Logger, callerID, consumerID string, started time.Time,
	res *analyzeResponse, out *gateway.ProxyResult, perr error) obs.Outcome {

	deps := h.srv.deps
	llmSeconds := out.LLM.Seconds()
	if out.Sent {
		outcome := obs.OutcomeOK
		if errors.Is(perr, gateway.ErrUpstream) {
			outcome = obs.OutcomeUpstreamError
		}
		deps.Metrics.LLM(outcome, llmSeconds)
	}
	deps.Metrics.PII(&out.DetectedCounts, &out.MaskedCounts)
	deps.Metrics.Traffic(out.BytesIn, out.BytesOut)
	outcome := outcomeOf(perr)
	h.finish(callerID, outcome, started, llmSeconds)

	log.Info("стенд: прогон выполнен",
		logKeyConsumer, consumerID,
		"op", obs.OpProxy.String(),
		"chain_status", res.ChainStatus,
		"upstream_class", out.UpstreamClass,
		"upstream_status", out.UpstreamStatus,
		logKeyDetectedTypes, out.Detected.Keys(),
		logKeyMaskedTypes, out.Masked.Keys(),
		logKeyMaskedCount, out.Replaced,
		logKeyRestoredCount, out.Restored,
		"leak_checked", res.LeakCheck.Checked,
		"leak_found", res.LeakCheck.Found,
		logKeyBytesIn, out.BytesIn,
		"llm_ms", out.LLM.Milliseconds(),
		logKeyDurationMS, time.Since(started).Milliseconds(),
	)
	if res.LeakCheck.Found > 0 {
		// Такого быть не должно: предусловие выпуска проверяет то же самое и
		// строже. Если всё же случилось — это блокирующий дефект, и он обязан
		// быть виден в журнале.
		log.Error("стенд: замаскированное значение найдено в отправленном теле",
			logKeyConsumer, consumerID, "found", res.LeakCheck.Found)
	}
	return outcome
}

// historyRow — строка таблицы истории запросов.
//
// В строке нет ни одного поля, способного унести значение персональных данных:
// идентификаторы, перечислимые метки, имена типов, счётчики и длительности.
type historyRow struct {
	Seq       uint64 `json:"seq"`
	At        string `json:"at"`
	RequestID string `json:"request_id"`
	Consumer  string `json:"consumer"`
	Endpoint  string `json:"endpoint"`
	Op        string `json:"op"`
	Outcome   string `json:"outcome"`
	Degraded  bool   `json:"degraded"`
	// Types — имена найденных типов ПД.
	Types []string `json:"types"`
	// MaskedTypes — имена замаскированных типов ПД.
	MaskedTypes []string `json:"masked_types"`
	// Detected и Masked — суммарные счётчики.
	Detected int `json:"detected"`
	Masked   int `json:"masked"`
	BytesIn  int `json:"bytes_in"`
	// ServiceMS — время сервиса, LLMMS — ожидание модели. Раздельно всегда.
	ServiceMS float64 `json:"service_ms"`
	LLMMS     float64 `json:"llm_ms"`
	// Access — чьим обращением сделана запись: key — по ключу, и тогда она
	// видна только владельцу ключа; public — контракт /process без ключа,
	// видимый любому допущенному ключу (Б4-17). AccessNote — та же пометка
	// для человека.
	Access     string `json:"access"`
	AccessNote string `json:"access_note,omitempty"`
}

// Пометки видимости строки истории.
const (
	accessKey        = "key"
	accessPublic     = "public"
	accessPublicNote = "контракт /process, без ключа: запись видна любому ключу стенда"
)

type historyResponse struct {
	// Enabled сообщает, ведётся ли история. Выключенный буфер — не ошибка.
	Enabled bool         `json:"enabled"`
	Cap     int          `json:"cap"`
	Rows    []historyRow `json:"rows"`
}

// handleHistory отдаёт историю запросов, доступную предъявителю ключа.
func (h *uiHandler) handleHistory(w http.ResponseWriter, r *http.Request) {
	caller, ok := h.authorize(w, r)
	if !ok {
		return
	}
	rec := h.srv.deps.Recorder
	limit := intParam(r, queryLimit, 50, rec.HistoryCap())
	records := rec.History(caller.ID, limit)

	out := historyResponse{Enabled: rec.Enabled(), Cap: rec.HistoryCap(), Rows: make([]historyRow, 0, len(records))}
	for i := range records {
		out.Rows = append(out.Rows, historyRowOf(&records[i]))
	}
	noStore(w)
	writeJSON(w, http.StatusOK, out)
}

func historyRowOf(rc *obs.Record) historyRow {
	row := historyRow{
		Seq:       rc.Seq,
		At:        rc.At.Format(time.RFC3339Nano),
		RequestID: rc.RequestID,
		Consumer:  rc.Consumer,
		Endpoint:  rc.Endpoint.String(),
		Op:        rc.Op.String(),
		Outcome:   rc.Outcome.String(),
		Degraded:  rc.Degraded,
		Types:     labelsOf(rc.Detected),
		BytesIn:   int(rc.BytesIn),
		ServiceMS: ms(rc.Service),
		LLMMS:     ms(rc.LLM),
		Access:    accessKey,
	}
	if rc.Caller == "" {
		// Записи без предъявителя ключа видны всем допущенным (правило
		// obs.visible): это демонстрация журнала контракта автопроверки, и
		// ответ говорит об этом прямо, а не оставляет догадываться, почему в
		// истории ключа demo видны чужие запросы.
		row.Access = accessPublic
		row.AccessNote = accessPublicNote
	}
	row.MaskedTypes = labelsOf(rc.Masked)
	for t := 1; t < pii.Count; t++ {
		row.Detected += int(rc.DetectedCounts[t])
		row.Masked += int(rc.MaskedCounts[t])
	}
	return row
}

// labelsOf переводит битовую маску типов в человекочитаемые имена.
func labelsOf(s pii.Set) []string {
	ts := s.Types()
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Label())
	}
	return out
}

// traceSpanView — отрезок трассировки на шкале.
type traceSpanView struct {
	Stage string  `json:"stage"`
	Label string  `json:"label"`
	Depth int     `json:"depth"`
	AtMS  float64 `json:"at_ms"`
	MS    float64 `json:"ms"`
	// Service — входит ли отрезок во время сервиса. Ложь только у ожидания
	// модели: страница обязана показать это отдельной дорожкой.
	Service bool `json:"service"`
}

// traceTypeRow — разбор маскирования по одному типу ПД.
type traceTypeRow struct {
	Type     string `json:"type"`
	Label    string `json:"label"`
	Detected int    `json:"detected"`
	Masked   int    `json:"masked"`
}

// traceResponse — разбор одного запроса из истории.
type traceResponse struct {
	Row historyRow `json:"row"`
	// Spans — отрезки этапов в порядке выполнения.
	Spans []traceSpanView `json:"spans"`
	// TotalMS — длина трассировки, ServiceMS — её часть, входящая во время
	// сервиса, WaitMS — ожидание модели.
	TotalMS   float64        `json:"total_ms"`
	ServiceMS float64        `json:"service_ms"`
	WaitMS    float64        `json:"wait_ms"`
	Types     []traceTypeRow `json:"types"`
}

// handleTrace отдаёт трассировку и разбор одного запроса из истории.
func (h *uiHandler) handleTrace(w http.ResponseWriter, r *http.Request) {
	caller, ok := h.authorize(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("id")
	rc, found := h.srv.deps.Recorder.Find(caller.ID, id)
	if !found {
		// Чужая запись неотличима от несуществующей: перебор идентификаторов
		// не должен раскрывать факт обращения другого потребителя.
		writeError(w, http.StatusNotFound, "запрос не найден в истории")
		return
	}

	out := traceResponse{
		Row:       historyRowOf(&rc),
		Spans:     make([]traceSpanView, 0, obs.StageCount),
		TotalMS:   nsToMS(rc.Trace.TotalNs()),
		ServiceMS: nsToMS(rc.Trace.ServiceNs()),
		WaitMS:    nsToMS(rc.Trace.WaitNs()),
	}
	for i := 0; i < obs.StageCount; i++ {
		st := obs.Stage(i)
		sp, has := rc.Trace.Span(st)
		if !has {
			continue
		}
		depth := 0
		if !st.Root() {
			depth = 1
		}
		out.Spans = append(out.Spans, traceSpanView{
			Stage: st.Key(), Label: st.Label(), Depth: depth,
			AtMS: nsToMS(sp.StartNs), MS: nsToMS(sp.DurNs), Service: st.InService(),
		})
	}
	for t := 1; t < pii.Count; t++ {
		if rc.DetectedCounts[t] == 0 && rc.MaskedCounts[t] == 0 {
			continue
		}
		typ := pii.Type(t)
		out.Types = append(out.Types, traceTypeRow{
			Type: typ.Key(), Label: typ.Label(),
			Detected: int(rc.DetectedCounts[t]), Masked: int(rc.MaskedCounts[t]),
		})
	}
	noStore(w)
	writeJSON(w, http.StatusOK, out)
}

// journalRow — строка потока журнала.
type journalRow struct {
	Seq       uint64 `json:"seq"`
	At        string `json:"at"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
	Consumer  string `json:"consumer,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Op        string `json:"op,omitempty"`
	Outcome   string `json:"outcome,omitempty"`
	// Types — машинные ключи типов ПД: по ним работает фильтр на странице.
	Types      []string `json:"types,omitempty"`
	TypeLabels []string `json:"type_labels,omitempty"`
	Masked     int      `json:"masked,omitempty"`
	DurationMS int      `json:"duration_ms,omitempty"`
}

type journalResponse struct {
	Enabled bool `json:"enabled"`
	Cap     int  `json:"cap"`
	// Seq — номер последней отданной записи. Страница возвращает его в
	// следующем запросе параметром after, и опрос становится разностным.
	Seq  uint64       `json:"seq"`
	Rows []journalRow `json:"rows"`
}

// handleJournal отдаёт поток журнала, доступный предъявителю ключа.
func (h *uiHandler) handleJournal(w http.ResponseWriter, r *http.Request) {
	caller, ok := h.authorize(w, r)
	if !ok {
		return
	}
	rec := h.srv.deps.Recorder
	var after uint64
	if v, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64); err == nil {
		after = v
	}
	limit := intParam(r, queryLimit, 200, rec.JournalCap())
	entries := rec.Journal(caller.ID, after, limit)

	out := journalResponse{Enabled: rec.JournalCap() > 0, Cap: rec.JournalCap(), Seq: after}
	out.Rows = make([]journalRow, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		row := journalRow{
			Seq:        e.Seq,
			At:         e.At.Format(time.RFC3339Nano),
			Level:      strings.ToLower(e.Level.String()),
			Message:    e.Message,
			RequestID:  e.RequestID,
			Consumer:   e.Consumer,
			Endpoint:   e.Endpoint,
			Op:         e.Op,
			Outcome:    e.Outcome,
			Masked:     int(e.MaskedCount),
			DurationMS: int(e.DurationMS),
		}
		types := e.Detected.Union(e.Masked)
		row.Types = types.Keys()
		row.TypeLabels = labelsOf(types)
		out.Rows = append(out.Rows, row)
		out.Seq = e.Seq
	}
	noStore(w)
	writeJSON(w, http.StatusOK, out)
}

// authorize проверяет ключ доступа и возвращает потребителя-владельца.
//
// Новые эндпоинты наблюдаемости — продуктовые: без ключа они отвечают 401, как
// и /api/v1/analyze. Исключение сделано только для самой страницы по GET /:
// она статический документ и сама по себе ничего не раскрывает.
//
// Отказ пишется в журнал и метрики так же, как на остальных продуктовых
// маршрутах (P4-9), но успешное чтение не учитывается: опрос страницы раз в
// секунду иначе заполнил бы журнал и счётчики собственными обращениями.
func (h *uiHandler) authorize(w http.ResponseWriter, r *http.Request) (*policy.Consumer, bool) {
	started := time.Now()
	caller, ok := h.srv.deps.Config.Current().Consumers.ByKey(apiKey(r))
	if !ok {
		rid := "r" + strconv.FormatUint(requestSeq.Add(1), 36)
		w.Header().Set(headerRequestID, rid)
		log := h.srv.deps.Logger.With(logKeyRequestID, rid, logKeyEndpoint, obs.EndpointUI.String())
		h.srv.unauthorized(w, r, log, obs.EndpointUI, obs.OpRead, started)
		return nil, false
	}
	return caller, true
}

// queryLimit — параметр запроса с числом строк в ответе.
const queryLimit = "limit"

// intParam читает положительный целочисленный параметр запроса с потолком
// ceiling; нулевой потолок не ограничивает.
func intParam(r *http.Request, name string, def, ceiling int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || v <= 0 {
		v = def
	}
	if ceiling > 0 && v > ceiling {
		v = ceiling
	}
	return v
}

func nsToMS(ns int64) float64 { return float64(ns) / 1e6 }

// pickConsumer выбирает потребителя, чья политика применяется к прогону.
//
// По умолчанию это владелец ключа. Явный выбор из списка нужен для
// демонстрации: одно и то же обращение показывается под разными политиками.
// Данные чужого потребителя это не открывает — соответствия живут в пределах
// одного запроса, а хранилище пишется под выбранным потребителем.
//
// Выбранная политика задаёт только правила маскирования. Право
// демаскирования — свойство ключа (Ж-2, T-56): предъявитель ключа без права
// demask, выбрав политику с правом, получает её правила маскирования, но не
// восстановленный ответ модели.
func (h *uiHandler) pickConsumer(reg *policy.Registry, caller *policy.Consumer, id string) (*policy.Consumer, error) {
	c := caller
	if id != "" && id != caller.ID {
		found, ok := reg.ByID(id)
		if !ok || !found.Enabled {
			return nil, errors.New("система-потребитель не настроена или отключена")
		}
		c = found
		if !caller.Demask && c.Demask {
			// Копия: политика из реестра общая для всех запросов и не
			// меняется. Поля копии — неизменяемые после сборки значения.
			restricted := *c
			restricted.Demask = false
			c = &restricted
		}
	}
	if !c.MaskingEnabled {
		// Маскирование отключено административно: прогон отправил бы в модель
		// незащищённый текст. На демонстрации это провал ключевой функции, а
		// не иллюстрация настройки, поэтому стенд такой прогон не выполняет.
		return nil, errors.New("у системы-потребителя маскирование отключено: стенд не выпускает незащищённый текст")
	}
	return c, nil
}

// diagnose выполняет этапы защиты по отдельности, чтобы показать спаны и
// развести время детекции и маскирования.
//
// Порядок вызовов повторяет gateway.Mask: те же токенизация, движок, правила
// политики и применение замен. Расхождение результата с боевым путём
// отмечается в notes, а не прячется.
func (h *uiHandler) diagnose(ctx context.Context, text string, c *policy.Consumer) analyzeResponse {
	var (
		doc  lex.Doc
		cand detect.Candidates
		det  detect.Result
		appl mask.Applier
	)

	detectStart := time.Now()
	lex.Tokenize(text, &doc)
	if _, err := h.srv.deps.Gateway.Engine().Detect(ctx, &doc, c.DetectOptions(), &cand, &det); err != nil {
		// Бюджет запроса исчерпан. Стенд не показывает частичный разбор:
		// неполная разметка на демонстрации вводит в заблуждение сильнее, чем отказ.
		return analyzeResponse{Notes: []string{"разбор не уложился в отведённое время"}}
	}
	if det.LimitExceeded {
		// Разметка неполна по той же причине: значения сверх предела замен в
		// неё не вошли, и маска по ней выглядела бы защищённой, не будучи
		// такой.
		return analyzeResponse{Notes: []string{"значений больше предела замен на один запрос"}}
	}
	selected := c.Filter(&det)
	detectMS := msSince(detectStart)

	maskStart := time.Now()
	// Повторы отобранных значений закрываются так же, как на боевом пути
	// (gateway.Mask, С-4), — иначе показанная маска разошлась бы с
	// отправленной.
	selected = appl.CoverRepeats(text, selected)
	if c.MaxSpans > 0 && len(selected) > c.MaxSpans {
		return analyzeResponse{Notes: []string{"значений больше предела замен на один запрос"}}
	}
	masked, applied := appl.Apply(text, selected, c.Strategy)
	maskMS := msSince(maskStart)

	// Повторы в разборе детекции не значатся: подсветка берёт их из
	// отобранного списка, чтобы жюри видело каждое скрытое вхождение.
	shown := det.Spans
	if reps := repeatsOf(selected); len(reps) > 0 {
		shown = append(slices.Clone(det.Spans), reps...)
		slices.SortStableFunc(shown, func(a, b detect.Span) int { return int(a.Start) - int(b.Start) })
	}

	var maskedCounts [pii.Count]uint16
	detectedCounts := det.Counts
	spans := spanViewsOf(shown, applied, &detectedCounts, &maskedCounts)
	summary := summaryOf(c, &detectedCounts, &maskedCounts)

	return analyzeResponse{
		Consumer: consumerView{
			ID:              c.ID,
			Profile:         c.Profile.String(),
			DefaultStrategy: c.DefaultStrategyName(),
			Demask:          c.Demask,
			MaskedTypes:     c.Types.Len(),
		},
		Spans:      spans,
		Summary:    summary,
		MaskedText: masked,
		Timings:    timingsView{Detect: detectMS, Mask: maskMS},
	}
}

// spanViewsOf переводит показываемые спаны в представление стенда и
// досчитывает счётчики: повтор добавляется к найденным, спан, дошедший до
// замены, — к замаскированным.
func spanViewsOf(shown []detect.Span, applied []mask.Applied, detected, masked *[pii.Count]uint16) []spanView {
	byStart := make(map[int32]mask.Applied, len(applied))
	for _, a := range applied {
		byStart[a.Start] = a
	}
	spans := make([]spanView, 0, len(shown))
	for _, sp := range shown {
		if sp.Rule == mask.RuleRepeat {
			detected[sp.Type]++
		}
		v := spanView{
			Start:      int(sp.Start),
			End:        int(sp.End),
			Type:       sp.Type.Key(),
			Label:      sp.Type.Label(),
			Confidence: sp.Conf.String(),
			Rule:       sp.Rule,
		}
		if a, ok := byStart[sp.Start]; ok && a.End == sp.End {
			v.Masked = true
			v.Replacement = a.Replacement
			masked[sp.Type]++
		}
		spans = append(spans, v)
	}
	return spans
}

// summaryOf собирает счётчики по типам, встретившимся в прогоне, со
// стратегией маскирования потребителя c.
func summaryOf(c *policy.Consumer, detected, masked *[pii.Count]uint16) []summaryRow {
	summary := make([]summaryRow, 0, 8)
	for _, t := range pii.All() {
		if detected[t] == 0 && masked[t] == 0 {
			continue
		}
		summary = append(summary, summaryRow{
			Type:     t.Key(),
			Label:    t.Label(),
			Detected: int(detected[t]),
			Masked:   int(masked[t]),
			Strategy: c.StrategyName(t),
		})
	}
	return summary
}

// repeatsOf возвращает спаны-повторы, добавленные mask.CoverRepeats.
func repeatsOf(spans []detect.Span) []detect.Span {
	var out []detect.Span
	for _, sp := range spans {
		if sp.Rule == mask.RuleRepeat {
			out = append(out, sp)
		}
	}
	return out
}

// fillChain переносит в ответ результат боевого пути: записанное тело,
// ответы модели, тайминги и исход цепочки.
func (h *uiHandler) fillChain(res *analyzeResponse, text string, rec *recordingChatter, out gateway.ProxyResult,
	perr error, proxyStart, proxyEnd time.Time) {

	res.SentToModel = sentView{Performed: rec.called}
	if rec.called {
		res.SentToModel.Body = string(rec.body)
		res.SentToModel.Messages = rec.request.Messages
		res.Timings.Protect = ms(rec.startedAt.Sub(proxyStart))
		res.Timings.LLM = ms(out.LLM)
		res.Timings.Restore = ms(proxyEnd.Sub(rec.finishedAt))
		if res.Timings.Restore < 0 {
			res.Timings.Restore = 0
		}
	} else {
		// Наружу ничего не ушло: всё время заняла защита запроса.
		res.Timings.Protect = ms(proxyEnd.Sub(proxyStart))
	}
	res.Timings.Service = res.Timings.Protect + res.Timings.Restore

	res.LeakCheck = leakCheck(text, res.Spans, res.SentToModel)
	res.ModelResponseRaw = rec.content()
	if out.Response != nil && len(out.Response.Choices) > 0 {
		res.ModelResponseRestored = out.Response.Choices[0].Message.Content
	}

	switch {
	case errors.Is(perr, gateway.ErrFailClosed):
		res.ChainStatus = "fail_closed"
		res.ChainNote = "сработал инвариант fail-closed: предусловие выпуска не выполнено, запрос в модель не отправлялся"
	case errors.Is(perr, gateway.ErrUpstream):
		res.ChainStatus = "upstream_error"
		res.ChainNote = "модель не ответила; защита запроса при этом выполнена полностью"
		// Причина отказа приходит из транспорта уже разобранной: класс и код
		// ответа, без тела. Без неё сообщение на стенде одинаково выглядит и
		// при неверном ключе, и при отказе проверки сертификата, и при
		// недоступности хоста — разобрать такое на защите нечем.
		if note := out.UpstreamNote(); note != "" {
			res.ChainNote += ". Причина: " + note
		}
	case perr != nil:
		res.ChainStatus = "response_error"
		res.ChainNote = "ответ модели не прошёл повторную проверку и не отдаётся"
	default:
		res.ChainStatus = "ok"
	}

	// Сверка дорожек. Диагностический прогон и боевой путь выполняют одни и те
	// же шаги, поэтому обязаны дать один и тот же защищённый текст. Расхождение
	// не скрывается: показанное жюри должно совпадать с отправленным.
	if rec.called && len(rec.request.Messages) == 1 && rec.request.Messages[0].Content != res.MaskedText {
		res.Notes = append(res.Notes,
			"Диагностический прогон и боевой путь дали разный защищённый текст; в блоке «что ушло в модель» показан боевой путь.")
	}
}

// leakCheck ищет каждое замаскированное значение в фактически отправленном
// теле по отдельности.
//
// Сравнение целого текста не годится: оно пропускает частичную утечку.
// Проверка дублирует предусловие выпуска сознательно — на демонстрации важно
// не «мы проверили это в тестах», а «проверено вот на этом теле прямо сейчас».
//
// Область поиска — содержимое отправленных сообщений: текст потребителя
// попадает в тело запроса только туда, а остальные поля собраны сервисом из
// конфигурации и от текста не зависят. Искать по всему телу было бы хуже, а
// не строже: идентификатор модели содержит цифры, и односимвольное значение
// совпало бы с ними, превратив честную проверку в ложную тревогу.
//
// Проверяются только замаскированные значения: тип, который политика
// потребителя маскировать не обязана, уходит в модель законно, и называть это
// утечкой было бы подлогом.
func leakCheck(text string, spans []spanView, sent sentView) leakView {
	var out leakView
	seen := make(map[string]struct{}, len(spans))

	var hay strings.Builder
	for _, m := range sent.Messages {
		hay.WriteString(m.Content)
		hay.WriteByte('\n')
	}
	body := hay.String()

	for _, sp := range spans {
		if !sp.Masked || sp.Start < 0 || sp.End > len(text) || sp.Start >= sp.End {
			continue
		}
		value := text[sp.Start:sp.End]
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		out.Checked++
		if sent.Performed && strings.Contains(body, value) {
			out.Found++
		}
	}
	return out
}

// outcomeOf переводит ошибку цепочки в исход для метрик.
func outcomeOf(err error) obs.Outcome {
	switch {
	case err == nil:
		return obs.OutcomeOK
	case errors.Is(err, gateway.ErrUpstream):
		return obs.OutcomeUpstreamError
	default:
		return obs.OutcomeFailClosed
	}
}

// overloaded отвечает 429 с Retry-After: защита не уложилась в предел
// обработки, и запрос в модель не отправлялся.
func (h *uiHandler) overloaded(w http.ResponseWriter, log *slog.Logger, caller string, started time.Time, limit string) {
	log.Warn("стенд: обработка не уложилась в предел", logKeyLimit, limit,
		logKeyOutcome, obs.OutcomeOverloaded.String())
	h.finish(caller, obs.OutcomeOverloaded, started, 0)
	setRetryAfter(w, retryAfterSeconds)
	writeError(w, http.StatusTooManyRequests, msgDeadline)
}

// finish фиксирует метрики запроса стенда.
//
// Время ожидания модели вычитается: организаторы измеряют время сервиса, и
// чужая задержка в него входить не должна.
func (h *uiHandler) finish(caller string, out obs.Outcome, started time.Time, llmSeconds float64) {
	service := time.Since(started).Seconds() - llmSeconds
	if service < 0 {
		service = 0
	}
	h.srv.deps.Metrics.Request(obs.EndpointAnalyze, obs.OpProxy, out, service)
	h.srv.deps.Metrics.ConsumerRequest(caller, obs.EndpointAnalyze, out)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func msSince(t time.Time) float64 { return ms(time.Since(t)) }

// recordingChatter — прослойка между точкой выпуска наружу и клиентом модели.
//
// Прослойка стоит в самом пути запроса, а не пересобирает тело для показа:
// иначе стенд показывал бы не отправленное, а своё представление о нём —
// ровно то, чему жюри верить не обязано.
//
// Экземпляр живёт в пределах одного запроса стенда и между горутинами не
// разделяется.
type recordingChatter struct {
	next llm.Chatter

	called     bool
	request    llm.Request
	body       []byte
	response   *llm.Response
	startedAt  time.Time
	finishedAt time.Time
}

// Chat записывает переданный запрос и ответ модели, ничего в них не меняя.
func (r *recordingChatter) Chat(ctx context.Context, req llm.Request) (*llm.Response, error) {
	r.called = true
	r.request = req
	// Клиент сериализует ту же структуру тем же кодировщиком, поэтому
	// записанные байты совпадают с уходящими в сеть.
	if b, err := json.Marshal(req); err == nil {
		r.body = b
	}

	r.startedAt = time.Now()
	resp, err := r.next.Chat(ctx, req)
	r.finishedAt = time.Now()

	if resp != nil {
		// Копия: дальше по пути варианты ответа переписываются
		// восстановленными значениями, а стенд обязан показать ответ как есть.
		clone := *resp
		clone.Choices = append([]llm.Choice(nil), resp.Choices...)
		r.response = &clone
	}
	return resp, err
}

// content возвращает содержимое первого варианта ответа модели.
func (r *recordingChatter) content() string {
	if r.response == nil || len(r.response.Choices) == 0 {
		return ""
	}
	return r.response.Choices[0].Message.Content
}
