package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/detect"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/store"
)

// Тесты доступа и ограничений на корневом обработчике сервера (T-68, раунд 4
// жюри): лимит частоты к модели, аудит отказов доступа, метка consumer,
// 405 JSON, предел payload_id, пометка записей /process в истории стенда.
// Модель — режим stub, в сеть тесты не выходят. Ключи и значения
// синтетические.

const (
	routerLimitedKey  = "r4-limited-key-0123456789"
	routerFreeKey     = "r4-free-key-9876543210"
	routerNoDemaskKey = "r4-nodemask-key-5555555"
	// routerProbeKey — непринятый ключ, который тест ищет в журнале и метриках.
	routerProbeKey = "r4-probe-SECRET-4242-zz"
)

const routerConfig = `
server:
  addr: ":0"
  max_body_bytes: 1MiB
  max_concurrent: 16
store:
  ttl: 1h
llm:
  mode: stub
consumers:
  - id: benchmark
    types: [all]
    demask: true
  - id: limited
    api_key: ` + routerLimitedKey + `
    types: [all]
    model_rate: {rps: 1, burst: 2}
  - id: free
    api_key: ` + routerFreeKey + `
    types: [all]
  - id: nodemask
    api_key: ` + routerNoDemaskKey + `
    types: [all]
    demask: false
`

type routerServer struct {
	ctx     context.Context
	srv     *Server
	metrics *obs.Metrics
	mu      sync.Mutex
	log     bytes.Buffer
}

func (r *routerServer) journal() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.log.String()
}

func newRouterServer(t *testing.T) *routerServer {
	t.Helper()
	holder := newTestHolder(t, routerConfig)
	st := store.NewMemory(holder.Current().Store)
	t.Cleanup(func() { _ = st.Close() })

	r := &routerServer{ctx: t.Context(), metrics: obs.NewMetrics()}
	r.srv = NewServer(Deps{
		Config:    holder,
		Gateway:   gateway.New(detect.New(nil, proxyMarkScanner{}), st),
		Metrics:   r.metrics,
		Logger:    slog.New(slog.NewJSONHandler(lockedWriter{mu: &r.mu, buf: &r.log}, nil)),
		Recorder:  obs.NewRecorder(50, 100),
		Version:   "test",
		StartedAt: time.Now(),
	})
	return r
}

// do отправляет запрос через настоящий корневой обработчик сервера — с
// проверкой метода и маршрутизатором.
func (r *routerServer) do(method, path, key, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(r.ctx, method, path, strings.NewReader(body))
	req.Header.Set(headerContentType, jsonContentType)
	if key != "" {
		req.Header.Set(headerAPIKey, key)
	}
	rec := httptest.NewRecorder()
	r.srv.http.Handler.ServeHTTP(rec, req)
	return rec
}

func (r *routerServer) metricsText() string {
	return r.do(http.MethodGet, pathMetrics, "", "").Body.String()
}

const routerChat = `{"messages":[{"role":"user","content":"Добрый день, подготовьте ответ."}]}`

// Тела запросов и адрес клиента, общие для нескольких проверок.
const (
	textX         = `{"text":"x"}`
	unmaskX       = `{"masked":"x","id":"a"}`
	textGreeting  = `{"text":"Добрый день"}`
	limiterClient = "10.0.0.1"
	unknownRoute  = "/no-such-route"
	allowGetHead  = "GET, HEAD"
)

// TestModelRateLimitOnModelRoutes — строка 1: сверх всплеска запросы к модели
// по ключу с лимитом получают 429 с Retry-After и JSON; корзина общая для
// /v1/chat/completions и /api/v1/analyze и восполняется со временем.
func TestModelRateLimitOnModelRoutes(t *testing.T) {
	r := newRouterServer(t)
	now := time.Unix(1_000_000, 0)
	r.srv.limiter.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		if rec := r.do(http.MethodPost, pathChat, routerLimitedKey, routerChat); rec.Code != http.StatusOK {
			t.Fatalf("запрос %d в пределах всплеска: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	checkRateLimited(t, r.do(http.MethodPost, pathAnalyze, routerLimitedKey, textGreeting))
	if rec := r.do(http.MethodPost, pathChat, routerLimitedKey, routerChat); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("чат после исчерпания корзины вернул %d", rec.Code)
	}

	// Через секунду корзина пополнилась на один запрос.
	now = now.Add(time.Second)
	if rec := r.do(http.MethodPost, pathChat, routerLimitedKey, routerChat); rec.Code != http.StatusOK {
		t.Fatalf("после паузы запрос вернул %d: %s", rec.Code, rec.Body)
	}

	// Ключ без лимита и маршруты без модели не ограничены.
	for i := 0; i < 10; i++ {
		r.checkUnlimitedRoutes(t, i)
	}

	assertContainsAll(t, "метриках", r.metricsText(), []string{
		`aigw_requests_total{endpoint="analyze",op="proxy",outcome="rate_limited"} 1`,
		`aigw_consumer_requests_total{consumer="limited",endpoint="chat_completions",outcome="rate_limited"} 1`,
	})
	if !strings.Contains(r.journal(), "лимиту частоты") {
		t.Error("отказ по лимиту частоты не записан в журнал")
	}
}

// checkRateLimited проверяет отказ по лимиту частоты: 429, Retry-After не
// меньше секунды и JSON-тело с полем error.
func checkRateLimited(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("третий запрос к модели вернул %d, ожидался 429: %s", rec.Code, rec.Body)
	}
	retry, err := strconv.Atoi(rec.Header().Get(headerRetryAfter))
	if err != nil || retry < 1 {
		t.Fatalf("Retry-After = %q", rec.Header().Get(headerRetryAfter))
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == "" {
		t.Fatalf("тело 429 не JSON с полем error: %s", rec.Body)
	}
}

// checkUnlimitedRoutes — i-й запрос по ключу без лимита и по маршрутам без
// модели: ни один не ограничен лимитом частоты.
func (r *routerServer) checkUnlimitedRoutes(t *testing.T, i int) {
	t.Helper()
	if rec := r.do(http.MethodPost, pathChat, routerFreeKey, routerChat); rec.Code != http.StatusOK {
		t.Fatalf("ключ без лимита, запрос %d: %d", i+1, rec.Code)
	}
	if rec := r.do(http.MethodPost, pathMask, routerLimitedKey, textGreeting); rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/mask под ключом с лимитом, запрос %d: %d", i+1, rec.Code)
	}
	body := fmt.Sprintf(`{"payload":"Добрый день","payload_id":"r4-%d"}`, i)
	if rec := r.do(http.MethodPost, pathProcess, "", body); rec.Code != http.StatusOK {
		t.Fatalf("/process, запрос %d: %d", i+1, rec.Code)
	}
}

// assertContainsAll отмечает ошибкой каждую строку wants, которой нет в text;
// where называет проверяемую поверхность в предложном падеже.
func assertContainsAll(t *testing.T, where, text string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("в %s нет %q", where, want)
		}
	}
}

// TestModelLimiterRefillAndReload — корзина не копит больше ёмкости, а
// уменьшение ёмкости при перезагрузке урезает накопленный остаток.
func TestModelLimiterRefillAndReload(t *testing.T) {
	l := newModelLimiter()
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	rate := config.RateLimit{RPS: 2, Burst: 3}

	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("c", limiterClient, rate); !ok {
			t.Fatalf("запрос %d в пределах всплеска отклонён", i+1)
		}
	}
	ok, wait := l.allow("c", limiterClient, rate)
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("сверх всплеска: ok=%v, wait=%s", ok, wait)
	}
	if got := retryAfterFor(wait); got != 1 {
		t.Fatalf("Retry-After для %s = %d, ожидалась 1", wait, got)
	}

	now = now.Add(time.Hour)
	small := config.RateLimit{RPS: 2, Burst: 1}
	if ok, _ := l.allow("c", limiterClient, small); !ok {
		t.Fatal("после паузы запрос отклонён")
	}
	if ok, _ := l.allow("c", limiterClient, small); ok {
		t.Fatal("после уменьшения ёмкости корзина отдала больше одного запроса")
	}
}

// TestAccessDeniedIsAuditedWithoutKey — строки 2 и 3, AC-3: отказы 401 и 403
// пишутся в журнал «доступ отклонён» и в метрики исходами unauthorized и
// forbidden, метка consumer — идентификатор из конфигурации либо anonymous;
// ключ не попадает ни в журнал, ни в метрики ни целиком, ни префиксом.
func TestAccessDeniedIsAuditedWithoutKey(t *testing.T) {
	r := newRouterServer(t)

	for _, c := range []deniedCall{
		{http.MethodPost, pathChat, "", routerChat},
		{http.MethodPost, pathChat, routerProbeKey, routerChat},
		{http.MethodPost, pathMask, routerProbeKey, textX},
		{http.MethodPost, pathUnmask, routerProbeKey, unmaskX},
		{http.MethodPost, pathAnalyze, routerProbeKey, textX},
		{http.MethodGet, pathUIHistory, routerProbeKey, ""},
		{http.MethodGet, pathUIJournal, "", ""},
	} {
		r.checkUnauthorized(t, c)
	}
	if rec := r.do(http.MethodPost, pathUnmask, routerNoDemaskKey, unmaskX); rec.Code != http.StatusForbidden {
		t.Fatalf("unmask без права demask: %d вместо 403", rec.Code)
	}
	if rec := r.do(http.MethodPost, pathAnalyze, routerFreeKey, `{"text":"x","consumer":"missing"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("стенд с несуществующей политикой: %d вместо 403", rec.Code)
	}

	journal := r.journal()
	if n := strings.Count(journal, msgDenied); n != 9 {
		t.Errorf("записей «доступ отклонён» %d, ожидалось 9:\n%s", n, journal)
	}
	assertContainsAll(t, "журнале", journal, []string{`"reason":"no_key"`, `"reason":"key_not_accepted"`,
		`"reason":"demask_not_allowed"`, `"outcome":"unauthorized"`, `"outcome":"forbidden"`})
	metrics := r.metricsText()
	assertContainsAll(t, "метриках", metrics, []string{
		`aigw_requests_total{endpoint="chat_completions",op="proxy",outcome="unauthorized"} 2`,
		`aigw_requests_total{endpoint="ui",op="read",outcome="unauthorized"} 2`,
		`aigw_requests_total{endpoint="unmask",op="unmask",outcome="forbidden"} 1`,
		`aigw_consumer_requests_total{consumer="anonymous",endpoint="mask",outcome="unauthorized"} 1`,
		`aigw_consumer_requests_total{consumer="nodemask",endpoint="unmask",outcome="forbidden"} 1`,
		`aigw_consumer_requests_total{consumer="free",endpoint="analyze",outcome="forbidden"} 1`,
	})
	if strings.Contains(metrics, "bad_request") {
		t.Error("отказ доступа учтён как bad_request")
	}

	// Ключ целиком, его префикс, хвост и уникальная середина.
	assertNoKeyParts(t, sourceJournal, journal)
	assertNoKeyParts(t, "метрики", metrics)
}

// deniedCall — запрос, который обязан получить 401.
type deniedCall struct{ method, path, key, body string }

// checkUnauthorized проверяет, что запрос c получает 401 и тело ответа не
// содержит предъявленного ключа.
func (r *routerServer) checkUnauthorized(t *testing.T, c deniedCall) {
	t.Helper()
	rec := r.do(c.method, c.path, c.key, c.body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%s %s: %d вместо 401", c.method, c.path, rec.Code)
	}
	if strings.Contains(rec.Body.String(), routerProbeKey[:8]) {
		t.Fatalf("%s: тело ответа содержит ключ: %s", c.path, rec.Body)
	}
}

// assertNoKeyParts прерывает тест, если в text есть проверочный ключ целиком,
// его префикс, хвост или уникальная середина.
func assertNoKeyParts(t *testing.T, where, text string) {
	t.Helper()
	for _, part := range []string{routerProbeKey, routerProbeKey[:8], routerProbeKey[len(routerProbeKey)-8:], "SECRET", "4242"} {
		if strings.Contains(text, part) {
			t.Fatalf("%s содержит часть ключа %q", where, part)
		}
	}
}

// TestProcessRejectsOtherMethodsWithJSON — строка 4: любой метод, кроме POST,
// на /process — 405 JSON с Allow: POST; неизвестный путь не GET — 404 JSON.
func TestProcessRejectsOtherMethodsWithJSON(t *testing.T) {
	r := newRouterServer(t)
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodOptions, "PROPFIND"} {
		checkProcessMethodRejected(t, m, r.do(m, pathProcess, "", ""))
	}
	if rec := r.do(http.MethodGet, pathChat, "", ""); rec.Code != http.StatusMethodNotAllowed ||
		rec.Header().Get(headerAllow) != http.MethodPost {
		t.Fatalf("GET /v1/chat/completions: %d, Allow %q", rec.Code, rec.Header().Get(headerAllow))
	}
	if rec := r.do(http.MethodPost, pathHealth, "", ""); rec.Code != http.StatusMethodNotAllowed ||
		rec.Header().Get(headerAllow) != allowGetHead {
		t.Fatalf("POST /healthz: %d, Allow %q", rec.Code, rec.Header().Get(headerAllow))
	}
	for _, m := range []string{http.MethodPut, http.MethodPost} {
		rec := r.do(m, unknownRoute, "", "")
		if rec.Code != http.StatusNotFound || !strings.HasPrefix(rec.Header().Get(headerContentType), jsonContentType) {
			t.Fatalf("%s неизвестного пути: %d %q", m, rec.Code, rec.Header().Get(headerContentType))
		}
	}
	if rec := r.do(http.MethodHead, pathHealth, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("HEAD /healthz: %d", rec.Code)
	}
	if rec := r.do(http.MethodPost, pathProcess, "", `{"payload":"x","payload_id":"m1"}`); rec.Code != http.StatusOK {
		t.Fatalf("POST /process после проверки метода: %d", rec.Code)
	}
}

// checkProcessMethodRejected проверяет ответ на /process методом m: 405,
// Allow: POST, Content-Type JSON и, кроме HEAD, JSON-тело с полем error.
func checkProcessMethodRejected(t *testing.T, m string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("%s /process: %d вместо 405", m, rec.Code)
	}
	if got := rec.Header().Get(headerAllow); got != http.MethodPost {
		t.Fatalf("%s /process: Allow = %q", m, got)
	}
	if ct := rec.Header().Get(headerContentType); !strings.HasPrefix(ct, jsonContentType) {
		t.Fatalf("%s /process: Content-Type = %q", m, ct)
	}
	if m == http.MethodHead {
		return
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == "" {
		t.Fatalf("%s /process: тело не JSON с полем error: %q", m, rec.Body)
	}
}

// TestMethodGuardMatchesRoutes — таблица методов совпадает с регистрацией:
// объявленный метод на каждом пути доходит до обработчика, а не до 405.
func TestMethodGuardMatchesRoutes(t *testing.T) {
	r := newRouterServer(t)
	for _, path := range []string{pathProcess, pathChat, pathMask, pathUnmask,
		pathAnalyze, pathRoot, pathHealth, pathReady, pathMetrics, pathUIConsumers,
		pathUIHistory, pathUITrace, pathUIJournal} {
		allow, known := allowedMethod(path)
		if !known {
			t.Fatalf("%s отсутствует в таблице методов", path)
		}
		rec := r.do(allow, path, "", "{}")
		if rec.Code == http.StatusMethodNotAllowed || rec.Code == http.StatusNotFound {
			t.Fatalf("%s %s: %d — таблица расходится с маршрутизатором", allow, path, rec.Code)
		}
	}
}

// TestProcessPayloadIDLengthLimit — строка 5: payload_id до 1024 байт
// принимается, длиннее — 400 JSON; пустой payload по-прежнему 200.
func TestProcessPayloadIDLengthLimit(t *testing.T) {
	r := newRouterServer(t)
	ok := strings.Repeat("a", maxPayloadIDBytes)
	if rec := r.do(http.MethodPost, pathProcess, "", `{"payload":"x","payload_id":"`+ok+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("payload_id 1024 байта: %d %s", rec.Code, rec.Body)
	}
	long := strings.Repeat("я", maxPayloadIDBytes/2+1) // 1026 байт
	rec := r.do(http.MethodPost, pathProcess, "", `{"payload":"x","payload_id":"`+long+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("payload_id 1026 байт: %d вместо 400", rec.Code)
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != msgLongPayloadID {
		t.Fatalf("тело отказа: %s", rec.Body)
	}
	if strings.Contains(r.journal(), long[:20]) {
		t.Error("отвергнутый payload_id попал в журнал")
	}
	if rec := r.do(http.MethodPost, pathProcess, "", `{"payload_id":"empty-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("отсутствующий payload: %d, контракт не должен меняться", rec.Code)
	}
}

// TestHistoryMarksContractRecords — строка 7: записи /process видны в
// истории любому ключу и помечены как контракт без ключа; записи по ключу
// помечены key и чужому ключу не видны.
func TestHistoryMarksContractRecords(t *testing.T) {
	r := newRouterServer(t)
	if rec := r.do(http.MethodPost, pathProcess, "", `{"payload":"x","payload_id":"h1"}`); rec.Code != http.StatusOK {
		t.Fatalf("/process: %d", rec.Code)
	}
	if rec := r.do(http.MethodPost, pathMask, routerFreeKey, textX); rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/mask: %d", rec.Code)
	}

	own := r.history(t, routerFreeKey)
	if len(own.Rows) != 2 {
		t.Fatalf("владельцу видно %d записей, ожидалось 2", len(own.Rows))
	}
	for _, row := range own.Rows {
		checkAccessMark(t, row)
	}
	other := r.history(t, routerNoDemaskKey)
	if len(other.Rows) != 1 || other.Rows[0].Endpoint != obs.EndpointProcess.String() || other.Rows[0].Access != accessPublic {
		t.Fatalf("чужому ключу видно %+v, ожидалась одна запись /process", other.Rows)
	}
}

// history читает историю стенда под ключом key.
func (r *routerServer) history(t *testing.T, key string) historyResponse {
	t.Helper()
	rec := r.do(http.MethodGet, pathUIHistory, key, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("история: %d", rec.Code)
	}
	var h historyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatalf("история не JSON: %v", err)
	}
	return h
}

// checkAccessMark проверяет пометку видимости строки истории: запись /process
// — публичная с пояснением, запись по ключу — key без пояснения.
func checkAccessMark(t *testing.T, row historyRow) {
	t.Helper()
	switch row.Endpoint {
	case obs.EndpointProcess.String():
		if row.Access != accessPublic || row.AccessNote == "" {
			t.Errorf("запись /process помечена %q/%q", row.Access, row.AccessNote)
		}
	case "mask":
		if row.Access != accessKey || row.AccessNote != "" {
			t.Errorf("запись по ключу помечена %q/%q", row.Access, row.AccessNote)
		}
	}
}

// TestModelLimiterPerClient — Б5-11 раунда 5: посторонний с тем же
// опубликованным ключом не выбирает корзину другого клиента, а общая корзина
// потребителя ограничивает суммарный расход квоты по ключу.
func TestModelLimiterPerClient(t *testing.T) {
	l := newModelLimiter()
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	rate := config.RateLimit{RPS: 1, Burst: 2}

	for i := 0; i < 2; i++ {
		if ok, _ := l.allow("demo", "203.0.113.9", rate); !ok {
			t.Fatalf("посторонний, запрос %d в пределах всплеска отклонён", i+1)
		}
	}
	if ok, _ := l.allow("demo", "203.0.113.9", rate); ok {
		t.Fatal("посторонний получил больше всплеска")
	}
	if ok, _ := l.allow("demo", "198.51.100.7", rate); !ok {
		t.Fatal("другой клиент того же ключа отклонён из-за чужой корзины")
	}

	// Общая корзина: всплеск × modelAggregateFactor запросов на ключ, сколько
	// бы адресов ни было.
	l = newModelLimiter()
	l.now = func() time.Time { return now }
	passed := 0
	for i := 0; i < 100; i++ {
		if ok, _ := l.allow("demo", fmt.Sprintf("192.0.2.%d", i), rate); ok {
			passed++
		}
	}
	if want := rate.Burst * modelAggregateFactor; passed != want {
		t.Fatalf("через общую корзину прошло %d запросов, ожидалось %d", passed, want)
	}
}

// TestModelLimiterSweepBoundsMemory — корзины клиентов, восполнившиеся до
// ёмкости, забываются, и карта не растёт без предела.
func TestModelLimiterSweepBoundsMemory(t *testing.T) {
	l := newModelLimiter()
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	rate := config.RateLimit{RPS: 1, Burst: 2}
	for i := 0; i < modelClientBuckets+10; i++ {
		l.allow("demo", fmt.Sprintf("c%d", i), rate)
		now = now.Add(time.Second)
	}
	if n := len(l.buckets); n > modelClientBuckets+2 {
		t.Fatalf("корзин в памяти %d, предел %d", n, modelClientBuckets)
	}
}
