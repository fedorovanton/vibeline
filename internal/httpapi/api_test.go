package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/store"
)

// Значения синтетические. Реальные персональные данные в репозиторий не
// попадают ни в фикстурах, ни в примерах.
var apiMarked = map[string]pii.Type{
	"Иванов Иван Иванович":   pii.FullName,
	"Петрова Анна Сергеевна": pii.FullName,
	"+7 916 123-45-67":       pii.Phone,
	"+7 916 765-43-21":       pii.Phone,
	"ivanov@example.test":    pii.Email,
	"4276 5500 1234 5678":    pii.CardNumber,
}

// Ключи потребителей — синтетические, задаются через окружение.
const (
	apiCrmKey      = "key-api-crm-test"
	apiReadonlyKey = "key-api-readonly-test"
	apiLockedKey   = "key-api-locked-test"
	apiStarsKey    = "key-api-stars-test"
)

// apiTestConfig — потребители с разными правами и стратегиями.
const apiTestConfig = `
server:
  addr: ":0"
  max_body_bytes: 64KiB
  max_concurrent: 64
  request_timeout: %s
store:
  ttl: 1h
llm:
  mode: stub
consumers:
  - id: benchmark
    types: [all]
    demask: true
  - id: crm
    api_key_env: TEST_API_CRM_KEY
    types: [all]
    demask: true
  - id: readonly
    api_key_env: TEST_API_READONLY_KEY
    types: [all]
    demask: false
  - id: locked
    enabled: false
    api_key_env: TEST_API_LOCKED_KEY
    types: [all]
    demask: true
  - id: stars
    api_key_env: TEST_API_STARS_KEY
    types: [all]
    demask: true
    mask:
      default: placeholder
      per_type:
        phone: asterisks
  - id: limited
    api_key_env: TEST_API_LIMITED_KEY
    types: [all]
    demask: true
    max_spans: 3
`

// apiLimitedKey — ключ потребителя с пределом в три замены (T-52).
const apiLimitedKey = "key-api-limited-test"

// apiMarkScanner отмечает синтетические значения как ПД, а служебные слова
// превращает в отказ или задержку защитной обработки.
type apiMarkScanner struct{}

func (apiMarkScanner) Name() string { return "api-mark" }

func (apiMarkScanner) Scan(doc *lex.Doc, _ *dict.Set, out *detect.Candidates) {
	if strings.Contains(doc.Text, "СБОЙЗАЩИТЫ") {
		panic("сканер отказал")
	}
	if strings.Contains(doc.Text, "МЕДЛЕННО") {
		time.Sleep(100 * time.Millisecond)
	}
	for v, t := range apiMarked {
		for i := 0; i < len(doc.Text); {
			j := strings.Index(doc.Text[i:], v)
			if j < 0 {
				break
			}
			at := i + j
			out.Add(at, at+len(v), t, detect.Certain, "api-mark")
			i = at + len(v)
		}
	}
}

type apiServer struct {
	ctx   context.Context
	srv   *Server
	store store.Store
	log   *bytes.Buffer
	logMu *sync.Mutex
}

// lockedWriter делает общий буфер журнала безопасным для конкурентной записи.
type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (a *apiServer) journal() string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	return a.log.String()
}

func newAPIServer(t *testing.T, st store.Store, requestTimeout string) *apiServer {
	t.Helper()
	return newAPIServerEngine(t, st, requestTimeout, detect.New(nil, apiMarkScanner{}))
}

// newAPIServerEngine — то же, что newAPIServer, с заданным движком детекции.
func newAPIServerEngine(t *testing.T, st store.Store, requestTimeout string, engine *detect.Engine) *apiServer {
	t.Helper()
	t.Setenv("TEST_API_CRM_KEY", apiCrmKey)
	t.Setenv("TEST_API_READONLY_KEY", apiReadonlyKey)
	t.Setenv("TEST_API_LOCKED_KEY", apiLockedKey)
	t.Setenv("TEST_API_STARS_KEY", apiStarsKey)
	t.Setenv("TEST_API_LIMITED_KEY", apiLimitedKey)

	holder := newTestHolder(t, fmt.Sprintf(apiTestConfig, requestTimeout))
	if st == nil {
		mem := store.NewMemory(holder.Current().Store)
		t.Cleanup(func() { _ = mem.Close() })
		st = mem
	}
	a := &apiServer{ctx: t.Context(), store: st, log: &bytes.Buffer{}, logMu: &sync.Mutex{}}
	a.srv = NewServer(Deps{
		Config:    holder,
		Gateway:   gateway.New(engine, st),
		Metrics:   obs.NewMetrics(),
		Logger:    slog.New(slog.NewJSONHandler(lockedWriter{mu: a.logMu, buf: a.log}, nil)),
		Version:   "test",
		StartedAt: time.Now(),
	})
	return a
}

// do отправляет запрос через настоящий маршрутизатор сервера: так проверяется
// и регистрация маршрута, а не только обработчик.
func (a *apiServer) do(method, path, key, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(a.ctx, method, path, strings.NewReader(body))
	req.Header.Set(headerContentType, jsonContentType)
	if key != "" {
		req.Header.Set(headerAPIKey, key)
	}
	rec := httptest.NewRecorder()
	a.srv.http.Handler.ServeHTTP(rec, req)
	return rec
}

func jsonBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("сериализация: %v", err)
	}
	return string(b)
}

func (a *apiServer) mask(t *testing.T, key string, body any) (int, maskAPIResponse, string) {
	t.Helper()
	rec := a.do(http.MethodPost, pathMask, key, jsonBody(t, body))
	var out maskAPIResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("ответ mask не JSON: %v", err)
		}
	}
	return rec.Code, out, rec.Body.String()
}

func (a *apiServer) unmask(t *testing.T, key, masked, id string) (int, string, string) {
	t.Helper()
	rec := a.do(http.MethodPost, pathUnmask, key,
		jsonBody(t, map[string]string{fieldMasked: masked, "id": id}))
	var out unmaskAPIResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("ответ unmask не JSON: %v", err)
		}
	}
	return rec.Code, out.Text, rec.Body.String()
}

// assertNoValues проверяет, что в тексте нет ни одного размеченного значения
// — ни в исходном виде, ни в виде JSON-escape.
func assertNoValues(t *testing.T, where, text string) {
	t.Helper()
	for v := range apiMarked {
		esc, _ := json.Marshal(v)
		if strings.Contains(text, v) || strings.Contains(text, strings.Trim(string(esc), `"`)) {
			t.Fatalf("%s содержит значение типа %s", where, apiMarked[v].Key())
		}
	}
}

// withoutRequestID убирает из тела ошибки идентификатор запроса: он разный у
// любых двух запросов и к сравнению ответов отношения не имеет.
func withoutRequestID(t *testing.T, body string) errorResponse {
	t.Helper()
	var e errorResponse
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("тело ошибки не JSON: %v", err)
	}
	e.RequestID = ""
	return e
}

const apiSample = "Клиент Иванов Иван Иванович, телефон +7 916 123-45-67, почта ivanov@example.test, карта 4276 5500 1234 5678."

// Идентификаторы корреляции и сообщения, общие для нескольких проверок.
const (
	sharedID      = "shared-1"
	logID         = "log-1"
	idemID        = "idem-1"
	literalID     = "lit-1"
	fieldMasked   = "masked"
	where429      = "ответ 429"
	msgMaskFailed = "mask: код %d, тело %s"
)

func TestAPIRoutesRegistered(t *testing.T) {
	// AC-1: оба маршрута зарегистрированы в маршрутизаторе сервера и отвечают.
	a := newAPIServer(t, nil, "9s")

	code, m, body := a.maskText(t, apiCrmKey, apiSample, "ac1")
	if code != http.StatusOK {
		t.Fatalf(msgMaskFailed, code, body)
	}
	code, text, body := a.unmask(t, apiCrmKey, m.Masked, "ac1")
	if code != http.StatusOK || text != apiSample {
		t.Fatalf("unmask: код %d, тело %s", code, body)
	}

	// Маршруты принимают только POST. GET уходит в обработчик страницы стенда
	// по «GET /», который на чужие пути отвечает 404, — но не в API.
	for _, p := range []string{pathMask, pathUnmask} {
		if rec := a.do(http.MethodGet, p, apiCrmKey, ""); rec.Code == http.StatusOK {
			t.Fatalf("GET %s обслужен как POST", p)
		}
	}
}

func TestAPIRequiresValidKey(t *testing.T) {
	// AC-2: без ключа, с неизвестным ключом и с ключом отключённого
	// потребителя — 401, и ответы неотличимы друг от друга.
	a := newAPIServer(t, nil, "9s")
	bodies := map[string]string{
		pathMask:   jsonBody(t, map[string]string{"text": apiSample, "id": "ac2"}),
		pathUnmask: jsonBody(t, map[string]string{"masked": placeholderName, "id": "ac2"}),
	}
	for path, body := range bodies {
		var first errorResponse
		for i, key := range []string{"", unknownKey, apiLockedKey} {
			rec := a.do(http.MethodPost, path, key, body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s, ключ #%d: код %d, ожидался 401", path, i, rec.Code)
			}
			assertNoValues(t, "ответ 401", rec.Body.String())
			e := withoutRequestID(t, rec.Body.String())
			if i == 0 {
				first = e
			} else if e != first {
				t.Fatalf("%s: ответы 401 различаются: %+v и %+v", path, first, e)
			}
		}
	}
	if a.store.Stats().Entries != 0 {
		t.Fatal("запрос без действующего ключа записал соответствие")
	}

	// Authorization с префиксом Bearer принимается так же, как X-API-Key.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathMask, strings.NewReader(bodies[pathMask]))
	req.Header.Set(headerAuthorization, "Bearer "+apiCrmKey)
	rec := httptest.NewRecorder()
	a.srv.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Authorization: Bearer: код %d", rec.Code)
	}
}

func TestAPIUnmaskRequiresDemaskRight(t *testing.T) {
	// AC-3: маскировать потребитель без права demask может, восстанавливать —
	// нет, в том числе собственную маску.
	a := newAPIServer(t, nil, "9s")

	code, m, body := a.maskText(t, apiReadonlyKey, apiSample, "ac3")
	if code != http.StatusOK {
		t.Fatalf(msgMaskFailed, code, body)
	}
	code, _, body = a.unmask(t, apiReadonlyKey, m.Masked, "ac3")
	if code != http.StatusForbidden {
		t.Fatalf("unmask без права: код %d, ожидался 403", code)
	}
	assertNoValues(t, "ответ 403", body)

	// Ответ без права одинаков для существующего и несуществующего
	// идентификатора: он не служит оракулом.
	_, _, other := a.unmask(t, apiReadonlyKey, m.Masked, "no-such-id")
	if withoutRequestID(t, body) != withoutRequestID(t, other) {
		t.Fatal("ответ 403 зависит от существования записи")
	}
}

func TestAPIForeignIDRevealsNothing(t *testing.T) {
	// AC-4 (REQ-404): чужой идентификатор ищется в собственной области и
	// неотличим от неизвестного; запись владельца не затирается.
	a := newAPIServer(t, nil, "9s")

	code, m, body := a.maskText(t, apiCrmKey, apiSample, sharedID)
	if code != http.StatusOK {
		t.Fatalf("mask crm: код %d, тело %s", code, body)
	}

	codeForeign, textForeign, bodyForeign := a.unmask(t, apiStarsKey, m.Masked, sharedID)
	codeUnknown, _, bodyUnknown := a.unmask(t, apiStarsKey, m.Masked, "never-issued")
	if codeForeign != http.StatusNotFound || codeUnknown != http.StatusNotFound {
		t.Fatalf("коды: чужой %d, неизвестный %d, ожидался 404", codeForeign, codeUnknown)
	}
	if textForeign != "" {
		t.Fatal("чужой идентификатор вернул текст")
	}
	assertNoValues(t, "ответ на чужой идентификатор", bodyForeign)
	if withoutRequestID(t, bodyForeign) != withoutRequestID(t, bodyUnknown) {
		t.Fatalf("ответ на чужой идентификатор отличим от неизвестного: %s / %s", bodyForeign, bodyUnknown)
	}

	// Тот же идентификатор у другого потребителя — своя область: маскирование
	// проходит и не разрушает запись владельца.
	other := "Звонила Петрова Анна Сергеевна."
	if code, _, body := a.maskText(t, apiStarsKey, other, sharedID); code != http.StatusOK {
		t.Fatalf("mask stars с тем же id: код %d, тело %s", code, body)
	}
	if code, text, _ := a.unmask(t, apiCrmKey, m.Masked, sharedID); code != http.StatusOK || text != apiSample {
		t.Fatalf("запись владельца разрушена: код %d", code)
	}

	// Запись контракта /process с тем же идентификатором тоже изолирована.
	rec := httptest.NewRecorder()
	a.srv.http.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathProcess,
		strings.NewReader(jsonBody(t, map[string]string{"payload": other, "payload_id": sharedID}))))
	if rec.Code != http.StatusOK {
		t.Fatalf("/process: код %d", rec.Code)
	}
	if code, text, _ := a.unmask(t, apiCrmKey, m.Masked, sharedID); code != http.StatusOK || text != apiSample {
		t.Fatalf("запись API разрушена записью /process: код %d", code)
	}
}

func TestAPIRoundTripIsByteExact(t *testing.T) {
	// AC-5: маска → восстановление возвращает исходную строку побайтово,
	// включая CRLF, табуляцию, кириллицу, эмодзи, кавычки и обратный слеш.
	a := newAPIServer(t, nil, "9s")
	texts := []string{
		apiSample,
		"Строка 1\r\nИванов Иван Иванович\tтел. +7 916 123-45-67\r\n",
		"«Петрова Анна Сергеевна» 😀 \"цитата\" \\путь\\ ivanov@example.test конец",
		"Без персональных данных — просто текст.",
		"",
		"Иванов Иван Иванович и снова Иванов Иван Иванович, +7 916 123-45-67 и +7 916 765-43-21",
	}
	for _, key := range []string{apiCrmKey, apiStarsKey} {
		for i, text := range texts {
			code, m, body := a.maskText(t, key, text, "")
			if code != http.StatusOK {
				t.Fatalf("mask #%d: код %d, тело %s", i, code, body)
			}
			if m.ID == "" {
				t.Fatalf("mask #%d: сервис не выдал идентификатор", i)
			}
			assertNoValues(t, "маска", m.Masked)
			assertNoValues(t, "ответ mask", body)
			code, got, body := a.unmask(t, key, m.Masked, m.ID)
			if code != http.StatusOK {
				t.Fatalf("unmask #%d: код %d, тело %s", i, code, body)
			}
			if got != text {
				t.Fatalf("круговой путь #%d не точен: %q != %q", i, got, text)
			}
		}
	}
}

func TestAPIMaskResponseCarriesTypesAndCounts(t *testing.T) {
	a := newAPIServer(t, nil, "9s")
	text := "Иванов Иван Иванович, Петрова Анна Сергеевна, +7 916 123-45-67"
	code, m, body := a.maskText(t, apiCrmKey, text, "types-1")
	if code != http.StatusOK {
		t.Fatalf(msgMaskFailed, code, body)
	}
	if m.ID != "types-1" {
		t.Fatalf("идентификатор не сохранён: %q", m.ID)
	}
	if want := []string{typeFullName, "phone"}; strings.Join(m.Types, ",") != strings.Join(want, ",") {
		t.Fatalf("types = %v, ожидалось %v", m.Types, want)
	}
	if m.Counts[typeFullName] != 2 || m.Counts["phone"] != 1 || len(m.Counts) != 2 {
		t.Fatalf("counts = %v", m.Counts)
	}
	if !strings.Contains(m.Masked, placeholderName) || !strings.Contains(m.Masked, "[ФИО_2]") {
		t.Fatalf("плейсхолдеры не пронумерованы: %s", m.Masked)
	}

	// Текст без ПД: пустые, но не null, types и counts.
	_, _, body = a.maskText(t, apiCrmKey, "просто текст", "")
	if !strings.Contains(body, `"types":[]`) || !strings.Contains(body, `"counts":{}`) {
		t.Fatalf("пустые types/counts сериализованы не как [] и {}: %s", body)
	}
}

func TestAPIUnmaskRestoresPlaceholdersInChangedText(t *testing.T) {
	// Продуктовый режим: маска изменена (ответ модели) — восстанавливаются
	// только плейсхолдеры этого идентификатора; подделанные остаются как есть.
	a := newAPIServer(t, nil, "9s")
	text := "Клиент Иванов Иван Иванович, почта ivanov@example.test."
	_, m, _ := a.maskText(t, apiCrmKey, text, "chg-1")

	answer := "Уважаемый [ФИО_1]! Ответ отправлен на [EMAIL_1]. Коллега [ФИО_2] и [ФИО_1] в копии."
	if !strings.Contains(m.Masked, placeholderName) || !strings.Contains(m.Masked, "[EMAIL_1]") {
		t.Fatalf("неожиданная маска: %s", m.Masked)
	}
	code, got, body := a.unmask(t, apiCrmKey, answer, "chg-1")
	if code != http.StatusOK {
		t.Fatalf("unmask: код %d, тело %s", code, body)
	}
	want := "Уважаемый Иванов Иван Иванович! Ответ отправлен на ivanov@example.test. Коллега [ФИО_2] и Иванов Иван Иванович в копии."
	if got != want {
		t.Fatalf("восстановление:\n%s\nожидалось\n%s", got, want)
	}

	// Звёздочки неоднозначны: два разных телефона дают одну маску, и
	// восстанавливать её нельзя — вернулось бы не то значение.
	two := "Телефоны +7 916 123-45-67 и +7 916 765-43-21, Иванов Иван Иванович."
	_, ms, _ := a.maskText(t, apiStarsKey, two, "chg-2")
	changed := answerPrefix + ms.Masked
	code, got, _ = a.unmask(t, apiStarsKey, changed, "chg-2")
	if code != http.StatusOK {
		t.Fatalf("unmask stars: код %d", code)
	}
	if strings.Contains(got, "+7 916 123-45-67") || strings.Contains(got, "+7 916 765-43-21") {
		t.Fatal("неоднозначная маска звёздочками восстановлена")
	}
	if !strings.Contains(got, "Иванов Иван Иванович") {
		t.Fatalf("однозначный плейсхолдер не восстановлен: %s", got)
	}
}

func TestAPIMaskIsIdempotentAndRejectsReusedID(t *testing.T) {
	a := newAPIServer(t, nil, "9s")
	req := map[string]string{"text": apiSample, "id": idemID}
	_, first, _ := a.mask(t, apiCrmKey, req)
	code, again, body := a.mask(t, apiCrmKey, req)
	if code != http.StatusOK || again.Masked != first.Masked {
		t.Fatalf("повтор прямого шага: код %d, тело %s", code, body)
	}

	code, _, body = a.maskText(t, apiCrmKey, "Петрова Анна Сергеевна", idemID)
	if code != http.StatusConflict {
		t.Fatalf("занятый идентификатор: код %d, ожидался 409", code)
	}
	assertNoValues(t, "ответ 409", body)
	if code, text, _ := a.unmask(t, apiCrmKey, first.Masked, idemID); code != http.StatusOK || text != apiSample {
		t.Fatalf("запись затёрта конфликтом: код %d", code)
	}
}

func TestAPIMaskFailClosed(t *testing.T) {
	// Отказ защиты: маска не выдаётся, соответствие не записывается, в ответе
	// нет ни исходного текста, ни значений.
	a := newAPIServer(t, nil, "9s")
	text := "СБОЙЗАЩИТЫ " + apiSample
	code, _, body := a.maskText(t, apiCrmKey, text, "fc-1")
	if code != http.StatusInternalServerError {
		t.Fatalf("отказ защиты: код %d, ожидался 500", code)
	}
	assertNoValues(t, "ответ 500", body)
	if strings.Contains(body, "СБОЙЗАЩИТЫ") || strings.Contains(body, fieldMasked) {
		t.Fatalf("ответ 500 содержит текст запроса или маску: %s", body)
	}
	if n := a.store.Stats().Entries; n != 0 {
		t.Fatalf("при отказе защиты записано %d соответствий", n)
	}

	// Отказ записи соответствия: маска не выдаётся, ответ 429 с Retry-After.
	f := newAPIServer(t, proxyFailingStore{}, "9s")
	rec := f.do(http.MethodPost, pathMask, apiCrmKey, jsonBody(t, map[string]string{"text": apiSample}))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get(headerRetryAfter) == "" {
		t.Fatalf("отказ хранилища: код %d, Retry-After %q", rec.Code, rec.Header().Get(headerRetryAfter))
	}
	if strings.Contains(rec.Body.String(), placeholderName) {
		t.Fatal("маска выдана без записанного соответствия")
	}
	assertNoValues(t, where429, rec.Body.String())
}

func TestAPIRequestTimeoutApplies(t *testing.T) {
	// Предел обработки действует так же, как на /process: 429 с Retry-After.
	a := newAPIServer(t, nil, "20ms")
	rec := a.do(http.MethodPost, pathMask, apiCrmKey,
		jsonBody(t, map[string]string{"text": "МЕДЛЕННО " + apiSample}))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get(headerRetryAfter) == "" {
		t.Fatalf("предел обработки: код %d, Retry-After %q", rec.Code, rec.Header().Get(headerRetryAfter))
	}
	assertNoValues(t, where429, rec.Body.String())
	if a.store.Stats().Entries != 0 {
		t.Fatal("соответствие записано после истечения предела")
	}
}

func TestAPIRejectsBadRequests(t *testing.T) {
	a := newAPIServer(t, nil, "9s")
	cases := []struct {
		name, path, body string
		want             int
	}{
		{"битый JSON", pathMask, `{"text":`, http.StatusBadRequest},
		{"нет text", pathMask, `{"id":"x"}`, http.StatusBadRequest},
		{"id с пробелом", pathMask, `{"text":"a","id":"Иванов Иван"}`, http.StatusBadRequest},
		{"слишком длинный id", pathMask, `{"text":"a","id":"` + strings.Repeat("a", 65) + `"}`, http.StatusBadRequest},
		{"большое тело", pathMask, `{"text":"` + strings.Repeat("я", 64<<10) + `"}`, http.StatusRequestEntityTooLarge},
		{"нет masked", pathUnmask, `{"id":"x"}`, http.StatusBadRequest},
		{"нет id", pathUnmask, `{"masked":"x"}`, http.StatusBadRequest},
		{"битый JSON unmask", pathUnmask, `[`, http.StatusBadRequest},
	}
	for _, c := range cases {
		rec := a.do(http.MethodPost, c.path, apiCrmKey, c.body)
		if rec.Code != c.want {
			t.Fatalf("%s: код %d, ожидался %d", c.name, rec.Code, c.want)
		}
		if strings.Contains(rec.Body.String(), "Иванов") {
			t.Fatalf("%s: ответ содержит данные запроса", c.name)
		}
	}
}

func TestAPIDoesNotLogValues(t *testing.T) {
	a := newAPIServer(t, nil, "9s")
	_, m, _ := a.maskText(t, apiCrmKey, apiSample, logID)
	a.unmask(t, apiCrmKey, m.Masked, logID)
	a.unmask(t, apiCrmKey, "Ответ [ФИО_1]", logID)
	a.maskText(t, apiCrmKey, "СБОЙЗАЩИТЫ "+apiSample, "")
	a.unmask(t, apiReadonlyKey, m.Masked, logID)

	j := a.journal()
	if !strings.Contains(j, `"endpoint":"mask"`) || !strings.Contains(j, `"endpoint":"unmask"`) {
		t.Fatalf("в журнале нет записей эндпоинтов: %s", j)
	}
	if !strings.Contains(j, `"payload_id":"`+logID+`"`) || !strings.Contains(j, typeFullName) {
		t.Fatal("в журнале нет идентификатора корреляции или типов")
	}
	assertNoValues(t, sourceJournal, j)
}

func TestAPIConcurrentUse(t *testing.T) {
	// Под -race: параллельные круговые пути по разным идентификаторам и
	// гонка разных текстов за один идентификатор. Выиграть гонку может ровно
	// один запрос, и восстановление возвращает именно его текст.
	a := newAPIServer(t, nil, "9s")
	const n = 32

	var wg sync.WaitGroup
	errs := make(chan string, 2*n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := apiRoundTrip(t, a, i); e != "" {
				errs <- e
			}
		}()
	}

	var mu sync.Mutex
	winners := map[string]string{}
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			masked, text, e := apiRaceForID(t, a, i)
			switch {
			case e != "":
				errs <- e
			case masked != "":
				mu.Lock()
				winners[masked] = text
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if len(winners) != 1 {
		t.Fatalf("гонку за идентификатор выиграли %d запросов, ожидался один", len(winners))
	}
	for masked, text := range winners {
		if code, got, _ := a.unmask(t, apiCrmKey, masked, "race-1"); code != http.StatusOK || got != text {
			t.Fatalf("восстановление после гонки: код %d", code)
		}
	}
}

// apiRoundTrip — круговой путь i-го участника TestAPIConcurrentUse под
// собственным идентификатором. Возвращает описание отказа или пустую строку.
func apiRoundTrip(t *testing.T, a *apiServer, i int) string {
	text := fmt.Sprintf("Запрос %d: Иванов Иван Иванович, +7 916 123-45-67", i)
	id := fmt.Sprintf("par-%d", i)
	code, m, _ := a.maskText(t, apiCrmKey, text, id)
	if code != http.StatusOK {
		return fmt.Sprintf("mask %d: код %d", i, code)
	}
	code, got, _ := a.unmask(t, apiCrmKey, m.Masked, id)
	if code != http.StatusOK || got != text {
		return fmt.Sprintf("круговой путь %d: код %d", i, code)
	}
	return ""
}

// apiRaceForID — i-й участник гонки за общий идентификатор race-1. Победитель
// возвращает свою маску и текст, проигравший с 409 — пустые строки, любой
// другой код — описание отказа.
func apiRaceForID(t *testing.T, a *apiServer, i int) (masked, text, failure string) {
	text = fmt.Sprintf("Вариант %d: Петрова Анна Сергеевна", i)
	code, m, _ := a.maskText(t, apiCrmKey, text, "race-1")
	switch code {
	case http.StatusOK:
		return m.Masked, text, ""
	case http.StatusConflict:
		return "", "", ""
	default:
		return "", "", fmt.Sprintf("гонка %d: код %d", i, code)
	}
}

// TestAPIMaskSpanLimitFailClosed — T-52 AC-2 на явном API: значений больше
// предела замен — отказ 413 без маски и без записи соответствия; в теле
// ответа и в журнале ни одного значения. До правки ответ был 200 с
// частичной маской, а значения сверх предела оставались открытыми.
func TestAPIMaskSpanLimitFailClosed(t *testing.T) {
	a := newAPIServer(t, nil, "9s")

	// Четыре значения при пределе три.
	code, _, body := a.maskText(t, apiLimitedKey, apiSample, "limit-1")
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("сверх предела: код %d, ожидался 413; тело %s", code, body)
	}
	assertNoValues(t, "ответ 413", body)
	if strings.Contains(body, `"masked"`) || strings.Contains(body, placeholderName) {
		t.Fatalf("ответ 413 содержит маску: %s", body)
	}
	if e := withoutRequestID(t, body); !strings.Contains(e.Error, "предел замен") || !strings.Contains(e.Error, "(3)") {
		t.Fatalf("сообщение не называет причину и предел: %q", e.Error)
	}
	if n := a.store.Stats().Entries; n != 0 {
		t.Fatalf("при превышении предела записано %d соответствий", n)
	}
	journal := a.journal()
	assertNoValues(t, sourceJournal, journal)
	if !strings.Contains(journal, `"outcome":"fail_closed"`) {
		t.Fatalf("исход fail_closed не записан в журнал: %s", journal)
	}

	// Ровно по пределу — штатная маска.
	const three = "Клиент Иванов Иван Иванович, телефон +7 916 123-45-67, почта ivanov@example.test."
	code, m, body := a.maskText(t, apiLimitedKey, three, "limit-2")
	if code != http.StatusOK {
		t.Fatalf("по пределу: код %d, тело %s", code, body)
	}
	assertNoValues(t, "маска по пределу", m.Masked)
}

// analyzeLimitConfig — стенд с потребителем, у которого предел в три замены.
// Детекция — apiMarkScanner: он же умеет имитировать медленную защиту.
const analyzeLimitConfig = `
server:
  addr: ":0"
  max_body_bytes: 64KiB
  max_concurrent: 8
  request_timeout: %s
store:
  ttl: 1h
llm:
  mode: alfagen
  base_url: %s
  model: test-model
  timeout: 5s
  api_key_env: TEST_UI_MODEL_KEY
consumers:
  - id: benchmark
    types: [all]
    demask: true
  - id: limited
    api_key_env: TEST_API_LIMITED_KEY
    types: [all]
    demask: true
    max_spans: 3
`

// newAnalyzeLimitServer поднимает маршруты стенда с фальшивой моделью.
func newAnalyzeLimitServer(t *testing.T, modelURL, requestTimeout string) (*http.ServeMux, *bytes.Buffer) {
	t.Helper()
	t.Setenv("TEST_UI_MODEL_KEY", uiModelKey)
	t.Setenv("TEST_API_LIMITED_KEY", apiLimitedKey)

	body := fmt.Sprintf(analyzeLimitConfig, requestTimeout, modelURL+"/v1")
	holder := newTestHolder(t, body)
	mem := store.NewMemory(holder.Current().Store)
	t.Cleanup(func() { _ = mem.Close() })

	journal := &bytes.Buffer{}
	s := NewServer(Deps{
		Config:    holder,
		Gateway:   gateway.New(detect.New(nil, apiMarkScanner{}), mem),
		Metrics:   obs.NewMetrics(),
		Logger:    slog.New(slog.NewJSONHandler(journal, nil)),
		Version:   "test",
		StartedAt: time.Now(),
	})
	mux := http.NewServeMux()
	s.registerUIRoutes(mux)
	return mux, journal
}

// TestAnalyzeSpanLimitFailClosed — T-52 AC-2 на стенде: превышение предела
// замен — отказ 413, ноль запросов в фальшивую модель, в теле ответа ни
// частичной маски, ни значений.
func TestAnalyzeSpanLimitFailClosed(t *testing.T) {
	model := newUIModel(t, fixtureReply, 0)
	mux, journal := newAnalyzeLimitServer(t, model.srv.URL, "9s")

	code, _, body := analyze(t, mux, apiLimitedKey, "", apiSample)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("сверх предела: код %d, ожидался 413; тело %s", code, body)
	}
	if model.calls() != 0 {
		t.Fatalf("модель получила %d запросов при превышении предела", model.calls())
	}
	assertNoValues(t, "ответ стенда", body)
	if strings.Contains(body, placeholderName) || strings.Contains(body, "masked_text") {
		t.Fatalf("стенд показал частичную маску: %s", body)
	}
	assertNoValues(t, "журнал стенда", journal.String())

	// Ровно по пределу цепочка проходит до модели.
	const three = "Клиент Иванов Иван Иванович, телефон +7 916 123-45-67, почта ivanov@example.test."
	code, res, body := analyze(t, mux, apiLimitedKey, "", three)
	if code != http.StatusOK || res.ChainStatus != "ok" {
		t.Fatalf("по пределу: код %d, цепочка %q; тело %s", code, res.ChainStatus, body)
	}
	if model.calls() != 1 {
		t.Fatalf("модель получила %d запросов, ожидался один", model.calls())
	}
}

// TestAnalyzeRequestTimeoutBeforeModel — предел обработки на стенде (REQ-604):
// защита, не уложившаяся в request_timeout, — 429 с Retry-After и ноль
// запросов в модель. Проверяются оба места исчерпания: диагностический
// прогон и боевой путь, которому передаётся остаток предела.
func TestAnalyzeRequestTimeoutBeforeModel(t *testing.T) {
	// МЕДЛЕННО — 100 мс на каждый прогон детекции.
	const slow = "МЕДЛЕННО Клиент Иванов Иван Иванович."
	for _, tc := range []struct {
		name, timeout string
	}{
		{"предел исчерпан диагностикой", "50ms"},
		{"остатка не хватило боевому пути", "150ms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model := newUIModel(t, fixtureReply, 0)
			mux, _ := newAnalyzeLimitServer(t, model.srv.URL, tc.timeout)

			body, err := json.Marshal(analyzeRequest{Text: slow})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathAnalyze, bytes.NewReader(body))
			req.Header.Set(headerContentType, jsonContentType)
			req.Header.Set(headerAPIKey, apiLimitedKey)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusTooManyRequests || rec.Header().Get(headerRetryAfter) == "" {
				t.Fatalf("код %d, Retry-After %q; тело %s", rec.Code, rec.Header().Get(headerRetryAfter), rec.Body.String())
			}
			if model.calls() != 0 {
				t.Fatalf("модель получила %d запросов при исчерпании предела", model.calls())
			}
			assertNoValues(t, where429, rec.Body.String())
		})
	}
}

// TestAPIMaskCoversRepeatsOnRealEngine — С-4, AC-1 на явном API: повтор даты
// рождения в дате договора и повтор ПИН в коде из смс детекция не опознаёт.
// До T-56 — 500 «защита текста не завершена»; теперь 200, все вхождения
// скрыты, обратный шаг побайтовый, изменённая маска восстанавливается
// в обоих местах.
func TestAPIMaskCoversRepeatsOnRealEngine(t *testing.T) {
	dicts, err := dict.Load()
	if err != nil {
		t.Fatalf("загрузка справочников: %v", err)
	}
	a := newAPIServerEngine(t, nil, "9s", detect.New(dicts, detect.Registered()...))
	for i, tt := range []struct{ text, value string }{
		{"Клиент Иванов Иван Иванович, дата рождения 01.02.1990. Договор от 01.02.1990 подписан.", "01.02.1990"},
		{"Клиент сообщил пин-код 1234, код из смс 1234.", "1234"},
	} {
		id := fmt.Sprintf("c4-%d", i)
		code, m, body := a.maskText(t, apiCrmKey, tt.text, id)
		if code != http.StatusOK {
			t.Fatalf("%q: код %d, тело %s", tt.text, code, body)
		}
		if strings.Contains(m.Masked, tt.value) {
			t.Fatalf("повтор %q остался открытым: %q", tt.value, m.Masked)
		}
		if code, got, _ := a.unmask(t, apiCrmKey, m.Masked, id); code != http.StatusOK || got != tt.text {
			t.Fatalf("обратный шаг: код %d, %q", code, got)
		}
		code, got, _ := a.unmask(t, apiCrmKey, answerPrefix+m.Masked, id)
		if code != http.StatusOK || got != answerPrefix+tt.text {
			t.Fatalf("изменённая маска: код %d, %q", code, got)
		}
	}
}

// TestAPILiteralPlaceholderIsNotRestored — С-6: буквальный «[ФИО_1]» во входе
// явного API не совпадает с выданной маской, и unmask изменённой маски не
// подставляет ФИО на место буквального текста. До T-56 — подставлял.
func TestAPILiteralPlaceholderIsNotRestored(t *testing.T) {
	a := newAPIServer(t, nil, "9s")
	const text = "Шаблон [ФИО_1] заполнить: клиент Иванов Иван Иванович."
	code, m, body := a.maskText(t, apiCrmKey, text, literalID)
	if code != http.StatusOK {
		t.Fatalf(msgMaskFailed, code, body)
	}
	if m.Masked != "Шаблон [ФИО_1] заполнить: клиент [ФИО_2]." {
		t.Fatalf("маска: %q", m.Masked)
	}
	code, got, _ := a.unmask(t, apiCrmKey, answerPrefix+m.Masked, literalID)
	if code != http.StatusOK || got != answerPrefix+text {
		t.Fatalf("восстановление: код %d, %q", code, got)
	}
	if code, got, _ := a.unmask(t, apiCrmKey, m.Masked, literalID); code != http.StatusOK || got != text {
		t.Fatalf("обратный шаг: код %d, %q", code, got)
	}
}

// TestAPIUnmaskRestoresMarkupFramedPlaceholder — Ж-1 на явном API: та же
// реализация восстановления, что у прокси, — метка выданного плейсхолдера в
// разметке восстанавливается, чужая остаётся.
func TestAPIUnmaskRestoresMarkupFramedPlaceholder(t *testing.T) {
	a := newAPIServer(t, nil, "9s")
	_, m, _ := a.maskText(t, apiCrmKey, apiSample, "md-1")
	answer := "Письмо для **ФИО_1**, телефон `ТЕЛЕФОН_1`, коллега **ФИО_2**."
	code, got, body := a.unmask(t, apiCrmKey, answer, "md-1")
	if code != http.StatusOK {
		t.Fatalf("unmask: код %d, тело %s; маска %q", code, body, m.Masked)
	}
	if want := "Письмо для **Иванов Иван Иванович**, телефон `+7 916 123-45-67`, коллега **ФИО_2**."; got != want {
		t.Fatalf("получено  %q\nожидалось %q", got, want)
	}
}
