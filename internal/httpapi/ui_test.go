package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/llm"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/store"
	"ai-gateway/web"
)

// Тесты стенда в сеть не выходят: downstream-моделью работает httptest.Server.
//
// Значения синтетические. Реальные персональные данные в репозиторий не
// попадают ни в фикстурах, ни в примерах на странице.
var uiMarked = map[string]pii.Type{
	uiName:  pii.FullName,
	uiPhone: pii.Phone,
	uiEmail: pii.Email,
}

// uiText — обращение, в котором размечены все значения из uiMarked.
const uiText = "Клиент " + uiName + ", телефон " + uiPhone + ", " +
	"почта " + uiEmail + ". Подготовьте ответ на обращение."

// Ключи потребителей — синтетические, задаются через окружение.
const (
	uiAllKey   = "key-ui-all"
	uiNamesKey = "key-ui-names"
	uiOpenKey  = "key-ui-open"
	uiOffKey   = "key-ui-off"
	uiModelKey = "sk-ui-model"
)

// uiTestConfig — конфигурация стенда. Потребители различаются политикой:
// на этом строится проверка того, что переключение меняет результат.
const uiTestConfig = `
server:
  addr: ":0"
  max_body_bytes: 1MiB
  max_concurrent: 8
  request_timeout: %s
store:
  ttl: 1h
llm:
  mode: %s
  base_url: %s
  model: test-model
  timeout: 5s
  api_key_env: TEST_UI_MODEL_KEY
consumers:
  - id: benchmark
    types: [all]
    demask: true
  - id: demo-all
    api_key_env: TEST_UI_ALL_KEY
    types: [all]
    demask: true
  - id: demo-names
    api_key_env: TEST_UI_NAMES_KEY
    types: [full_name]
    demask: false
  - id: demo-open
    api_key_env: TEST_UI_OPEN_KEY
    types: [all]
    masking: false
  - id: demo-off
    enabled: false
    api_key_env: TEST_UI_OFF_KEY
    types: [all]
`

// uiMarkScanner отмечает известные синтетические значения как ПД.
//
// Сканеры детекции развиваются в отдельных задачах; поведение стенда обязано
// проверяться независимо от их текущей готовности.
type uiMarkScanner struct{}

func (uiMarkScanner) Name() string { return "ui-mark" }

// uiFirstOnly — маркер в тексте: тестовый сканер отмечает только первое
// вхождение каждого значения, как детекция, не опознавшая повтор (С-4).
const uiFirstOnly = "ТОЛЬКОПЕРВОЕ"

func (uiMarkScanner) Scan(doc *lex.Doc, _ *dict.Set, out *detect.Candidates) {
	firstOnly := strings.Contains(doc.Text, uiFirstOnly)
	for v, t := range uiMarked {
		for i := 0; i < len(doc.Text); {
			j := strings.Index(doc.Text[i:], v)
			if j < 0 {
				break
			}
			at := i + j
			out.Add(at, at+len(v), t, detect.Certain, "ui-mark")
			i = at + len(v)
			if firstOnly {
				break
			}
		}
	}
}

// uiModel — фальшивая модель: записывает фактически полученные тела и умеет
// отвечать с задержкой, чтобы время модели было отличимо от времени сервиса.
type uiModel struct {
	srv   *httptest.Server
	delay time.Duration

	mu     sync.Mutex
	bodies []string
}

func newUIModel(t *testing.T, reply string, delay time.Duration) *uiModel {
	t.Helper()
	m := &uiModel{delay: delay}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.bodies = append(m.bodies, string(body))
		m.mu.Unlock()

		if m.delay > 0 {
			time.Sleep(m.delay)
		}
		resp := llm.Response{
			ID: "chatcmpl-ui", Object: "chat.completion", Model: "test-model",
			Choices: []llm.Choice{{Index: 0,
				Message:      llm.Message{Role: "assistant", Content: reply},
				FinishReason: "stop"}},
		}
		w.Header().Set(headerContentType, jsonContentType)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *uiModel) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bodies)
}

// wire возвращает всё, что фактически ушло наружу: сырые тела и раскодированное
// содержимое сообщений. Поиск ведётся по обоим представлениям, чтобы утечка не
// спряталась в escape-последовательностях JSON.
func (m *uiModel) wire(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	for _, raw := range m.bodies {
		b.WriteString(raw)
		b.WriteString("\n")
		var req llm.Request
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			t.Fatalf("перехваченное тело не является JSON: %v", err)
		}
		for _, msg := range req.Messages {
			b.WriteString(msg.Content)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// uiFailingStore отказывает в сохранении соответствия: это нарушение
// предусловия выпуска наружу.
type uiFailingStore struct{}

func (uiFailingStore) Get(string) (store.Record, bool) { return store.Record{}, false }
func (uiFailingStore) Put(string, store.Record) error  { return store.ErrFull }
func (uiFailingStore) Stats() store.Stats              { return store.Stats{} }
func (uiFailingStore) Close() error                    { return nil }

// newUIServer поднимает сервер стенда и маршрутизатор с его маршрутами.
//
// Маршруты регистрируются тем же методом, который предстоит вызвать в
// NewServer: проверяется не обработчик в отрыве от дерева путей, а маршрут.
func newUIServer(t *testing.T, mode string, base string, st store.Store, log io.Writer) (*Server, *http.ServeMux) {
	t.Helper()
	return newUIServerTimeout(t, mode, base, st, log, "9s")
}

// newUIServerTimeout позволяет задать бюджет локальной обработки.
//
// Нужен там, где проверяется, что ожидание модели этим бюджетом не ограничено:
// боевые 9 с сделали бы такой тест непозволительно медленным.
func newUIServerTimeout(t *testing.T, mode string, base string, st store.Store, log io.Writer, requestTimeout string) (*Server, *http.ServeMux) {
	t.Helper()

	t.Setenv("TEST_UI_MODEL_KEY", uiModelKey)
	t.Setenv("TEST_UI_ALL_KEY", uiAllKey)
	t.Setenv("TEST_UI_NAMES_KEY", uiNamesKey)
	t.Setenv("TEST_UI_OPEN_KEY", uiOpenKey)
	t.Setenv("TEST_UI_OFF_KEY", uiOffKey)

	body := fmt.Sprintf(uiTestConfig, requestTimeout, mode, base+"/v1")
	holder := newTestHolder(t, body)

	if st == nil {
		mem := store.NewMemory(holder.Current().Store)
		t.Cleanup(func() { _ = mem.Close() })
		st = mem
	}
	if log == nil {
		log = io.Discard
	}

	s := NewServer(Deps{
		Config:    holder,
		Gateway:   gateway.New(detect.New(nil, uiMarkScanner{}), st),
		Metrics:   obs.NewMetrics(),
		Logger:    slog.New(slog.NewTextHandler(log, nil)),
		Version:   "test",
		StartedAt: time.Now(),
	})
	mux := http.NewServeMux()
	s.registerUIRoutes(mux)
	return s, mux
}

// uiGet выполняет GET через маршрутизатор стенда.
func uiGet(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// analyze выполняет прогон стенда с заданным ключом и потребителем.
func analyze(t *testing.T, mux *http.ServeMux, key, consumer, text string) (int, analyzeResponse, string) {
	t.Helper()
	body, err := json.Marshal(analyzeRequest{Text: text, Consumer: consumer})
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathAnalyze, bytes.NewReader(body))
	req.Header.Set(headerContentType, jsonContentType)
	if key != "" {
		req.Header.Set(headerAPIKey, key)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var out analyzeResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("ответ не разобран: %v; тело %s", err, rec.Body.String())
		}
	}
	return rec.Code, out, rec.Body.String()
}

func TestUIPageServedWithoutKey(t *testing.T) {
	// AC-1: страница отдаётся по GET / и не требует ключа.
	mux, _ := newStubUI(t)

	rec := uiGet(t, mux, "/")
	assertCode(t, rec, http.StatusOK)
	if ct := rec.Header().Get(headerContentType); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("неожиданный тип содержимого %q", ct)
	}
	if csp := rec.Header().Get(headerCSP); !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("политика безопасности не ограничивает исходящие запросы: %q", csp)
	}
	body := rec.Body.String()
	if len(body) != web.PageSize() {
		t.Errorf("отдана не встроенная страница: %d байт против %d", len(body), web.PageSize())
	}
	for _, want := range []string{
		"Что фактически ушло в модель",
		"Ответ после восстановления",
		"Тайминги по этапам",
		"Сводка найденного",
		"Подставить пример",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("на странице нет блока %q", want)
		}
	}
}

func TestUIPageIsSelfContained(t *testing.T) {
	// AC-1: страница обязана открываться без доступа в интернет, поэтому ни
	// одной внешней ссылки в ней быть не может.
	page := string(web.Page())
	for _, bad := range []string{"http://", "https://", "src=\"//", "href=\"//", "@import"} {
		if strings.Contains(page, bad) {
			t.Errorf("страница ссылается наружу: найдено %q", bad)
		}
	}
	if strings.Contains(page, "console.log") {
		t.Error("страница пишет в журнал браузера")
	}
}

func TestUIPresentationServedWithoutKey(t *testing.T) {
	// T-70 AC-2: презентация отдаётся по GET /presentation без ключа и под
	// той же политикой безопасности, что и стенд.
	mux, _ := newStubUI(t)

	rec := uiGet(t, mux, "/presentation")
	assertCode(t, rec, http.StatusOK)
	if ct := rec.Header().Get(headerContentType); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("неожиданный тип содержимого %q", ct)
	}
	if csp := rec.Header().Get(headerCSP); csp != contentSecurityPolicy {
		t.Errorf("политика безопасности отличается от стенда: %q", csp)
	}
	if n := rec.Body.Len(); n != web.PresentationSize() {
		t.Errorf("отдана не встроенная презентация: %d байт против %d", n, web.PresentationSize())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Инструкция для жюри",
		"Архитектура",
		"Производительность",
		"Ограничения",
		"План развития",
		"Обязательные артефакты",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в презентации нет раздела %q", want)
		}
	}
}

func TestUIPresentationIsSelfContained(t *testing.T) {
	// Презентация открывается и с сервиса, и с диска без интернета, а CSP
	// стенда всё равно не дал бы загрузить внешний ресурс.
	page := string(web.Presentation())
	for _, bad := range []string{"http://", "https://", "src=\"//", "href=\"//", "@import"} {
		if strings.Contains(page, bad) {
			t.Errorf("презентация ссылается наружу: найдено %q", bad)
		}
	}
	if strings.Contains(page, "console.log") {
		t.Error("презентация пишет в журнал браузера")
	}
}

func TestUIPageRejectsUnknownPath(t *testing.T) {
	// Шаблон "GET /" покрывает всё дерево путей: всё несовпавшее обязано
	// получить 404, а не страницу стенда.
	mux, _ := newStubUI(t)

	rec := uiGet(t, mux, "/no-such-page")
	assertCode(t, rec, http.StatusNotFound)
}

func TestUIConsumersListedWithoutSecrets(t *testing.T) {
	mux, _ := newStubUI(t)

	rec := uiGet(t, mux, pathUIConsumers)
	assertCode(t, rec, http.StatusOK)
	var out consumersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("ответ не разобран: %v", err)
	}
	if out.LLMMode != "stub" {
		t.Errorf("режим модели не показан: %q", out.LLMMode)
	}

	states := make(map[string]bool, len(out.Consumers))
	for _, c := range out.Consumers {
		states[c.ID] = c.Enabled
	}
	if !states[consumerDemoAll] {
		t.Error("потребитель demo-all не показан как действующий")
	}
	if enabled, ok := states["demo-off"]; !ok || enabled {
		t.Error("отключённый потребитель не помечен отключённым")
	}
	for _, key := range []string{uiAllKey, uiNamesKey, uiOpenKey, uiOffKey, uiModelKey} {
		if strings.Contains(rec.Body.String(), key) {
			t.Error("ключ доступа попал в список потребителей")
		}
	}
}

func TestUIConsumersListPIIRegistry(t *testing.T) {
	// T-69: метрики несут машинные ключи типов, и дашборд берёт имена из
	// реестра сервиса, а не из второго словаря в странице. Реестр обязан
	// совпадать с internal/pii целиком, включая отметку обязательности по ТЗ.
	mux, _ := newStubUI(t)

	rec := uiGet(t, mux, pathUIConsumers)
	assertCode(t, rec, http.StatusOK)
	var out consumersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("ответ не разобран: %v", err)
	}
	all := pii.All()
	if len(out.PIITypes) != len(all) {
		t.Fatalf("в реестре %d типов, в internal/pii — %d", len(out.PIITypes), len(all))
	}
	for i, typ := range all {
		got := out.PIITypes[i]
		want := piiTypeBrief{Key: typ.Key(), Label: typ.Label(), Placeholder: typ.Placeholder(), Required: typ.Required()}
		if got != want {
			t.Errorf("тип %d: получено %+v, ожидалось %+v", i, got, want)
		}
	}
}

func TestAnalyzeRequiresKey(t *testing.T) {
	// AC-7: обслуживающий эндпоинт требует ключ так же, как продуктовые.
	mux, model := newStubUI(t)

	cases := []struct {
		name string
		key  string
	}{
		{"без ключа", ""},
		{"неизвестный ключ", unknownKey},
		{"ключ отключённого потребителя", uiOffKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, body := analyze(t, mux, tc.key, "", uiText)
			if code != http.StatusUnauthorized {
				t.Fatalf(msgCodeBody, code, body)
			}
			if strings.Contains(body, "demo-") {
				t.Errorf("ответ раскрывает подробности проверки: %s", body)
			}
		})
	}
	if model.calls() != 0 {
		t.Fatalf("неаутентифицированный запрос дошёл до модели: %d вызовов", model.calls())
	}
}

func TestAnalyzeRejectsEmptyText(t *testing.T) {
	mux, _ := newStubUI(t)

	if code, _, body := analyze(t, mux, uiAllKey, "", "   "); code != http.StatusBadRequest {
		t.Fatalf(msgCodeBody, code, body)
	}
}

// TestAnalyzeModelWaitOutlivesRequestTimeout охраняет ту же границу, что и
// одноимённый тест продуктового контура: стенд обязан вести себя как боевой
// путь. Диагностический прогон идёт под бюджетом обработки, а вызов модели —
// под своим таймаутом клиента. Подчинить второй первому значит обрезать на
// стенде любой ответ модели медленнее бюджета.
func TestAnalyzeModelWaitOutlivesRequestTimeout(t *testing.T) {
	model := newUIModel(t, "Готовлю ответ для [ФИО_1].", 400*time.Millisecond)
	_, mux := newUIServerTimeout(t, modeAlfaGen, model.srv.URL, nil, nil, "150ms")

	code, res, body := analyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	if code != http.StatusOK {
		t.Fatalf("ожидание модели обрезано бюджетом обработки: код %d, тело %s", code, body)
	}
	if res.ChainStatus != "ok" {
		t.Fatalf("цепочка не завершилась: %s (%s)", res.ChainStatus, res.ChainNote)
	}
	if !res.SentToModel.Performed {
		t.Fatal("боевой путь не дошёл до модели")
	}
	if !strings.Contains(res.ModelResponseRestored, uiName) {
		t.Fatalf("ответ модели не восстановлен: %q", res.ModelResponseRestored)
	}
	// Диагностический прогон при этом бюджету подчинён — он уложился и дал спаны.
	if len(res.Spans) == 0 {
		t.Fatal("диагностический прогон не дал спанов")
	}
}

func TestAnalyzeShowsWhatWasActuallySent(t *testing.T) {
	// AC-3 и главный смысл стенда: блок «что ушло в модель» показывает
	// фактически отправленное тело. Проверка независимая: сравнивается с тем,
	// что получила фальшивая модель.
	model := newUIModel(t, "Готовлю ответ для [ФИО_1].", 0)
	_, mux := newUIServer(t, modeAlfaGen, model.srv.URL, nil, nil)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	if res.ChainStatus != "ok" {
		t.Fatalf("цепочка не завершилась: %s (%s)", res.ChainStatus, res.ChainNote)
	}
	if !res.SentToModel.Performed || res.SentToModel.Body == "" {
		t.Fatal("блок «что ушло в модель» пуст")
	}

	// Показанное на стенде обязано совпасть с фактически полученным моделью.
	wire := model.wire(t)
	if !strings.Contains(wire, res.SentToModel.Messages[0].Content) {
		t.Fatalf("показанное тело не совпадает с полученным моделью:\nстенд: %s\nмодель: %s",
			res.SentToModel.Body, wire)
	}

	// Поиск ведётся по каждому размеченному значению отдельно: сравнение
	// целого тела пропустило бы частичную утечку.
	for value := range uiMarked {
		if strings.Contains(res.SentToModel.Body, value) {
			t.Errorf("значение %q показано как отправленное в модель", value)
		}
		if strings.Contains(wire, value) {
			t.Errorf("значение %q фактически ушло в модель", value)
		}
	}
	for _, p := range []string{placeholderName, "[ТЕЛЕФОН_1]", "[EMAIL_1]"} {
		if !strings.Contains(res.SentToModel.Body, p) {
			t.Errorf("в отправленном теле нет маски %s: %s", p, res.SentToModel.Body)
		}
	}
	if res.LeakCheck.Checked != len(uiMarked) || res.LeakCheck.Found != 0 {
		t.Errorf("проверка перехвата на стенде: проверено %d из %d, найдено %d",
			res.LeakCheck.Checked, len(uiMarked), res.LeakCheck.Found)
	}
}

func TestAnalyzeHighlightsSpansWithTypeAndConfidence(t *testing.T) {
	// AC-2: спаны подписаны типом и уровнем уверенности, смещения указывают
	// на значение точно.
	mux, _ := newStubUI(t)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	if len(res.Spans) != len(uiMarked) {
		t.Fatalf("найдено спанов %d, ожидалось %d", len(res.Spans), len(uiMarked))
	}

	levels := map[string]bool{"certain": true, "strong": true, "weak": true}
	for _, sp := range res.Spans {
		value := uiText[sp.Start:sp.End]
		want, ok := uiMarked[value]
		if !ok {
			t.Errorf("спан %d:%d указывает не на размеченное значение", sp.Start, sp.End)
			continue
		}
		if sp.Type != want.Key() {
			t.Errorf("значение по смещению %d отнесено к типу %s вместо %s", sp.Start, sp.Type, want.Key())
		}
		if sp.Label != want.Label() {
			t.Errorf("тип %s подписан как %q", sp.Type, sp.Label)
		}
		if !levels[sp.Confidence] {
			t.Errorf("уровень уверенности %q не из перечисления", sp.Confidence)
		}
		if !sp.Masked || sp.Replacement == "" {
			t.Errorf("спан %s не отмечен как замаскированный", sp.Type)
		}
	}
	if len(res.Summary) != len(uiMarked) {
		t.Errorf("в сводке %d строк, ожидалось %d", len(res.Summary), len(uiMarked))
	}
}

func TestAnalyzeConsumerSwitchChangesResult(t *testing.T) {
	// AC-5: переключение потребителя меняет результат согласно его политике.
	// demo-names маскирует только ФИО, demo-all — все типы.
	_, mux, _ := newModelUI(t, fixtureReply)

	_, all, _ := analyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	_, names, _ := analyze(t, mux, uiAllKey, consumerDemoNames, uiText)

	if len(all.Spans) <= len(names.Spans) {
		t.Fatalf("политика не повлияла на разбор: demo-all %d спанов, demo-names %d",
			len(all.Spans), len(names.Spans))
	}
	if names.Consumer.ID != consumerDemoNames {
		t.Fatalf("применена политика потребителя %s", names.Consumer.ID)
	}
	if names.Consumer.Demask {
		t.Error("demo-names получил право на демаскирование")
	}
	// Телефон в политику demo-names не входит: он законно уходит в модель,
	// и стенд не должен выдавать это за утечку.
	if !strings.Contains(names.SentToModel.Body, uiPhone) {
		t.Error("тип вне политики потребителя не дошёл до модели")
	}
	if !strings.Contains(names.SentToModel.Body, placeholderName) {
		t.Error("тип из политики потребителя не замаскирован")
	}
	if names.LeakCheck.Found != 0 {
		t.Errorf("проверка перехвата нашла %d значений", names.LeakCheck.Found)
	}
}

func TestAnalyzeRefusesConsumerWithMaskingDisabled(t *testing.T) {
	// Прогон под потребителем с отключённым маскированием отправил бы в модель
	// незащищённый текст. На демонстрации это провал ключевой функции.
	_, mux, model := newModelUI(t, fixtureReply)

	code, _, body := analyze(t, mux, uiAllKey, "demo-open", uiText)
	if code != http.StatusForbidden {
		t.Fatalf(msgCodeBody, code, body)
	}
	if model.calls() != 0 {
		t.Fatalf("запрос ушёл наружу: %d вызовов", model.calls())
	}
	if code, _, body := analyze(t, mux, uiAllKey, "demo-off", uiText); code != http.StatusForbidden {
		t.Fatalf("отключённый потребитель принят: код %d, тело %s", code, body)
	}
}

func TestAnalyzeFailClosedShowsNothingSent(t *testing.T) {
	// Отказ хранилища — нарушение предусловия выпуска: наружу не уходит
	// ничего, и стенд обязан показать именно это.
	model := newUIModel(t, fixtureReply, 0)
	_, mux := newUIServer(t, modeAlfaGen, model.srv.URL, uiFailingStore{}, nil)

	code, res, body := analyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	mustStatus(t, code, http.StatusOK, body)
	if res.ChainStatus != "fail_closed" {
		t.Fatalf("исход цепочки %q вместо fail_closed", res.ChainStatus)
	}
	if res.SentToModel.Performed || res.SentToModel.Body != "" {
		t.Error("стенд показал отправку, которой не было")
	}
	if model.calls() != 0 {
		t.Fatalf("модель получила %d запросов при сработавшем fail-closed", model.calls())
	}
	for value := range uiMarked {
		if strings.Contains(body, value) {
			t.Errorf("значение %q попало в тело ответа стенда", value)
		}
	}
}

func TestAnalyzeUpstreamFailureKeepsDemonstration(t *testing.T) {
	// Сертификат провайдера истёк — это внешняя поломка. Стенд обязан
	// показать защиту запроса и без ответа модели.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer dead.Close()
	_, mux := newUIServer(t, modeAlfaGen, dead.URL, nil, nil)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	if res.ChainStatus != "upstream_error" {
		t.Fatalf("исход цепочки %q вместо upstream_error", res.ChainStatus)
	}
	if !res.SentToModel.Performed || !strings.Contains(res.SentToModel.Body, placeholderName) {
		t.Error("блок «что ушло в модель» не заполнен при недоступной модели")
	}
	if len(res.Spans) == 0 {
		t.Error("разбор текста потерян при недоступной модели")
	}
}

func TestAnalyzeStubModeWorksWithoutNetwork(t *testing.T) {
	// Сейчас llm.mode: stub, и стенд обязан работать в обоих режимах.
	model := newUIModel(t, "этот ответ не должен использоваться", 0)
	_, mux := newUIServer(t, llm.ModeStub, model.srv.URL, nil, nil)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	if model.calls() != 0 {
		t.Fatalf("режим stub обратился к сети: %d запросов", model.calls())
	}
	if res.ChainStatus != "ok" {
		t.Fatalf("исход цепочки %q", res.ChainStatus)
	}
	if !strings.Contains(res.ModelResponseRaw, placeholderName) {
		t.Errorf("ответ модели не показан как есть: %q", res.ModelResponseRaw)
	}
	if !strings.Contains(res.ModelResponseRestored, uiName) {
		t.Errorf("ответ после восстановления не содержит исходного значения: %q", res.ModelResponseRestored)
	}
	if res.Model.Mode != "stub" {
		t.Errorf("режим работы с моделью показан как %q", res.Model.Mode)
	}
}

func TestAnalyzeDemaskDeniedKeepsPlaceholders(t *testing.T) {
	// У demo-names demask: false — восстановления быть не должно.
	model := newUIModel(t, "Ответ для [ФИО_1].", 0)
	_, mux := newUIServer(t, modeAlfaGen, model.srv.URL, nil, nil)

	res := mustAnalyze(t, mux, uiNamesKey, "", uiText)
	if !strings.Contains(res.ModelResponseRestored, placeholderName) {
		t.Errorf("плейсхолдер восстановлен вопреки политике: %q", res.ModelResponseRestored)
	}
	if strings.Contains(res.ModelResponseRestored, uiName) {
		t.Error("значение раскрыто потребителю без права демаскирования")
	}
}

func TestAnalyzeSeparatesModelTimeFromServiceTime(t *testing.T) {
	// AC-4: время модели измеряется отдельно и во время сервиса не входит.
	const delay = 150 * time.Millisecond
	model := newUIModel(t, fixtureReply, delay)
	s, mux := newUIServer(t, modeAlfaGen, model.srv.URL, nil, nil)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)

	t3 := res.Timings
	if t3.LLM < float64(delay.Milliseconds()) {
		t.Fatalf("время модели %v мс меньше заданной задержки %v", t3.LLM, delay)
	}
	if t3.Service >= t3.LLM {
		t.Fatalf("время сервиса %v мс не отделено от времени модели %v мс", t3.Service, t3.LLM)
	}
	if t3.Detect <= 0 || t3.Mask <= 0 || t3.Protect <= 0 {
		t.Errorf("этапы защиты не измерены: %+v", t3)
	}
	if got, want := t3.Service, t3.Protect+t3.Restore; got != want {
		t.Errorf("время сервиса %v не равно сумме этапов %v", got, want)
	}

	// Та же граница проходит и в метриках сервиса.
	var b strings.Builder
	s.deps.Metrics.WriteProm(&b)
	out := b.String()
	if !strings.Contains(out, `aigw_requests_total{endpoint="analyze",op="proxy",outcome="ok"} 1`) {
		t.Fatalf("запрос стенда не учтён метрикой:\n%s", out)
	}
	llmSum := promValue(t, out, "aigw_llm_duration_seconds_sum{}")
	svcSum := promValue(t, out, `aigw_request_duration_seconds_sum{endpoint="analyze",op="proxy"}`)
	if llmSum <= 0 {
		t.Fatalf("время модели не измерено: %v", llmSum)
	}
	if svcSum >= llmSum {
		t.Fatalf("время модели (%v) не вычтено из времени сервиса (%v)", llmSum, svcSum)
	}
}

func TestAnalyzeDoesNotLogTextOrValues(t *testing.T) {
	// AC-8: ни исходный текст, ни значения ПД в журнал не попадают.
	var log bytes.Buffer
	model := newUIModel(t, fixtureReply, 0)
	_, mux := newUIServer(t, modeAlfaGen, model.srv.URL, nil, &log)

	mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)

	out := log.String()
	if out == "" {
		t.Fatal("журнал пуст: проверять нечего")
	}
	for value := range uiMarked {
		if strings.Contains(out, value) {
			t.Errorf("значение %q попало в журнал", value)
		}
	}
	if strings.Contains(out, "Подготовьте ответ на обращение") {
		t.Error("исходный текст попал в журнал")
	}
	for _, key := range []string{uiAllKey, uiModelKey} {
		if strings.Contains(out, key) {
			t.Error("ключ доступа попал в журнал")
		}
	}
	if !strings.Contains(out, typeFullName) {
		t.Errorf("типы ПД в журнале не отражены:\n%s", out)
	}
}

// uiGetKey выполняет GET с ключом доступа через маршрутизатор стенда.
func uiGetKey(t *testing.T, mux *http.ServeMux, path, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	if key != "" {
		req.Header.Set(headerAPIKey, key)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// uiHistoryRows разбирает ответ истории.
func uiHistoryRows(t *testing.T, body string) []historyRow {
	t.Helper()
	var out historyResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("история не разобрана: %v; тело %s", err, body)
	}
	return out.Rows
}

func TestUIObservabilityRoutesRequireKey(t *testing.T) {
	// AC-9: новые эндпоинты — продуктовые. Без ключа и с чужим ключом они
	// отвечают 401, различить эти два случая клиент не может.
	mux, _ := newStubUI(t)

	for _, path := range []string{
		pathUIHistory, pathUIJournal, uiTraceByID + "r1",
	} {
		if rec := uiGetKey(t, mux, path, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s без ключа вернул %d", path, rec.Code)
		}
		if rec := uiGetKey(t, mux, path, "не-тот-ключ"); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s с чужим ключом вернул %d", path, rec.Code)
		}
		// Ключ отключённого потребителя равноценен отсутствию ключа.
		if rec := uiGetKey(t, mux, path, uiOffKey); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s с ключом отключённого потребителя вернул %d", path, rec.Code)
		}
	}
}

func TestUIHistoryIsolatesConsumers(t *testing.T) {
	// REQ-404 и AC-9: поток журнала и история не должны стать способом увидеть
	// чужие запросы. Прогон выполняет demo-all; читает demo-names.
	mux, _ := newStubUI(t)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)

	own := uiHistoryRows(t, uiGetKey(t, mux, pathUIHistory, uiAllKey).Body.String())
	if len(own) != 1 || own[0].RequestID != res.RequestID {
		t.Fatalf("владелец не увидел собственный прогон: %+v", own)
	}

	foreign := uiGetKey(t, mux, pathUIHistory, uiNamesKey)
	if rows := uiHistoryRows(t, foreign.Body.String()); len(rows) != 0 {
		t.Errorf("чужому ключу видно %d записей: %+v", len(rows), rows)
	}
	if strings.Contains(foreign.Body.String(), res.RequestID) {
		t.Error("идентификатор чужого запроса попал в историю другого потребителя")
	}

	// Разбор чужого запроса неотличим от несуществующего.
	if rec := uiGetKey(t, mux, uiTraceByID+res.RequestID, uiNamesKey); rec.Code != http.StatusNotFound {
		t.Errorf("трассировка чужого запроса вернула %d вместо 404: %s", rec.Code, rec.Body.String())
	}
	if rec := uiGetKey(t, mux, uiTraceByID+res.RequestID, uiAllKey); rec.Code != http.StatusOK {
		t.Errorf("владелец не получил свою трассировку: %d", rec.Code)
	}

	// Поток журнала подчиняется тому же правилу.
	jrn := uiGetKey(t, mux, pathUIJournal, uiNamesKey).Body.String()
	if strings.Contains(jrn, res.RequestID) || strings.Contains(jrn, consumerDemoAll) {
		t.Errorf("запись чужого прогона видна в потоке журнала: %s", jrn)
	}
}

func TestUIHistoryKeepsRunUnderForeignPolicyWithOwner(t *testing.T) {
	// Стенд позволяет прогнать текст под чужой политикой. Запись принадлежит
	// предъявителю ключа: иначе она исчезла бы из его собственной истории,
	// а владелец политики увидел бы чужое обращение.
	mux, _ := newStubUI(t)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoNames, uiText)

	rows := uiHistoryRows(t, uiGetKey(t, mux, pathUIHistory, uiAllKey).Body.String())
	if len(rows) != 1 || rows[0].RequestID != res.RequestID {
		t.Fatalf("прогон под чужой политикой пропал из истории владельца ключа: %+v", rows)
	}
	if rows[0].Consumer != consumerDemoNames {
		t.Errorf("показана политика %q вместо demo-names", rows[0].Consumer)
	}
	if got := uiHistoryRows(t, uiGetKey(t, mux, pathUIHistory, uiNamesKey).Body.String()); len(got) != 0 {
		t.Errorf("владельцу политики видно чужое обращение: %+v", got)
	}
}

func TestUITraceSeparatesModelWaitFromServiceTime(t *testing.T) {
	// AC-7: ожидание модели отделено от времени сервиса. Модель отвечает с
	// задержкой, заведомо большей работы сервиса, — перепутать их нельзя.
	const delay = 120 * time.Millisecond
	model := newUIModel(t, fixtureReply, delay)
	_, mux := newUIServer(t, modeAlfaGen, model.srv.URL, nil, nil)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)

	rec := uiGetKey(t, mux, uiTraceByID+res.RequestID, uiAllKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("трассировка вернула %d: %s", rec.Code, rec.Body.String())
	}
	var tr traceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil {
		t.Fatalf("трассировка не разобрана: %v", err)
	}

	llm := checkTraceStages(t, &tr)
	if llm.Service {
		t.Error("ожидание модели помечено как входящее во время сервиса")
	}
	if llm.MS < float64(delay.Milliseconds()) {
		t.Errorf("ожидание модели %.1f мс меньше задержки %d мс", llm.MS, delay.Milliseconds())
	}
	if tr.WaitMS < float64(delay.Milliseconds()) {
		t.Errorf("время вне сервиса %.1f мс меньше задержки модели", tr.WaitMS)
	}
	if tr.ServiceMS >= tr.WaitMS {
		t.Errorf("время сервиса %.1f мс не меньше ожидания модели %.1f мс: они перепутаны",
			tr.ServiceMS, tr.WaitMS)
	}
	checkTraceBounds(t, &tr)
}

// checkTraceStages проверяет, что на трассировке есть все этапы продуктового
// пути, и возвращает отрезок ожидания модели; без него тест прерывается.
func checkTraceStages(t *testing.T, tr *traceResponse) *traceSpanView {
	t.Helper()
	var llm *traceSpanView
	stages := make(map[string]bool, len(tr.Spans))
	for i := range tr.Spans {
		stages[tr.Spans[i].Stage] = true
		if tr.Spans[i].Stage == "llm" {
			llm = &tr.Spans[i]
		}
	}
	for _, want := range []string{"accept", "protect", "detect", "mask", "store", "llm", "restore"} {
		if !stages[want] {
			t.Errorf("на трассировке нет этапа %q", want)
		}
	}
	if llm == nil {
		t.Fatal("на трассировке нет ожидания модели")
	}
	return llm
}

// checkTraceBounds проверяет, что отрезки родителя и его детей не выходят за
// пределы шкалы.
func checkTraceBounds(t *testing.T, tr *traceResponse) {
	t.Helper()
	for _, sp := range tr.Spans {
		if sp.AtMS < 0 || sp.AtMS+sp.MS > tr.TotalMS+0.001 {
			t.Errorf("отрезок %q выходит за пределы шкалы: %+v при общей длине %.3f",
				sp.Stage, sp, tr.TotalMS)
		}
	}
}

func TestUIHistoryAndTraceCarryNoValues(t *testing.T) {
	// AC-2 на уровне транспорта: поиск каждого размеченного значения отдельно
	// в теле истории, потока журнала и трассировки.
	model := newUIModel(t, "Свяжитесь с "+uiName+" по "+uiPhone, 0)
	_, mux := newUIServer(t, llm.ModeStub, model.srv.URL, nil, nil)

	res := mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)

	surfaces := map[string]string{
		"история":     uiGetKey(t, mux, pathUIHistory, uiAllKey).Body.String(),
		sourceJournal: uiGetKey(t, mux, pathUIJournal, uiAllKey).Body.String(),
		"трассировка": uiGetKey(t, mux, uiTraceByID+res.RequestID, uiAllKey).Body.String(),
	}
	for name, surface := range surfaces {
		if len(surface) < 40 {
			t.Fatalf("поверхность «%s» почти пуста: проверка была бы бессодержательной", name)
		}
		for value, typ := range uiMarked {
			if strings.Contains(surface, value) {
				t.Errorf("значение типа %s найдено в поверхности «%s»", typ, name)
			}
		}
		if strings.Contains(surface, uiText) {
			t.Errorf("исходный текст найден в поверхности «%s»", name)
		}
	}
}

func TestUIHistoryRejectsClientSuppliedRequestID(t *testing.T) {
	// Идентификатор запроса приходит заголовком и потому единственный из
	// строковых полей истории зависит от клиента. Посторонние символы в нём
	// приводят к выдаче собственного идентификатора, и значение ПД в буфер
	// таким путём не попадает.
	if got := sanitizeRequestID(uiName); got != "" {
		t.Errorf("идентификатор с посторонними символами принят: %q", got)
	}
	if got := sanitizeRequestID(strings.Repeat("a", maxRequestIDBytes+1)); got != "" {
		t.Error("слишком длинный идентификатор принят")
	}
	if got := sanitizeRequestID("trace-id_42.a:b"); got != "trace-id_42.a:b" {
		t.Errorf("обычный идентификатор отвергнут: %q", got)
	}
}

func TestUIHistoryIsBoundedOnStand(t *testing.T) {
	// AC-1 на уровне транспорта: сколько бы прогонов ни выполнили, буфер не
	// растёт. Предел выборки проверяется тем же запросом.
	mux, _ := newStubUI(t)

	const runs = 12
	for i := 0; i < runs; i++ {
		if code, _, body := analyze(t, mux, uiAllKey, consumerDemoAll, uiText); code != http.StatusOK {
			t.Fatalf("прогон %d вернул %d: %s", i, code, body)
		}
	}
	all := uiHistoryRows(t, uiGetKey(t, mux, pathUIHistory+"?limit=1000", uiAllKey).Body.String())
	if len(all) != runs {
		t.Fatalf("в истории %d записей после %d прогонов", len(all), runs)
	}
	if len(all) > obs.DefaultHistorySize {
		t.Fatalf("история переросла вместимость буфера: %d", len(all))
	}
	limited := uiHistoryRows(t, uiGetKey(t, mux, pathUIHistory+"?limit=3", uiAllKey).Body.String())
	if len(limited) != 3 {
		t.Errorf("предел выборки не соблюдён: отдано %d записей", len(limited))
	}
	// Новые записи идут первыми: на демонстрации последний прогон обязан быть
	// вверху таблицы.
	if limited[0].Seq <= limited[1].Seq {
		t.Error("история отдана не от новых к старым")
	}
}

func TestUIJournalPollIsIncrementalOnStand(t *testing.T) {
	// AC-5: поток обновляется без перезагрузки страницы. Опрос разностный —
	// повторно передаётся только то, чего страница ещё не видела.
	mux, _ := newStubUI(t)

	mustAnalyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	var first journalResponse
	if err := json.Unmarshal(uiGetKey(t, mux, pathUIJournal, uiAllKey).Body.Bytes(), &first); err != nil {
		t.Fatalf("поток не разобран: %v", err)
	}
	if !first.Enabled || len(first.Rows) == 0 {
		t.Fatalf("поток журнала пуст: %+v", first)
	}

	var repeat journalResponse
	path := pathUIJournal + "?after=" + strconv.FormatUint(first.Seq, 10)
	if err := json.Unmarshal(uiGetKey(t, mux, path, uiAllKey).Body.Bytes(), &repeat); err != nil {
		t.Fatalf("повторный опрос не разобран: %v", err)
	}
	if len(repeat.Rows) != 0 {
		t.Errorf("повторный опрос вернул %d записей вместо нуля", len(repeat.Rows))
	}

	if code, _, body := analyze(t, mux, uiAllKey, consumerDemoAll, uiText); code != http.StatusOK {
		t.Fatalf("второй прогон вернул %d: %s", code, body)
	}
	var next journalResponse
	if err := json.Unmarshal(uiGetKey(t, mux, path, uiAllKey).Body.Bytes(), &next); err != nil {
		t.Fatalf("разностный опрос не разобран: %v", err)
	}
	if len(next.Rows) == 0 {
		t.Error("разностный опрос не вернул новых записей")
	}
	for _, row := range next.Rows {
		if row.Seq <= first.Seq {
			t.Errorf("разностный опрос вернул уже отданную запись %d", row.Seq)
		}
	}
}

// TestAnalyzeForeignPolicyDoesNotGrantDemask — Ж-2: ключ без права
// демаскирования, выбрав на стенде политику с правом, получает её правила
// маскирования, но не восстановленный ответ модели — ни в скобках, ни в
// разметке. Ключ с правом под той же политикой ответ получает.
func TestAnalyzeForeignPolicyDoesNotGrantDemask(t *testing.T) {
	model := newUIModel(t, "Ответ для [ФИО_1] и **ТЕЛЕФОН_1**.", 0)
	_, mux := newUIServer(t, modeAlfaGen, model.srv.URL, nil, nil)

	res := mustAnalyze(t, mux, uiNamesKey, consumerDemoAll, uiText)
	if res.Consumer.ID != consumerDemoAll || res.Consumer.Demask {
		t.Fatalf("политика %s, право демаскирования %v", res.Consumer.ID, res.Consumer.Demask)
	}
	if res.ModelResponseRestored != "Ответ для [ФИО_1] и **ТЕЛЕФОН_1**." {
		t.Fatalf("ответ восстановлен ключу без права: %q", res.ModelResponseRestored)
	}
	for v := range uiMarked {
		if strings.Contains(res.ModelResponseRestored, v) {
			t.Fatalf("значение %q раскрыто ключу без права", v)
		}
	}
	// Правила маскирования — выбранной политики: телефон скрыт, хотя у
	// demo-names он в список типов не входит.
	if strings.Contains(model.wire(t), uiPhone) {
		t.Fatal("правила маскирования выбранной политики не применены")
	}

	_, res, _ = analyze(t, mux, uiAllKey, consumerDemoAll, uiText)
	if res.ModelResponseRestored != "Ответ для "+uiName+" и **"+uiPhone+"**." {
		t.Fatalf("ключ с правом не получил восстановленный ответ: %q", res.ModelResponseRestored)
	}
}

// TestAnalyzeHighlightsRepeats — С-4 на стенде: повтор, закрытый маской,
// подсвечивается и попадает в проверку перехвата; показанная маска совпадает
// с отправленной.
func TestAnalyzeHighlightsRepeats(t *testing.T) {
	_, mux, model := newModelUI(t, fixtureReply)

	// Маркер велит тестовому сканеру отмечать только первое вхождение:
	// повтор почты детекция «не опознаёт».
	const text = uiText + " " + uiFirstOnly + ": повторно " + uiEmail + "."
	res := mustAnalyze(t, mux, uiAllKey, "", text)
	if len(res.Notes) != 0 {
		t.Fatalf("дорожки разошлись: %v", res.Notes)
	}
	if repeats := countEmailRepeats(t, text, res.Spans); repeats != 1 {
		t.Fatalf("повторов в разборе %d, ожидался 1: %+v", repeats, res.Spans)
	}
	if res.LeakCheck.Found != 0 || strings.Contains(model.wire(t), uiEmail) {
		t.Fatalf("почта ушла в модель: %+v", res.LeakCheck)
	}
	for _, row := range res.Summary {
		if row.Type == "email" && (row.Detected != 2 || row.Masked != 2) {
			t.Fatalf("сводка по почте: %+v", row)
		}
	}
}

// countEmailRepeats считает спаны-повторы и прерывает тест, если повтор
// показан не как замаскированная почта uiEmail.
func countEmailRepeats(t *testing.T, text string, spans []spanView) int {
	t.Helper()
	var repeats int
	for _, sp := range spans {
		if sp.Rule != "repeat" {
			continue
		}
		repeats++
		if !sp.Masked || sp.Replacement != "[EMAIL_1]" || text[sp.Start:sp.End] != uiEmail {
			t.Fatalf("повтор показан неверно: %+v", sp)
		}
	}
	return repeats
}

func TestUIPageHasObservabilitySections(t *testing.T) {
	// AC-5, AC-6, AC-7, AC-8: на странице есть все четыре новых блока.
	page := string(web.Page())
	for _, want := range []string{
		"Метрики сервиса",
		"История запросов",
		"Трассировка этапов",
		"Поток журнала",
		"Latency средняя",
		"RPS — запросов в секунду",
		"TPS — токенов в секунду",
		pathUIHistory,
		pathUIJournal,
		"/api/v1/ui/trace",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("на странице нет %q", want)
		}
	}
}

func TestUIPageHasTabs(t *testing.T) {
	// T-69: стенд разнесён по вкладкам, вкладка живёт в location.hash.
	page := string(web.Page())
	for _, tab := range []string{"jury", "dashboard", "history", "logs", "config"} {
		for _, want := range []string{`id="tab-` + tab + `"`, `id="panel-` + tab + `"`, `data-tab="` + tab + `"`} {
			if !strings.Contains(page, want) {
				t.Errorf("у вкладки %s нет %s", tab, want)
			}
		}
		// Элемент с id, совпадающим с именем вкладки, перехватил бы переход
		// по «#имя»: браузер прокрутил бы к нему вместо переключения вкладки.
		if strings.Contains(page, `id="`+tab+`"`) {
			t.Errorf("id=%q совпадает с именем вкладки", tab)
		}
	}
	for _, want := range []string{
		"Проверка жюри",
		"Дашборд",
		"История и трассировка",
		"Конфигурация",
		"Запросы в секунду",
		"Время ответа сервиса",
		"Распределение времени ответа",
		"Персональные данные по типам",
		"Исходы запросов",
		"Каталог типов персональных данных",
		"/healthz",
		"/readyz",
		"pii_types",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("на странице нет %q", want)
		}
	}
}
