package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
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
	"ai-gateway/internal/llm"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/store"
)

// Тесты не выходят в сеть: downstream-моделью работает httptest.Server.
//
// Значения ниже синтетические. Реальные персональные данные в репозиторий не
// попадают ни в фикстурах, ни в примерах.
var proxyMarked = map[string]pii.Type{
	"Иванов Иван Иванович": pii.FullName,
	"+7 916 123-45-67":     pii.Phone,
	"ivanov@example.test":  pii.Email,
	"4276 5500 1234 5678":  pii.CardNumber,
}

// Ключи потребителей и модели — синтетические, задаются через окружение.
const (
	crmKey      = "key-crm-test"
	readonlyKey = "key-readonly-test"
	lockedKey   = "key-locked-test"
	modelKey    = "sk-alfagen-test"
)

// proxyTestConfig — конфигурация продуктового контура. Адрес модели
// подставляется адресом фальшивого сервера.
const proxyTestConfig = `
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
  timeout: 3s
  api_key_env: TEST_ALFAGEN_KEY
consumers:
  - id: benchmark
    types: [all]
    demask: true
  - id: crm
    api_key_env: TEST_CRM_KEY
    types: [all]
    demask: true
  - id: readonly
    api_key_env: TEST_READONLY_KEY
    types: [all]
    demask: false
  - id: locked
    enabled: false
    api_key_env: TEST_LOCKED_KEY
    types: [all]
`

// proxyMarkScanner отмечает известные синтетические значения как ПД.
//
// Сканеры детекции разрабатываются в отдельных задачах; инвариант выпуска
// наружу обязан проверяться независимо от их готовности.
type proxyMarkScanner struct{}

func (proxyMarkScanner) Name() string { return "proxy-mark" }

func (proxyMarkScanner) Scan(doc *lex.Doc, _ *dict.Set, out *detect.Candidates) {
	for v, t := range proxyMarked {
		for i := 0; i < len(doc.Text); {
			j := strings.Index(doc.Text[i:], v)
			if j < 0 {
				break
			}
			at := i + j
			out.Add(at, at+len(v), t, detect.Certain, "proxy-mark")
			i = at + len(v)
		}
	}
}

// fakeLLM — фальшивый сервер модели: сохраняет фактически полученные тела.
type fakeLLM struct {
	srv *httptest.Server

	mu     sync.Mutex
	bodies []string
	auth   []string

	status int           // код ответа; 0 означает 200
	reply  string        // содержимое choices[0].message.content
	delay  time.Duration // задержка ответа: имитация медленной модели
}

func newFakeLLM(t *testing.T, reply string) *fakeLLM {
	t.Helper()
	f := &fakeLLM{reply: reply}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(body))
		f.auth = append(f.auth, r.Header.Get(headerAuthorization))
		status, reply, delay := f.status, f.reply, f.delay
		f.mu.Unlock()

		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		resp := llm.Response{
			ID: "chatcmpl-fake", Object: "chat.completion", Model: "test-model",
			Choices: []llm.Choice{{Index: 0,
				Message:      llm.Message{Role: "assistant", Content: reply},
				FinishReason: "stop"}},
			Usage: llm.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
		}
		w.Header().Set(headerContentType, jsonContentType)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLLM) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

// wire возвращает всё, что фактически ушло наружу: сырые тела и раскодированное
// содержимое сообщений. Поиск ведётся по обоим представлениям, чтобы утечка не
// спряталась в escape-последовательностях JSON.
func (f *fakeLLM) wire(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()

	var b strings.Builder
	for _, raw := range f.bodies {
		b.WriteString(raw)
		b.WriteString("\n")
		var req llm.Request
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			t.Fatalf("перехваченное тело не является JSON: %v", err)
		}
		for _, m := range req.Messages {
			b.WriteString(m.Content)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// proxyFailingStore отказывает в сохранении соответствия: это нарушение
// предусловия выпуска наружу.
type proxyFailingStore struct{}

func (proxyFailingStore) Get(string) (store.Record, bool) { return store.Record{}, false }
func (proxyFailingStore) Put(string, store.Record) error  { return store.ErrFull }
func (proxyFailingStore) Stats() store.Stats              { return store.Stats{} }
func (proxyFailingStore) Close() error                    { return nil }

// newProxyTestServer поднимает сервер, направленный на фальшивую модель.
func newProxyTestServer(t *testing.T, base string, st store.Store) *Server {
	t.Helper()
	return newProxyTestServerMode(t, modeAlfaGen, base, st)
}

// newProxyTestServerMode поднимает сервер в заданном режиме работы с моделью.
func newProxyTestServerMode(t *testing.T, mode, base string, st store.Store) *Server {
	t.Helper()
	return newProxyTestServerTimeout(t, mode, base, st, "9s")
}

// newProxyTestServerTimeout позволяет задать бюджет локальной обработки.
//
// Нужен там, где проверяется, что ожидание модели этим бюджетом не ограничено:
// боевые 9 с сделали бы такой тест непозволительно медленным.
func newProxyTestServerTimeout(t *testing.T, mode, base string, st store.Store, requestTimeout string) *Server {
	t.Helper()

	t.Setenv("TEST_ALFAGEN_KEY", modelKey)
	t.Setenv("TEST_CRM_KEY", crmKey)
	t.Setenv("TEST_READONLY_KEY", readonlyKey)
	t.Setenv("TEST_LOCKED_KEY", lockedKey)

	body := fmt.Sprintf(proxyTestConfig, requestTimeout, mode, base+"/v1")
	holder := newTestHolder(t, body)

	if st == nil {
		mem := store.NewMemory(holder.Current().Store)
		t.Cleanup(func() { _ = mem.Close() })
		st = mem
	}

	return NewServer(Deps{
		Config:    holder,
		Gateway:   gateway.New(detect.New(nil, proxyMarkScanner{}), st),
		Metrics:   obs.NewMetrics(),
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:   "test",
		StartedAt: time.Now(),
	})
}

// chat отправляет запрос на /v1/chat/completions с заданным ключом.
func chat(t *testing.T, s *Server, key, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathChat, strings.NewReader(body))
	req.Header.Set(headerContentType, jsonContentType)
	if key != "" {
		req.Header.Set(headerAuthorization, "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h := s.newProxyHandler()
	s.wrap(http.HandlerFunc(h.handleChat)).ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// markedChatBody — запрос с размеченными синтетическими значениями.
const markedChatBody = `{"model":"test-model","messages":[
{"role":"system","content":"Ты — ассистент банка."},
{"role":"user","content":"Клиент Иванов Иван Иванович, телефон +7 916 123-45-67, почта ivanov@example.test, карта 4276 5500 1234 5678. Составь письмо."}]}`

func TestChatRequiresValidKey(t *testing.T) {
	// AC-1: без ключа, с неизвестным ключом и с ключом отключённого
	// потребителя ответ одинаков — 401 без подробностей.
	fake := newFakeLLM(t, fixtureReply)
	s := newProxyTestServer(t, fake.srv.URL, nil)

	cases := map[string]string{
		"без ключа":                  "",
		"неизвестный ключ":           unknownKey,
		"отключённый ключ":           lockedKey,
		"ключ с пробелами":           "   ",
		"идентификатор вместо ключа": "benchmark",
	}
	for name, key := range cases {
		code, body := chat(t, s, key, markedChatBody)
		if code != http.StatusUnauthorized {
			t.Errorf("%s: получен код %d вместо 401, тело %s", name, code, body)
		}
		if strings.Contains(body, "отключ") || strings.Contains(body, "неизвест") {
			t.Errorf("%s: ответ раскрывает, какая проверка не прошла: %s", name, body)
		}
	}
	if fake.calls() != 0 {
		t.Fatalf("фальшивая модель получила %d запросов от неаутентифицированных клиентов", fake.calls())
	}
}

func TestChatReturnsOpenAICompatibleResponse(t *testing.T) {
	// AC-2: с валидным ключом запрос проходит цепочку и возвращается ответ
	// в формате модели.
	fake := newFakeLLM(t, "Письмо для [ФИО_1] готово.")
	s := newProxyTestServer(t, fake.srv.URL, nil)

	code, body := chat(t, s, crmKey, markedChatBody)
	if code != http.StatusOK {
		t.Fatalf(msgCodeBody, code, body)
	}

	var got struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("ответ не является JSON: %v", err)
	}
	if got.Object != "chat.completion" || len(got.Choices) == 0 {
		t.Fatalf("ответ не OpenAI-совместим: %s", body)
	}
	if got.Choices[0].Message.Role != "assistant" {
		t.Errorf("роль в ответе: %q", got.Choices[0].Message.Role)
	}
	// Плейсхолдер восстановлен: потребителю возвращается его собственное значение.
	if !strings.Contains(got.Choices[0].Message.Content, "Иванов Иван Иванович") {
		t.Errorf("плейсхолдер не восстановлен: %q", got.Choices[0].Message.Content)
	}
}

// TestChatDoesNotLeakMarkedValuesDownstream — обязательный тест перехвата.
//
// Проверяется фактически отправленное тело, а не код ответа и не журнал.
// Поиск ведётся по каждому размеченному значению отдельно: сравнение целого
// payload пропустило бы частичную утечку.
func TestChatDoesNotLeakMarkedValuesDownstream(t *testing.T) {
	fake := newFakeLLM(t, "Письмо для [ФИО_1] готово.")
	s := newProxyTestServer(t, fake.srv.URL, nil)

	code, body := chat(t, s, crmKey, markedChatBody)
	if code != http.StatusOK {
		t.Fatalf(msgCodeBody, code, body)
	}
	if fake.calls() != 1 {
		t.Fatalf("фальшивая модель получила %d запросов", fake.calls())
	}

	wire := fake.wire(t)
	for value := range proxyMarked {
		if strings.Contains(wire, value) {
			t.Errorf("значение %q найдено в фактически отправленном теле", value)
		}
	}
	// Дополнительно: фрагменты значений тоже не должны утекать целиком.
	for _, part := range []string{"Иванов", "5500 1234", "916 123-45-67", "ivanov@"} {
		if strings.Contains(wire, part) {
			t.Errorf("фрагмент %q найден в фактически отправленном теле", part)
		}
	}
	if !strings.Contains(wire, placeholderName) || !strings.Contains(wire, "[КАРТА_1]") {
		t.Errorf("в отправленном теле нет ожидаемых плейсхолдеров: %s", wire)
	}

	// Ключ модели уходит без префикса Bearer: с префиксом AlfaGen отвечает 400.
	fake.mu.Lock()
	auth := fake.auth[0]
	fake.mu.Unlock()
	if auth != modelKey {
		t.Fatalf("заголовок Authorization = %q, ожидался ключ без префикса", auth)
	}
	// Ключ потребителя наружу не уходит вообще.
	if strings.Contains(wire, crmKey) || strings.Contains(auth, crmKey) {
		t.Error("ключ потребителя ушёл наружу")
	}
}

// TestChatFailClosedSendsNothing — второй обязательный сценарий перехвата:
// при отказе защиты фальшивый сервер обязан получить ноль запросов.
func TestChatFailClosedSendsNothing(t *testing.T) {
	fake := newFakeLLM(t, fixtureReply)
	s := newProxyTestServer(t, fake.srv.URL, proxyFailingStore{})

	code, body := chat(t, s, crmKey, markedChatBody)
	if code != http.StatusInternalServerError {
		t.Fatalf("получен код %d вместо 500, тело %s", code, body)
	}
	if fake.calls() != 0 {
		t.Fatalf("фальшивая модель получила %d запросов вместо нуля", fake.calls())
	}
	for value := range proxyMarked {
		if strings.Contains(body, value) {
			t.Errorf("значение %q попало в тело ответа об ошибке: %s", value, body)
		}
	}
}

func TestChatDemaskDeniedKeepsPlaceholders(t *testing.T) {
	// AC-6: потребитель с demask: false получает ответ без восстановления.
	fake := newFakeLLM(t, "Письмо для [ФИО_1] и [ТЕЛЕФОН_1] готово.")
	s := newProxyTestServer(t, fake.srv.URL, nil)

	code, body := chat(t, s, readonlyKey, markedChatBody)
	if code != http.StatusOK {
		t.Fatalf(msgCodeBody, code, body)
	}
	for value := range proxyMarked {
		if strings.Contains(body, value) {
			t.Errorf("значение %q восстановлено для потребителя без права демаскирования", value)
		}
	}
	if !strings.Contains(body, placeholderName) {
		t.Errorf("плейсхолдер не сохранён в ответе: %s", body)
	}
}

func TestChatUpstreamFailureReturns502(t *testing.T) {
	// Отказ модели не должен выглядеть как отказ защиты: 502, а не 500.
	fake := newFakeLLM(t, fixtureReply)
	fake.mu.Lock()
	fake.status = http.StatusInternalServerError
	fake.mu.Unlock()

	s := newProxyTestServer(t, fake.srv.URL, nil)
	code, body := chat(t, s, crmKey, markedChatBody)
	if code != http.StatusBadGateway {
		t.Fatalf("получен код %d вместо 502, тело %s", code, body)
	}
	for value := range proxyMarked {
		if strings.Contains(body, value) {
			t.Errorf("значение %q попало в тело ответа об ошибке", value)
		}
	}
}

func TestChatRejectsBadRequests(t *testing.T) {
	fake := newFakeLLM(t, fixtureReply)
	s := newProxyTestServer(t, fake.srv.URL, nil)

	cases := map[string]string{
		"битый JSON":       `{"messages":`,
		"нет сообщений":    `{"model":"test-model","messages":[]}`,
		"потоковый режим":  `{"model":"m","messages":[{"role":"user","content":"привет"}],"stream":true}`,
		"сообщения не тот": `{"model":"m","messages":{}}`,
	}
	for name, body := range cases {
		code, resp := chat(t, s, crmKey, body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: получен код %d вместо 400, тело %s", name, code, resp)
		}
	}
	if fake.calls() != 0 {
		t.Fatalf("фальшивая модель получила %d запросов по некорректным запросам", fake.calls())
	}
}

func TestChatErrorBodiesHideSecrets(t *testing.T) {
	// AC-10: ни ключ, ни исходный текст не попадают в тела ответов.
	fake := newFakeLLM(t, fixtureReply)
	s := newProxyTestServer(t, fake.srv.URL, proxyFailingStore{})

	_, unauthorized := chat(t, s, unknownKey, markedChatBody)
	_, failClosed := chat(t, s, crmKey, markedChatBody)

	for _, body := range []string{unauthorized, failClosed} {
		for _, secret := range []string{crmKey, modelKey, unknownKey, "Иванов", "4276"} {
			if strings.Contains(body, secret) {
				t.Errorf("тело ответа содержит %q: %s", secret, body)
			}
		}
	}
}

func TestChatModelTimeIsNotCountedAsServiceTime(t *testing.T) {
	// AC-11: время модели уходит в отдельную метрику и вычитается из времени
	// ответа сервиса — организаторы измеряют только наше время.
	fake := newFakeLLM(t, fixtureReply)
	s := newProxyTestServer(t, fake.srv.URL, nil)

	if code, body := chat(t, s, crmKey, markedChatBody); code != http.StatusOK {
		t.Fatalf(msgCodeBody, code, body)
	}

	var b strings.Builder
	s.deps.Metrics.WriteProm(&b)
	out := b.String()
	if !strings.Contains(out, "aigw_llm_duration_seconds_count") {
		t.Fatalf("метрика времени модели не опубликована:\n%s", out)
	}
	if !strings.Contains(out, `aigw_requests_total{endpoint="chat_completions",op="proxy",outcome="ok"} 1`) {
		t.Fatalf("запрос продуктового контура не учтён:\n%s", out)
	}

	llmSum := promValue(t, out, "aigw_llm_duration_seconds_sum{}")
	svcSum := promValue(t, out, `aigw_request_duration_seconds_sum{endpoint="chat_completions",op="proxy"}`)
	if llmSum <= 0 {
		t.Fatalf("время модели не измерено: %v", llmSum)
	}
	if svcSum >= llmSum {
		t.Fatalf("время модели (%v) не вычтено из времени сервиса (%v)", llmSum, svcSum)
	}
}

// TestChatModelWaitOutlivesRequestTimeout охраняет границу двух бюджетов.
//
// request_timeout — предел нашей работы (детекция, политика, маскирование),
// а не всего запроса: ожидание модели ограничено отдельно, llm.timeout. Если
// подчинить вызов модели родительскому дедлайну, context.WithTimeout внутри
// клиента возьмёт минимум из двух, и продуктовый прокси начнёт рвать любой
// ответ медленнее 9 с — при заявленном пределе модели в 60 с. Тест держит
// это разделение: модель отвечает втрое дольше бюджета, запрос обязан дойти.
func TestChatModelWaitOutlivesRequestTimeout(t *testing.T) {
	fake := newFakeLLM(t, "ответ пришёл позже бюджета обработки")
	fake.delay = 400 * time.Millisecond
	s := newProxyTestServerTimeout(t, modeAlfaGen, fake.srv.URL, nil, "150ms")

	code, body := chat(t, s, crmKey, markedChatBody)
	if code != http.StatusOK {
		t.Fatalf("ожидание модели обрезано бюджетом обработки: код %d, тело %s", code, body)
	}
	if !strings.Contains(body, "ответ пришёл позже бюджета обработки") {
		t.Fatalf("ответ модели не доехал до клиента: %s", body)
	}
	if n := fake.calls(); n != 1 {
		t.Fatalf("модель вызвана %d раз, ожидался ровно один вызов", n)
	}
}

// promValue достаёт значение метрики по точному имени с метками.
func promValue(t *testing.T, exposition, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(exposition, "\n") {
		rest, ok := strings.CutPrefix(line, name+" ")
		if !ok {
			continue
		}
		var v float64
		if _, err := fmt.Sscanf(rest, "%g", &v); err != nil {
			t.Fatalf("значение метрики %s не разобрано: %v", name, err)
		}
		return v
	}
	t.Fatalf("метрика %s не найдена:\n%s", name, exposition)
	return 0
}

func TestChatStubModeWorksWithoutNetwork(t *testing.T) {
	// AC-8: режим stub отвечает без сети и цитирует полученные плейсхолдеры.
	// Демо не должно зависеть от доступности AlfaGen.
	fake := newFakeLLM(t, "этот ответ не должен использоваться")
	s := newProxyTestServerMode(t, llm.ModeStub, fake.srv.URL, nil)

	code, body := chat(t, s, readonlyKey, markedChatBody)
	if code != http.StatusOK {
		t.Fatalf(msgCodeBody, code, body)
	}
	if fake.calls() != 0 {
		t.Fatalf("режим stub обратился к сети: %d запросов", fake.calls())
	}
	for _, p := range []string{placeholderName, "[ТЕЛЕФОН_1]", "[EMAIL_1]", "[КАРТА_1]"} {
		if !strings.Contains(body, p) {
			t.Errorf("ответ заглушки не цитирует %s: %s", p, body)
		}
	}
	for value := range proxyMarked {
		if strings.Contains(body, value) {
			t.Errorf("значение %q попало в ответ заглушки", value)
		}
	}
}
