package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"ai-gateway/internal/lex"
	"ai-gateway/internal/llm"
	"ai-gateway/internal/mask"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
	"ai-gateway/internal/store"
)

// Значения ниже — синтетические. Реальные персональные данные в репозиторий
// не попадают ни в тестах, ни в фикстурах.
var marked = map[string]pii.Type{
	fioIvanov:             pii.FullName,
	"+7 916 123-45-67":    pii.Phone,
	emailIvanov:           pii.Email,
	"4276 5500 1234 5678": pii.CardNumber,
}

// markScanner отмечает заранее известные значения как ПД.
//
// Сканеры детекции разрабатываются в отдельных задачах; инвариант выпуска
// наружу обязан проверяться независимо от их готовности и точности.
type markScanner struct {
	values map[string]pii.Type
	// firstOnly имитирует неполную детекцию: отмечается только первое
	// вхождение значения, остальные остаются в тексте.
	firstOnly bool
}

func (markScanner) Name() string { return "mark" }

func (m markScanner) Scan(doc *lex.Doc, _ *dict.Set, out *detect.Candidates) {
	for v, t := range m.values {
		for i := 0; i < len(doc.Text); {
			j := strings.Index(doc.Text[i:], v)
			if j < 0 {
				break
			}
			at := i + j
			out.Add(at, at+len(v), t, detect.Certain, "mark")
			i = at + len(v)
			if m.firstOnly {
				break
			}
		}
	}
}

// recordingModel — фальшивая модель: запоминает фактически полученные запросы.
type recordingModel struct {
	mu    sync.Mutex
	got   []llm.Request
	reply string
	err   error
	delay time.Duration
}

func (m *recordingModel) Chat(_ context.Context, req llm.Request) (*llm.Response, error) {
	m.mu.Lock()
	// Копия: вызывающий код не должен влиять на то, что увидит тест.
	cp := req
	cp.Messages = append([]llm.Message(nil), req.Messages...)
	m.got = append(m.got, cp)
	m.mu.Unlock()

	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.err != nil {
		return nil, m.err
	}
	return &llm.Response{
		ID:      "chatcmpl-fake",
		Object:  "chat.completion",
		Model:   req.Model,
		Choices: []llm.Choice{{Index: 0, Message: llm.Message{Role: roleAssistant, Content: m.reply}, FinishReason: "stop"}},
	}, nil
}

func (m *recordingModel) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.got)
}

// wire возвращает фактически отправленное наружу тело в виде строки.
func (m *recordingModel) wire(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := json.Marshal(m.got)
	if err != nil {
		t.Fatalf("сериализация перехваченных запросов: %v", err)
	}
	// Экранированный JSON тоже проверяется: утечка могла бы спрятаться в
	// \u-последовательностях, поэтому кириллица разэкранируется.
	var buf strings.Builder
	var decoded []llm.Request
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("разбор перехваченных запросов: %v", err)
	}
	buf.WriteString(string(raw))
	for _, r := range decoded {
		for _, msg := range r.Messages {
			buf.WriteString("\n")
			buf.WriteString(msg.Content)
		}
	}
	return buf.String()
}

type failingStore struct{}

func (failingStore) Get(string) (store.Record, bool) { return store.Record{}, false }
func (failingStore) Put(string, store.Record) error  { return store.ErrFull }
func (failingStore) Stats() store.Stats              { return store.Stats{} }
func (failingStore) Close() error                    { return nil }

func newProxyService(t *testing.T, sc detect.Scanner, st store.Store) *Service {
	t.Helper()
	if st == nil {
		mem := store.NewMemory(store.Options{TTL: time.Hour})
		t.Cleanup(func() { _ = mem.Close() })
		st = mem
	}
	return New(detect.New(nil, sc), st)
}

func newProxyConsumer(t *testing.T, demask bool) *policy.Consumer {
	t.Helper()
	c := mustConsumer(t, policy.Consumer{
		ID:             consumerCRM,
		Enabled:        true,
		Types:          pii.FullSet(),
		Demask:         demask,
		MaskingEnabled: true,
	}, strategyPlaceholder)
	return c
}

func markedRequest() ProxyRequest {
	return ProxyRequest{
		ID: "req-1",
		Chat: llm.Request{
			Model: testModelName,
			Messages: []llm.Message{
				{Role: "system", Content: "Ты — ассистент банка."},
				{Role: roleUser, Content: "Клиент Иванов Иван Иванович, телефон +7 916 123-45-67, " +
					"почта ivanov@example.test, карта 4276 5500 1234 5678. Составь письмо."},
			},
		},
	}
}

// TestProxyDoesNotLeakMarkedValues — тест-перехватчик downstream.
//
// Проверяется не целый payload, а каждое размеченное значение по отдельности:
// сравнение строк целиком пропустило бы частичную утечку.
func TestProxyDoesNotLeakMarkedValues(t *testing.T) {
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{reply: "Письмо для [ФИО_1] готово."}

	res := mustProxy(t, svc, model, markedRequest(), newProxyConsumer(t, true))
	if !res.Sent {
		t.Fatal("запрос не был отправлен")
	}
	if model.calls() != 1 {
		t.Fatalf("модель получила %d запросов", model.calls())
	}

	wire := model.wire(t)
	for value := range marked {
		if strings.Contains(wire, value) {
			t.Errorf("значение %q найдено в фактически отправленном теле", value)
		}
	}
	if !strings.Contains(wire, placeholderFIO1) {
		t.Errorf("в отправленном теле нет плейсхолдеров: %s", wire)
	}
	if res.Replaced != 4 {
		t.Errorf("выполнено замен: %d, ожидалось 4", res.Replaced)
	}
}

func TestProxyFailClosedOnStoreFailure(t *testing.T) {
	// Предусловие 5: без сохранённого соответствия выпуск запрещён.
	svc := newProxyService(t, markScanner{values: marked}, failingStore{})
	model := &recordingModel{reply: replyAnswer}

	res, err := svc.Proxy(context.Background(), model, markedRequest(), newProxyConsumer(t, true))
	if !errors.Is(err, ErrFailClosed) {
		t.Fatalf(fmtFailClosed, err)
	}
	assertNoModelCalls(t, model)
	if res.Sent {
		t.Error("результат отмечен как отправленный")
	}
	if res.Response != nil {
		t.Error("при отказе защиты возвращён ответ модели")
	}
}

func TestProxyFailClosedOnIncompleteMasking(t *testing.T) {
	// Предусловие 4: если значение осталось в тексте, запрос не отправляется.
	// Неполную детекцию имитирует сканер, отмечающий только первое вхождение.
	// Отдельно стоящий повтор закрывает маскирование (T-56), поэтому второе
	// вхождение здесь прилипло к слову: повтором по границе токена оно не
	// считается, а открытым значением остаётся.
	svc := newProxyService(t, markScanner{values: marked, firstOnly: true}, nil)
	model := &recordingModel{reply: replyAnswer}

	req := ProxyRequest{ID: "req-2", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Иванов Иван Иванович пришёл. ЗвонилИванов Иван Иванович."},
	}}}

	if _, err := svc.Proxy(context.Background(), model, req, newProxyConsumer(t, true)); !errors.Is(err, ErrFailClosed) {
		t.Fatalf(fmtFailClosed, err)
	}
	assertNoModelCalls(t, model)
}

// TestProxyCoversRepeatNotFoundByDetection — С-4 на прокси: детекция
// отметила только первое вхождение, повтор закрыт той же маской, запрос
// ушёл без ложного fail-closed, и в теле к модели нет ни одного значения.
func TestProxyCoversRepeatNotFoundByDetection(t *testing.T) {
	svc := newProxyService(t, markScanner{values: marked, firstOnly: true}, nil)
	model := &recordingModel{reply: "Ответ для [ФИО_1]."}
	req := ProxyRequest{ID: "repeat", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Иванов Иван Иванович пришёл. Иванов Иван Иванович ушёл."},
	}}}
	res := mustProxy(t, svc, model, req, newProxyConsumer(t, true))
	if got := model.got[0].Messages[0].Content; got != "[ФИО_1] пришёл. [ФИО_1] ушёл." {
		t.Fatalf(fmtSentToModel, got)
	}
	if strings.Contains(model.wire(t), surnameIvanov) {
		t.Fatal("значение найдено в фактически отправленном теле")
	}
	if got := replyOf(res); got != "Ответ для Иванов Иван Иванович." {
		t.Fatalf(fmtReply, got)
	}
}

func TestProxyFailClosedOnDeniedConsumer(t *testing.T) {
	// Предусловие 1: отключённый потребитель не выпускает данные наружу,
	// даже если транспорт по ошибке его пропустил.
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{reply: replyAnswer}

	disabled := mustConsumer(t, policy.Consumer{
		ID: consumerCRM, Enabled: false, Types: pii.FullSet(), MaskingEnabled: true,
	}, strategyPlaceholder)

	for name, c := range map[string]*policy.Consumer{"отключён": disabled, "отсутствует": nil} {
		if _, err := svc.Proxy(context.Background(), model, markedRequest(), c); !errors.Is(err, ErrFailClosed) {
			t.Errorf("потребитель %s: получена ошибка %v, ожидалась ErrFailClosed", name, err)
		}
	}
	assertNoModelCalls(t, model)
}

func TestProxyRestoresOwnPlaceholders(t *testing.T) {
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{reply: "Уважаемый [ФИО_1], мы позвоним на [ТЕЛЕФОН_1]."}

	res := mustProxy(t, svc, model, markedRequest(), newProxyConsumer(t, true))
	content := replyOf(res)
	if !strings.Contains(content, fioIvanov) {
		t.Errorf("плейсхолдер ФИО не восстановлен: %q", content)
	}
	if !strings.Contains(content, "+7 916 123-45-67") {
		t.Errorf("плейсхолдер телефона не восстановлен: %q", content)
	}
	if res.Restored != 2 {
		t.Errorf("восстановлено плейсхолдеров: %d, ожидалось 2", res.Restored)
	}
}

func TestProxyIgnoresForeignPlaceholders(t *testing.T) {
	// Неизвестный и подделанный плейсхолдер не раскрывают ничего: область
	// корреляции ограничена этим запросом.
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{reply: "Данные [ФИО_9], [ПАСПОРТ_1] и [CARD_7] не найдены."}

	res := mustProxy(t, svc, model, markedRequest(), newProxyConsumer(t, true))
	content := replyOf(res)
	for value := range marked {
		if strings.Contains(content, value) {
			t.Errorf("чужой плейсхолдер раскрыл значение %q: %q", value, content)
		}
	}
	if res.Restored != 0 {
		t.Errorf("восстановлено %d чужих плейсхолдеров", res.Restored)
	}
	if !strings.Contains(content, "[ФИО_9]") {
		t.Errorf("неизвестный плейсхолдер изменён: %q", content)
	}
}

func TestProxyDemaskDeniedKeepsPlaceholders(t *testing.T) {
	// AC-6: потребителю без права демаскирования ответ возвращается как есть.
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{reply: "Письмо для [ФИО_1] на [ТЕЛЕФОН_1] готово."}

	res := mustProxy(t, svc, model, markedRequest(), newProxyConsumer(t, false))
	content := replyOf(res)
	if content != model.reply {
		t.Fatalf("ответ изменён: %q", content)
	}
	if res.Restored != 0 {
		t.Errorf("восстановлено %d плейсхолдеров при demask: false", res.Restored)
	}
}

func TestProxyMasksModelGeneratedPII(t *testing.T) {
	// AC-7: модель могла породить ПД, которых в запросе не было.
	svc := newProxyService(t, markScanner{values: map[string]pii.Type{
		fioIvanov: pii.FullName,
		fioPetrov: pii.FullName,
	}}, nil)
	model := &recordingModel{reply: "Ответ для [ФИО_1]: обратитесь к Петров Пётр Петрович."}

	req := ProxyRequest{ID: "req-3", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Клиент Иванов Иван Иванович просит помощи."},
	}}}

	res := mustProxy(t, svc, model, req, newProxyConsumer(t, true))
	content := replyOf(res)
	if strings.Contains(content, fioPetrov) {
		t.Errorf("ПД, порождённые моделью, не замаскированы: %q", content)
	}
	if !strings.Contains(content, fioIvanov) {
		t.Errorf("собственный плейсхолдер потребителя не восстановлен: %q", content)
	}
	if res.ResponseMasked != 1 {
		t.Errorf("в ответе замаскировано значений: %d, ожидалось 1", res.ResponseMasked)
	}
	// Нумерация ответа продолжает нумерацию запроса: [ФИО_1] уже занят.
	if !strings.Contains(content, "[ФИО_2]") {
		t.Errorf("маска ответа получила занятый номер: %q", content)
	}
}

func TestProxyUpstreamFailureIsDistinguishable(t *testing.T) {
	// Отказ модели — не отказ защиты: транспорт обязан различать их и не
	// отвечать 500 там, где виновата внешняя система.
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{err: errors.New("llm: модель ответила кодом 503")}

	res, err := svc.Proxy(context.Background(), model, markedRequest(), newProxyConsumer(t, true))
	assertUpstream(t, err)
	if errors.Is(err, ErrFailClosed) {
		t.Error("отказ модели выдан за отказ защиты")
	}
	if !res.Sent {
		t.Error("запрос был отправлен, но результат этого не отражает")
	}
}

// liveClient собирает настоящего клиента модели на адрес фальшивого сервера.
//
// Отказ воспроизводится сетью на петле, а не подменой ошибки: классификация
// обязана работать на тех ошибках, которые возвращает реальный транспорт.
func liveClient(t *testing.T, baseURL string) llm.Chatter {
	t.Helper()
	// Ключ синтетический: настоящий ключ AlfaGen в репозиторий не попадает.
	c, err := llm.New(llm.Options{
		BaseURL:     baseURL,
		Model:       testModelName,
		APIKey:      testAPIKey,
		Timeout:     2 * time.Second,
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatalf("сборка клиента модели: %v", err)
	}
	return c
}

func TestProxyReportsUpstreamStatusCode(t *testing.T) {
	// AC-1: код ответа модели доходит до слоя, который пишет журнал и
	// показывает стенд. Без него 401 неотличим от отказа сети.
	for _, code := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer srv.Close()

			svc := newProxyService(t, markScanner{values: marked}, nil)
			res, err := svc.Proxy(context.Background(), liveClient(t, srv.URL), markedRequest(), newProxyConsumer(t, true))
			assertUpstream(t, err)
			if res.UpstreamStatus != code {
				t.Errorf("код ответа в результате: %d, ожидался %d", res.UpstreamStatus, code)
			}
			if res.UpstreamClass != "http_status" {
				t.Errorf("класс отказа %q вместо http_status", res.UpstreamClass)
			}
			if note := res.UpstreamNote(); !strings.Contains(note, strconv.Itoa(code)) {
				t.Errorf("описание причины не называет код ответа: %q", note)
			}
		})
	}
}

func TestProxyReportsUpstreamFailureClass(t *testing.T) {
	// AC-2: отказ TLS, таймаут и отказ соединения различимы по классу. Отказ
	// разрешения имени классифицируется тем же кодом и проверяется в
	// internal/llm, где его можно воспроизвести без обращения к резолверу.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer tlsSrv.Close()

	// Обработчик отпускается тестом, а не ожиданием отмены: закрытие сервера
	// не должно зависеть от того, заметил ли он разрыв соединения.
	release := make(chan struct{})
	slowSrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer slowSrv.Close()
	defer close(release)

	closedSrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close()

	cases := []struct {
		name  string
		model llm.Chatter
		want  string
	}{
		{"отказ проверки сертификата", liveClient(t, tlsSrv.URL), "tls"},
		{"соединение не установлено", liveClient(t, closedURL), "connect"},
		{"таймаут ожидания", timeoutClient(t, slowSrv.URL), "timeout"},
		{"ошибка чужой реализации", &recordingModel{err: errors.New("своя ошибка")}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newProxyService(t, markScanner{values: marked}, nil)
			res, err := svc.Proxy(context.Background(), tc.model, markedRequest(), newProxyConsumer(t, true))
			assertUpstream(t, err)
			if res.UpstreamClass != tc.want {
				t.Fatalf("класс отказа %q вместо %q: %v", res.UpstreamClass, tc.want, err)
			}
			if res.UpstreamStatus != 0 {
				t.Errorf("код ответа %d при отсутствии ответа", res.UpstreamStatus)
			}
			if res.UpstreamNote() == "" {
				t.Error("описание причины пусто")
			}
		})
	}
}

// timeoutClient собирает клиента с коротким бюджетом ожидания.
func timeoutClient(t *testing.T, baseURL string) llm.Chatter {
	t.Helper()
	c, err := llm.New(llm.Options{
		BaseURL:     baseURL,
		Model:       testModelName,
		APIKey:      testAPIKey,
		Timeout:     50 * time.Millisecond,
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatalf("сборка клиента модели: %v", err)
	}
	return c
}

func TestProxyUpstreamCauseKeepsModelBodyOutOfJournal(t *testing.T) {
	// AC-3 и инвариант приватности: модель может отразить в теле ответа эхо
	// запроса вместе с персональными данными. В журнал уходит причина отказа,
	// и в ней тела ответа нет — проверяется на настоящей записи журнала, а не
	// на полях результата.
	echo := markedRequest().Chat.Messages[1].Content
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Тело отказа повторяет присланный текст — так ведут себя реальные
		// шлюзы, сообщая «не смог обработать вот это».
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"message": "не удалось обработать: " + echo},
		})
	}))
	defer srv.Close()

	svc := newProxyService(t, markScanner{values: marked}, nil)
	res, err := svc.Proxy(context.Background(), liveClient(t, srv.URL), markedRequest(), newProxyConsumer(t, true))
	assertUpstream(t, err)

	// Запись журнала собирается теми же полями, что пишет транспорт.
	// Метка времени slog в запись не пишется: её наносекунды — случайные цифры,
	// и короткий цифровой фрагмент («916», «4276») совпадал с ними раз в
	// несколько сотен прогонов. К телу ответа модели она отношения не имеет.
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: dropTimeAttr})).Warn("модель не ответила",
		"error", err.Error(),
		"consumer", consumerCRM,
		"outcome", "upstream_error",
		"upstream_class", res.UpstreamClass,
		"upstream_status", res.UpstreamStatus,
		"upstream_reason", res.UpstreamReason,
		"chain_note", res.UpstreamNote(),
		"llm_ms", res.LLM.Milliseconds(),
	)
	journal := buf.String()

	// Проверка осмысленна только если запись содержит саму причину.
	if !strings.Contains(journal, "http_status") || !strings.Contains(journal, "400") {
		t.Fatalf("причина отказа не попала в запись журнала: %s", journal)
	}
	// Поиск по каждому размеченному значению отдельно: сравнение целого тела
	// пропустило бы частичную утечку.
	// Тело ответа может попасть в запись только строкой: числовые поля —
	// код ответа и длительность — измеряются, а не копируются из тела.
	// Поэтому фрагменты ищутся в строковых значениях записи, а не в её
	// тексте целиком, где цифры длительности случайны.
	text := journalStrings(t, journal)
	for value := range marked {
		if strings.Contains(text, value) {
			t.Errorf("значение %q попало в журнал: %s", value, journal)
		}
	}
	for _, frag := range []string{surnameIvanov, "4276", "5678", "ivanov@", "916", "не удалось обработать"} {
		if strings.Contains(text, frag) {
			t.Errorf("фрагмент тела ответа %q попал в журнал: %s", frag, journal)
		}
	}
}

// dropTimeAttr убирает метку времени из записи журнала в тесте.
func dropTimeAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// journalStrings возвращает строковые значения JSON-записи журнала,
// склеенные переводом строки.
func journalStrings(t *testing.T, record string) string {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(record), &fields); err != nil {
		t.Fatalf("запись журнала не разбирается: %v: %s", err, record)
	}
	var b strings.Builder
	for _, v := range fields {
		if s, ok := v.(string); ok {
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func TestProxyMeasuresModelTimeSeparately(t *testing.T) {
	// AC-11: время ожидания модели измеряется отдельно от времени сервиса.
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{reply: "готово", delay: 20 * time.Millisecond}

	res := mustProxy(t, svc, model, markedRequest(), newProxyConsumer(t, true))
	if res.LLM < 20*time.Millisecond {
		t.Fatalf("время модели измерено как %s", res.LLM)
	}
}

func TestProxyStoresCorrespondence(t *testing.T) {
	// Предусловие 5 наблюдаемо: соответствие записано до выпуска наружу.
	mem := store.NewMemory(store.Options{TTL: time.Hour})
	t.Cleanup(func() { _ = mem.Close() })
	svc := New(detect.New(nil, markScanner{values: marked}), mem)

	mustProxy(t, svc, &recordingModel{reply: "ok"}, markedRequest(), newProxyConsumer(t, true))
	if mem.Stats().Entries == 0 {
		t.Fatal("соответствие не сохранено")
	}
	rec, ok := mem.Get(scopedKey(consumerCRM, proxyKeyPrefix+"req-1"))
	if !ok {
		t.Fatal("запись не найдена по ключу области корреляции")
	}
	if strings.Contains(rec.Masked, fioIvanov) {
		t.Error("в сохранённой маске осталось исходное значение")
	}
}

func TestProxyRejectsEmptyRequest(t *testing.T) {
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{reply: replyAnswer}

	cases := map[string]ProxyRequest{
		"без области корреляции": {ID: "", Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: "текст"}}}},
		"без сообщений":          {ID: "req-4", Chat: llm.Request{}},
	}
	for name, req := range cases {
		if _, err := svc.Proxy(context.Background(), model, req, newProxyConsumer(t, true)); !errors.Is(err, ErrFailClosed) {
			t.Errorf("%s: получена ошибка %v, ожидалась ErrFailClosed", name, err)
		}
	}
	assertNoModelCalls(t, model)
}

func strategyConsumer(t *testing.T, strategy string, demask bool) *policy.Consumer {
	t.Helper()
	c := mustConsumer(t, policy.Consumer{
		ID: consumerCRM, Enabled: true, Types: pii.FullSet(), Demask: demask, MaskingEnabled: true,
	}, strategy)
	return c
}

// TestVerifyReplacedTokenBoundaries — D-8: значение, продолженное цифрой, —
// часть другого числа и утечкой не считается; самостоятельное вхождение, в
// том числе прилипшее к букве, по-прежнему отклоняет запрос.
func TestVerifyReplacedTokenBoundaries(t *testing.T) {
	tests := []struct {
		name, original, value, masked string
		leak                          bool
	}{
		{"внутри большего числа", "CVV 123, сумма 1230", cvvValue, "CVV [CVV_1], сумма 1230", false},
		{"цифра слева", "CVV 123, заявка 9123", cvvValue, "CVV [CVV_1], заявка 9123", false},
		{"цифры с обеих сторон", "ПИН 4321, номер 843219", "4321", "ПИН [ПИН_1], номер 843219", false},
		{"повтор отдельным токеном", "CVV 123, повторяю: 123", cvvValue, "CVV [CVV_1], повторяю: 123", true},
		{"повтор в конце текста", "CVV 123 и 123", cvvValue, "CVV [CVV_1] и 123", true},
		{"повтор в начале текста", "123 — это CVV 123", cvvValue, "123 — это CVV [CVV_1]", true},
		{"повтор через знак", "CVV 123, код 123-й", cvvValue, "CVV [CVV_1], код 123-й", true},
		{"повтор, прилипший к букве", "CVV 123, кодA123", cvvValue, "CVV [CVV_1], кодA123", true},
		{"email, прилипший к букве", "почта ivanov@example.test, ещё Жivanov@example.test", emailIvanov,
			"почта [EMAIL_1], ещё Жivanov@example.test", true},
		{"одно вхождение внутри числа, другое отдельно", "CVV 123, 1230 и 123", cvvValue, "CVV [CVV_1], 1230 и 123", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at := strings.Index(tt.original, tt.value)
			mr := MaskResult{
				Text:    tt.masked,
				Spans:   []detect.Span{{Start: int32(at), End: int32(at + len(tt.value)), Type: pii.CVV}},
				Applied: []mask.Applied{{Start: int32(at), End: int32(at + len(tt.value)), Type: pii.CVV}},
			}
			err := VerifyReplaced(tt.original, mr)
			if (err != nil) != tt.leak {
				t.Fatalf("ошибка %v, ожидалась утечка: %v", err, tt.leak)
			}
		})
	}
}

// TestProxyShortValueRepeatCoveredGluedFailsClosed — D-8 и С-4 в прокси:
// детекция отметила только первое вхождение. Второе, внутри суммы, запрос не
// блокирует и остаётся как есть; второе самостоятельное закрыто той же
// маской (до T-56 — ложный fail-closed); значение, прилипшее к слову,
// по-прежнему блокирует запрос, и модель не получает ничего.
func TestProxyShortValueRepeatCoveredGluedFailsClosed(t *testing.T) {
	svc := newProxyService(t, markScanner{values: map[string]pii.Type{
		cvvValue:    pii.CVV,
		emailIvanov: pii.Email,
	}, firstOnly: true}, nil)
	c := newProxyConsumer(t, true)
	send := func(text string) (*recordingModel, error) {
		model := &recordingModel{reply: "ок"}
		_, err := svc.Proxy(context.Background(), model, ProxyRequest{ID: "cvv",
			Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: text}}}}, c)
		return model, err
	}

	model, err := send("CVV 123, сумма заказа 1230 рублей")
	if err != nil || model.calls() != 1 || model.got[0].Messages[0].Content != "CVV [CVV_1], сумма заказа 1230 рублей" {
		t.Fatalf("значение внутри числа: %v, запросов %d", err, model.calls())
	}
	model, err = send("CVV 123, повторяю: 123")
	if err != nil || model.calls() != 1 || model.got[0].Messages[0].Content != "CVV [CVV_1], повторяю: [CVV_1]" {
		t.Fatalf("самостоятельный повтор CVV: %v, запросов %d", err, model.calls())
	}
	model, err = send("почта ivanov@example.test, ещё Жivanov@example.test")
	if !errors.Is(err, ErrFailClosed) || model.calls() != 0 {
		t.Fatalf("открытая почта не остановила запрос: %v, запросов %d", err, model.calls())
	}
}

// TestProxyNumberingSharedAcrossMessages — D-1: одно значение в разных
// сообщениях — одна маска, разные значения — разные, и все восстанавливаются.
func TestProxyNumberingSharedAcrossMessages(t *testing.T) {
	svc := newProxyService(t, markScanner{values: map[string]pii.Type{
		fioIvanov: pii.FullName,
		fioPetrov: pii.FullName,
	}}, nil)
	model := &recordingModel{reply: "[ФИО_1] и [ФИО_2]"}
	res := mustProxy(t, svc, model, ProxyRequest{ID: "multi", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: clientIvanov},
		{Role: roleAssistant, Content: "Петров Пётр Петрович и снова Иванов Иван Иванович"},
	}}}, newProxyConsumer(t, true))
	got := model.got[0].Messages
	if got[0].Content != "Клиент [ФИО_1]" || got[1].Content != "[ФИО_2] и снова [ФИО_1]" {
		t.Fatalf("в модель ушло %q и %q", got[0].Content, got[1].Content)
	}
	if content := replyOf(res); content != "Иванов Иван Иванович и Петров Пётр Петрович" {
		t.Fatalf("ответ восстановлен неверно: %q", content)
	}
}

// TestProxyLiteralTokenInInputIsNotRestored — D-3 для стратегии, у которой
// замена не зависит от номера: токен, написанный во входе буквально и
// совпавший с выданным, не восстанавливается — ни на месте буквального,
// ни на месте выданного.
func TestProxyLiteralTokenInInputIsNotRestored(t *testing.T) {
	const name = fioIvanov
	svc := newProxyService(t, markScanner{values: map[string]pii.Type{name: pii.FullName}}, nil)
	tok := (mask.Token{}).Mask(name, pii.FullName, 1)
	model := &recordingModel{reply: tok + " пишет: Клиент " + tok}
	res := mustProxy(t, svc, model, ProxyRequest{ID: "lit-token", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: tok + " пишет: Клиент " + name},
	}}}, strategyConsumer(t, strategyToken, true))
	if content := replyOf(res); content != model.reply || res.Restored != 0 {
		t.Fatalf("неразличимый токен восстановлен (%d): %q", res.Restored, content)
	}
}

// TestProxyDemaskDeniedKeepsSyntheticMasks — D-2 без права демаскирования:
// выданные синтетические значения не маскируются повторно новой синтетикой,
// а с T-68 (Б4-8) и не выдаются клиенту как настоящие: на их месте —
// плейсхолдеры тех же значений.
func TestProxyDemaskDeniedKeepsSyntheticMasks(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := strategyConsumer(t, syntheticStrategy, false)
	const text = "Клиент Иванов Иван Иванович, карта 4276 5500 1234 5678, ИНН 500100732259"
	res := mustProxy(t, svc, &echoModel{}, ProxyRequest{ID: "syn-nodemask",
		Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: text}}}}, c)
	const want = "Клиент [ФИО_1], карта [КАРТА_1], ИНН [ИНН_1]"
	if content := replyOf(res); content != want || res.ResponseMasked != 0 {
		t.Fatalf("выданная синтетика (%d):\nполучено  %q\nожидалось %q", res.ResponseMasked, content, want)
	}
}

// TestProxyMasksModelExtensionOfRestoredValue — D-2, частичное перекрытие:
// модель дописала к восстановленному значению новые данные. Восстановленное
// значение остаётся, дописанное маскируется.
func TestProxyMasksModelExtensionOfRestoredValue(t *testing.T) {
	svc := newProxyService(t, markScanner{values: map[string]pii.Type{
		"Иванов Иван":          pii.FullName,
		"Иванов Иван Петрович": pii.FullName,
	}}, nil)
	model := &recordingModel{reply: "Ответ: [ФИО_1] Петрович."}
	res := mustProxy(t, svc, model, ProxyRequest{ID: "ext", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Клиент Иванов Иван"},
	}}}, newProxyConsumer(t, true))
	if content := replyOf(res); content != "Ответ: Иванов Иван [ФИО_2]." {
		t.Fatalf("ответ: %q (восстановлено %d, замаскировано %d)", content, res.Restored, res.ResponseMasked)
	}
}

// TestProxyFailClosedOnSpanLimit — T-52 AC-2 на продуктовом контуре:
// 20 050 телефонов при пределе 20 000. Строгий fail-closed: ноль запросов в
// фальшивую модель, соответствие не записано, в ошибке ни одного значения.
func TestProxyFailClosedOnSpanLimit(t *testing.T) {
	svc, st := realService(t, store.Options{})
	c := limitConsumer(t, consumerCRM, 20_000)
	text, phones := spanLimitPhones(20_050)
	model := &recordingModel{reply: replyAnswer}
	req := ProxyRequest{ID: "limit-proxy", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: text},
	}}}

	res, err := svc.Proxy(context.Background(), model, req, c)
	if !errors.Is(err, ErrFailClosed) || !errors.Is(err, ErrSpanLimit) {
		t.Fatalf("получена ошибка %v, ожидались ErrFailClosed и ErrSpanLimit", err)
	}
	assertNoModelCalls(t, model)
	if res.Sent || res.Response != nil || res.Replaced != 0 {
		t.Fatalf("при отказе: sent=%v response=%v replaced=%d", res.Sent, res.Response != nil, res.Replaced)
	}
	if _, ok := st.Get(scopedKey(c.ID, proxyKeyPrefix+req.ID)); ok {
		t.Fatal("при отказе записано соответствие")
	}
	msg := err.Error()
	for _, p := range phones {
		if strings.Contains(msg, p) {
			t.Fatalf("значение %q попало в текст ошибки", p)
		}
	}
}

// TestProxySpanLimitInLaterMessage — превышение в любом сообщении запроса
// останавливает выпуск всего запроса: первое, уже защищённое сообщение одно
// наружу не уходит.
func TestProxySpanLimitInLaterMessage(t *testing.T) {
	svc := newProxyService(t, markScanner{values: marked}, nil)
	c := limitConsumer(t, consumerCRM, 2)
	model := &recordingModel{reply: replyAnswer}
	req := ProxyRequest{ID: "limit-later", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Клиент Иванов Иван Иванович."},
		{Role: roleUser, Content: "Телефон +7 916 123-45-67, почта ivanov@example.test, карта 4276 5500 1234 5678."},
	}}}

	if _, err := svc.Proxy(context.Background(), model, req, c); !errors.Is(err, ErrSpanLimit) || !errors.Is(err, ErrFailClosed) {
		t.Fatalf("получена ошибка %v, ожидались ErrFailClosed и ErrSpanLimit", err)
	}
	assertNoModelCalls(t, model)

	// Ровно по пределу в каждом сообщении — штатный выпуск.
	req.Chat.Messages[1].Content = "Телефон +7 916 123-45-67, почта ivanov@example.test."
	if _, err := svc.Proxy(context.Background(), model, req, c); err != nil {
		t.Fatalf("по пределу: %v", err)
	}
	if model.calls() != 1 {
		t.Fatalf("модель получила %d запросов, ожидался один", model.calls())
	}
}

// TestProxyResponseOverSpanLimitIsNotReturned — ответ модели, в котором
// значений больше предела, клиенту не отдаётся: разметка ответа неполна, и
// значения сверх предела ушли бы открытыми.
func TestProxyResponseOverSpanLimitIsNotReturned(t *testing.T) {
	svc := newProxyService(t, markScanner{values: marked}, nil)
	c := limitConsumer(t, consumerCRM, 2)
	model := &recordingModel{reply: "Звоните +7 916 123-45-67, пишите ivanov@example.test, карта 4276 5500 1234 5678."}
	req := ProxyRequest{ID: "limit-resp", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Клиент Иванов Иван Иванович просит реквизиты."},
	}}}

	res, err := svc.Proxy(context.Background(), model, req, c)
	if !errors.Is(err, ErrResponse) || !errors.Is(err, ErrSpanLimit) {
		t.Fatalf("получена ошибка %v, ожидались ErrResponse и ErrSpanLimit", err)
	}
	if res.Response != nil {
		t.Fatal("непроверенный ответ модели возвращён клиенту")
	}
}

// slowScanner имитирует детекцию, которая не укладывается в предел.
type slowScanner struct{ d time.Duration }

func (slowScanner) Name() string { return "slow" }

func (s slowScanner) Scan(*lex.Doc, *dict.Set, *detect.Candidates) { time.Sleep(s.d) }

// TestProxyBudgetBoundsProtectionNotModel — REQ-604 на продуктовом контуре:
// предел ограничивает защиту, но не ожидание модели. Защита, не уложившаяся
// в предел, — fail-closed с причиной DeadlineExceeded и ноль запросов;
// медленная модель при быстрой защите пределом не обрывается.
func TestProxyBudgetBoundsProtectionNotModel(t *testing.T) {
	slow := newProxyService(t, slowScanner{d: 50 * time.Millisecond}, nil)
	model := &recordingModel{reply: replyAnswer}
	req := markedRequest()
	req.Budget = 10 * time.Millisecond

	res, err := slow.Proxy(context.Background(), model, req, newProxyConsumer(t, true))
	if !errors.Is(err, ErrFailClosed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("получена ошибка %v, ожидались ErrFailClosed и DeadlineExceeded", err)
	}
	if res.Sent || model.calls() != 0 {
		t.Fatalf("при исчерпании предела отправлено запросов: %d", model.calls())
	}

	fast := newProxyService(t, markScanner{values: marked}, nil)
	patient := &recordingModel{reply: "Письмо для [ФИО_1] готово.", delay: 60 * time.Millisecond}
	req.Budget = 30 * time.Millisecond
	res, err = fast.Proxy(context.Background(), patient, req, newProxyConsumer(t, true))
	if err != nil {
		t.Fatalf("медленная модель при быстрой защите: %v", err)
	}
	if got := replyOf(res); got != "Письмо для Иванов Иван Иванович готово." {
		t.Fatalf(fmtReply, got)
	}
}

// largeVerifyText — С-5: около 600 КБ и 15 000 спанов, как в отчёте
// проверки качества 23.09 (605 КБ, 14 955 спанов). В строке — синтетическое
// ФИО из тысячи сочетаний (кириллица длиннее 32 байт: на таких значениях
// поиск подстроки медленнее всего) и различный телефон.
func largeVerifyText(lines int) string {
	surnames := []string{surnameIvanov, "Петров", "Сидоров", "Смирнов", "Кузнецов", "Попов", "Васильев", "Соколов", "Михайлов", "Новиков"}
	names := []string{"Иван", "Пётр", "Алексей", "Сергей", "Андрей", "Дмитрий", "Михаил", "Николай", "Павел", "Олег"}
	patronymics := []string{"Иванович", "Петрович", "Алексеевич", "Сергеевич", "Андреевич", "Дмитриевич", "Михайлович", "Николаевич", "Павлович", "Олегович"}
	var b strings.Builder
	b.Grow(lines * 80)
	for i := 1; i <= lines; i++ {
		d := fmt.Sprintf("%07d", i)
		fmt.Fprintf(&b, "Клиент %s %s %s, тел. +7 916 %s-%s-%s\n",
			surnames[i%10], names[(i/10)%10], patronymics[(i/100)%10], d[:3], d[3:5], d[5:])
	}
	return b.String()
}

// largeMask маскирует largeVerifyText реальным движком.
func largeMask(tb testing.TB, n int) (string, MaskResult) {
	tb.Helper()
	invDictsOnce.Do(func() { invDicts, invDictsErr = dict.Load() })
	if invDictsErr != nil {
		tb.Fatalf("загрузка справочников: %v", invDictsErr)
	}
	st := store.NewMemory(store.Options{TTL: time.Hour})
	tb.Cleanup(func() { _ = st.Close() })
	svc := New(detect.New(invDicts, detect.Registered()...), st)
	c, err := policy.NewConsumer(policy.Consumer{
		ID: consumerCRM, Enabled: true, Types: pii.FullSet(), Demask: true, MaskingEnabled: true,
	}, strategyPlaceholder, nil, nil)
	if err != nil {
		tb.Fatal(err)
	}
	text := largeVerifyText(n)
	mr, err := svc.Mask(context.Background(), text, c)
	if err != nil {
		tb.Fatal(err)
	}
	return text, mr
}

// BenchmarkVerifyReplacedLarge — С-5: проверка полноты на 600 КБ и 15 000
// спанах. До T-56 проверка шла за O(спаны × длина текста): 4,05 с на M1 Max.
func BenchmarkVerifyReplacedLarge(b *testing.B) {
	text, mr := largeMask(b, 7_500)
	b.Logf("текст %d Б, спанов %d", len(text), len(mr.Applied))
	b.ResetTimer()
	for b.Loop() {
		if err := VerifyReplaced(text, mr); err != nil {
			b.Fatal(err)
		}
	}
}

// TestVerifyReplacedLargeIsSinglePass — С-5, AC-2: на 600 КБ и 15 000 спанах
// проверка укладывается в предел и по-прежнему ловит единственное открытое
// значение в конце текста. Предел — секунда с запасом на детектор гонок;
// прежняя проверка занимала 4 с и без него.
func TestVerifyReplacedLargeIsSinglePass(t *testing.T) {
	if testing.Short() {
		t.Skip("длинный вход")
	}
	text, mr := largeMask(t, 7_500)
	if len(mr.Applied) != 15_000 {
		t.Fatalf("замен %d, ожидалось 15 000", len(mr.Applied))
	}
	started := time.Now()
	if err := VerifyReplaced(text, mr); err != nil {
		t.Fatalf("полная маска отклонена: %v", err)
	}
	if spent := time.Since(started); spent > time.Second {
		t.Fatalf("проверка на %d Б и %d спанах заняла %v", len(text), len(mr.Applied), spent)
	}

	last := mr.Applied[len(mr.Applied)-1]
	leaked := mr
	leaked.Text = mr.Text + " " + text[last.Start:last.End]
	err := VerifyReplaced(text, leaked)
	if err == nil {
		t.Fatal("открытое значение в конце текста не поймано")
	}
	if strings.Contains(err.Error(), text[last.Start:last.End]) {
		t.Fatal("значение попало в текст ошибки")
	}
}

// TestProxyRealEngineRepeatsNotFailClosed — С-4, AC-1 на реальной детекции:
// повтор даты рождения в дате договора и повтор ПИН в коде из смс закрыты
// той же маской, запрос ушёл (до T-56 — ложный fail-closed), в теле к
// модели нет ни одного значения, ответ восстановлен.
func TestProxyRealEngineRepeatsNotFailClosed(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, consumerCRM, strategyPlaceholder)
	for _, tt := range []struct{ text, value string }{
		{"Клиент Иванов Иван Иванович, дата рождения 01.02.1990. Договор от 01.02.1990 подписан.", "01.02.1990"},
		{"Клиент сообщил пин-код 1234, код из смс 1234.", pinValue},
	} {
		model := &recordingModel{reply: "Повторяю запрос."}
		_, err := svc.Proxy(context.Background(), model, ProxyRequest{ID: "c4",
			Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: tt.text}}}}, c)
		if err != nil || model.calls() != 1 {
			t.Fatalf("%q: ошибка %v, запросов %d", tt.text, err, model.calls())
		}
		if sent := model.wire(t); strings.Contains(sent, tt.value) {
			t.Fatalf("значение %q ушло в модель: %s", tt.value, model.got[0].Messages[0].Content)
		}
		mr, err := svc.MaskReserved(context.Background(), tt.text, c)
		if err != nil {
			t.Fatalf(fmtMaskErr, err)
		}
		if err := VerifyReplaced(tt.text, mr); err != nil {
			t.Fatalf("%q: проверка полноты отклонила маску %q: %v", tt.text, mr.Text, err)
		}
	}
}

// TestProxyRestoresMarkupFramedPlaceholder — Ж-1: модель переписала выданный
// плейсхолдер без скобок в разметке. Выданные метки восстанавливаются, чужие
// и метка вне разметки — нет, разметка остаётся.
func TestProxyRestoresMarkupFramedPlaceholder(t *testing.T) {
	svc := newProxyService(t, markScanner{values: marked}, nil)
	model := &recordingModel{reply: "Уважаемый **ФИО_1**, телефон *ТЕЛЕФОН_1*, почта `EMAIL_1`, " +
		"карта __КАРТА_1__. Чужой **ФИО_9**, метка ФИО_1 без разметки, слово X_ФИО_1_ и [ФИО_1]."}

	res := mustProxy(t, svc, model, markedRequest(), newProxyConsumer(t, true))
	const want = "Уважаемый **Иванов Иван Иванович**, телефон *+7 916 123-45-67*, почта `ivanov@example.test`, " +
		"карта __4276 5500 1234 5678__. Чужой **ФИО_9**, метка ФИО_1 без разметки, слово X_ФИО_1_ и Иванов Иван Иванович."
	if got := replyOf(res); got != want {
		t.Fatalf("получено  %q\nожидалось %q", got, want)
	}
	if res.Restored != 5 {
		t.Errorf("восстановлено %d, ожидалось 5", res.Restored)
	}

	// Без права демаскирования метка в разметке остаётся как есть и не
	// маскируется повторно.
	model = &recordingModel{reply: "Письмо для **ФИО_1** готово."}
	res, err := svc.Proxy(context.Background(), model, markedRequest(), newProxyConsumer(t, false))
	if err != nil {
		t.Fatalf("проксирование без права: %v", err)
	}
	if got := replyOf(res); got != model.reply || res.Restored != 0 {
		t.Fatalf("без права демаскирования ответ изменён (%d): %q", res.Restored, got)
	}
}

// TestProxyLiteralBareLabelIsReserved — Ж-1 и D-3: метка, буквально
// написанная во входе без скобок, не выдаётся — её эхо в разметке не
// отличить от выданной. Модель повторяет буквальный «**ФИО_1**» из входа:
// он остаётся как есть, выданный [ФИО_2] восстанавливается.
func TestProxyLiteralBareLabelIsReserved(t *testing.T) {
	const name = fioIvanov
	svc := newProxyService(t, markScanner{values: map[string]pii.Type{name: pii.FullName}}, nil)
	model := &recordingModel{reply: "Поле **ФИО_1** заполнено: **ФИО_2**."}
	res := mustProxy(t, svc, model, ProxyRequest{ID: "lit-label", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Заполни поле **ФИО_1**: клиент " + name},
	}}}, newProxyConsumer(t, true))
	if got := model.got[0].Messages[0].Content; got != "Заполни поле **ФИО_1**: клиент [ФИО_2]" {
		t.Fatalf(fmtSentToModel, got)
	}
	if got := replyOf(res); got != "Поле **ФИО_1** заполнено: **"+name+"**." {
		t.Fatalf(fmtReply, got)
	}
}

// TestRestoreIssuedMatchesProxyRestore — С-6: восстановление явного API и
// прокси — одна реализация. Буквальный плейсхолдер во входе не выдаётся
// (MaskReserved) и при восстановлении изменённой маски остаётся буквальным;
// выданный восстанавливается, в том числе в разметке.
func TestRestoreIssuedMatchesProxyRestore(t *testing.T) {
	const name = fioIvanov
	const text = "Шаблон [ФИО_1] заполнить: клиент " + name + "."
	svc := newProxyService(t, markScanner{values: map[string]pii.Type{name: pii.FullName}}, nil)
	c := newProxyConsumer(t, true)

	mr, err := svc.MaskReserved(context.Background(), text, c)
	if err != nil {
		t.Fatalf(fmtMaskErr, err)
	}
	if mr.Text != "Шаблон [ФИО_1] заполнить: клиент [ФИО_2]." {
		t.Fatalf("маска: %q", mr.Text)
	}
	got, n := RestoreIssued("Ответ: "+mr.Text+" И ещё **ФИО_2**.", text, mr.Applied, c)
	if want := "Ответ: " + text + " И ещё **" + name + "**."; got != want || n != 2 {
		t.Fatalf("восстановлено %d: %q", n, got)
	}

	// Маскирование без резерва по-прежнему нумерует с единицы: /process не
	// меняется ни на каком входе.
	plain, err := svc.Mask(context.Background(), text, c)
	if err != nil || plain.Text != "Шаблон [ФИО_1] заполнить: клиент [ФИО_1]." {
		t.Fatalf("Mask: %q, %v", plain.Text, err)
	}

	// Токен не зависит от номера: развести его с буквальным нельзя, и такая
	// маска не восстанавливается ни на месте буквальной, ни на месте выданной.
	tc := strategyConsumer(t, strategyToken, true)
	tok := (mask.Token{}).Mask(name, pii.FullName, 1)
	tokText := tok + " пишет: клиент " + name
	tmr, err := svc.MaskReserved(context.Background(), tokText, tc)
	if err != nil {
		t.Fatalf("маскирование токеном: %v", err)
	}
	if got, n := RestoreIssued(tmr.Text+"!", tokText, tmr.Applied, tc); got != tmr.Text+"!" || n != 0 {
		t.Fatalf("неразличимый токен восстановлен (%d): %q", n, got)
	}
}

// markerScanner отмечает значения только в тексте с маркером: так значение
// «находится» в одном сообщении запроса и «не опознаётся» в другом.
type markerScanner struct {
	marker string
	values map[string]pii.Type
}

func (markerScanner) Name() string { return "marker" }

func (m markerScanner) Scan(doc *lex.Doc, d *dict.Set, out *detect.Candidates) {
	if strings.Contains(doc.Text, m.marker) {
		markScanner{values: m.values}.Scan(doc, d, out)
	}
}

// TestProxyCoversRepeatAcrossMessages — С-4 между сообщениями: значение,
// найденное в одном сообщении, закрывается той же маской в другом, где
// детекция его не опознала; прилипшее к слову — запрос не уходит. До T-56
// повтор в другом сообщении уходил в модель открытым: проверка полноты шла
// по значениям своего сообщения.
func TestProxyCoversRepeatAcrossMessages(t *testing.T) {
	svc := newProxyService(t, markerScanner{marker: "пин-код", values: map[string]pii.Type{
		pinValue:    pii.PIN,
		emailIvanov: pii.Email,
	}}, nil)
	c := newProxyConsumer(t, true)

	model := &recordingModel{reply: "Код [ПИН_1] принят."}
	res := mustProxy(t, svc, model, ProxyRequest{ID: "across", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Напомни код 1234 из смс."},
		{Role: roleUser, Content: "Мой пин-код 1234, почта ivanov@example.test."},
		{Role: roleAssistant, Content: "Записал 1234 и ivanov@example.test"},
	}}}, c)
	got := model.got[0].Messages
	if got[0].Content != "Напомни код [ПИН_1] из смс." ||
		got[1].Content != "Мой пин-код [ПИН_1], почта [EMAIL_1]." ||
		got[2].Content != "Записал [ПИН_1] и [EMAIL_1]" {
		t.Fatalf(fmtSentToModel, []string{got[0].Content, got[1].Content, got[2].Content})
	}
	if wire := model.wire(t); strings.Contains(wire, pinValue) || strings.Contains(wire, "ivanov@") {
		t.Fatal("значение ушло в модель")
	}
	if res.Replaced != 5 || res.MaskedCounts[pii.PIN] != 3 || res.DetectedCounts[pii.PIN] != 3 {
		t.Fatalf("замен %d, ПИН замаскировано %d, обнаружено %d", res.Replaced, res.MaskedCounts[pii.PIN], res.DetectedCounts[pii.PIN])
	}
	if content := replyOf(res); content != "Код 1234 принят." {
		t.Fatalf(fmtReply, content)
	}

	model = &recordingModel{reply: "ок"}
	_, err := svc.Proxy(context.Background(), model, ProxyRequest{ID: "across-glued", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: "Мой пин-код 1234, почта ivanov@example.test."},
		{Role: roleUser, Content: "Ещё раз: Жivanov@example.test"},
	}}}, c)
	if !errors.Is(err, ErrFailClosed) || model.calls() != 0 {
		t.Fatalf("прилипшее значение из другого сообщения не остановило запрос: %v, запросов %d", err, model.calls())
	}
}

// TestLiteralInLabels — метка плейсхолдера ищется отдельным словом: в
// скобках, в разметке и сама по себе, но не как часть другого слова.
func TestLiteralInLabels(t *testing.T) {
	reserved := literalIn("поле [ФИО_1], **ТЕЛЕФОН_2**, EMAIL_3 и КОД_ИНН_4, ФИО_12, ПИН_5x", "второе сообщение CVV_7")
	for repl, want := range map[string]bool{
		placeholderFIO1: true, "[ТЕЛЕФОН_2]": true, "[EMAIL_3]": true, "[CVV_7]": true, "[КОД_ИНН_4]": true,
		"[ИНН_4]": false, "[ФИО_2]": false, "[ФИО_12]": true, "[ПИН_5]": false,
		"{{pii:0000beef}}": false, "поле": true,
	} {
		if got := reserved(repl); got != want {
			t.Errorf("reserved(%q) = %v, ожидалось %v", repl, got, want)
		}
	}
}
