package llm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Сообщения о провале и фикстуры, общие для тестов клиента.
const (
	msgChatFailed = "вызов модели: %v"
	msgNoError    = "ошибка не возвращена"
	msgWrongClass = "класс отказа %q вместо %q: %v"
	stubModel     = "stub-model"
)

// Тесты не выходят в сеть: все обращения идут на httptest.Server на петле.

// testKey — синтетический ключ. Настоящий ключ AlfaGen в репозиторий не
// попадает ни в каком виде.
const testKey = "sk-test-0000000000000000"

// okBody — минимальный OpenAI-совместимый ответ.
const okBody = `{"id":"chatcmpl-1","object":"chat.completion","model":"m",
"choices":[{"index":0,"message":{"role":"assistant","content":"привет"},"finish_reason":"stop"}],
"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

func newTestClient(t *testing.T, baseURL string, tune func(*Options)) *Client {
	t.Helper()
	o := Options{
		BaseURL:     baseURL,
		Model:       "test-model",
		APIKey:      testKey,
		Timeout:     2 * time.Second,
		MaxAttempts: 3,
		BaseBackoff: time.Millisecond,
		MaxBackoff:  2 * time.Millisecond,
	}
	if tune != nil {
		tune(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatalf("сборка клиента: %v", err)
	}
	return c
}

func testRequest() Request {
	return Request{Messages: []Message{{Role: "user", Content: "текст [ФИО_1]"}}}
}

func TestChatSendsKeyWithoutBearerPrefix(t *testing.T) {
	// С префиксом Bearer AlfaGen отвечает 400 — это подтверждено живым
	// запросом и зафиксировано в контракте.
	var got http.Header
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		path = r.URL.Path
		_, _ = w.Write([]byte(okBody))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL+"/v1", nil)
	if _, err := c.Chat(context.Background(), testRequest()); err != nil {
		t.Fatalf(msgChatFailed, err)
	}

	if auth := got.Get(headerAuthorization); auth != testKey {
		t.Fatalf("заголовок Authorization = %q, ожидался ключ без префикса", auth)
	}
	if strings.Contains(strings.ToLower(got.Get(headerAuthorization)), "bearer") {
		t.Fatal("ключ отправлен с префиксом Bearer")
	}
	if ct := got.Get("Content-Type"); ct != mimeJSON {
		t.Errorf("Content-Type = %q", ct)
	}
	if path != "/v1/chat/completions" {
		t.Errorf("запрос ушёл на %q", path)
	}
}

func TestChatFillsModelAndDisablesStreaming(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(okBody))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	req := testRequest()
	req.Stream = true    // клиент обязан выключить поток: ответ обрабатывается целиком
	req.Model = "gpt-4o" // имя модели клиента заменяется моделью из конфигурации
	if _, err := c.Chat(context.Background(), req); err != nil {
		t.Fatalf(msgChatFailed, err)
	}

	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("тело запроса не JSON: %v", err)
	}
	if sent["model"] != "test-model" {
		t.Errorf("модель в запросе: %v", sent["model"])
	}
	if v, ok := sent["stream"]; ok && v == true {
		t.Error("клиент отправил stream: true")
	}
}

func TestChatRetriesTemporaryStatuses(t *testing.T) {
	// Повтор допустим только для временных отказов: сетевых и 429/502/503/504.
	for _, code := range []int{
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(code)
					return
				}
				_, _ = w.Write([]byte(okBody))
			}))
			defer srv.Close()

			c := newTestClient(t, srv.URL, nil)
			resp, err := c.Chat(context.Background(), testRequest())
			if err != nil {
				t.Fatalf(msgChatFailed, err)
			}
			if resp.Choices[0].Message.Content != "привет" {
				t.Fatalf("неожиданный ответ: %q", resp.Choices[0].Message.Content)
			}
			if n := calls.Load(); n != 2 {
				t.Fatalf("выполнено попыток: %d, ожидалось 2", n)
			}
		})
	}
}

func TestChatDoesNotRetryPermanentStatuses(t *testing.T) {
	// 400, 401 и 403 повтор не исправит: лишние попытки только удлинят ответ.
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(code)
			}))
			defer srv.Close()

			c := newTestClient(t, srv.URL, nil)
			if _, err := c.Chat(context.Background(), testRequest()); err == nil {
				t.Fatal(msgNoError)
			}
			if n := calls.Load(); n != 1 {
				t.Fatalf("выполнено попыток: %d, ожидалась 1", n)
			}
		})
	}
}

func TestChatRetriesNetworkError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			// Обрыв соединения без ответа — сетевой сбой, повтор уместен.
			hj, ok := w.(http.Hijacker)
			if !ok {
				// Обработчик работает в горутине сервера: t.Fatal отсюда нельзя.
				t.Error("ResponseWriter не поддерживает Hijack")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = w.Write([]byte(okBody))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	if _, err := c.Chat(context.Background(), testRequest()); err != nil {
		t.Fatalf(msgChatFailed, err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("выполнено попыток: %d, ожидалось 2", n)
	}
}

func TestChatRespectsAttemptBudget(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, func(o *Options) { o.MaxAttempts = 3 })
	if _, err := c.Chat(context.Background(), testRequest()); err == nil {
		t.Fatal(msgNoError)
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("выполнено попыток: %d, ожидалось 3 (бюджет)", n)
	}
}

func TestChatStopsRetryingAtDeadline(t *testing.T) {
	// Дедлайн важнее бюджета попыток: ждать дольше, чем клиент готов ждать,
	// бессмысленно.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, func(o *Options) {
		o.MaxAttempts = 10
		o.Timeout = 60 * time.Millisecond
		o.BaseBackoff = 50 * time.Millisecond
		o.MaxBackoff = 400 * time.Millisecond
	})
	start := time.Now()
	if _, err := c.Chat(context.Background(), testRequest()); err == nil {
		t.Fatal(msgNoError)
	}
	if n := calls.Load(); n >= 10 {
		t.Fatalf("бюджет исчерпан вместо остановки по дедлайну: %d попыток", n)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("вызов занял %s: дедлайн не соблюдён", d)
	}
}

func TestChatHonorsContextCancellation(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c := newTestClient(t, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if _, err := c.Chat(ctx, testRequest()); err == nil {
		t.Fatal("отмена не прервала вызов")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("отмена обработана за %s", d)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("после отмены выполнено попыток: %d", n)
	}
}

func TestChatErrorsHideKeyAndBody(t *testing.T) {
	// AC-10: ни ключ, ни тело запроса или ответа не попадают в текст ошибки.
	const secret = "Иванов Иван Иванович, 4276 5500 1234 5678"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"` + secret + `"}}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	req := Request{Messages: []Message{{Role: "user", Content: secret}}}
	_, err := c.Chat(context.Background(), req)
	if err == nil {
		t.Fatal(msgNoError)
	}
	msg := err.Error()
	if strings.Contains(msg, testKey) {
		t.Fatalf("ключ попал в текст ошибки: %s", msg)
	}
	for _, part := range []string{"Иванов", "Иван", "4276", "5678"} {
		if strings.Contains(msg, part) {
			t.Fatalf("фрагмент %q попал в текст ошибки: %s", part, msg)
		}
	}
	if !strings.Contains(msg, "500") {
		t.Errorf("текст ошибки не называет код ответа: %s", msg)
	}
}

func TestChatFailureCarriesStatusCode(t *testing.T) {
	// AC-1: код ответа модели доступен вызывающему коду как число, а не как
	// фрагмент текста ошибки. По журналу 401 и 429 должны различаться без
	// повторения ручной сверки с хоста и из контейнера.
	for _, code := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer srv.Close()

			c := newTestClient(t, srv.URL, func(o *Options) { o.MaxAttempts = 1 })
			_, err := c.Chat(context.Background(), testRequest())
			if err == nil {
				t.Fatal(msgNoError)
			}
			f := Classify(err)
			if f.Class != ClassStatus {
				t.Errorf("класс отказа %q вместо %q", f.Class, ClassStatus)
			}
			if f.Status != code {
				t.Errorf("код ответа в причине: %d, ожидался %d", f.Status, code)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(code)) {
				t.Errorf("текст ошибки не называет код ответа: %s", err)
			}
		})
	}
}

func TestChatFailureOnUntrustedCertificate(t *testing.T) {
	// AC-2: ровно тот отказ, который 22.09.2026 искали час вручную. Сертификат
	// httptest подписан собственным корнем, которого нет в хранилище доверия —
	// это та же ситуация, что и образ без корней AlfaGen.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(okBody))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, func(o *Options) { o.MaxAttempts = 1 })
	_, err := c.Chat(context.Background(), testRequest())
	if err == nil {
		t.Fatal("клиент принял недоверенный сертификат")
	}
	if f := Classify(err); f.Class != ClassTLS {
		t.Fatalf(msgWrongClass, f.Class, ClassTLS, err)
	}
}

func TestChatFailureOnRefusedConnection(t *testing.T) {
	// Закрытый порт на петле: соединение отвергнуто, ответа нет.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close()

	c := newTestClient(t, addr, func(o *Options) { o.MaxAttempts = 1 })
	_, err := c.Chat(context.Background(), testRequest())
	if err == nil {
		t.Fatal("вызов закрытого порта завершился успехом")
	}
	f := Classify(err)
	if f.Class != ClassConnect {
		t.Fatalf(msgWrongClass, f.Class, ClassConnect, err)
	}
	if f.Status != 0 {
		t.Errorf("код ответа %d при отсутствии ответа", f.Status)
	}
}

func TestChatFailureOnTimeout(t *testing.T) {
	// Таймаут отличается от отказа сервера: сервер не ответил вовсе.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c := newTestClient(t, srv.URL, func(o *Options) {
		o.MaxAttempts = 1
		o.Timeout = 50 * time.Millisecond
	})
	_, err := c.Chat(context.Background(), testRequest())
	if err == nil {
		t.Fatal("ожидание не прервано по таймауту")
	}
	if f := Classify(err); f.Class != ClassTimeout {
		t.Fatalf(msgWrongClass, f.Class, ClassTimeout, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("исчерпанный дедлайн не распознаётся через errors.Is: %v", err)
	}
}

func TestClassifySeparatesFailureClasses(t *testing.T) {
	// Классификация проверяется на синтетических ошибках: отказ разрешения
	// имени и отказ маршрутизации воспроизводить настоящей сетью в тесте
	// нельзя — он обязан работать в закрытом контуре.
	cases := []struct {
		name string
		err  error
		want FailureClass
	}{
		{"имя не разрешилось", &net.DNSError{Err: "no such host", Name: "model.invalid", IsNotFound: true}, ClassDNS},
		{"разрешение имени не завершилось", &net.DNSError{Err: "timeout", Name: "model.invalid", IsTimeout: true}, ClassDNS},
		{"сертификат не проверен", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, ClassTLS},
		{"неизвестный корень", x509.UnknownAuthorityError{}, ClassTLS},
		{"соединение отвергнуто", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, ClassConnect},
		{"нет маршрута", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}, ClassConnect},
		{"дедлайн исчерпан", context.DeadlineExceeded, ClassTimeout},
		{"вызов отменён", context.Canceled, ClassCanceled},
		{"чужая ошибка", errors.New("ошибка чужой реализации Chatter"), ClassUnknown},
		{"обёрнутый отказ TLS", fmt.Errorf("обёртка: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), ClassTLS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err).Class; got != tc.want {
				t.Fatalf("класс отказа %q вместо %q", got, tc.want)
			}
		})
	}
	if got := Classify(nil).Class; got != "" {
		t.Errorf("отсутствие ошибки получило класс %q", got)
	}
}

func TestFailureNeverCarriesResponseBody(t *testing.T) {
	// AC-3: тело ответа модели может содержать эхо запроса, а вместе с ним
	// персональные данные. Ни в текст ошибки, ни в поля причины оно не
	// попадает ни при каком исходе — включая отказ разбора, где сообщение
	// json умеет цитировать разбираемые байты.
	const secret = "Кузнецова Анфиса Валерьевна, 5211 6702 4488 1093"
	bodies := map[string]struct {
		code int
		body string
	}{
		"ошибка сервера с эхом": {http.StatusInternalServerError, `{"error":{"message":"` + secret + `"}}`},
		"отказ по ключу с эхом": {http.StatusUnauthorized, `{"error":"ключ отклонён","echo":"` + secret + `"}`},
		"битый JSON с эхом":     {http.StatusOK, `{"choices": [` + secret},
		"ответ без вариантов":   {http.StatusOK, `{"id":"x","choices":[],"echo":"` + secret + `"}`},
	}
	fragments := []string{secret, "Кузнецова", "Анфиса", "Валерьевна", "5211", "1093"}

	for name, tc := range bodies {
		t.Run(name, func(t *testing.T) {
			assertFailureHidesBody(t, tc.code, tc.body, secret, fragments)
		})
	}
}

// assertFailureHidesBody поднимает модель, отвечающую кодом code и телом body,
// и проверяет, что ни один из fragments и ни ключ доступа не попали ни в одно
// поле отказа, которое вызывающий код может записать в журнал.
func assertFailureHidesBody(t *testing.T, code int, body, secret string, fragments []string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, func(o *Options) { o.MaxAttempts = 1 })
	req := Request{Messages: []Message{{Role: "user", Content: secret}}}
	_, err := c.Chat(context.Background(), req)
	if err == nil {
		t.Fatal(msgNoError)
	}
	f := Classify(err)
	// Проверяется всё, что вызывающий код может записать в журнал.
	fields := []string{err.Error(), f.Reason, string(f.Class), fmt.Sprint(f.Status), fmt.Sprintf("%+v", f)}
	for _, field := range fields {
		assertFieldHides(t, field, fragments)
	}
}

// assertFieldHides проверяет одно поле отказа: в нём нет ни фрагментов
// тела ответа, ни ключа доступа.
func assertFieldHides(t *testing.T, field string, fragments []string) {
	t.Helper()
	for _, frag := range fragments {
		if strings.Contains(field, frag) {
			t.Fatalf("фрагмент %q попал в причину отказа: %s", frag, field)
		}
	}
	if strings.Contains(field, testKey) {
		t.Fatalf("ключ доступа попал в причину отказа: %s", field)
	}
}

func TestChatRejectsMalformedResponse(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("не json"))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	if _, err := c.Chat(context.Background(), testRequest()); err == nil {
		t.Fatal("некорректный ответ принят")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("разбор ответа повторялся: %d попыток", n)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	if _, err := New(Options{BaseURL: "", APIKey: testKey}); err == nil {
		t.Error("пустой адрес принят")
	}
	if _, err := New(Options{BaseURL: "не-адрес", APIKey: testKey}); err == nil {
		t.Error("некорректный адрес принят")
	}
	if _, err := New(Options{BaseURL: "https://example.invalid/v1"}); err != ErrNoAPIKey {
		t.Errorf("пустой ключ: получено %v, ожидалась ErrNoAPIKey", err)
	}
}

func TestStubQuotesPlaceholders(t *testing.T) {
	// AC-8: ответ показывает, что модель «увидела» именно маску.
	s := Stub{Model: stubModel}
	resp, err := s.Chat(context.Background(), Request{Messages: []Message{
		{Role: "system", Content: "Ты — ассистент."},
		{Role: "user", Content: "Клиент [ФИО_1], карта [CARD_1], телефон [ТЕЛЕФОН_1]."},
	}})
	if err != nil {
		t.Fatalf("stub вернул ошибку: %v", err)
	}
	content := resp.Choices[0].Message.Content
	for _, p := range []string{"[ФИО_1]", "[CARD_1]", "[ТЕЛЕФОН_1]"} {
		if !strings.Contains(content, p) {
			t.Errorf("ответ не цитирует плейсхолдер %s: %q", p, content)
		}
	}
	if resp.Model != stubModel {
		t.Errorf("модель в ответе: %q", resp.Model)
	}
}

func TestStubIsDeterministic(t *testing.T) {
	s := Stub{Model: stubModel}
	req := Request{Messages: []Message{{Role: "user", Content: "[EMAIL_1] и [EMAIL_1]"}}}

	first, err := s.Chat(context.Background(), req)
	if err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	second, err := s.Chat(context.Background(), req)
	if err != nil {
		t.Fatalf("второй вызов: %v", err)
	}
	if first.ID != second.ID || first.Created != second.Created || first.Usage != second.Usage {
		t.Fatal("метаданные ответов заглушки разошлись")
	}
	if first.Choices[0] != second.Choices[0] {
		t.Fatal("содержимое ответов заглушки разошлось")
	}
	if got := strings.Count(first.Choices[0].Message.Content, "[EMAIL_1]"); got != 1 {
		t.Errorf("повторный плейсхолдер процитирован %d раз", got)
	}
}

func TestStubWithoutPlaceholders(t *testing.T) {
	s := Stub{Model: stubModel}
	resp, err := s.Chat(context.Background(), Request{Messages: []Message{
		{Role: "user", Content: "Просто вопрос про погоду [не маска] и [lower_1]."},
	}})
	if err != nil {
		t.Fatalf("stub вернул ошибку: %v", err)
	}
	if strings.Contains(resp.Choices[0].Message.Content, "маски:") {
		t.Errorf("текст в скобках принят за плейсхолдер: %q", resp.Choices[0].Message.Content)
	}
}

func TestStubHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Stub{}).Chat(ctx, testRequest()); err == nil {
		t.Fatal("отменённый контекст проигнорирован")
	}
}
