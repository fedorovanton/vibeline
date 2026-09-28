package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestBodyReadTimeoutIsRetryable — тело, не дочитанное до ReadTimeout, даёт
// 429 с Retry-After, а не 400: медленный канал — не ошибка клиента, и
// проверяющая система такой ответ повторяет (T-48, D-1 нагрузочного прогона).
func TestBodyReadTimeoutIsRetryable(t *testing.T) {
	srv := newAPIServer(t, nil, "9s").srv
	ts := httptest.NewUnstartedServer(srv.http.Handler)
	ts.Config.ReadHeaderTimeout = 200 * time.Millisecond
	ts.Config.ReadTimeout = 200 * time.Millisecond
	ts.Start()
	defer ts.Close()

	for _, path := range []string{pathProcess, "/api/v1/mask"} {
		t.Run(path, func(t *testing.T) {
			assertSlowBodyRetryable(t, ts, path)
		})
	}
}

// assertSlowBodyRetryable отправляет на path тело, поступающее медленнее
// ReadTimeout сервера, и проверяет ответ 429 с Retry-After.
func assertSlowBodyRetryable(t *testing.T, ts *httptest.Server, path string) {
	t.Helper()
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte(`{"payload":"Клиент Иванов Иван Иванович`))
		time.Sleep(500 * time.Millisecond)
		_, _ = pw.Write([]byte(`","payload_id":"slow-1"}`))
		_ = pw.Close()
	}()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+path, pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerContentType, jsonContentType)
	req.Header.Set(headerAuthorization, apiCrmKey)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("закрытие тела ответа: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("код %d, ожидался 429", resp.StatusCode)
	}
	if resp.Header.Get(headerRetryAfter) == "" {
		t.Fatal("нет заголовка Retry-After")
	}
}

// TestBodyReadTimeoutCoversRequestBudget — тело получает бюджет обработки, а не
// предел заголовков.
func TestBodyReadTimeoutCoversRequestBudget(t *testing.T) {
	if got := bodyReadTimeout(5*time.Second, 9*time.Second); got != 9*time.Second {
		t.Fatalf("bodyReadTimeout = %s, ожидалось 9s", got)
	}
	if got := bodyReadTimeout(12*time.Second, 9*time.Second); got != 12*time.Second {
		t.Fatalf("bodyReadTimeout = %s, ожидалось 12s", got)
	}
}

// TestProcessClientGoneIsNotFailClosed — обрыв соединения клиентом до ответа
// учитывается отдельным исходом, а не как отказ защиты (O-1 нагрузочного
// прогона 23.09).
func TestProcessClientGoneIsNotFailClosed(t *testing.T) {
	srv := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathProcess,
		strings.NewReader(`{"payload":"Клиент Иванов Иван Иванович","payload_id":"gone-1"}`)).WithContext(ctx)
	srv.http.Handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := httptest.NewRecorder()
	srv.http.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, pathMetrics, nil))
	metrics := rec.Body.String()
	if !strings.Contains(metrics, `outcome="client_gone"`) {
		t.Fatal("обрыв клиента не учтён исходом client_gone")
	}
	for _, line := range strings.Split(metrics, "\n") {
		if strings.Contains(line, `endpoint="process"`) && strings.Contains(line, `outcome="fail_closed"`) &&
			!strings.HasSuffix(line, " 0") && !strings.HasPrefix(line, "#") {
			t.Fatalf("обрыв клиента учтён как fail_closed: %s", line)
		}
	}
}
