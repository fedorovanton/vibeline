package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/store"
)

const testConfig = `
server:
  addr: ":0"
  max_body_bytes: 1MiB
  max_concurrent: 8
store:
  ttl: 1h
llm:
  mode: stub
consumers:
  - id: benchmark
    types: [all]
    demask: true
    mask:
      default: placeholder
`

func newTestServer(t *testing.T) *Server {
	t.Helper()

	holder := newTestHolder(t, testConfig)

	st := store.NewMemory(holder.Current().Store)
	t.Cleanup(func() { _ = st.Close() })

	return NewServer(Deps{
		Config:    holder,
		Gateway:   gateway.New(detect.New(nil), st),
		Metrics:   obs.NewMetrics(),
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:   "test",
		StartedAt: time.Now(),
	})
}

// post отправляет запрос на /process и возвращает код ответа и тело.
func post(t *testing.T, s *Server, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathProcess, strings.NewReader(body))
	req.Header.Set(headerContentType, jsonContentType)
	rec := httptest.NewRecorder()
	s.wrap(http.HandlerFunc(s.handleProcess)).ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestProcessContract(t *testing.T) {
	s := newTestServer(t)

	code, body := post(t, s, `{"payload":"тестовая строка","payload_id":"c-1"}`)
	if code != http.StatusOK {
		t.Fatalf("получен код %d, тело %s", code, body)
	}

	// Контракт задан организаторами: ответ обязан содержать ровно поле result
	// со строковым значением.
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("ответ не является JSON: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ответ содержит лишние поля: %s", body)
	}
	if _, ok := got["result"].(string); !ok {
		t.Fatalf("поле result отсутствует или не строка: %s", body)
	}
}

func TestProcessRejectsMissingPayloadID(t *testing.T) {
	s := newTestServer(t)
	code, body := post(t, s, `{"payload":"текст"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("получен код %d вместо 400, тело %s", code, body)
	}
}

func TestProcessRejectsBrokenJSON(t *testing.T) {
	s := newTestServer(t)
	code, _ := post(t, s, `{"payload":`)
	if code != http.StatusBadRequest {
		t.Fatalf("получен код %d вместо 400", code)
	}
}

func TestProcessAcceptsUnknownFields(t *testing.T) {
	// Контракт не запрещает проверяющей системе слать дополнительные поля;
	// отвечать на них ошибкой означало бы придумать ограничение за неё.
	s := newTestServer(t)
	code, body := post(t, s, `{"payload":"текст","payload_id":"c-2","extra":42}`)
	if code != http.StatusOK {
		t.Fatalf("получен код %d, тело %s", code, body)
	}
}

func TestProcessRejectsOversizedBody(t *testing.T) {
	s := newTestServer(t)
	huge := strings.Repeat("я", 1<<20)
	code, _ := post(t, s, `{"payload":"`+huge+`","payload_id":"c-3"}`)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("получен код %d вместо 413", code)
	}
}

func TestErrorResponsesDoNotLeakPayload(t *testing.T) {
	// Тела ответов об ошибках проверяются на утечки наравне с логами.
	s := newTestServer(t)
	const secret = "Иванов Иван Иванович"
	_, body := post(t, s, `{"payload":"`+secret+`"}`) // нет payload_id
	if strings.Contains(body, "Иванов") {
		t.Fatalf("ответ об ошибке содержит исходные данные: %s", body)
	}
}

func TestHealthAndReady(t *testing.T) {
	s := newTestServer(t)
	for _, path := range []string{"/healthz", "/readyz", pathMetrics} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		switch path {
		case "/healthz":
			s.handleHealth(rec, req)
		case "/readyz":
			s.handleReady(rec, req)
		case pathMetrics:
			s.handleMetrics(rec, req)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("%s вернул код %d", path, rec.Code)
		}
	}
}

func TestOverloadReturns429WithRetryAfter(t *testing.T) {
	// Перегрузка обязана давать управляемый отказ с Retry-After: проверяющая
	// система учитывает его и не считает ответ невалидным.
	s := newTestServer(t)
	for i := 0; i < cap(s.sem); i++ {
		s.sem <- struct{}{}
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathProcess, strings.NewReader(`{"payload":"x","payload_id":"o-1"}`))
	rec := httptest.NewRecorder()
	s.wrap(http.HandlerFunc(s.handleProcess)).ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("получен код %d вместо 429", rec.Code)
	}
	if rec.Header().Get(headerRetryAfter) == "" {
		t.Error("в ответе 429 отсутствует заголовок Retry-After")
	}
}

// TestProcessNumericPayloadID — payload_id числом принимается и работает как
// ключ пары; «42» строкой и 42 числом — один идентификатор.
func TestProcessNumericPayloadID(t *testing.T) {
	s := newTestServer(t)
	code, body := post(t, s, `{"payload":"тестовая строка","payload_id":42}`)
	if code != http.StatusOK {
		t.Fatalf("числовой payload_id: код %d, тело %s", code, body)
	}
	var fwd processResponse
	if err := json.Unmarshal([]byte(body), &fwd); err != nil {
		t.Fatal(err)
	}
	code, body = post(t, s, `{"payload":`+strconv.Quote(fwd.Result)+`,"payload_id":"42"}`)
	if code != http.StatusOK || !strings.Contains(body, "тестовая строка") {
		t.Fatalf("обратный шаг по строковому «42»: код %d, тело %s", code, body)
	}
	for _, bad := range []string{`{"payload":"x","payload_id":null}`, `{"payload":"x","payload_id":{}}`, `{"payload":"x","payload_id":[1]}`} {
		if code, _ := post(t, s, bad); code != http.StatusBadRequest {
			t.Errorf("%s: код %d, ожидался 400", bad, code)
		}
	}
}
