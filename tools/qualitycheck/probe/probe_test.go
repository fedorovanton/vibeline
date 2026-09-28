package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Синтетические значения, общие для тестов пакета.
const (
	testName         = "Петров Пётр"
	headerRetryAfter = "Retry-After"
	testPayloadID    = "id-1"
)

// fakeGateway — минимальная модель автомата сервиса: первый запрос с новым
// идентификатором маскирует, повторный с полученной маской восстанавливает.
type fakeGateway struct {
	mu    sync.Mutex
	saved map[string]string
}

func newFakeGateway() *fakeGateway { return &fakeGateway{saved: map[string]string{}} }

func (f *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req processRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if orig, ok := f.saved[req.PayloadID]; ok {
		writeResult(w, orig)
		return
	}
	f.saved[req.PayloadID] = req.Payload
	writeResult(w, strings.ReplaceAll(req.Payload, testName, "[ФИО_1]"))
}

func writeResult(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(processResponse{Result: s})
}

func TestProcessRoundTrip(t *testing.T) {
	srv := httptest.NewServer(newFakeGateway())
	defer srv.Close()

	c := New(srv.URL, 2*time.Second)
	ctx := context.Background()
	original := "Клиент Петров Пётр ждёт."

	masked, err := c.Process(ctx, testPayloadID, original)
	if err != nil {
		t.Fatalf("прямой шаг: %v", err)
	}
	if strings.Contains(masked, testName) {
		t.Fatal("значение осталось в маске")
	}
	restored, err := c.Process(ctx, testPayloadID, masked)
	if err != nil {
		t.Fatalf("обратный шаг: %v", err)
	}
	if restored != original {
		t.Fatalf("восстановление не побайтовое")
	}
}

// 429 ошибкой не считается: проверяющая система ждёт и повторяет
// (07-clarifications.md §7.2), инструмент обязан вести себя так же.
func TestProcessRetriesOnTooManyRequests(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set(headerRetryAfter, "0")
			http.Error(w, "перегрузка", http.StatusTooManyRequests)
			return
		}
		writeResult(w, "ответ")
	}))
	defer srv.Close()

	c := New(srv.URL, 2*time.Second)
	got, err := c.Process(context.Background(), testPayloadID, "текст")
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got != "ответ" || calls != 2 {
		t.Fatalf("ответ %q после %d обращений", got, calls)
	}
}

// Текст ошибки уходит в отчёт и в консоль: тела запроса в нём быть не должно.
func TestProcessErrorHasNoPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "внутренняя ошибка: Петров Пётр", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL, 2*time.Second)
	_, err := c.Process(context.Background(), testPayloadID, "Клиент Петров Пётр ждёт.")
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if strings.Contains(err.Error(), testName) {
		t.Fatalf("в тексте ошибки оказались персональные данные: %v", err)
	}
	if !strings.Contains(err.Error(), testPayloadID) {
		t.Errorf("в тексте ошибки нет идентификатора записи: %v", err)
	}
}

func TestProcessGivesUpAfterRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerRetryAfter, "0")
		http.Error(w, "перегрузка", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New(srv.URL, time.Second)
	if _, err := c.Process(context.Background(), testPayloadID, "текст"); err == nil {
		t.Fatal("бесконечный 429 должен завершаться ошибкой")
	}
}

func TestDescribeReadsServiceVersion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(healthResponse{Status: "ok", Version: "dev"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readyResponse{
			ConfigLoaded: "2026-09-22T19:12:45+03:00",
			Consumers:    []string{"benchmark:enabled"},
			Scanners:     []string{"name", "digits"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s, err := New(srv.URL, time.Second).Describe(context.Background())
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if s.Version != "dev" || len(s.Scanners) != 2 || s.ConfigLoaded == "" {
		t.Fatalf("сведения о сервисе: %+v", s)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	tests := map[string]time.Duration{
		"":      defaultRetryAfter,
		"мусор": defaultRetryAfter,
		"0":     minRetryAfter,
		"-1":    defaultRetryAfter,
		"3":     3 * time.Second,
	}
	for header, want := range tests {
		if got := retryAfter(header); got != want {
			t.Errorf("Retry-After %q дал %s, ожидалось %s", header, got, want)
		}
	}
}
