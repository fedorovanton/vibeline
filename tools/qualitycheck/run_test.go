package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"qualitycheck/corpus"
	"qualitycheck/eval"
	"qualitycheck/probe"
	"qualitycheck/report"
)

// Синтетические значения и параметры прогона, общие для тестов пакета.
const (
	testPhone    = "+7 900 000-00-00"
	testRunID    = "qc-test"
	testFullName = "Петров Пётр Петрович"
	testToponym  = "Пушкина"
	loadFailFmt  = "Load: %v"
)

// stubGateway — модель сервиса: маскирует ФИО и телефон, помнит оригинал по
// payload_id и отдаёт его на повторный запрос.
type stubGateway struct {
	mu    sync.Mutex
	saved map[string]string
	// leak — значение, которое сервис намеренно не маскирует: без пропуска
	// в прогоне нечего проверять.
	leak string
}

func (g *stubGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Payload   string `json:"payload"`
		PayloadID string `json:"payload_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.saved == nil {
		g.saved = map[string]string{}
	}
	out, ok := g.saved[req.PayloadID]
	if !ok {
		out = req.Payload
		for _, v := range []string{testFullName, testPhone, testToponym} {
			if v == g.leak {
				continue
			}
			out = strings.ReplaceAll(out, v, "[МАСКА]")
		}
		g.saved[req.PayloadID] = req.Payload
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"result": out})
}

func writeCorpus(t *testing.T, recs []corpus.Record) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corpus.jsonl")
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	for i := range recs {
		if err := enc.Encode(&recs[i]); err != nil {
			t.Fatalf("сборка корпуса: %v", err)
		}
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatalf("запись корпуса: %v", err)
	}
	return path
}

func spanOf(text, typ, value string) corpus.Span {
	at := strings.Index(text, value)
	return corpus.Span{Start: at, End: at + len(value), Type: typ, Value: value}
}

func trapOf(text, typ, reason, value string) corpus.Trap {
	at := strings.Index(text, value)
	return corpus.Trap{Start: at, End: at + len(value), Type: typ, Reason: reason, Value: value}
}

func sampleCorpus(t *testing.T) string {
	t.Helper()
	t1 := "Клиент Петров Пётр Петрович, телефон +7 900 000-00-00."
	t2 := "Ближайшее отделение — на улице Пушкина, уточни часы."
	t3 := "Как долго идёт перевод между банками?"
	return writeCorpus(t, []corpus.Record{
		{ID: "c-1", Kind: corpus.KindMulti, Text: t1, Spans: []corpus.Span{
			spanOf(t1, "full_name", testFullName),
			spanOf(t1, "phone", testPhone),
		}, Traps: []corpus.Trap{}},
		{ID: "c-2", Kind: corpus.KindTrap, Text: t2, Spans: []corpus.Span{}, Traps: []corpus.Trap{
			trapOf(t2, "full_name", "toponym", testToponym),
		}},
		{ID: "c-3", Kind: corpus.KindClean, Text: t3, Spans: []corpus.Span{}, Traps: []corpus.Trap{}},
	})
}

// Сквозной прогон: корпус → сервис → метрики → отчёт.
func TestRunnerEndToEnd(t *testing.T) {
	srv := httptest.NewServer(&stubGateway{leak: testPhone})
	defer srv.Close()

	corp, err := corpus.Load(sampleCorpus(t))
	if err != nil {
		t.Fatalf(loadFailFmt, err)
	}

	runner := &Runner{Client: probe.New(srv.URL, 2*time.Second), RunID: testRunID, Concurrency: 2}
	results := runner.Run(context.Background(), corp.Records)
	m := eval.Aggregate(results)

	if m.Totals.Errors != 0 {
		t.Fatalf("ошибок прогона %d: %+v", m.Totals.Errors, m.Errors)
	}
	// ФИО скрыто, телефон оставлен сервисом намеренно.
	if m.Totals.Hidden != 1 || m.Totals.Leaked != 1 {
		t.Fatalf("скрыто %d, утечек %d, ожидалось 1 и 1", m.Totals.Hidden, m.Totals.Leaked)
	}
	if len(m.Leaks) != 1 || m.Leaks[0].Type != "phone" {
		t.Fatalf("список утечек: %+v", m.Leaks)
	}
	// Топоним замаскирован — это ложное срабатывание.
	if m.Totals.TrapsMasked != 1 {
		t.Fatalf("сработавших ловушек %d, ожидалась 1", m.Totals.TrapsMasked)
	}
	// Обратный шаг обязан вернуть оригинал побайтово по каждой записи.
	if m.Restore.Failed != 0 {
		t.Fatalf("ошибок восстановления %d", m.Restore.Failed)
	}
	if m.Redundancy.CleanChanged != 0 {
		t.Errorf("запись без ПД изменена %d раз", m.Redundancy.CleanChanged)
	}
	// Порядок итогов повторяет порядок корпуса: отчёты разных прогонов
	// должны сравниваться диффом.
	for i := range results {
		if results[i].ID != corp.Records[i].ID {
			t.Fatalf("итог %d относится к записи %s, ожидалась %s", i, results[i].ID, corp.Records[i].ID)
		}
	}
}

// Недоступный сервис не должен выглядеть как чистый прогон: записи попадают в
// ошибки, а не в успешно скрытые значения.
func TestRunnerRecordsFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "сломано", http.StatusInternalServerError)
	}))
	defer srv.Close()

	corp, err := corpus.Load(sampleCorpus(t))
	if err != nil {
		t.Fatalf(loadFailFmt, err)
	}
	runner := &Runner{Client: probe.New(srv.URL, time.Second), RunID: testRunID, Concurrency: 2}
	m := eval.Aggregate(runner.Run(context.Background(), corp.Records))

	if m.Totals.Errors != 3 || m.Totals.Evaluated != 0 {
		t.Fatalf("итоги: %+v", m.Totals)
	}
	if m.Totals.Hidden != 0 {
		t.Fatal("при недоступном сервисе засчитаны скрытые значения")
	}
}

// Отмена прогона не должна оставлять записи без отметки: пустой итог выглядел
// бы как запись без персональных данных и завысил бы метрики.
func TestRunnerMarksCancelledRecords(t *testing.T) {
	srv := httptest.NewServer(&stubGateway{})
	defer srv.Close()

	corp, err := corpus.Load(sampleCorpus(t))
	if err != nil {
		t.Fatalf(loadFailFmt, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	runner := &Runner{Client: probe.New(srv.URL, time.Second), RunID: testRunID, Concurrency: 1}
	for _, r := range runner.Run(ctx, corp.Records) {
		if r.ID == "" {
			t.Fatal("итог записи остался пустым после отмены")
		}
	}
}

// Отчёт целиком, как его печатает команда: значений персональных данных в нём
// нет, а происхождение корпуса и методика есть.
func TestReportFromRunHasNoValues(t *testing.T) {
	srv := httptest.NewServer(&stubGateway{leak: testPhone})
	defer srv.Close()

	corp, err := corpus.Load(sampleCorpus(t))
	if err != nil {
		t.Fatalf(loadFailFmt, err)
	}
	runner := &Runner{Client: probe.New(srv.URL, 2*time.Second), RunID: testRunID, Concurrency: 2}
	m := eval.Aggregate(runner.Run(context.Background(), corp.Records))
	m.Redact()

	rep := &report.Report{
		Tool: "qualitycheck", Version: report.Version,
		Corpus:  report.Corpus{Path: corp.Path, SHA256: corp.SHA256, Bytes: corp.Bytes, Seed: 20260922, Count: 3, Summary: corp.Summarize()},
		Method:  report.Method(),
		Metrics: m,
	}

	var table, machine bytes.Buffer
	if err := rep.Render(&table, false); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := rep.WriteJSON(&machine); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	for _, secret := range []string{testFullName, testPhone, testToponym} {
		if strings.Contains(table.String(), secret) {
			t.Errorf("значение оказалось в таблице отчёта")
		}
		if strings.Contains(machine.String(), secret) {
			t.Errorf("значение оказалось в JSON-отчёте")
		}
	}
	if !strings.Contains(table.String(), corp.SHA256) {
		t.Error("в отчёте нет отпечатка корпуса")
	}
}
