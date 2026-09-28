package main

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleMetrics = `# HELP aigw_requests_total Число обработанных запросов
# TYPE aigw_requests_total counter
aigw_requests_total{endpoint="process",op="mask",outcome="ok"} 100
aigw_requests_total{endpoint="process",op="unmask",outcome="ok"} 90
aigw_requests_total{endpoint="process",op="mask",outcome="throttled"} 7
# TYPE aigw_request_duration_seconds histogram
aigw_request_duration_seconds_bucket{endpoint="process",op="mask",le="0.0005"} 40
aigw_request_duration_seconds_bucket{endpoint="process",op="mask",le="0.001"} 95
aigw_request_duration_seconds_bucket{endpoint="process",op="mask",le="0.005"} 100
aigw_request_duration_seconds_bucket{endpoint="process",op="mask",le="+Inf"} 100
aigw_request_duration_seconds_sum{endpoint="process",op="mask"} 0.06
aigw_request_duration_seconds_count{endpoint="process",op="mask"} 100
aigw_store_entries 4242
aigw_store_bytes 9000
`

func TestScrapeMetricsParsesExposition(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	snap, err := scrapeMetrics(context.Background(), srv.Client(), srv.URL+"/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.sum("aigw_requests_total"); got != 197 {
		t.Fatalf("сумма всех серий = %f, ожидалось 197", got)
	}
	if got := snap.sum("aigw_requests_total", `op="mask"`); got != 107 {
		t.Fatalf("сумма по маскированию = %f, ожидалось 107", got)
	}
	if got := snap.sum("aigw_store_entries"); got != 4242 {
		t.Fatalf("метрика без меток = %f, ожидалось 4242", got)
	}
	if got := snap.sum("нет_такой_метрики"); got != 0 {
		t.Fatalf("отсутствующая метрика вернула %f", got)
	}
}

func TestScrapeMetricsHandlesBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "нет", http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := scrapeMetrics(context.Background(), srv.Client(), srv.URL+"/metrics"); err == nil {
		t.Fatal("код 404 принят как успешный снимок")
	}
}

// maskLabels — метки серий операции маскирования в синтетических снимках.
const maskLabels = `endpoint="process",op="mask"`

// TestServerLatenciesUsesDelta — в цифры прогона не должен попадать трафик,
// прошедший через сервис до старта.
func TestServerLatenciesUsesDelta(t *testing.T) {
	before := &metricsSnapshot{samples: []sample{
		{name: "aigw_request_duration_seconds_count", labels: maskLabels, value: 100},
		{name: "aigw_request_duration_seconds_sum", labels: maskLabels, value: 10},
		{name: histBucketMetric, labels: `endpoint="process",op="mask",le="0.001"`, value: 50},
		{name: histBucketMetric, labels: `endpoint="process",op="mask",le="+Inf"`, value: 100},
	}}
	after := &metricsSnapshot{samples: []sample{
		{name: "aigw_request_duration_seconds_count", labels: maskLabels, value: 1100},
		{name: "aigw_request_duration_seconds_sum", labels: maskLabels, value: 11},
		{name: histBucketMetric, labels: `endpoint="process",op="mask",le="0.001"`, value: 1050},
		{name: histBucketMetric, labels: `endpoint="process",op="mask",le="+Inf"`, value: 1100},
	}}
	got := serverLatencies(before, after, []string{testOpMask, "unmask"})
	if len(got) != 1 {
		t.Fatalf("получено %d операций, ожидалась одна (по unmask дельты нет)", len(got))
	}
	if got[0].Count != 1000 {
		t.Fatalf("дельта запросов = %f, ожидалось 1000", got[0].Count)
	}
	// Дельта суммы 1 с на 1000 запросов — 1 мс в среднем.
	if math.Abs(got[0].MeanMS-1) > 1e-9 {
		t.Fatalf("среднее = %f мс, ожидалась 1 мс", got[0].MeanMS)
	}
	if got[0].P95MS != 1 {
		t.Fatalf("p95 = %f мс, ожидалась граница корзины 1 мс", got[0].P95MS)
	}
}

func TestServerLatenciesWithoutSnapshots(t *testing.T) {
	if got := serverLatencies(nil, nil, []string{testOpMask}); got != nil {
		t.Fatalf("без снимков вернулось %v", got)
	}
}

func TestBucketLE(t *testing.T) {
	cases := map[string]float64{
		`op="mask",le="0.025"`: 0.025,
		`le="+Inf"`:            1e18,
		`op="mask"`:            0,
		`le="мусор"`:           0,
	}
	for in, want := range cases {
		if got := bucketLE(in); got != want {
			t.Fatalf("bucketLE(%q) = %g, ожидалось %g", in, got, want)
		}
	}
}

const sampleGCTrace = `{"time":"2026-09-22T19:00:00Z","level":"INFO","msg":"старт"}
gc 1 @0.012s 0%: 0.015+0.35+0.003 ms clock, 0.12+0.17/0.29/0+0.029 ms cpu, 4->4->1 MB, 5 MB goal, 0 MB stacks, 0 MB globals, 10 P
gc 2 @0.520s 1%: 0.020+1.50+0.004 ms clock, 0.20+0.30/1.20/0+0.04 ms cpu, 41->43->21 MB, 43 MB goal, 0 MB stacks, 0 MB globals, 10 P
gc 3 @1.100s 2%: 0.030+2.00+0.005 ms clock, 0.30+0.40/1.90/0+0.05 ms cpu, 60->62->30 MB, 62 MB goal, 0 MB stacks, 0 MB globals, 10 P (forced)
строка без сборки мусора
`

func TestParseGCTrace(t *testing.T) {
	got := parseGCTrace(strings.NewReader(sampleGCTrace))
	if got.Cycles != 3 {
		t.Fatalf("циклов %d, ожидалось 3", got.Cycles)
	}
	wantPause := 0.368 + 1.524 + 2.035
	if math.Abs(got.PauseTotalMS-wantPause) > 1e-6 {
		t.Fatalf("суммарное время %f мс, ожидалось %f", got.PauseTotalMS, wantPause)
	}
	if math.Abs(got.PauseMaxMS-2.035) > 1e-6 {
		t.Fatalf("максимум цикла %f мс, ожидалось 2.035", got.PauseMaxMS)
	}
	if got.HeapPeakMB != 60 {
		t.Fatalf("пик кучи %d МБ, ожидалось 60", got.HeapPeakMB)
	}
	if got.HeapLiveLastMB != 30 {
		t.Fatalf("живое %d МБ, ожидалось 30", got.HeapLiveLastMB)
	}
	// Оценка выделений: (4-0) + (41-1) + (60-21) = 83 МБ.
	if got.AllocEstMB != 83 {
		t.Fatalf("оценка выделений %d МБ, ожидалось 83", got.AllocEstMB)
	}
}

func TestParseGCTraceEmpty(t *testing.T) {
	got := parseGCTrace(strings.NewReader("обычный журнал без gctrace\n"))
	if got.Cycles != 0 {
		t.Fatalf("в журнале без gctrace найдено %d циклов", got.Cycles)
	}
}

func TestIsLoopback(t *testing.T) {
	for _, h := range []string{"localhost", "127.0.0.1", "::1", ""} {
		if !isLoopback(h) {
			t.Fatalf("%q не признан локальным", h)
		}
	}
	for _, h := range []string{"example.com", "10.0.0.5"} {
		if isLoopback(h) {
			t.Fatalf("%q признан локальным", h)
		}
	}
}

func TestDetectPIDRemoteTargetIsSkipped(t *testing.T) {
	pid, note := detectPID(context.Background(), "http://gateway.example.com:8080/process")
	if pid != 0 || note == "" {
		t.Fatalf("для удалённой цели получено pid=%d note=%q", pid, note)
	}
}

func TestRSSWatcherOnSelf(t *testing.T) {
	w := newRSSWatcher(1) // launchd/init существует на обеих поддерживаемых платформах
	w.start(20 * time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	w.close()
	if w.Samples == 0 {
		t.Skip("ps недоступен в этой среде")
	}
	if w.PeakKB <= 0 {
		t.Fatalf("RSS пик = %d", w.PeakKB)
	}
}
