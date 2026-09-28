package main

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

// Префикс маски фальшивого шлюза и путь контракта в тестах прогона.
const (
	fakeMaskPrefix = "МАСКА:"
	processPath    = "/process"
)

// fakeGateway воспроизводит автомат /process: первый запрос с данным
// payload_id маскируется, повторный запрос с полученной маской восстанавливает
// исходный текст.
type fakeGateway struct {
	mu    sync.Mutex
	store map[string]string // payload_id -> оригинал

	inflight    int
	maxInflight int
	// perConn фиксирует, что у одного соединения не бывает двух запросов
	// одновременно — это и есть закрытый контур.
	perConn      map[string]bool
	overlap      int
	masks        int
	unmasks      int
	throttleFor  int // сколько первых запросов отвечать 429
	retryAfter   string
	corruptAfter int // с какого запроса возвращать неверное восстановление
	total        int
}

func newFakeGateway() *fakeGateway {
	return &fakeGateway{store: map[string]string{}, perConn: map[string]bool{}}
}

func connKey(payloadID string) string {
	// payload_id имеет вид lt-<метка прогона>-<воркер>-<номер>.
	parts := strings.Split(payloadID, "-")
	if len(parts) < 4 {
		return payloadID
	}
	return parts[len(parts)-2]
}

func (f *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req processRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	key := connKey(req.PayloadID)

	f.mu.Lock()
	f.total++
	n := f.total
	f.inflight++
	if f.inflight > f.maxInflight {
		f.maxInflight = f.inflight
	}
	if f.perConn[key] {
		f.overlap++
	}
	f.perConn[key] = true
	throttle := n <= f.throttleFor
	corrupt := f.corruptAfter > 0 && n >= f.corruptAfter
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		f.inflight--
		f.perConn[key] = false
		f.mu.Unlock()
	}()

	if throttle {
		if f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	f.mu.Lock()
	orig, seen := f.store[req.PayloadID]
	var result string
	switch {
	case seen && req.Payload == fakeMaskPrefix+orig:
		result = orig
		if corrupt {
			result = orig + "испорчено"
		}
		f.unmasks++
	case seen && req.Payload == orig:
		result = fakeMaskPrefix + orig
	default:
		f.store[req.PayloadID] = req.Payload
		result = fakeMaskPrefix + req.Payload
		f.masks++
	}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	// Отказ записи ответа клиент прогона увидит сам как транспортную ошибку.
	_ = json.NewEncoder(w).Encode(processResponse{Result: result})
}

func testCorpus() *corpus {
	c := &corpus{source: "тестовый"}
	c.add(item{id: "t1", text: "Клиент Волошин Пётр, паспорт 4509 123456"})
	c.add(item{id: "t2", text: "Телефон +7 916 000-11-22, почта user@example.org"})
	c.setWeights([classCount]float64{1, 0, 0, 0})
	return c
}

func runAgainst(t *testing.T, f *fakeGateway, cfg runConfig) *runResult {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	cfg.URL = srv.URL + processPath
	return runClosedLoop(context.Background(), cfg, testCorpus(), nil)
}

// TestClosedLoopNeverOverlapsOnAConnection — AC-2. Прямое доказательство
// закрытого контура: ни одно соединение не держит два запроса одновременно,
// а всего в обработке не больше заданного числа соединений.
func TestClosedLoopNeverOverlapsOnAConnection(t *testing.T) {
	f := newFakeGateway()
	res := runAgainst(t, f, runConfig{Conns: 8, Duration: 700 * time.Millisecond, Ramp: 0, Timeout: 5 * time.Second, Seed: 1})

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overlap != 0 {
		t.Fatalf("на соединении оказалось два одновременных запроса %d раз — это открытый контур", f.overlap)
	}
	if f.maxInflight > 8 {
		t.Fatalf("одновременно в обработке %d запросов при 8 соединениях", f.maxInflight)
	}
	if res.Steady.pairs == 0 {
		t.Fatal("не завершено ни одной пары")
	}
}

// TestPairPerItem — по каждому элементу ровно два запроса: маскирование и
// демаскирование тем же payload_id.
func TestPairPerItem(t *testing.T) {
	f := newFakeGateway()
	res := runAgainst(t, f, runConfig{Conns: 4, Duration: 500 * time.Millisecond, Timeout: 5 * time.Second, Seed: 2})

	steady := res.Steady
	mask := steady.ops[opMask].lat.count
	unmask := steady.ops[opUnmask].lat.count
	if mask == 0 || unmask == 0 {
		t.Fatalf("маскирований %d, демаскирований %d", mask, unmask)
	}
	// Прогон обрывается по времени, поэтому допускается один незавершённый
	// шаг на соединение.
	if mask < unmask || mask-unmask > 4 {
		t.Fatalf("маскирований %d, демаскирований %d — пары не сходятся", mask, unmask)
	}
	if steady.mismatch != 0 {
		t.Fatalf("расхождений восстановления %d при исправном сервере", steady.mismatch)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unmasks == 0 {
		t.Fatal("сервер не увидел ни одного обратного шага")
	}
}

// TestPayloadIDsAreUnique — повтор payload_id переключил бы сервис на обратный
// шаг и измерял бы не ту работу.
func TestPayloadIDsAreUnique(t *testing.T) {
	f := newFakeGateway()
	runAgainst(t, f, runConfig{Conns: 6, Duration: 500 * time.Millisecond, Timeout: 5 * time.Second, Seed: 3})
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.store) != f.masks {
		t.Fatalf("уникальных payload_id %d при %d маскированиях — идентификаторы повторяются", len(f.store), f.masks)
	}
}

// TestThrottledIsNotAnError — AC-5. 429 учитывается отдельно, ошибкой не
// считается, запрос повторяется.
func TestThrottledIsNotAnError(t *testing.T) {
	f := newFakeGateway()
	// Первые запросы всех соединений получают 429; после паузы Retry-After
	// прогон обязан продолжиться.
	f.throttleFor = 4
	f.retryAfter = "1"
	res := runAgainst(t, f, runConfig{Conns: 4, Duration: 3 * time.Second, Timeout: 5 * time.Second, Seed: 4})

	total := res.Steady.total()
	warm := res.Warmup.total()
	throttled := total.throttled + warm.throttled
	if throttled == 0 {
		t.Fatal("429 не учтены")
	}
	if total.errors+warm.errors != 0 {
		t.Fatalf("429 попали в ошибки: %d", total.errors+warm.errors)
	}
	if total.failed+warm.failed != 0 {
		t.Fatalf("429 попали в неуспешные ответы: %d", total.failed+warm.failed)
	}
	if got := total.codes[429] + warm.codes[429]; got != throttled {
		t.Fatalf("в разбивке кодов 429 встретился %d раз, в счётчике %d", got, throttled)
	}
	if total.ok == 0 {
		t.Fatal("после 429 прогон не восстановился")
	}
	// Латентность 429 в перцентили успешных ответов не попадает.
	if total.lat.count != total.ok {
		t.Fatalf("в гистограмму попало %d значений при %d успешных ответах", total.lat.count, total.ok)
	}
}

// TestRestoreMismatchIsCounted — неверное восстановление не должно раствориться
// в цифрах латентности.
func TestRestoreMismatchIsCounted(t *testing.T) {
	f := newFakeGateway()
	f.corruptAfter = 1
	res := runAgainst(t, f, runConfig{Conns: 2, Duration: 400 * time.Millisecond, Timeout: 5 * time.Second, Seed: 5})
	if res.Steady.mismatch == 0 {
		t.Fatal("испорченное восстановление не замечено")
	}
}

// TestServerErrorsCountedAsFailed — 5xx не 429 и не транспортный отказ.
func TestServerErrorsCountedAsFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	res := runClosedLoop(context.Background(), runConfig{
		URL: srv.URL + processPath, Conns: 2, Duration: 300 * time.Millisecond,
		Timeout: 2 * time.Second, Seed: 6,
	}, testCorpus(), nil)

	total := res.Steady.total()
	if total.failed == 0 {
		t.Fatal("ответы 500 не учтены")
	}
	if total.throttled != 0 {
		t.Fatalf("ответы 500 попали в 429: %d", total.throttled)
	}
	if total.codes[500] == 0 {
		t.Fatal("код 500 не попал в разбивку")
	}
}

// TestRampSplitsPhases — замеры разгона не смешиваются с окном удержания.
func TestRampSplitsPhases(t *testing.T) {
	f := newFakeGateway()
	res := runAgainst(t, f, runConfig{Conns: 4, Duration: 900 * time.Millisecond, Ramp: 400 * time.Millisecond, Timeout: 5 * time.Second, Seed: 7})
	if res.Warmup.total().lat.count == 0 {
		t.Fatal("на разгоне не собрано ни одного замера")
	}
	if res.Steady.total().lat.count == 0 {
		t.Fatal("на удержании не собрано ни одного замера")
	}
	if res.SteadyWall <= 0 {
		t.Fatalf("окно удержания %s", res.SteadyWall)
	}
}

// TestRunStopsOnContextCancel — у каждой горутины есть условие выхода.
func TestRunStopsOnContextCancel(t *testing.T) {
	f := newFakeGateway()
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runClosedLoop(ctx, runConfig{URL: srv.URL + processPath, Conns: 4, Duration: time.Hour, Timeout: time.Second, Seed: 8}, testCorpus(), nil)
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("прогон не остановился по отмене контекста")
	}
}

func TestGoodputUsesSteadyWindow(t *testing.T) {
	r := &runResult{SteadyWall: 2 * time.Second, Steady: newPhaseStats()}
	r.Steady.ops[opMask].ok = 100
	r.Steady.ops[opUnmask].ok = 100
	if got := r.goodput(); got != 100 {
		t.Fatalf("goodput = %f, ожидалось 100", got)
	}
	empty := &runResult{Steady: newPhaseStats()}
	if got := empty.goodput(); got != 0 {
		t.Fatalf("goodput при нулевом окне = %f", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", defaultRetryAfter},
		{"2", 2 * time.Second},
		{"0", defaultRetryAfter},
		{"-5", defaultRetryAfter},
		{"99999", maxRetryAfter},
		{"мусор", defaultRetryAfter},
		{now.Add(3 * time.Second).Format(http.TimeFormat), 3 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), defaultRetryAfter},
	}
	for _, c := range cases {
		got := parseRetryAfter(c.in, now)
		if got != c.want {
			t.Fatalf("parseRetryAfter(%q) = %s, ожидалось %s", c.in, got, c.want)
		}
	}
}
