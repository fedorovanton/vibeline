package httpapi

import (
	"encoding/json"
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
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/store"
)

// middlewareConfig отличается от общей тестовой конфигурации пределом
// одновременной обработки: он задаётся каждым тестом отдельно, потому что
// именно он и проверяется.
const middlewareConfig = `
server:
  addr: ":0"
  max_body_bytes: 1MiB
  max_concurrent: %d
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

// newMiddlewareServer собирает сервер с заданным пределом одновременной
// обработки и журналом в подставленный приёмник.
func newMiddlewareServer(t *testing.T, maxConcurrent int, log io.Writer) *Server {
	t.Helper()

	body := strings.Replace(middlewareConfig, "%d", strconv.Itoa(maxConcurrent), 1)
	holder := newTestHolder(t, body)

	st := store.NewMemory(holder.Current().Store)
	t.Cleanup(func() { _ = st.Close() })

	return NewServer(Deps{
		Config:    holder,
		Gateway:   gateway.New(detect.New(nil), st),
		Metrics:   obs.NewMetrics(),
		Logger:    slog.New(slog.NewTextHandler(log, nil)),
		Version:   "test",
		StartedAt: time.Now(),
	})
}

// call прогоняет запрос через middleware и возвращает записанный ответ.
func call(s *Server, next http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.wrap(next).ServeHTTP(rec, req)
	return rec
}

func processReq(t *testing.T, id string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathProcess,
		strings.NewReader(`{"payload":"текст","payload_id":"`+id+`"}`))
	req.Header.Set(headerContentType, jsonContentType)
	return req
}

// okHandler — обработчик, не делающий ничего сверх ответа 200.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestMiddlewareReturnsRequestID(t *testing.T) {
	// AC-8: идентификатор запроса возвращается всегда — он связывает ответ
	// с записью журнала, без него разбор инцидента невозможен.
	s := newMiddlewareServer(t, 8, io.Discard)

	t.Run("свой идентификатор клиента", func(t *testing.T) {
		req := processReq(t, "rid-1")
		req.Header.Set(headerRequestID, "client-supplied-42")
		rec := call(s, http.HandlerFunc(s.handleProcess), req)
		if got := rec.Header().Get(headerRequestID); got != "client-supplied-42" {
			t.Errorf("идентификатор клиента не возвращён: %q", got)
		}
	})

	t.Run("сгенерированный идентификатор", func(t *testing.T) {
		rec := call(s, http.HandlerFunc(s.handleProcess), processReq(t, "rid-2"))
		if got := rec.Header().Get(headerRequestID); got == "" {
			t.Error("идентификатор не сгенерирован")
		}
	})

	t.Run("идентификатор в теле ошибки", func(t *testing.T) {
		// Тело ошибки повторяет идентификатор: клиент сообщает его в
		// обращении, и запись журнала находится по нему же.
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, pathProcess, strings.NewReader(`{"payload":`))
		rec := call(s, http.HandlerFunc(s.handleProcess), req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("получен код %d вместо 400", rec.Code)
		}
		var body errorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("тело ошибки не является JSON: %v", err)
		}
		if body.RequestID == "" || body.RequestID != rec.Header().Get(headerRequestID) {
			t.Errorf("идентификатор в теле %q не совпадает с заголовком %q",
				body.RequestID, rec.Header().Get(headerRequestID))
		}
	})
}

func TestMiddlewareRequestIDsAreUnique(t *testing.T) {
	// Совпадение идентификаторов склеило бы записи разных запросов. Предел
	// одновременной обработки поднят: проверяется генератор, а не отказ.
	const workers = 64

	s := newMiddlewareServer(t, workers, io.Discard)

	var mu sync.Mutex
	seen := make(map[string]bool, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			rec := call(s, okHandler, processReq(t, "uniq-"+strconv.Itoa(i)))
			rid := rec.Header().Get(headerRequestID)

			mu.Lock()
			defer mu.Unlock()
			if rid == "" {
				t.Errorf("пустой идентификатор при конкурентной подаче")
				return
			}
			if seen[rid] {
				t.Errorf("идентификатор %q выдан повторно", rid)
			}
			seen[rid] = true
		}(i)
	}
	wg.Wait()

	if len(seen) != workers {
		t.Errorf("получено %d различных идентификаторов из %d", len(seen), workers)
	}
}

func TestMiddlewarePanicBecomes500WithoutDetails(t *testing.T) {
	// AC-7: паника не роняет процесс и не выносит наружу ни текста паники,
	// ни стека. Текст паники намеренно похож на утёкшие данные.
	const panicText = "Кузнецова Анфиса Валерьевна, карта 5211 6702 4488 1093"

	var log strings.Builder
	s := newMiddlewareServer(t, 8, &log)
	boom := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(panicText) })

	rec := call(s, boom, processReq(t, "panic-1"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("получен код %d вместо 500", rec.Code)
	}

	body := rec.Body.String()
	for _, fragment := range []string{panicText, "Кузнецова", "5211", "goroutine", "runtime.", ".go:"} {
		if strings.Contains(body, fragment) {
			t.Errorf("тело ответа содержит %q: %s", fragment, body)
		}
	}
	var parsed errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("тело ответа на панику не является JSON: %v (%s)", err, body)
	}
	if parsed.Error == "" {
		t.Error("тело ответа на панику не описывает класс ошибки")
	}

	// Сервер продолжает работать: следующий запрос обслуживается штатно.
	next := call(s, http.HandlerFunc(s.handleProcess), processReq(t, "panic-2"))
	if next.Code != http.StatusOK {
		t.Errorf("после паники запрос получил код %d: %s", next.Code, next.Body.String())
	}
}

func TestMiddlewareReleasesSlotAfterPanic(t *testing.T) {
	// Если бы место в пределе одновременной обработки не освобождалось,
	// каждая паника сокращала бы пропускную способность, и сервис
	// выродился бы в постоянные 429 без единого сообщения об этом.
	const limit = 4

	s := newMiddlewareServer(t, limit, io.Discard)
	boom := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("сбой") })

	for i := 0; i < limit*2; i++ {
		if rec := call(s, boom, processReq(t, "slot-"+strconv.Itoa(i))); rec.Code != http.StatusInternalServerError {
			t.Fatalf("паника %d дала код %d вместо 500", i, rec.Code)
		}
	}
	if len(s.sem) != 0 {
		t.Errorf("после паник занято %d мест из %d", len(s.sem), cap(s.sem))
	}
	if rec := call(s, http.HandlerFunc(s.handleProcess), processReq(t, "slot-ok")); rec.Code != http.StatusOK {
		t.Errorf("после паник запрос получил код %d вместо 200", rec.Code)
	}
}

func TestMiddlewareOverloadIsPredictable(t *testing.T) {
	// REQ-602 и AC-6: при исчерпании предела ответ немедленный и
	// управляемый — 429 с Retry-After. Ни таймаут, ни 5XX здесь
	// недопустимы: устойчивые 5XX останавливают нагрузочный прогон.
	const limit = 2

	s := newMiddlewareServer(t, limit, io.Discard)
	for i := 0; i < limit; i++ {
		s.sem <- struct{}{}
	}

	started := time.Now()
	rec := call(s, http.HandlerFunc(s.handleProcess), processReq(t, "over-1"))
	elapsed := time.Since(started)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("получен код %d вместо 429: %s", rec.Code, rec.Body.String())
	}
	if elapsed > time.Second {
		t.Errorf("отказ занял %s: очередь копится вместо немедленного ответа", elapsed)
	}
	retry := rec.Header().Get(headerRetryAfter)
	if retry == "" {
		t.Fatal("в ответе 429 нет заголовка Retry-After")
	}
	// Проверяющая система читает Retry-After как число секунд.
	if v, err := strconv.Atoi(retry); err != nil || v <= 0 {
		t.Errorf("Retry-After = %q: ожидалось положительное число секунд", retry)
	}

	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("тело ответа 429 не является JSON: %v (%s)", err, rec.Body.String())
	}
	if body.Error == "" {
		t.Error("тело ответа 429 не описывает причину")
	}

	// После освобождения места обслуживание возобновляется без перезапуска.
	<-s.sem
	resumed := call(s, http.HandlerFunc(s.handleProcess), processReq(t, "over-2"))
	if resumed.Code != http.StatusOK {
		t.Errorf("после освобождения места получен код %d: %s", resumed.Code, resumed.Body.String())
	}
}

func TestMiddlewareLimitsConcurrency(t *testing.T) {
	// Предел обязан действительно ограничивать число одновременно
	// обрабатываемых запросов, а не только считаться: иначе backpressure
	// декларативный, и под нагрузкой растёт латентность.
	const limit, workers = 3, 32

	s := newMiddlewareServer(t, limit, io.Discard)
	p := &concurrencyProbe{release: make(chan struct{})}

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			p.count(t, call(s, p, processReq(t, "conc-"+strconv.Itoa(i))))
		}(i)
	}

	// Отказы приходят сразу; успешные ответы ждут освобождения.
	p.waitSaturated(limit, 5*time.Second)
	close(p.release)
	wg.Wait()

	if p.peak > limit {
		t.Errorf("одновременно обрабатывалось %d запросов при пределе %d", p.peak, limit)
	}
	if p.served+p.rejected != workers {
		t.Errorf("учтено %d ответов из %d", p.served+p.rejected, workers)
	}
	if p.rejected == 0 {
		t.Error("ни один запрос не получил отказа: предел не сработал")
	}
}

// concurrencyProbe — обработчик, который держит запрос до закрытия release и
// считает одновременно обрабатываемые запросы и исходы.
type concurrencyProbe struct {
	release chan struct{}

	mu                               sync.Mutex
	inFlight, peak, served, rejected int
}

func (p *concurrencyProbe) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	p.inFlight++
	if p.inFlight > p.peak {
		p.peak = p.inFlight
	}
	p.mu.Unlock()

	<-p.release

	p.mu.Lock()
	p.inFlight--
	p.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// count учитывает исход одного запроса: 200 — обслужен, 429 — отказ, который
// обязан нести Retry-After; любой другой код — ошибка теста.
func (p *concurrencyProbe) count(t *testing.T, rec *httptest.ResponseRecorder) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch rec.Code {
	case http.StatusOK:
		p.served++
	case http.StatusTooManyRequests:
		p.rejected++
		if rec.Header().Get(headerRetryAfter) == "" {
			t.Errorf("отказ без Retry-After")
		}
	default:
		t.Errorf("неожиданный код %d: %s", rec.Code, rec.Body.String())
	}
}

// waitSaturated ждёт, пока отказы и запросы в обработке вместе не достигнут
// предела limit, но не дольше timeout.
func (p *concurrencyProbe) waitSaturated(limit int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		enough := p.rejected+p.inFlight >= limit
		p.mu.Unlock()
		if enough || time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// overloadRID — идентификатор запроса, присланный клиентом в сценарии перегрузки.
const overloadRID = "client-supplied-overload"

func TestMiddlewareOverloadIsObservable(t *testing.T) {
	// Отказ по пределу одновременной обработки обязан быть наблюдаемым наравне
	// с успехом: заголовок X-Request-Id (AC-8), запись в журнале (REQ-700)
	// и счётчик с outcome="overloaded" (REQ-702). Иначе backpressure не виден
	// ни оператору, ни в отчёте по нагрузочному прогону.

	var log strings.Builder
	s := newMiddlewareServer(t, 1, &log)
	s.sem <- struct{}{}

	req := processReq(t, "observable-1")
	req.Header.Set(headerRequestID, overloadRID)
	rec := call(s, http.HandlerFunc(s.handleProcess), req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("получен код %d вместо 429", rec.Code)
	}

	// Идентификатор возвращается всегда: без него клиент не может сослаться
	// на отказ, а отказ приходит именно тогда, когда разбор нужнее всего.
	if got := rec.Header().Get(headerRequestID); got != overloadRID {
		t.Errorf("на пути отказа идентификатор запроса потерян: %q", got)
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("тело ответа 429 не является JSON: %v", err)
	}
	if body.RequestID == "" {
		t.Error("в теле ответа 429 нет идентификатора запроса")
	}

	// Отказ обязан попадать в журнал и в метрики: иначе backpressure не
	// виден ни оператору, ни в отчёте по нагрузочному прогону.
	if !strings.Contains(log.String(), overloadRID) {
		t.Errorf("отказ не записан в журнал: %q", log.String())
	}
	mrec := httptest.NewRecorder()
	s.handleMetrics(mrec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, pathMetrics, nil))
	if !strings.Contains(mrec.Body.String(), `outcome="overloaded"`) {
		t.Error("отказ по перегрузке не учтён счётчиком запросов по исходам")
	}
}
