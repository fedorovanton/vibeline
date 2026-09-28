package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Режимы прогона.
const (
	modeMixed = "mixed" // короткие и длинные тексты
	modeLong  = "long"  // только тексты на 100 000 токенов
	modeLimit = "limit" // поиск предела по числу соединений
)

// Операции пары. По каждому элементу уходит ровно два запроса с одним
// payload_id: маскирование, затем демаскирование полученной маски.
const (
	opMask = iota
	opUnmask
	opCount
)

var opName = [opCount]string{"mask", "unmask"}

// maxThrottleRetries ограничивает число повторов на один шаг при 429.
// Без предела воркер мог бы застрять на перегруженном сервисе до конца прогона
// и исказить состав нагрузки.
const maxThrottleRetries = 8

// defaultRetryAfter применяется, когда сервис вернул 429 без заголовка.
const defaultRetryAfter = 200 * time.Millisecond

// maxRetryAfter ограничивает паузу: проверяющая система ждёт, но прогон
// конечен, и час ожидания в нём смысла не имеет.
const maxRetryAfter = 10 * time.Second

type opStats struct {
	lat       histogram
	ok        uint64
	throttled uint64         // 429 — отдельная категория, не ошибка
	failed    uint64         // ответы 4xx/5xx, кроме 429
	errors    uint64         // транспортные отказы и таймауты
	codes     map[int]uint64 // все полученные коды ответа
	bytesOut  uint64
	bytesIn   uint64
}

func newOpStats() opStats { return opStats{codes: map[int]uint64{}} }

func (s *opStats) merge(o *opStats) {
	s.lat.merge(&o.lat)
	s.ok += o.ok
	s.throttled += o.throttled
	s.failed += o.failed
	s.errors += o.errors
	s.bytesOut += o.bytesOut
	s.bytesIn += o.bytesIn
	for c, n := range o.codes {
		s.codes[c] += n
	}
}

// phaseStats — счётчики одной фазы прогона (разгон или удержание).
type phaseStats struct {
	ops      [opCount]opStats
	pairs    uint64 // завершённые пары «маска + демаска»
	mismatch uint64 // демаскирование вернуло не исходный текст
}

func newPhaseStats() phaseStats {
	var p phaseStats
	for i := range p.ops {
		p.ops[i] = newOpStats()
	}
	return p
}

func (p *phaseStats) merge(o *phaseStats) {
	for i := range p.ops {
		p.ops[i].merge(&o.ops[i])
	}
	p.pairs += o.pairs
	p.mismatch += o.mismatch
}

// total сводит маскирование и демаскирование в одну статистику.
func (p *phaseStats) total() opStats {
	t := newOpStats()
	for i := range p.ops {
		t.merge(&p.ops[i])
	}
	return t
}

type runConfig struct {
	URL      string
	Conns    int
	Duration time.Duration
	Ramp     time.Duration
	Timeout  time.Duration
	Mode     string
	Seed     int64
}

type runResult struct {
	Conns      int
	Requested  time.Duration
	Ramp       time.Duration
	Warmup     phaseStats
	Steady     phaseStats
	SteadyWall time.Duration
	TotalWall  time.Duration
}

// goodput — успешные ответы в секунду на фазе удержания.
func (r *runResult) goodput() float64 {
	if r.SteadyWall <= 0 {
		return 0
	}
	t := r.Steady.total()
	return float64(t.ok) / r.SteadyWall.Seconds()
}

// newClient создаёт клиента ровно с одним соединением к цели.
//
// Ограничение MaxConnsPerHost=1 — это и есть закрытый контур на уровне
// транспорта: воркер физически не может открыть второе соединение и отправить
// следующий запрос, не дождавшись ответа на предыдущий. Открытый контур с
// заданным RPS воспроизводить нельзя — проверяющая система работает иначе.
func newClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		MaxIdleConns:        1,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// runTag — метка прогона в payload_id: момент запуска в base36.
var runTag = strconv.FormatInt(time.Now().UnixNano(), 36)

type worker struct {
	id     int
	client *http.Client
	rnd    *rand.Rand
	req    bytes.Buffer
	resp   bytes.Buffer
	warm   phaseStats
	steady phaseStats
	seq    uint64
	// lastRetryAfter — пауза из последнего 429; хранится в воркере, потому что
	// ожидание применяется уже после закрытия тела ответа.
	lastRetryAfter time.Duration
}

type processRequest struct {
	Payload   string `json:"payload"`
	PayloadID string `json:"payload_id"`
}

type processResponse struct {
	Result string `json:"result"`
}

// runClosedLoop выполняет один прогон и возвращает собранную статистику.
func runClosedLoop(ctx context.Context, cfg runConfig, c *corpus, progress func(string)) *runResult {
	ramp := cfg.Ramp
	if ramp >= cfg.Duration {
		ramp = cfg.Duration / 10
	}
	if ramp < 0 {
		ramp = 0
	}

	start := time.Now()
	steadyAt := start.Add(ramp)
	deadline := start.Add(cfg.Duration)

	runCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	workers := make([]*worker, cfg.Conns)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Conns; i++ {
		w := &worker{
			id:     i,
			client: newClient(cfg.Timeout),
			rnd:    rand.New(rand.NewPCG(uint64(cfg.Seed), uint64(i)+1)),
			warm:   newPhaseStats(),
			steady: newPhaseStats(),
		}
		workers[i] = w
		wg.Add(1)
		go func(w *worker, idx int) {
			defer wg.Done()
			defer w.client.CloseIdleConnections()
			// Разгон: соединения включаются равномерно, а не все разом.
			// Одномоментный старт 200 соединений измерял бы холодный старт.
			if ramp > 0 && cfg.Conns > 1 {
				delay := time.Duration(int64(ramp) * int64(idx) / int64(cfg.Conns))
				t := time.NewTimer(delay)
				defer t.Stop()
				select {
				case <-t.C:
				case <-runCtx.Done():
					return
				}
			}
			w.loop(runCtx, cfg, c, steadyAt)
		}(w, i)
	}

	if progress != nil {
		go reportProgress(runCtx, start, deadline, progress)
	}

	wg.Wait()
	totalWall := time.Since(start)

	res := &runResult{
		Conns:     cfg.Conns,
		Requested: cfg.Duration,
		Ramp:      ramp,
		Warmup:    newPhaseStats(),
		Steady:    newPhaseStats(),
		TotalWall: totalWall,
	}
	res.SteadyWall = totalWall - ramp
	if res.SteadyWall < 0 {
		res.SteadyWall = 0
	}
	for _, w := range workers {
		res.Warmup.merge(&w.warm)
		res.Steady.merge(&w.steady)
	}
	return res
}

func reportProgress(ctx context.Context, start, deadline time.Time, progress func(string)) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			progress(fmt.Sprintf("прогон: %s из %s",
				now.Sub(start).Truncate(time.Second),
				deadline.Sub(start).Truncate(time.Second)))
		}
	}
}

// loop — тело воркера: пара запросов на элемент, следующий запрос только
// после ответа на предыдущий.
func (w *worker) loop(ctx context.Context, cfg runConfig, c *corpus, steadyAt time.Time) {
	for ctx.Err() == nil {
		it := c.pick(w.rnd)
		w.seq++
		// Идентификатор уникален по всему прогону и между прогонами: метка
		// прогона, номер воркера и собственный счётчик. Без метки второй
		// прогон подряд на том же сервисе повторял идентификаторы первого в
		// пределах TTL хранилища (техническое жюри 23.09, раунд 2).
		payloadID := "lt-" + runTag + "-" + strconv.Itoa(w.id) + "-" + strconv.FormatUint(w.seq, 10)

		mask, ok := w.step(ctx, cfg, opMask, payloadID, it.text, steadyAt)
		if !ok {
			continue
		}
		restored, ok := w.step(ctx, cfg, opUnmask, payloadID, mask, steadyAt)
		if !ok {
			continue
		}

		ph := w.phase(time.Now(), steadyAt)
		ph.pairs++
		if restored != it.text {
			// Не ошибка транспорта, а расхождение восстановления: считается
			// отдельно, иначе дефект корректности спрячется в цифрах латентности.
			ph.mismatch++
		}
	}
}

func (w *worker) phase(at, steadyAt time.Time) *phaseStats {
	if at.Before(steadyAt) {
		return &w.warm
	}
	return &w.steady
}

// step выполняет один запрос и возвращает поле result.
// Второе значение — можно ли продолжать пару.
func (w *worker) step(ctx context.Context, cfg runConfig, op int, payloadID, payload string, steadyAt time.Time) (string, bool) {
	for attempt := 0; attempt <= maxThrottleRetries; attempt++ {
		if ctx.Err() != nil {
			return "", false
		}
		body, code, lat, err := w.do(ctx, cfg, payloadID, payload)

		started := time.Now().Add(-lat)
		st := &w.phase(started, steadyAt).ops[op]

		if err != nil {
			// Отказ из-за конца прогона транспортной ошибкой не считается.
			if ctx.Err() == nil {
				st.errors++
			}
			return "", false
		}
		st.codes[code]++
		st.bytesOut += uint64(len(payload))
		st.bytesIn += uint64(len(body))

		if code != http.StatusTooManyRequests {
			return st.finish(code, body, lat)
		}
		// 429 — штатный ответ на перегрузку, а не ошибка: организаторы
		// учитывают его отдельно и повторяют запрос с учётом Retry-After.
		st.throttled++
		if !sleepCtx(ctx, w.lastRetryAfter) {
			return "", false
		}
	}
	return "", false
}

// finish учитывает окончательный ответ шага: успех — только код 200 с
// разобранным телом, остальное — отказ 4xx/5xx.
func (s *opStats) finish(code int, body []byte, lat time.Duration) (string, bool) {
	if code != http.StatusOK {
		s.failed++
		return "", false
	}
	var pr processResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		s.failed++
		return "", false
	}
	s.ok++
	s.lat.record(uint64(lat.Microseconds()))
	return pr.Result, true
}

// do выполняет HTTP-запрос и возвращает тело, код и наблюдаемую клиентом
// латентность — от отправки до полного чтения тела ответа.
func (w *worker) do(ctx context.Context, cfg runConfig, payloadID, payload string) ([]byte, int, time.Duration, error) {
	w.req.Reset()
	if err := json.NewEncoder(&w.req).Encode(processRequest{Payload: payload, PayloadID: payloadID}); err != nil {
		return nil, 0, 0, err
	}
	raw := w.req.Bytes()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(raw))

	started := time.Now()
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, 0, time.Since(started), err
	}
	w.resp.Reset()
	_, copyErr := w.resp.ReadFrom(resp.Body)
	closeErr := resp.Body.Close()
	lat := time.Since(started)
	if copyErr != nil {
		return nil, resp.StatusCode, lat, copyErr
	}
	if closeErr != nil {
		return nil, resp.StatusCode, lat, closeErr
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		w.lastRetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	return w.resp.Bytes(), resp.StatusCode, lat, nil
}

// parseRetryAfter разбирает заголовок Retry-After: целые секунды или HTTP-дату.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return defaultRetryAfter
	}
	if secs, err := strconv.Atoi(v); err == nil {
		d := time.Duration(secs) * time.Second
		if d <= 0 {
			return defaultRetryAfter
		}
		if d > maxRetryAfter {
			return maxRetryAfter
		}
		return d
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			return defaultRetryAfter
		}
		if d > maxRetryAfter {
			return maxRetryAfter
		}
		return d
	}
	return defaultRetryAfter
}

// sleepCtx ждёт d или отмену контекста. Возвращает false, если прогон окончен.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
