package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sample — одна строка экспозиции Prometheus.
type sample struct {
	name   string
	labels string
	value  float64
}

// metricsSnapshot — снимок GET /metrics целевого процесса.
type metricsSnapshot struct {
	at      time.Time
	samples []sample
	raw     int // размер ответа, признак того, что снимок действительно получен
}

// scrapeMetrics снимает экспозицию Prometheus. Ошибка не прерывает прогон:
// метрики цели — дополнение к клиентским замерам, а не их замена.
func scrapeMetrics(ctx context.Context, client *http.Client, metricsURL string) (*metricsSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// Тело уже прочитано или отброшено: ошибка закрытия снимок не портит.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// Остаток тела дочитывается ради переиспользования соединения;
		// сбой дочитывания на ответ не влияет — он уже отказ.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("%s вернул код %d", metricsURL, resp.StatusCode)
	}
	snap := &metricsSnapshot{at: time.Now()}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		snap.raw += len(line) + 1
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sp := strings.LastIndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(line[sp+1:]), 64)
		if err != nil {
			continue
		}
		key := strings.TrimSpace(line[:sp])
		name, labels := key, ""
		if b := strings.IndexByte(key, '{'); b >= 0 {
			name = key[:b]
			labels = strings.TrimSuffix(key[b+1:], "}")
		}
		snap.samples = append(snap.samples, sample{name: name, labels: labels, value: v})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return snap, nil
}

// sum складывает все серии метрики, у которых метки содержат все подстроки want.
func (m *metricsSnapshot) sum(name string, want ...string) float64 {
	var acc float64
	for _, s := range m.samples {
		if s.name != name {
			continue
		}
		ok := true
		for _, w := range want {
			if !strings.Contains(s.labels, w) {
				ok = false
				break
			}
		}
		if ok {
			acc += s.value
		}
	}
	return acc
}

// serverLatency оценивает латентность по гистограмме сервиса.
// Это независимая от клиента величина: организаторы измеряют именно ответ
// сервиса (07-clarifications §7.2, A6.3), без сети и без клиентских накладных.
type serverLatency struct {
	Op      string  `json:"op"`
	Count   float64 `json:"count"`
	MeanMS  float64 `json:"mean_ms"`
	P50MS   float64 `json:"p50_ms"`
	P95MS   float64 `json:"p95_ms"`
	P99MS   float64 `json:"p99_ms"`
	Partial bool    `json:"percentiles_from_buckets"`
}

// serverLatencies считает разницу двух снимков по гистограмме
// aigw_request_duration_seconds. Разница нужна, чтобы в цифры не попал
// прогрев и посторонний трафик до старта.
func serverLatencies(before, after *metricsSnapshot, ops []string) []serverLatency {
	if before == nil || after == nil {
		return nil
	}
	out := make([]serverLatency, 0, len(ops))
	for _, op := range ops {
		if sl, ok := serverLatencyOf(before, after, op); ok {
			out = append(out, sl)
		}
	}
	return out
}

// histBucket — прирост одной корзины гистограммы между снимками.
type histBucket struct {
	le float64
	n  float64
}

// serverLatencyOf считает латентность одной операции; false — запросов этой
// операции между снимками не было.
func serverLatencyOf(before, after *metricsSnapshot, op string) (serverLatency, bool) {
	sel := `op="` + op + `"`
	cnt := after.sum("aigw_request_duration_seconds_count", sel) - before.sum("aigw_request_duration_seconds_count", sel)
	sum := after.sum("aigw_request_duration_seconds_sum", sel) - before.sum("aigw_request_duration_seconds_sum", sel)
	if cnt <= 0 {
		return serverLatency{}, false
	}
	sl := serverLatency{Op: op, Count: cnt, MeanMS: sum / cnt * 1000, Partial: true}
	buckets := bucketDeltas(before, after, sel)
	sl.P50MS = bucketQuantileMS(buckets, 0.50*cnt)
	sl.P95MS = bucketQuantileMS(buckets, 0.95*cnt)
	sl.P99MS = bucketQuantileMS(buckets, 0.99*cnt)
	return sl, true
}

// bucketDeltas возвращает приросты корзин операции sel по возрастанию границы.
func bucketDeltas(before, after *metricsSnapshot, sel string) []histBucket {
	var buckets []histBucket
	for _, s := range after.samples {
		if s.name != histBucketMetric || !strings.Contains(s.labels, sel) {
			continue
		}
		le := bucketLE(s.labels)
		prev := before.sumBucket(sel, s.labels)
		buckets = append(buckets, histBucket{le: le, n: s.value - prev})
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].le < buckets[j].le })
	return buckets
}

// bucketQuantileMS — граница первой корзины, накопившей target запросов, в
// миллисекундах; ноль, если такой корзины нет.
func bucketQuantileMS(buckets []histBucket, target float64) float64 {
	for _, bk := range buckets {
		if bk.n >= target {
			return bk.le * 1000
		}
	}
	return 0
}

// histBucketMetric — корзины гистограммы латентности сервиса.
const histBucketMetric = "aigw_request_duration_seconds_bucket"

func (m *metricsSnapshot) sumBucket(sel, labels string) float64 {
	for _, s := range m.samples {
		if s.name == histBucketMetric && s.labels == labels && strings.Contains(s.labels, sel) {
			return s.value
		}
	}
	return 0
}

func bucketLE(labels string) float64 {
	i := strings.Index(labels, `le="`)
	if i < 0 {
		return 0
	}
	rest := labels[i+4:]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return 0
	}
	v := rest[:j]
	if v == "+Inf" {
		return 1e18
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	return f
}

// --- Ресурсы целевого процесса ---------------------------------------------

// rssWatcher снимает RSS целевого процесса. Процесс чужой, runtime/metrics из
// него недоступны, а /metrics сервиса счётчиков Go-рантайма не публикует,
// поэтому единственный доступный извне источник — ps(1).
type rssWatcher struct {
	pid     int
	stop    chan struct{}
	done    chan struct{}
	PeakKB  int
	FinalKB int
	Samples int
}

func newRSSWatcher(pid int) *rssWatcher {
	return &rssWatcher{pid: pid, stop: make(chan struct{}), done: make(chan struct{})}
}

func (w *rssWatcher) start(interval time.Duration) {
	go func() {
		defer close(w.done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			// Контекст без отмены: close ждёт завершения замера, и последний
			// замер обязан дойти до отчёта.
			if kb, err := readRSS(context.Background(), w.pid); err == nil {
				w.Samples++
				w.FinalKB = kb
				if kb > w.PeakKB {
					w.PeakKB = kb
				}
			}
			select {
			case <-t.C:
			case <-w.stop:
				return
			}
		}
	}()
}

func (w *rssWatcher) close() {
	close(w.stop)
	<-w.done
}

func readRSS(ctx context.Context, pid int) (int, error) {
	out, err := exec.CommandContext(ctx, "ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, err
	}
	f := strings.TrimSpace(string(out))
	if f == "" {
		return 0, fmt.Errorf("ps не вернул RSS для pid %d", pid)
	}
	return strconv.Atoi(f)
}

// detectPID ищет процесс, слушающий порт цели. Работает только для локальной
// цели: у удалённой снять RSS всё равно нечем.
func detectPID(ctx context.Context, target string) (int, string) {
	u, err := url.Parse(target)
	if err != nil {
		return 0, "цель не разобрана как URL"
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return 0, "у цели не указан порт"
	}
	if !isLoopback(host) {
		return 0, "цель не локальная, RSS процесса снять нечем"
	}
	out, err := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP:"+port, "-sTCP:LISTEN", "-t").Output()
	if err != nil {
		return 0, "lsof не определил процесс на порту " + port
	}
	for _, line := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(line); err == nil {
			return pid, ""
		}
	}
	return 0, "на порту " + port + " слушающий процесс не найден"
}

func isLoopback(host string) bool {
	if host == "localhost" || host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- GC целевого процесса ---------------------------------------------------

// gcTrace — сводка по журналу GODEBUG=gctrace=1 целевого процесса.
//
// Почему так: /metrics сервиса не публикует счётчиков Go-рантайма, pprof
// отключён, а runtime/metrics чужого процесса из клиента не читается. Журнал
// gctrace — единственный способ получить число сборок, время в них и размер
// кучи, не трогая чужой код. Флаг необязателен: без него раздел помечается
// как неизмеренный, а не выдумывается.
type gcTrace struct {
	Cycles         int     `json:"cycles"`
	PauseTotalMS   float64 `json:"pause_total_ms"`
	PauseMaxMS     float64 `json:"pause_max_ms"`
	HeapPeakMB     int     `json:"heap_peak_mb"`
	HeapLiveLastMB int     `json:"heap_live_last_mb"`
	AllocEstMB     int     `json:"alloc_estimate_mb"`
	Note           string  `json:"note"`
}

// parseGCTrace разбирает строки вида
//
//	gc 12 @3.201s 1%: 0.031+2.5+0.004 ms clock, 0.37+1.1/2.2/0+0.05 ms cpu, 41->43->21 MB, 43 MB goal, ...
//
// Берутся: число циклов, суммарное время clock, тройка размеров кучи.
// Объём выделений оценивается как сумма приростов «живое → перед сборкой»:
// прямого счётчика mallocs снаружи процесса не видно, поэтому величина
// помечается как оценка.
func parseGCTrace(r io.Reader) gcTrace {
	var acc gcAccumulator
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		acc.addLine(sc.Text())
	}
	acc.t.AllocEstMB = acc.allocKB / 1024
	return acc.t
}

// gcAccumulator копит сводку по строкам журнала gctrace.
type gcAccumulator struct {
	t        gcTrace
	prevLive int
	allocKB  int
}

func (a *gcAccumulator) addLine(line string) {
	i := strings.Index(line, "gc ")
	if i < 0 || !strings.Contains(line, " ms clock, ") {
		return
	}
	line = line[i:]
	a.t.Cycles++

	if p, ok := gcClockMS(line); ok {
		a.t.PauseTotalMS += p
		if p > a.t.PauseMaxMS {
			a.t.PauseMaxMS = p
		}
	}
	before, _, live, ok := gcHeapMB(line)
	if !ok {
		return
	}
	a.t.HeapPeakMB = max(a.t.HeapPeakMB, before)
	a.t.HeapLiveLastMB = live
	if d := before - a.prevLive; d > 0 {
		a.allocKB += d * 1024
	}
	a.prevLive = live
}

// gcClockMS суммирует три слагаемых clock-времени цикла.
func gcClockMS(line string) (float64, bool) {
	i := strings.Index(line, " ms clock,")
	if i < 0 {
		return 0, false
	}
	head := line[:i]
	sp := strings.LastIndexByte(head, ' ')
	if sp < 0 {
		return 0, false
	}
	var total float64
	found := false
	for _, part := range strings.Split(head[sp+1:], "+") {
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			continue
		}
		total += v
		found = true
	}
	return total, found
}

// gcHeapMB достаёт тройку «перед → после → живое» в мегабайтах.
func gcHeapMB(line string) (before, after, live int, ok bool) {
	i := strings.Index(line, " MB goal")
	if i < 0 {
		return 0, 0, 0, false
	}
	head := strings.TrimSuffix(strings.TrimSpace(line[:i]), ",")
	// Перед «N MB goal» идёт «A->B->C MB,». Ищем последнюю тройку со стрелками.
	j := strings.LastIndex(head, "->")
	if j < 0 {
		return 0, 0, 0, false
	}
	seg := head
	if k := strings.LastIndex(head[:j], ", "); k >= 0 {
		seg = head[k+2:]
	}
	seg = strings.TrimSuffix(strings.TrimSpace(seg), " MB")
	if c := strings.LastIndex(seg, " MB,"); c >= 0 {
		seg = seg[:c]
	}
	fields := strings.Split(seg, "->")
	if len(fields) != 3 {
		return 0, 0, 0, false
	}
	vals := make([]int, 3)
	for n, f := range fields {
		v, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			return 0, 0, 0, false
		}
		vals[n] = v
	}
	return vals[0], vals[1], vals[2], true
}

func readGCTraceFile(path string) (gcTrace, error) {
	f, err := os.Open(path)
	if err != nil {
		return gcTrace{}, err
	}
	// Файл открыт только на чтение: ошибка закрытия данных не теряет.
	defer func() { _ = f.Close() }()
	return parseGCTrace(f), nil
}
