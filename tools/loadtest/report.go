package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// latencyStats — сводка по одной операции, в миллисекундах.
type latencyStats struct {
	Op           string            `json:"op"`
	Count        uint64            `json:"ok_count"`
	MeanMS       float64           `json:"mean_ms"`
	P50MS        float64           `json:"p50_ms"`
	P95MS        float64           `json:"p95_ms"`
	P99MS        float64           `json:"p99_ms"`
	MinMS        float64           `json:"min_ms"`
	MaxMS        float64           `json:"max_ms"`
	Throttled429 uint64            `json:"throttled_429"`
	Failed       uint64            `json:"failed_responses"`
	Errors       uint64            `json:"transport_errors"`
	Codes        map[string]uint64 `json:"codes"`
	BytesOut     uint64            `json:"bytes_sent"`
	BytesIn      uint64            `json:"bytes_received"`
}

func statsOf(op string, s *opStats) latencyStats {
	ms := func(us uint64) float64 { return float64(us) / 1000 }
	codes := make(map[string]uint64, len(s.codes))
	for c, n := range s.codes {
		codes[strconv.Itoa(c)] = n
	}
	return latencyStats{
		Op:           op,
		Count:        s.lat.count,
		MeanMS:       s.lat.mean() / 1000,
		P50MS:        ms(s.lat.quantile(0.50)),
		P95MS:        ms(s.lat.quantile(0.95)),
		P99MS:        ms(s.lat.quantile(0.99)),
		MinMS:        ms(s.lat.min),
		MaxMS:        ms(s.lat.max),
		Throttled429: s.throttled,
		Failed:       s.failed,
		Errors:       s.errors,
		Codes:        codes,
		BytesOut:     s.bytesOut,
		BytesIn:      s.bytesIn,
	}
}

// targetLevel — целевой уровень RPS из docs/spec/SPEC.md §9 и §7.2 уточнений.
// Требуемая латентность считается из того же соотношения закрытого контура.
type targetLevel struct {
	RPS           int     `json:"rps"`
	Comment       string  `json:"comment"`
	RequiredMeanM float64 `json:"required_mean_ms"`
	MeasuredMeanM float64 `json:"measured_mean_ms"`
	Met           bool    `json:"met"`
}

type closedLoopSection struct {
	Conns       int           `json:"conns"`
	MeanMS      float64       `json:"mean_latency_ms"`
	CeilingRPS  float64       `json:"ceiling_rps"`
	GoodputRPS  float64       `json:"goodput_rps"`
	PairsPerSec float64       `json:"pairs_per_sec"`
	Targets     []targetLevel `json:"targets"`
}

type conditions struct {
	GoVersion     string             `json:"go_version"`
	OS            string             `json:"os"`
	Arch          string             `json:"arch"`
	NumCPU        int                `json:"num_cpu"`
	GOMAXPROCS    int                `json:"gomaxprocs"`
	MemTotalBytes uint64             `json:"memory_total_bytes"`
	MemNote       string             `json:"memory_note"`
	TargetURL     string             `json:"target_url"`
	Mode          string             `json:"mode"`
	Conns         int                `json:"conns"`
	DurationReq   string             `json:"duration_requested"`
	RampReq       string             `json:"ramp"`
	WallTotal     string             `json:"wall_total"`
	WallSteady    string             `json:"wall_steady"`
	Timeout       string             `json:"timeout"`
	Seed          int64              `json:"seed"`
	CorpusSource  string             `json:"corpus_source"`
	Composition   []compositionEntry `json:"composition"`
	ClientOnHost  string             `json:"client_placement"`
}

type resourcesSection struct {
	PID          int     `json:"pid"`
	RSSPeakKB    int     `json:"rss_peak_kb"`
	RSSFinalKB   int     `json:"rss_final_kb"`
	RSSSamples   int     `json:"rss_samples"`
	RSSNote      string  `json:"rss_note"`
	GC           gcTrace `json:"gc"`
	GCAvailable  bool    `json:"gc_available"`
	StoreEntries float64 `json:"store_entries"`
	StoreBytes   float64 `json:"store_bytes"`
	StoreEvicted float64 `json:"store_evicted_total"`
	StoreExpired float64 `json:"store_expired_total"`
	MetricsNote  string  `json:"metrics_note"`
}

type limitStep struct {
	Conns      int     `json:"conns"`
	MeanMS     float64 `json:"mean_ms"`
	P99MS      float64 `json:"p99_ms"`
	GoodputRPS float64 `json:"goodput_rps"`
	Throttled  uint64  `json:"throttled_429"`
	Errors     uint64  `json:"transport_errors"`
	WithinSLA  bool    `json:"p99_within_1s"`
}

type report struct {
	Tool        string             `json:"tool"`
	Task        string             `json:"task"`
	GeneratedAt string             `json:"generated_at"`
	Conditions  conditions         `json:"conditions"`
	Client      []latencyStats     `json:"client_latency"`
	ClosedLoop  closedLoopSection  `json:"closed_loop"`
	Server      []serverLatency    `json:"server_latency"`
	Resources   resourcesSection   `json:"resources"`
	Pairs       uint64             `json:"pairs_completed"`
	Mismatch    uint64             `json:"restore_mismatch"`
	WarmupPairs uint64             `json:"warmup_pairs_excluded"`
	Limit       []limitStep        `json:"limit_search,omitempty"`
	LimitConns  int                `json:"limit_conns,omitempty"`
	Notes       []string           `json:"notes"`
	Valid       bool               `json:"valid"`
	InvalidWhy  string             `json:"invalid_reason,omitempty"`
	Composition []compositionEntry `json:"-"`
}

// validityThreshold — доля успешных ответов, ниже которой прогон считается
// недостоверным, а его числа — не результатом измерения.
//
// Порог намеренно высокий. Нагрузочный прогон меряет латентность успешного
// пути; отказы latency не набирают, поэтому чем их больше, тем сильнее
// среднее смещается к нулю. В пределе прогон, где не прошёл ни один запрос,
// печатает «среднее 0,000 мс» — число, выглядящее как отличный результат.
const validityThreshold = 0.99

// checkValidity размечает отчёт как достоверный или нет и возвращает причину.
//
// Проверяется не goodput и не латентность, а доля ответов, которые вообще
// дошли до измеряемого пути. Ответ 429 отказом не считается: он входит в
// штатное поведение сервиса под нагрузкой и учитывается отдельной колонкой.
func (r *report) checkValidity() {
	var ok, failed, errs uint64
	for _, s := range r.Client {
		ok += s.Count
		failed += s.Failed
		errs += s.Errors
	}
	total := ok + failed + errs
	switch {
	case total == 0:
		r.Valid, r.InvalidWhy = false, "ни одного ответа: цель не отвечала или прогон не начался"
	case ok == 0:
		r.Valid, r.InvalidWhy = false, fmt.Sprintf(
			"успешных ответов нет: %d с кодом 4xx/5xx, %d транспортных отказов", failed, errs)
	case float64(ok)/float64(total) < validityThreshold:
		r.Valid, r.InvalidWhy = false, fmt.Sprintf(
			"успешны лишь %.1f %% ответов (%d из %d): порог достоверности %.0f %%",
			100*float64(ok)/float64(total), ok, total, 100*validityThreshold)
	default:
		r.Valid, r.InvalidWhy = true, ""
	}
}

// tag возвращает пометку, которой снабжаются измеренные величины.
//
// У недостоверного прогона числа остаются в выводе — по ним видно, что
// именно пошло не так, — но пометку RESULT они не получают: в отчёт о
// производительности попадают только величины с этой пометкой.
func (r *report) tag() string {
	if r.Valid {
		return "RESULT"
	}
	return "НЕДОСТОВЕРНО"
}

// memTotalBytes определяет объём оперативной памяти машины клиента.
func memTotalBytes(ctx context.Context) (uint64, string) {
	switch runtime.GOOS {
	case "darwin":
		return memTotalDarwin(ctx)
	case "linux":
		return memTotalLinux()
	}
	return 0, "объём памяти на этой платформе не определяется"
}

func memTotalDarwin(ctx context.Context) (uint64, string) {
	out, err := exec.CommandContext(ctx, "sysctl", "-n", "hw.memsize").Output()
	if err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); err == nil {
			return v, "sysctl hw.memsize"
		}
	}
	return 0, "sysctl hw.memsize недоступен"
}

func memTotalLinux() (uint64, string) {
	const unavailable = "/proc/meminfo недоступен"
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, unavailable
	}
	for _, line := range strings.Split(string(b), "\n") {
		if kb, ok := parseMemTotalKB(line); ok {
			return kb * 1024, "/proc/meminfo MemTotal"
		}
	}
	return 0, unavailable
}

// parseMemTotalKB разбирает строку «MemTotal: N kB» из /proc/meminfo.
func parseMemTotalKB(line string) (uint64, bool) {
	if !strings.HasPrefix(line, "MemTotal:") {
		return 0, false
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0, false
	}
	kb, err := strconv.ParseUint(f[1], 10, 64)
	return kb, err == nil
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %sБ", float64(n)/float64(div), []string{"Ки", "Ми", "Ги", "Ти"}[exp])
}

// writeJSON печатает машиночитаемый отчёт.
func (r *report) writeJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Заголовки колонок, общие для нескольких таблиц текстового отчёта.
const (
	colOp     = "операция"
	colMeanMS = "сред.мс"
	colP99MS  = "p99 мс"
)

// textOut печатает строки текстового отчёта.
//
// Отчёт идёт в стандартный вывод, и об отказе записи туда сообщить уже
// некуда, поэтому ошибка записи отбрасывается явно.
type textOut struct{ w io.Writer }

func (t textOut) p(format string, a ...any) { _, _ = fmt.Fprintf(t.w, format+"\n", a...) }

// writeText печатает отчёт для человека.
func (r *report) writeText(w io.Writer) {
	t := textOut{w: w}
	line := strings.Repeat("=", 78)

	t.p("%s", line)
	t.p("НАГРУЗОЧНЫЙ ПРОГОН ai-gateway — ЗАКРЫТЫЙ КОНТУР (%s)", r.Task)
	t.p("%s", line)
	t.p("")

	r.writeInvalidBanner(t)
	r.writeConditions(t)
	r.writeComposition(t)
	r.writeClientLatency(t)
	r.writeOutcomes(t)
	r.writeClosedLoop(t)
	r.writeServerLatency(t)
	r.writeResources(t)
	r.writeLimit(t)
	r.writeNotes(t)
	t.p("%s", line)
}

func (r *report) writeInvalidBanner(t textOut) {
	if r.Valid {
		return
	}
	t.p("!! ПРОГОН НЕДОСТОВЕРЕН — ЧИСЛА НИЖЕ НЕ ЯВЛЯЮТСЯ ИЗМЕРЕНИЕМ")
	t.p("   Причина: %s.", r.InvalidWhy)
	t.p("   Латентность набирается только по успешным ответам, поэтому при")
	t.p("   массовых отказах среднее стремится к нулю и выглядит достижением.")
	t.p("   Проверьте адрес цели: у контракта это -url http://host:порт/process,")
	t.p("   а не корень — на корень сервис отвечает 405.")
	t.p("")
}

func (r *report) writeConditions(t textOut) {
	c := r.Conditions
	t.p("УСЛОВИЯ ИЗМЕРЕНИЯ")
	t.p("  Без этого блока цифры несравнимы между прогонами.")
	t.p("  Дата прогона        : %s", r.GeneratedAt)
	t.p("  Версия Go (клиент)  : %s", c.GoVersion)
	t.p("  Платформа           : %s/%s", c.OS, c.Arch)
	t.p("  Ядер CPU            : %d (GOMAXPROCS клиента %d)", c.NumCPU, c.GOMAXPROCS)
	if c.MemTotalBytes > 0 {
		t.p("  Оперативная память  : %s (%s)", humanBytes(c.MemTotalBytes), c.MemNote)
	} else {
		t.p("  Оперативная память  : не определена (%s)", c.MemNote)
	}
	t.p("  Цель                : %s", c.TargetURL)
	t.p("  Режим               : %s", c.Mode)
	t.p("  Соединений          : %d", c.Conns)
	t.p("  Длительность        : задано %s, фактически %s (из них разгон %s)", c.DurationReq, c.WallTotal, c.RampReq)
	t.p("  Окно удержания      : %s — только оно попадает в цифры ниже", c.WallSteady)
	t.p("  Таймаут запроса     : %s", c.Timeout)
	t.p("  Seed                : %d", c.Seed)
	t.p("  Источник корпуса    : %s", c.CorpusSource)
	t.p("  Размещение клиента  : %s", c.ClientOnHost)
	t.p("")
}

func (r *report) writeComposition(t textOut) {
	t.p("СОСТАВ НАГРУЗКИ")
	t.p("  %-8s %7s %8s %10s %10s %10s", "класс", "элем.", "доля", "мин.ток.", "медиана", "макс.ток.")
	for _, e := range r.Conditions.Composition {
		t.p("  %-8s %7d %7.0f%% %10d %10d %10d", e.Class, e.Items, e.Weight*100, e.MinTokens, e.MedTokens, e.MaxTokens)
	}
	t.p("  Оценка токенов — 4 байта на токен, как в aigw_tokens_in_total сервиса.")
	t.p("")
}

func (r *report) writeClientLatency(t textOut) {
	t.p("ЛАТЕНТНОСТЬ, НАБЛЮДАЕМАЯ КЛИЕНТОМ (%s)", r.tag())
	t.p("  От отправки запроса до полного чтения тела ответа, только коды 200.")
	t.p("  %-8s %10s %9s %9s %9s %9s %9s %9s", colOp, "успешно", colMeanMS, "p50 мс", "p95 мс", colP99MS, "макс мс", "мин мс")
	for _, s := range r.Client {
		t.p("  %-8s %10d %9.3f %9.3f %9.3f %9.3f %9.3f %9.3f",
			s.Op, s.Count, s.MeanMS, s.P50MS, s.P95MS, s.P99MS, s.MaxMS, s.MinMS)
	}
	t.p("")
}

// codesLine печатает все коды ответа операции в порядке возрастания.
func codesLine(codes map[string]uint64) string {
	keys := make([]string, 0, len(codes))
	for k := range codes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, codes[k]))
	}
	return strings.Join(parts, " ")
}

func (r *report) writeOutcomes(t textOut) {
	t.p("КОДЫ ОТВЕТА И ИСХОДЫ")
	t.p("  %-8s %10s %10s %10s %10s %s", colOp, "429", "4xx/5xx", "трансп.", "успешно", "все коды")
	for _, s := range r.Client {
		t.p("  %-8s %10d %10d %10d %10d %s", s.Op, s.Throttled429, s.Failed, s.Errors, s.Count, codesLine(s.Codes))
	}
	t.p("  429 в ошибки не входит: это штатный ответ на перегрузку. Организаторы")
	t.p("  учитывают его отдельно и повторяют запрос с учётом Retry-After — прогон")
	t.p("  делает то же самое.")
	t.p("  Завершённых пар «маска+демаска» : %d", r.Pairs)
	t.p("  Расхождений восстановления      : %d", r.Mismatch)
	t.p("  Пар на разгоне (исключены)      : %d", r.WarmupPairs)
	t.p("")
}

func (r *report) writeClosedLoop(t textOut) {
	cl := r.ClosedLoop
	t.p("ПРЕДЕЛ ЗАКРЫТОГО КОНТУРА")
	t.p("  Контур закрытый: каждое из %d соединений отправляет следующий запрос", cl.Conns)
	t.p("  только после ответа на предыдущий. Поэтому пропускная способность равна")
	t.p("  «соединения / средняя латентность», и выше этого значения выдать физически")
	t.p("  невозможно: ограничивает конкурентность клиента, а не ёмкость сервиса.")
	t.p("")
	t.p("  соединения / средняя латентность = %d / %.3f мс = %.0f запр/с   (%s)",
		cl.Conns, cl.MeanMS, cl.CeilingRPS, r.tag())
	t.p("  фактический goodput              = %.0f запр/с   (%s)", cl.GoodputRPS, r.tag())
	t.p("  завершённых пар в секунду        = %.0f пар/с    (%s)", cl.PairsPerSec, r.tag())
	t.p("  Разрыв между потолком и goodput — паузы по Retry-After и накладные самого")
	t.p("  клиента: сборка запроса, разбор ответа, сверка восстановления.")
	t.p("")
	t.p("  Что требуется для целевых уровней при %d соединениях (TARGET):", cl.Conns)
	t.p("  %-8s %-34s %14s %10s", "RPS", "источник", "нужно сред.мс", "итог")
	for _, tl := range cl.Targets {
		verdict := "не выполнено"
		if tl.Met {
			verdict = "выполнено"
		}
		t.p("  %-8d %-34s %14.2f %10s", tl.RPS, tl.Comment, tl.RequiredMeanM, verdict)
	}
	t.p("  Измеренное среднее: %.3f мс (%s).", cl.MeanMS, r.tag())
	t.p("")
}

func (r *report) writeServerLatency(t textOut) {
	if len(r.Server) == 0 {
		return
	}
	t.p("ЛАТЕНТНОСТЬ, ИЗМЕРЕННАЯ САМИМ СЕРВИСОМ (%s, дельта по GET /metrics)", r.tag())
	t.p("  Организаторы измеряют только ответ сервиса, без сети и клиента")
	t.p("  (07-clarifications §7.2, A6.3). Перцентили здесь — оценка по корзинам")
	t.p("  гистограммы сервиса, то есть округление вверх до границы корзины.")
	t.p("  %-8s %12s %10s %10s %10s %10s", colOp, "запросов", colMeanMS, "p50 мс", "p95 мс", colP99MS)
	for _, s := range r.Server {
		t.p("  %-8s %12.0f %10.3f %10.3f %10.3f %10.3f", s.Op, s.Count, s.MeanMS, s.P50MS, s.P95MS, s.P99MS)
	}
	t.p("")
}

func (r *report) writeResources(t textOut) {
	res := r.Resources
	t.p("РЕСУРСЫ ЦЕЛЕВОГО ПРОЦЕССА")
	if res.PID > 0 {
		t.p("  PID                 : %d", res.PID)
		t.p("  RSS пик / финал     : %s / %s (%d замеров)",
			humanBytes(uint64(res.RSSPeakKB)*1024), humanBytes(uint64(res.RSSFinalKB)*1024), res.RSSSamples)
	} else {
		t.p("  RSS                 : не снят — %s", res.RSSNote)
	}
	if res.GCAvailable {
		t.p("  Сборок мусора       : %d", res.GC.Cycles)
		t.p("  Время в сборках     : %.1f мс суммарно, максимум цикла %.3f мс", res.GC.PauseTotalMS, res.GC.PauseMaxMS)
		t.p("  Куча пик / живое    : %d МБ / %d МБ", res.GC.HeapPeakMB, res.GC.HeapLiveLastMB)
		t.p("  Выделено (оценка)   : %d МБ за прогон", res.GC.AllocEstMB)
	} else {
		t.p("  Куча, сборки, время : NOT_MEASURED — %s", res.GC.Note)
	}
	t.p("  Соответствий в Store: %.0f, объём %s", res.StoreEntries, humanBytes(uint64(res.StoreBytes)))
	t.p("  Вытеснено / истекло : %.0f / %.0f", res.StoreEvicted, res.StoreExpired)
	if res.MetricsNote != "" {
		t.p("  Примечание          : %s", res.MetricsNote)
	}
	t.p("")
}

func (r *report) writeLimit(t textOut) {
	if len(r.Limit) == 0 {
		return
	}
	t.p("ПОИСК ПРЕДЕЛА ПО ЧИСЛУ СОЕДИНЕНИЙ")
	t.p("  Критерий — p99 в пределах 1 секунды (ориентир ТЗ, SPEC §9).")
	t.p("  %-8s %10s %10s %12s %10s %10s %s", "соед.", colMeanMS, colP99MS, "goodput/с", "429", "ошибки", "вердикт")
	for _, s := range r.Limit {
		verdict := "превышен"
		if s.WithinSLA {
			verdict = "в пределах"
		}
		t.p("  %-8d %10.3f %10.3f %12.0f %10d %10d %s",
			s.Conns, s.MeanMS, s.P99MS, s.GoodputRPS, s.Throttled, s.Errors, verdict)
	}
	last := r.Limit[len(r.Limit)-1]
	switch {
	case r.LimitConns > 0 && last.WithinSLA:
		// Ладдер упёрся в -max-conns, а не в латентность: это не найденный
		// предел, и выдавать его за предел нельзя.
		t.p("  Предел не достигнут: на верхней границе ладдера (%d соединений) p99 всё ещё", r.LimitConns)
		t.p("  укладывается в 1 с. Чтобы найти предел, поднимите -max-conns. (%s)", r.tag())
	case r.LimitConns > 0:
		t.p("  Наибольшее число соединений с p99 ≤ 1 с: %d; на %d p99 вышел за 1 с (%s)",
			r.LimitConns, last.Conns, r.tag())
	default:
		t.p("  Ни один шаг не уложился в 1 с (%s)", r.tag())
	}
	t.p("")
}

func (r *report) writeNotes(t textOut) {
	if len(r.Notes) == 0 {
		return
	}
	t.p("ЗАМЕЧАНИЯ К ПРОГОНУ")
	for _, n := range r.Notes {
		t.p("  - %s", n)
	}
	t.p("")
}

func fmtDur(d time.Duration) string { return d.Truncate(time.Millisecond).String() }
