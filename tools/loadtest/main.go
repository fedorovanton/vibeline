// Команда loadtest — нагрузочный прогон ai-gateway в закрытом контуре.
//
// Воспроизводится профиль проверяющей системы (docs/context/07-clarifications.md
// §7.2): фиксированное число соединений, каждое отправляет следующий запрос
// только после ответа на предыдущий. Это не генератор с заданным RPS: задать
// RPS здесь нечем, он получается из латентности и числа соединений.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "loadtest:", err)
		os.Exit(1)
	}
}

type options struct {
	url      string
	corpus   string
	conns    int
	duration time.Duration
	mode     string
	asJSON   bool
	timeout  time.Duration
	ramp     time.Duration
	seed     int64
	step     time.Duration
	maxConns int
	pid      int
	gctrace  string
	quiet    bool
}

func run() error {
	var o options
	flag.StringVar(&o.url, "url", "http://127.0.0.1:8080/process", "адрес эндпоинта POST /process")
	flag.StringVar(&o.corpus, "corpus", "", "корпус T-14 в формате JSON Lines; при отсутствии берётся встроенный набор")
	flag.IntVar(&o.conns, "conns", 200, "число одновременных соединений закрытого контура")
	flag.DurationVar(&o.duration, "duration", 5*time.Minute, "длительность прогона")
	flag.StringVar(&o.mode, "mode", modeMixed, "режим: mixed | long | limit")
	flag.BoolVar(&o.asJSON, "json", false, "печатать отчёт в JSON вместо текста")
	flag.DurationVar(&o.timeout, "timeout", 10*time.Second, "таймаут одного запроса")
	flag.DurationVar(&o.ramp, "ramp", 10*time.Second, "разгон: за это время включаются все соединения; замеры разгона в итог не входят")
	flag.Int64Var(&o.seed, "seed", 1, "seed выбора элементов корпуса; фиксирован для воспроизводимости")
	flag.DurationVar(&o.step, "step", 20*time.Second, "длительность одного шага в режиме limit")
	flag.IntVar(&o.maxConns, "max-conns", 3200, "верхняя граница числа соединений в режиме limit")
	flag.IntVar(&o.pid, "pid", 0, "PID целевого процесса для снятия RSS; 0 — определить автоматически")
	flag.StringVar(&o.gctrace, "gctrace", "", "журнал целевого процесса, запущенного с GODEBUG=gctrace=1; источник данных по куче и сборкам мусора")
	flag.BoolVar(&o.quiet, "quiet", false, "не печатать ход прогона")
	flag.Parse()

	if o.conns < 1 {
		return fmt.Errorf("-conns должен быть положительным, получено %d", o.conns)
	}
	if o.duration <= 0 {
		return fmt.Errorf("-duration должен быть положительным, получено %s", o.duration)
	}
	switch o.mode {
	case modeMixed, modeLong, modeLimit:
	default:
		return fmt.Errorf("-mode: допустимы mixed, long, limit; получено %q", o.mode)
	}
	if _, err := url.Parse(o.url); err != nil {
		return fmt.Errorf("-url: %w", err)
	}

	c, err := buildCorpus(o.corpus, o.mode, o.seed)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep, err := execute(ctx, o, c)
	if err != nil {
		return err
	}

	// Достоверность размечается до вывода: пометка RESULT у измеренных величин
	// зависит от неё, а отчёт печатается в обоих случаях — по числам видно,
	// что пошло не так.
	rep.checkValidity()

	if o.asJSON {
		if err := rep.writeJSON(os.Stdout); err != nil {
			return err
		}
	} else {
		rep.writeText(os.Stdout)
	}

	// Ненулевой код возврата обязателен: прогон вызывается из Makefile и из
	// сценариев, где отчёт никто не читает глазами, и молчаливый успех при
	// полном провале выдал бы нули за измерение. Отчёт уже напечатан, здесь
	// остаётся только признак.
	if !rep.Valid {
		return fmt.Errorf("прогон недостоверен: %s", rep.InvalidWhy)
	}
	return nil
}

func progressFunc(quiet bool) func(string) {
	if quiet {
		return nil
	}
	// Ход прогона — диагностика в поток ошибок; отказ её записи на замеры не влияет.
	return func(s string) { _, _ = fmt.Fprintln(os.Stderr, "…", s) }
}

// metricsURL выводит адрес /metrics из адреса /process: оба живут на одном
// сервисе, и отдельный флаг для этого не нужен.
func metricsURL(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	u.Path = "/metrics"
	u.RawQuery = ""
	return u.String()
}

func execute(ctx context.Context, o options, c *corpus) (*report, error) {
	var notes []string

	// PID цели: нужен для RSS. Отсутствие — не отказ, а помеченный пробел.
	pid, pidNote := o.pid, ""
	if pid == 0 {
		pid, pidNote = detectPID(ctx, o.url)
	}

	aux := &http.Client{Timeout: 10 * time.Second}
	mURL := metricsURL(o.url)
	// Снимки /metrics нужны и прерванному прогону: его отчёт тоже печатается,
	// поэтому отмена прогона на них не распространяется.
	scrapeCtx := context.WithoutCancel(ctx)

	// Базовый снимок /metrics берётся не до старта, а по окончании разгона:
	// иначе в серверные цифры попал бы прогрев, который из клиентских замеров
	// исключён, и две колонки отчёта считались бы по разным окнам.
	// В режиме limit шагов несколько, выравнивать не по чему — снимок до старта.
	baselineDelay := o.ramp
	if o.mode == modeLimit {
		baselineDelay = 0
		notes = append(notes, "серверные цифры в режиме limit охватывают все шаги сразу, а не отдельный шаг")
	}
	beforeCh := scrapeBaseline(ctx, scrapeCtx, aux, mURL, baselineDelay)

	var watcher *rssWatcher
	if pid > 0 {
		watcher = newRSSWatcher(pid)
		watcher.start(500 * time.Millisecond)
	}

	main, steps, limitConns, err := runMode(ctx, o, c)
	if err != nil {
		return nil, err
	}

	if watcher != nil {
		watcher.close()
	}
	before := <-beforeCh
	if before == nil {
		notes = append(notes, "базовый снимок /metrics не получен: серверные цифры не приводятся")
	}
	after, errAfter := scrapeMetrics(scrapeCtx, aux, mURL)
	if errAfter != nil {
		notes = append(notes, "снимок /metrics после прогона не получен: "+errAfter.Error())
	}

	rep := buildReport(scrapeCtx, reportInput{
		opts: o, corpus: c, res: main, before: before, after: after,
		pid: pid, pidNote: pidNote, watcher: watcher, notes: notes,
	})
	rep.Limit = steps
	rep.LimitConns = limitConns
	return rep, nil
}

// scrapeBaseline снимает базовый /metrics через delay или по отмене прогона,
// смотря что наступит раньше. Неудачный снимок приходит как nil.
func scrapeBaseline(ctx, scrapeCtx context.Context, client *http.Client, mURL string, delay time.Duration) <-chan *metricsSnapshot {
	ch := make(chan *metricsSnapshot, 1)
	go func() {
		if delay > 0 {
			t := time.NewTimer(delay)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
			}
		}
		snap, err := scrapeMetrics(scrapeCtx, client, mURL)
		if err != nil {
			snap = nil
		}
		ch <- snap
	}()
	return ch
}

// runMode выполняет прогон выбранного режима. Для режима limit возвращает
// ещё шаги ладдера и найденный предел.
func runMode(ctx context.Context, o options, c *corpus) (*runResult, []limitStep, int, error) {
	cfg := runConfig{
		URL:      o.url,
		Conns:    o.conns,
		Duration: o.duration,
		Ramp:     o.ramp,
		Timeout:  o.timeout,
		Mode:     o.mode,
		Seed:     o.seed,
	}
	if o.mode != modeLimit {
		return runClosedLoop(ctx, cfg, c, progressFunc(o.quiet)), nil, 0, nil
	}
	steps, limitConns, main := searchLimit(ctx, o, cfg, c)
	if main == nil {
		return nil, nil, 0, fmt.Errorf("режим limit не дал ни одного завершённого шага")
	}
	return main, steps, limitConns, nil
}

// searchLimit увеличивает число соединений, пока p99 укладывается в 1 секунду.
// Возвращает шаги, последнее удовлетворившее критерию число соединений и
// результат последнего шага — он идёт в основной отчёт.
func searchLimit(ctx context.Context, o options, base runConfig, c *corpus) ([]limitStep, int, *runResult) {
	var steps []limitStep
	var last *runResult
	limit := 0
	ramp := o.step / 5
	for conns := 25; conns <= o.maxConns; conns *= 2 {
		if ctx.Err() != nil {
			break
		}
		cfg := base
		cfg.Conns = conns
		cfg.Duration = o.step
		cfg.Ramp = ramp
		if !o.quiet {
			fmt.Fprintf(os.Stderr, "… шаг: %d соединений на %s\n", conns, o.step)
		}
		res := runClosedLoop(ctx, cfg, c, nil)
		last = res
		t := res.Steady.total()
		st := limitStep{
			Conns:      conns,
			MeanMS:     t.lat.mean() / 1000,
			P99MS:      float64(t.lat.quantile(0.99)) / 1000,
			GoodputRPS: res.goodput(),
			Throttled:  t.throttled,
			Errors:     t.errors,
		}
		st.WithinSLA = t.lat.count > 0 && st.P99MS <= 1000
		steps = append(steps, st)
		if st.WithinSLA {
			limit = conns
		} else {
			// Первое превышение — и есть искомая граница: дальше латентность
			// только растёт, продолжать нагрузку смысла нет.
			break
		}
	}
	return steps, limit, last
}

// reportInput — всё, из чего собирается отчёт прогона.
type reportInput struct {
	opts    options
	corpus  *corpus
	res     *runResult
	before  *metricsSnapshot
	after   *metricsSnapshot
	pid     int
	pidNote string
	watcher *rssWatcher
	notes   []string
}

// targetLevels — целевые уровни RPS для раздела закрытого контура.
var targetLevels = []struct {
	rps     int
	comment string
}{
	{330, "средний уровень прогона (A1.3)"},
	{1000, "пик прогона (A1.3)"},
	{2000, "бонус ТЗ §6"},
}

func buildReport(ctx context.Context, in reportInput) *report {
	o, c, res := in.opts, in.corpus, in.res
	memBytes, memNote := memTotalBytes(ctx)
	steady := res.Steady
	total := steady.total()

	client := make([]latencyStats, 0, opCount+1)
	for i := 0; i < opCount; i++ {
		client = append(client, statsOf(opName[i], &steady.ops[i]))
	}
	client = append(client, statsOf("итого", &total))

	rep := &report{
		Tool:        "tools/loadtest",
		Task:        "T-16",
		GeneratedAt: time.Now().Format(time.RFC3339),
		Conditions: conditions{
			GoVersion:     runtime.Version(),
			OS:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			NumCPU:        runtime.NumCPU(),
			GOMAXPROCS:    runtime.GOMAXPROCS(0),
			MemTotalBytes: memBytes,
			MemNote:       memNote,
			TargetURL:     o.url,
			Mode:          o.mode,
			Conns:         res.Conns,
			DurationReq:   fmtDur(res.Requested),
			RampReq:       fmtDur(res.Ramp),
			WallTotal:     fmtDur(res.TotalWall),
			WallSteady:    fmtDur(res.SteadyWall),
			Timeout:       fmtDur(o.timeout),
			Seed:          o.seed,
			CorpusSource:  c.source,
			Composition:   c.composition(),
			ClientOnHost:  clientPlacement(o.url),
		},
		Client:      client,
		ClosedLoop:  closedLoopOf(res, total.lat.mean()/1000),
		Server:      serverLatencies(in.before, in.after, []string{"mask", "unmask"}),
		Pairs:       steady.pairs,
		Mismatch:    steady.mismatch,
		WarmupPairs: res.Warmup.pairs,
		Notes:       in.notes,
		Resources:   resourcesOf(in),
	}
	rep.addRunNotes(&steady, &total)
	return rep
}

// closedLoopOf считает раздел закрытого контура по средней латентности meanMS.
func closedLoopOf(res *runResult, meanMS float64) closedLoopSection {
	ceiling := 0.0
	if meanMS > 0 {
		ceiling = float64(res.Conns) / (meanMS / 1000)
	}
	pairsPerSec := 0.0
	if res.SteadyWall > 0 {
		pairsPerSec = float64(res.Steady.pairs) / res.SteadyWall.Seconds()
	}

	// Требуемая средняя латентность выводится из того же соотношения
	// закрытого контура: mean = conns / RPS.
	targets := make([]targetLevel, 0, len(targetLevels))
	for _, l := range targetLevels {
		req := float64(res.Conns) / float64(l.rps) * 1000
		targets = append(targets, targetLevel{
			RPS:           l.rps,
			Comment:       l.comment,
			RequiredMeanM: req,
			MeasuredMeanM: meanMS,
			Met:           meanMS > 0 && meanMS <= req,
		})
	}
	return closedLoopSection{
		Conns:       res.Conns,
		MeanMS:      meanMS,
		CeilingRPS:  ceiling,
		GoodputRPS:  res.goodput(),
		PairsPerSec: pairsPerSec,
		Targets:     targets,
	}
}

// resourcesOf собирает раздел ресурсов целевого процесса.
func resourcesOf(in reportInput) resourcesSection {
	resources := resourcesSection{PID: in.pid, RSSNote: in.pidNote}
	if w := in.watcher; w != nil {
		resources.RSSPeakKB = w.PeakKB
		resources.RSSFinalKB = w.FinalKB
		resources.RSSSamples = w.Samples
		if w.Samples == 0 {
			resources.RSSNote = "ps не вернул RSS ни разу"
			resources.PID = 0
		}
	}
	resources.GC, resources.GCAvailable = gcSection(in.opts.gctrace)
	if after := in.after; after != nil {
		resources.StoreEntries = after.sum("aigw_store_entries")
		resources.StoreBytes = after.sum("aigw_store_bytes")
		resources.StoreEvicted = after.sum("aigw_store_evicted_total")
		resources.StoreExpired = after.sum("aigw_store_expired_total")
	} else {
		resources.MetricsNote = "снимок /metrics после прогона отсутствует"
	}
	return resources
}

// gcSection читает журнал gctrace, если он передан; второе значение — есть ли
// в журнале хоть одна сборка.
func gcSection(path string) (gcTrace, bool) {
	if path == "" {
		return gcTrace{Note: "журнал gctrace не передан: число сборок — в aigw_go_gc_cycles_total на /metrics; " +
			"для длительностей пауз запустите сервис с GODEBUG=gctrace=1 и передайте его журнал флагом -gctrace"}, false
	}
	gc, err := readGCTraceFile(path)
	switch {
	case err != nil:
		return gcTrace{Note: "журнал " + path + " не прочитан: " + err.Error()}, false
	case gc.Cycles == 0:
		return gcTrace{Note: "в журнале " + path + " нет строк gctrace"}, false
	}
	return gc, true
}

// addRunNotes дописывает замечания о корректности и отказах прогона.
func (r *report) addRunNotes(steady *phaseStats, total *opStats) {
	if steady.mismatch > 0 {
		// Расхождение восстановления — вопрос корректности, а не скорости, и
		// его нельзя растворить в латентности. Вытеснение по лимиту хранилища
		// приводится рядом: если соответствие вытеснено между прямым и
		// обратным шагом, сервис по REQ-101 маскирует обратный шаг как новый
		// вход, и текст закономерно не совпадёт. Инструмент фиксирует факт и
		// соседнее число, а не назначает причину.
		r.Notes = append(r.Notes, fmt.Sprintf(
			"демаскирование вернуло не исходный текст в %d случаях из %d пар; за тот же прогон хранилище вытеснило по лимиту %.0f соответствий — проверить, не вытесняется ли соответствие между прямым и обратным шагом",
			steady.mismatch, steady.pairs, r.Resources.StoreEvicted))
	}
	if total.errors > 0 {
		r.Notes = append(r.Notes,
			fmt.Sprintf("транспортных отказов: %d (таймауты, разрывы соединения)", total.errors))
	}
	if total.failed > 0 {
		r.Notes = append(r.Notes,
			fmt.Sprintf("ответов 4xx/5xx кроме 429: %d", total.failed))
	}
}

// clientPlacement фиксирует, где работает генератор нагрузки. На одной машине
// с сервисом клиент и сервис делят ядра, и латентность завышена — цифры
// нельзя переносить на выделенный стенд без оговорки.
func clientPlacement(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return "не определено"
	}
	host := u.Hostname()
	if isLoopback(host) {
		return "на одной машине с сервисом (loopback): клиент и сервис делят ядра, латентность завышена"
	}
	return "отдельно от цели (" + host + ")"
}
