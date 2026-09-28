// Package report печатает отчёт качества: таблицу для человека и JSON для
// машины.
//
// Инвариант приватности: без явного -verbose в выводе нет ни одного значения
// персональных данных — только типы, идентификаторы записей и позиции
// (AGENTS.md §7). Значения вычищаются из метрик до печати, а не скрываются
// форматированием.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"qualitycheck/corpus"
	"qualitycheck/eval"
	"qualitycheck/probe"
)

// Version — версия инструмента. Попадает в отчёт: методика подсчёта может
// меняться, и прогоны разных версий сравнимы только с оговоркой.
const Version = "1.0"

// maxListed — сколько пропусков и ложных срабатываний печатается в консоль.
// Полный список всегда есть в JSON.
const maxListed = 40

// Run — условия прогона.
type Run struct {
	RunID       string    `json:"run_id"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	DurationSec float64   `json:"duration_sec"`
	Concurrency int       `json:"concurrency"`
	TimeoutSec  float64   `json:"timeout_sec"`
	Verbose     bool      `json:"verbose"`
}

// Corpus — происхождение корпуса. Без отпечатка, seed и параметров генерации
// прогоны несравнимы между собой (docs/spec/ACCEPTANCE.md §4).
type Corpus struct {
	Path    string         `json:"path"`
	SHA256  string         `json:"sha256"`
	Bytes   int64          `json:"file_bytes"`
	Seed    uint64         `json:"generator_seed"`
	Count   int            `json:"generator_count"`
	Long    bool           `json:"generator_long"`
	Summary corpus.Summary `json:"summary"`
}

// Report — отчёт целиком.
type Report struct {
	Tool    string        `json:"tool"`
	Version string        `json:"version"`
	Run     Run           `json:"run"`
	Corpus  Corpus        `json:"corpus"`
	Service probe.Service `json:"service"`
	Method  []string      `json:"method"`
	Metrics eval.Metrics  `json:"metrics"`
}

// Method — методика подсчёта. Печатается в каждом отчёте: цифры без методики
// сравнивать нельзя, а трактовать — тем более.
func Method() []string {
	return []string{
		"Сокрытие (главная метрика). Значение считается скрытым, если его нет в ответе сервиса.",
		"  Проверяется каждое размеченное значение по отдельности: сравнение целых строк пропускает",
		"  частичную утечку. От границ спана и от стратегии замены метрика не зависит — эталонной",
		"  маски не существует (07-clarifications.md §7.1).",
		"Precision, recall, F1 считаются по факту сокрытия, а не по совпадению границ спана:",
		"  TP — размеченное значение исчезло из ответа; FN — осталось в ответе;",
		"  FP — ловушка этого типа исчезла из ответа (ложное срабатывание).",
		"  У типов без ловушек в корпусе источника FP нет: precision у них равна 1 по построению.",
		"Избыточность (вспомогательная метрика). Доля байтов оригинала, не сохранившихся в ответе,",
		"  вне размеченных спанов. Зависит от соглашения о границах: корпус размечает значение без",
		"  служебных слов, и расхождение конвенций поднимает эту долю, не будучи дефектом детекции.",
		"  Выравнивание оригинала и маски приблизительное — точного соответствия между произвольной",
		"  маской и оригиналом не существует; спорные байты трактуются как замаскированные.",
		"Спорные утечки. Короткое значение или обиходное слово может встретиться в исходном тексте",
		"  и вне разметки; тогда подсчёт вхождений не отличает уцелевший спан от обычного текста.",
		"  Такие спаны засчитаны как утечки, а recall↑ показывает верхнюю границу, если считать их",
		"  скрытыми. В отчёте они помечены отдельно — по пометке видна ширина неопределённости.",
		"Восстановление. Ответ на обратный шаг сравнивается с оригиналом побайтово,",
		"  включая пунктуацию и пробелы.",
		"Все числа получены измерением и являются RESULT: условия прогона указаны выше.",
	}
}

// Render печатает отчёт в виде таблиц.
func (r *Report) Render(w io.Writer, verbose bool) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "Отчёт качества маскирования — %s %s\n", r.Tool, r.Version)
	fmt.Fprintln(b, strings.Repeat("=", 78))
	fmt.Fprintln(b)

	writeKV(b, "прогон", []kv{
		{"идентификатор", r.Run.RunID},
		{"начат", r.Run.StartedAt.Format(time.RFC3339)},
		{"длительность", fmt.Sprintf("%.1f с", r.Run.DurationSec)},
		{"конкурентность", fmt.Sprintf("%d", r.Run.Concurrency)},
		{"таймаут запроса", fmt.Sprintf("%.0f с", r.Run.TimeoutSec)},
		{"значения ПД в отчёте", verboseWord(verbose)},
	})

	writeKV(b, "корпус", []kv{
		{"файл", r.Corpus.Path},
		{"sha256", r.Corpus.SHA256},
		{"размер", fmt.Sprintf("%d Б", r.Corpus.Bytes)},
		{"генерация", fmt.Sprintf("corpusgen -seed %d -count %d -long=%t", r.Corpus.Seed, r.Corpus.Count, r.Corpus.Long)},
		{"записей", fmt.Sprintf("%d", r.Corpus.Summary.Records)},
		{"спанов", fmt.Sprintf("%d", r.Corpus.Summary.Spans)},
		{"ловушек", fmt.Sprintf("%d", r.Corpus.Summary.Traps)},
	})

	writeKV(b, "сервис", []kv{
		{"адрес", r.Service.URL},
		{"версия", orDash(r.Service.Version)},
		{"конфигурация загружена", orDash(r.Service.ConfigLoaded)},
		{"потребители", orDash(strings.Join(r.Service.Consumers, ", "))},
		{"сканеры", orDash(strings.Join(r.Service.Scanners, ", "))},
	})

	fmt.Fprintln(b, "методика")
	for _, line := range r.Method {
		fmt.Fprintf(b, "  %s\n", line)
	}
	fmt.Fprintln(b)

	r.renderTypes(b)
	r.renderKinds(b)
	r.renderReasons(b)
	r.renderRedundancy(b)
	r.renderTotals(b)
	r.renderFindings(b, verbose)

	_, err := io.WriteString(w, b.String())
	return err
}

func (r *Report) renderTypes(b *strings.Builder) {
	fmt.Fprintln(b, "Сокрытие по типам ПД (RESULT)")
	tb := newTable(b)
	tb.row("  тип\tспанов\tскрыто\tутечек\tспорных\tловушек\tложных\tprecision\trecall\trecall↑\tF1" + "\n")
	for _, t := range r.Metrics.Types {
		tb.row("  %s\t%d\t%d\t%d\t%d\t%d\t%d\t%.4f\t%.4f\t%.4f\t%.4f\n",
			t.Type, t.Spans, t.Hidden, t.Leaked, t.LeakedAmbiguous, t.Traps, t.TrapsMasked,
			t.Precision, t.Recall, t.RecallUpper, t.F1)
	}
	tb.flush()
	fmt.Fprintln(b, "  «спорных» — утечки, значение которых встречается в тексте и вне разметки: отличить")
	fmt.Fprintln(b, "  уцелевший спан от обычного текста подсчётом вхождений нельзя. Они засчитаны как")
	fmt.Fprintln(b, "  утечки, а recall↑ показывает верхнюю границу, если считать их скрытыми.")
	fmt.Fprintln(b)
}

func (r *Report) renderKinds(b *strings.Builder) {
	fmt.Fprintln(b, "Записи по видам (RESULT)")
	tb := newTable(b)
	tb.row("  вид\tзаписей\tспанов\tскрыто\tутечек\tспорных\tловушек\tложных\tизменено\tсбоев восст." + "\n")
	for _, k := range r.Metrics.Kinds {
		tb.row("  %s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			k.Kind, k.Records, k.Spans, k.Hidden, k.Leaked, k.LeakedAmbiguous,
			k.Traps, k.TrapsMasked, k.Changed, k.RestoreErrors)
	}
	tb.flush()
	fmt.Fprintln(b, "  вид namesake — однофамилец публичной персоны: значение обязано быть скрыто,")
	fmt.Fprintln(b, "  пропуск здесь дороже всего.")
	fmt.Fprintln(b)
}

func (r *Report) renderReasons(b *strings.Builder) {
	fmt.Fprintln(b, "Ловушки: ошибочно замаскировано (RESULT)")
	tb := newTable(b)
	tb.row("  причина\tловушек\tзамаскировано\tдоля" + "\n")
	for _, rs := range r.Metrics.Reasons {
		tb.row("  %s\t%d\t%d\t%.4f\n", rs.Reason, rs.Traps, rs.Masked, rs.Rate)
	}
	tb.row("  ИТОГО\t%d\t%d\t%.4f\n", r.Metrics.Totals.Traps, r.Metrics.Totals.TrapsMasked, r.Metrics.Totals.TrapRate)
	tb.flush()
	fmt.Fprintln(b)
}

func (r *Report) renderRedundancy(b *strings.Builder) {
	rd := r.Metrics.Redundancy
	fmt.Fprintln(b, "Избыточное маскирование (RESULT)")
	writeKV(b, "", []kv{
		{"байтов текста", fmt.Sprintf("%d", rd.TextBytes)},
		{"из них размечено спанами", fmt.Sprintf("%d", rd.SpanBytes)},
		{"замаскировано байтов", fmt.Sprintf("%d", rd.MaskedBytes)},
		{"из них вне спанов", fmt.Sprintf("%d", rd.ExcessBytes)},
		{"доля избыточного среди замаскированного", frac(rd.ExcessOfMasked)},
		{"доля текста вне спанов, попавшего под маску", frac(rd.ExcessOfOutside)},
		{"записей замаскировано целиком", fmt.Sprintf("%d", rd.FullyMasked)},
		{"записей без ПД изменено", fmt.Sprintf("%d из %d", rd.CleanChanged, rd.CleanTotal)},
	})
}

func (r *Report) renderTotals(b *strings.Builder) {
	t := r.Metrics.Totals
	fmt.Fprintln(b, "Итого (RESULT)")
	rows := []kv{
		{"записей в корпусе", fmt.Sprintf("%d", t.Records)},
		{"записей прогнано", fmt.Sprintf("%d", t.Evaluated)},
		{"записей с ошибкой прогона", fmt.Sprintf("%d", t.Errors)},
		{"значений ПД", fmt.Sprintf("%d", t.Spans)},
		{"скрыто", fmt.Sprintf("%d", t.Hidden)},
		{"утечек", fmt.Sprintf("%d (из них спорных %d, частичных %d)", t.Leaked, t.LeakedAmbiguous, t.LeakedPartial)},
		{"доля сокрытия", fmt.Sprintf("%.4f (верхняя граница %.4f)", t.HideRate, t.HideRateUpper)},
		{"precision (микро)", frac(t.Precision)},
		{"recall (микро)", frac(t.Recall)},
		{"F1 (микро)", frac(t.F1)},
		{"ловушек сработало", fmt.Sprintf("%d из %d", t.TrapsMasked, t.Traps)},
		{"ошибок восстановления", fmt.Sprintf("%d из %d (доля %.4f)", r.Metrics.Restore.Failed, r.Metrics.Restore.Records, r.Metrics.Restore.Rate)},
	}
	if t.Ambiguous > 0 {
		rows = append(rows, kv{"спанов со спорным значением", fmt.Sprintf("%d (значение встречается и вне разметки)", t.Ambiguous)})
	}
	writeKV(b, "", rows)
}

func (r *Report) renderFindings(b *strings.Builder, verbose bool) {
	r.renderLeaks(b, verbose)
	r.renderFalsePositives(b, verbose)
	r.renderRunErrors(b)
}

// findingsHeader печатает заголовок таблицы находок; колонка значения есть
// только при -verbose.
func findingsHeader(t table, header string, verbose bool) {
	if verbose {
		header += "\tзначение"
	}
	t.line(header)
}

// withValue дописывает значение к строке находки только при -verbose.
func withValue(line, value string, verbose bool) string {
	if verbose {
		return line + "\t" + value
	}
	return line
}

func (r *Report) renderLeaks(b *strings.Builder, verbose bool) {
	if len(r.Metrics.Leaks) == 0 {
		return
	}
	fmt.Fprintf(b, "Пропущенные значения: %d (показано до %d)\n", len(r.Metrics.Leaks), maxListed)
	t := newTable(b)
	findingsHeader(t, "  запись\tвид\tтип\tпозиция\tспорная\tчастичная", verbose)
	for _, l := range r.Metrics.Leaks[:min(len(r.Metrics.Leaks), maxListed)] {
		line := fmt.Sprintf("  %s\t%s\t%s\t[%d;%d)\t%s\t%s",
			l.RecordID, l.Kind, l.Type, l.Start, l.End, yesNo(l.Ambiguous), yesNo(l.Partial))
		t.line(withValue(line, l.Value, verbose))
	}
	t.flush()
	fmt.Fprintln(b)
}

func (r *Report) renderFalsePositives(b *strings.Builder, verbose bool) {
	if len(r.Metrics.FalsePositives) == 0 {
		return
	}
	fmt.Fprintf(b, "Сработавшие ловушки: %d (показано до %d)\n", len(r.Metrics.FalsePositives), maxListed)
	t := newTable(b)
	findingsHeader(t, "  запись\tпричина\tтип\tпозиция", verbose)
	for _, f := range r.Metrics.FalsePositives[:min(len(r.Metrics.FalsePositives), maxListed)] {
		line := fmt.Sprintf("  %s\t%s\t%s\t[%d;%d)", f.RecordID, f.Reason, f.Type, f.Start, f.End)
		t.line(withValue(line, f.Value, verbose))
	}
	t.flush()
	fmt.Fprintln(b)
}

func (r *Report) renderRunErrors(b *strings.Builder) {
	if len(r.Metrics.Errors) == 0 {
		return
	}
	fmt.Fprintf(b, "Записи с ошибкой прогона: %d\n", len(r.Metrics.Errors))
	for _, e := range r.Metrics.Errors[:min(len(r.Metrics.Errors), maxListed)] {
		fmt.Fprintf(b, "  %s: %s\n", e.RecordID, e.Error)
	}
	fmt.Fprintln(b)
}

// WriteJSON печатает машинный отчёт.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// table — таблица с выравниванием колонок поверх strings.Builder.
//
// tabwriter буферизует строки и отдаёт их в strings.Builder, запись в который
// не отказывает, поэтому ошибки записи и Flush здесь отбрасываются явно.
type table struct{ tw *tabwriter.Writer }

func newTable(b *strings.Builder) table {
	return table{tw: tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)}
}

func (t table) row(format string, a ...any) { _, _ = fmt.Fprintf(t.tw, format, a...) }

// line пишет готовую строку таблицы как есть: в ней могут быть значения с «%».
func (t table) line(s string) { t.row("%s\n", s) }

func (t table) flush() { _ = t.tw.Flush() }

// frac печатает долю с четырьмя знаками после запятой — так все доли отчёта.
func frac(v float64) string { return fmt.Sprintf("%.4f", v) }

type kv struct{ k, v string }

func writeKV(b *strings.Builder, title string, rows []kv) {
	if title != "" {
		fmt.Fprintln(b, title)
	}
	t := newTable(b)
	for _, row := range rows {
		t.row("  %s\t%s\n", row.k, row.v)
	}
	t.flush()
	fmt.Fprintln(b)
}

func yesNo(v bool) string {
	if v {
		return "да"
	}
	return "нет"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func verboseWord(verbose bool) string {
	if verbose {
		return "да (-verbose)"
	}
	return "нет"
}

// SortStrings — детерминированный порядок для перечислений в шапке.
func SortStrings(v []string) []string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}
