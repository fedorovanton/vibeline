package obs

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"

	"ai-gateway/internal/pii"
)

// Метрики проверяются через ту же экспозицию, которую читает Prometheus.
// Внутренние счётчики могут быть верны, а текстовый формат — нет; тогда
// метрики бесполезны и для жюри, и для нагрузочного прогона.

// Перечислимость меток (REQ-703) держится на сигнатурах: произвольную строку
// в метку передать нельзя, потому что API её не принимает. Проверка
// выполняется компилятором — присваивание перестанет собираться, если в
// сигнатуре появится string.
var (
	_ func(*Metrics, Endpoint, Op, Outcome, float64)         = (*Metrics).Request
	_ func(*Metrics, *[pii.Count]uint16, *[pii.Count]uint16) = (*Metrics).PII
	_ func(*Metrics, Outcome, float64)                       = (*Metrics).LLM
	_ func(*Metrics, int, int)                               = (*Metrics).Traffic
	_ func(*Metrics, int, int64, uint64, uint64)             = (*Metrics).Store
)

// promSample — разобранная строка наблюдения.
type promSample struct {
	name   string
	labels map[string]string
	value  float64
	line   string
}

// promExposition — разобранная экспозиция целиком.
type promExposition struct {
	help    map[string]string
	typ     map[string]string
	samples []promSample
	text    string
}

// expose снимает экспозицию так же, как это делает обработчик /metrics.
func expose(m *Metrics) string {
	var b strings.Builder
	m.WriteProm(&b)
	return b.String()
}

// filled наполняет все семейства метрик, чтобы экспозиция проверялась
// целиком: семейство без наблюдений не печатает ни одной строки значения.
func filled() *Metrics {
	m := NewMetrics()
	m.Request(EndpointProcess, OpMask, OutcomeOK, 0.003)
	m.Request(EndpointProcess, OpUnmask, OutcomeOK, 0.001)
	m.Request(EndpointChat, OpProxy, OutcomeUpstreamError, 1.5)
	m.ConsumerRequest(callerBenchmark, EndpointProcess, OutcomeOK)
	m.ConsumerRequest("", EndpointChat, OutcomeUnauthorized)

	var detected, masked [pii.Count]uint16
	detected[pii.FullName] = 2
	detected[pii.CardNumber] = 1
	masked[pii.FullName] = 2
	m.PII(&detected, &masked)

	m.Traffic(4096, 2048)
	m.Store(7, 1024, 1, 2)
	m.LLM(OutcomeOK, 0.25)
	return m
}

func parseProm(t *testing.T, text string) promExposition {
	t.Helper()

	e := promExposition{help: map[string]string{}, typ: map[string]string{}, text: text}
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("экспозиция не завершена переводом строки")
	}
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			parseMeta(t, &e, line)
			continue
		}
		e.samples = append(e.samples, parseSample(t, line))
	}
	return e
}

func parseMeta(t *testing.T, e *promExposition, line string) {
	t.Helper()

	f := strings.SplitN(line, " ", 4)
	if len(f) < 4 {
		t.Fatalf("неполная строка метаданных: %q", line)
	}
	switch f[1] {
	case "HELP":
		if strings.TrimSpace(f[3]) == "" {
			t.Errorf("пустое описание метрики: %q", line)
		}
		if _, dup := e.help[f[2]]; dup {
			t.Errorf("повторный HELP для %s", f[2])
		}
		e.help[f[2]] = f[3]
	case "TYPE":
		switch f[3] {
		case "counter", "gauge", "histogram", "summary", "untyped":
		default:
			t.Errorf("неизвестный тип метрики: %q", line)
		}
		if _, dup := e.typ[f[2]]; dup {
			t.Errorf("повторный TYPE для %s", f[2])
		}
		e.typ[f[2]] = f[3]
	default:
		t.Errorf("неизвестная служебная строка: %q", line)
	}
}

func parseSample(t *testing.T, line string) promSample {
	t.Helper()

	s := promSample{labels: map[string]string{}, line: line}
	rest := line
	if i := strings.IndexByte(rest, '{'); i >= 0 {
		j := strings.LastIndexByte(rest, '}')
		if j < i {
			t.Fatalf("незакрытый набор меток: %q", line)
		}
		s.name = rest[:i]
		for name, value := range parseLabels(t, rest[i+1:j], line) {
			s.labels[name] = value
		}
		rest = strings.TrimSpace(rest[j+1:])
	} else {
		k := strings.IndexByte(rest, ' ')
		if k < 0 {
			t.Fatalf("строка без значения: %q", line)
		}
		s.name = rest[:k]
		rest = strings.TrimSpace(rest[k+1:])
	}

	if !validName(s.name, true) {
		t.Errorf("недопустимое имя метрики: %q", line)
	}
	v, err := strconv.ParseFloat(rest, 64)
	if err != nil {
		t.Errorf("значение не является числом: %q", line)
	}
	s.value = v
	return s
}

func parseLabels(t *testing.T, raw, line string) map[string]string {
	t.Helper()

	out := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		// Пустой набор меток `{}` формат допускает: так печатается
		// гистограмма без меток.
		return out
	}
	for _, pair := range strings.Split(raw, ",") {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			t.Fatalf("метка без значения: %q", line)
		}
		name := pair[:eq]
		value := pair[eq+1:]
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			t.Fatalf("значение метки не в кавычках: %q", line)
		}
		if !validName(name, false) {
			t.Errorf("недопустимое имя метки: %q", line)
		}
		out[name] = value[1 : len(value)-1]
	}
	return out
}

// validName проверяет имя метрики или метки по правилам текстового формата.
func validName(s string, metric bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c == ':' && metric:
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// family возвращает имя семейства, к которому относится наблюдение: у
// гистограммы суффиксы _bucket, _sum и _count принадлежат базовому имени.
func family(e promExposition, name string) string {
	if _, ok := e.typ[name]; ok {
		return name
	}
	for _, suffix := range []string{"_bucket", "_sum", "_count"} {
		if base := strings.TrimSuffix(name, suffix); base != name {
			if _, ok := e.typ[base]; ok {
				return base
			}
		}
	}
	return ""
}

// pick отбирает наблюдения по имени и подмножеству меток.
func pick(e promExposition, name string, match map[string]string) []promSample {
	var out []promSample
	for _, s := range e.samples {
		if s.name != name {
			continue
		}
		ok := true
		for k, v := range match {
			if s.labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, s)
		}
	}
	return out
}

// one требует ровно одно наблюдение и возвращает его значение.
func one(t *testing.T, e promExposition, name string, match map[string]string) float64 {
	t.Helper()
	got := pick(e, name, match)
	if len(got) != 1 {
		t.Fatalf("ожидалось одно наблюдение %s%v, получено %d", name, match, len(got))
	}
	return got[0].value
}

func TestExpositionIsValidPromText(t *testing.T) {
	// AC-1: каждое семейство снабжено HELP и TYPE, значения числовые.
	e := parseProm(t, expose(filled()))

	if len(e.samples) == 0 {
		t.Fatal("экспозиция не содержит ни одного наблюдения")
	}
	for _, s := range e.samples {
		f := family(e, s.name)
		if f == "" {
			t.Errorf("наблюдение без объявленного TYPE: %q", s.line)
			continue
		}
		if e.help[f] == "" {
			t.Errorf("семейство %s без HELP", f)
		}
		if math.IsNaN(s.value) {
			t.Errorf("значение NaN: %q", s.line)
		}
	}

	// Перечень семейств зафиксирован: REQ-702 требует и задержек, и исходов,
	// и объёма текста, и счётчиков по типам, и состояния хранилища, и
	// отдельного времени модели.
	want := []string{
		"aigw_requests_total",
		"aigw_request_duration_seconds",
		"aigw_llm_duration_seconds",
		metricPIIDetected,
		"aigw_pii_masked_total",
		"aigw_bytes_in_total",
		"aigw_bytes_out_total",
		"aigw_tokens_in_total",
		"aigw_tokens_out_total",
		metricStoreEntries,
		"aigw_store_bytes",
		"aigw_store_evicted_total",
		"aigw_store_expired_total",
	}
	for _, name := range want {
		if e.typ[name] == "" {
			t.Errorf("семейство %s отсутствует в экспозиции", name)
		}
	}
}

func TestExpositionLabelsAreEnumerable(t *testing.T) {
	// AC-5: набор имён меток закрыт, значения принадлежат перечислениям.
	// Идентификаторы запроса и корреляции в метки не попадают по построению,
	// но проверяется именно вывод: он и определяет кардинальность.
	e := parseProm(t, expose(filled()))

	allowed := map[string]map[string]bool{
		keyEndpoint: namesOf(endpointNames[:]),
		"op":        namesOf(opNames[:]),
		keyOutcome:  namesOf(outcomeNames[:]),
		keyType:     piiKeys(),
		"le":        bucketLabels(),
		keyConsumer: namesOf([]string{callerBenchmark, ConsumerAnonymous}),
	}
	for _, s := range e.samples {
		for name, value := range s.labels {
			values, ok := allowed[name]
			if !ok {
				t.Errorf("метка вне перечня: %q в %q", name, s.line)
				continue
			}
			if !values[value] {
				t.Errorf("значение метки вне перечисления: %s=%q в %q", name, value, s.line)
			}
		}
	}
}

func namesOf(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

func piiKeys() map[string]bool {
	out := make(map[string]bool, pii.Count)
	for _, t := range pii.All() {
		out[t.Key()] = true
	}
	return out
}

func bucketLabels() map[string]bool {
	out := make(map[string]bool, len(buckets)+1)
	for _, ub := range buckets {
		out[strconv.FormatFloat(ub, 'g', -1, 64)] = true
	}
	out[leInf] = true
	return out
}

func TestHistogramIsCumulative(t *testing.T) {
	// AC-2: корзины кумулятивны, +Inf вмещает все наблюдения, _count и _sum
	// согласованы с поданными значениями.
	m := NewMetrics()
	observations := []float64{0.0004, 0.003, 0.003, 0.07, 0.3, 4, 30}
	var sum float64
	for _, v := range observations {
		m.Request(EndpointProcess, OpMask, OutcomeOK, v)
		sum += v
	}
	e := parseProm(t, expose(m))
	match := map[string]string{keyEndpoint: endpointProcessName, "op": opMaskName}

	var prev float64
	for _, ub := range buckets {
		le := strconv.FormatFloat(ub, 'g', -1, 64)
		v := one(t, e, metricDurationBucket, merge(match, "le", le))
		if v < prev {
			t.Errorf("кумулятивность нарушена на le=%s: %v после %v", le, v, prev)
		}
		// Корзина обязана содержать ровно те наблюдения, что не превышают
		// её верхнюю границу: семантика le, а не «меньше».
		if want := countAtMost(observations, ub); v != want {
			t.Errorf("корзина le=%s содержит %v вместо %v", le, v, want)
		}
		prev = v
	}

	inf := one(t, e, metricDurationBucket, merge(match, "le", leInf))
	count := one(t, e, "aigw_request_duration_seconds_count", match)
	if inf != float64(len(observations)) {
		t.Errorf("корзина +Inf содержит %v вместо %d", inf, len(observations))
	}
	if count != inf {
		t.Errorf("_count = %v, а корзина +Inf = %v", count, inf)
	}
	if got := one(t, e, "aigw_request_duration_seconds_sum", match); math.Abs(got-sum) > 1e-6 {
		t.Errorf("_sum = %v вместо %v", got, sum)
	}
}

func merge(base map[string]string, key, value string) map[string]string {
	out := make(map[string]string, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[key] = value
	return out
}

func countAtMost(values []float64, ub float64) float64 {
	var n float64
	for _, v := range values {
		if v <= ub {
			n++
		}
	}
	return n
}

func TestHistogramGridEdges(t *testing.T) {
	// Края сетки: нулевая длительность обязана попасть в первую корзину, а
	// значение сверх последней границы — только в +Inf. Ошибка здесь
	// незаметна в агрегате и искажает перцентили.
	m := NewMetrics()
	m.Request(EndpointProcess, OpMask, OutcomeOK, 0)
	m.Request(EndpointProcess, OpMask, OutcomeOK, 3600)

	e := parseProm(t, expose(m))
	match := map[string]string{keyEndpoint: endpointProcessName, "op": opMaskName}

	first := strconv.FormatFloat(buckets[0], 'g', -1, 64)
	if v := one(t, e, metricDurationBucket, merge(match, "le", first)); v != 1 {
		t.Errorf("первая корзина содержит %v вместо 1", v)
	}
	last := strconv.FormatFloat(buckets[len(buckets)-1], 'g', -1, 64)
	if v := one(t, e, metricDurationBucket, merge(match, "le", last)); v != 1 {
		t.Errorf("последняя ограниченная корзина содержит %v вместо 1", v)
	}
	if v := one(t, e, metricDurationBucket, merge(match, "le", leInf)); v != 2 {
		t.Errorf("корзина +Inf содержит %v вместо 2", v)
	}

	// Наблюдение, равное границе, принадлежит этой границе.
	edge := NewMetrics()
	edge.Request(EndpointProcess, OpMask, OutcomeOK, buckets[4])
	ee := parseProm(t, expose(edge))
	le := strconv.FormatFloat(buckets[4], 'g', -1, 64)
	if v := one(t, ee, metricDurationBucket, merge(match, "le", le)); v != 1 {
		t.Errorf("наблюдение на границе le=%s не попало в свою корзину: %v", le, v)
	}
	below := strconv.FormatFloat(buckets[3], 'g', -1, 64)
	if v := one(t, ee, metricDurationBucket, merge(match, "le", below)); v != 0 {
		t.Errorf("наблюдение на границе попало в корзину le=%s: %v", below, v)
	}
}

func TestConcurrentObservationsAreNotLost(t *testing.T) {
	// AC-3: под -race конкурентные наблюдения не теряются. Счётчик и
	// гистограмма обновляются разными атомарными операциями, поэтому
	// сверяются оба.
	const goroutines, each = 16, 250

	m := NewMetrics()
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				m.Request(EndpointProcess, OpMask, OutcomeOK, 0.002)
				m.LLM(OutcomeOK, 0.01)
			}
		}()
	}
	wg.Wait()

	e := parseProm(t, expose(m))
	const want = goroutines * each

	if v := one(t, e, "aigw_requests_total", map[string]string{
		keyEndpoint: endpointProcessName, "op": opMaskName, keyOutcome: "ok",
	}); v != want {
		t.Errorf("счётчик запросов = %v вместо %d", v, want)
	}
	if v := one(t, e, "aigw_request_duration_seconds_count", map[string]string{
		keyEndpoint: endpointProcessName, "op": opMaskName,
	}); v != want {
		t.Errorf("_count гистограммы = %v вместо %d", v, want)
	}
	if v := one(t, e, metricDurationBucket, map[string]string{
		keyEndpoint: endpointProcessName, "op": opMaskName, "le": leInf,
	}); v != want {
		t.Errorf("корзина +Inf = %v вместо %d", v, want)
	}
	if v := one(t, e, "aigw_llm_duration_seconds_count", nil); v != want {
		t.Errorf("_count гистограммы модели = %v вместо %d", v, want)
	}
}

func TestPIICountersUseTypeKeys(t *testing.T) {
	// Счётчики по типам — обязательная часть REQ-700 и REQ-702. Тип Unknown
	// в экспозицию не выводится: он служебный.
	m := NewMetrics()
	var detected, masked [pii.Count]uint16
	detected[pii.Unknown] = 5
	detected[pii.Phone] = 3
	masked[pii.Phone] = 2
	m.PII(&detected, &masked)

	e := parseProm(t, expose(m))
	if v := one(t, e, metricPIIDetected, map[string]string{keyType: pii.Phone.Key()}); v != 3 {
		t.Errorf("найдено телефонов %v вместо 3", v)
	}
	if v := one(t, e, "aigw_pii_masked_total", map[string]string{keyType: pii.Phone.Key()}); v != 2 {
		t.Errorf("замаскировано телефонов %v вместо 2", v)
	}
	if got := pick(e, metricPIIDetected, map[string]string{keyType: pii.Unknown.Key()}); len(got) != 0 {
		t.Errorf("служебный тип unknown попал в экспозицию: %v", got)
	}
}

func TestTrafficTokenDefinition(t *testing.T) {
	// REQ-702 требует явного определения токена. Оно документировано
	// константой BytesPerToken, и экспозиция обязана ему соответствовать:
	// счётчик слов за токены модели не выдаётся.
	m := NewMetrics()
	m.Traffic(4000, 400)

	e := parseProm(t, expose(m))
	if v := one(t, e, "aigw_bytes_in_total", nil); v != 4000 {
		t.Errorf("bytes_in = %v вместо 4000", v)
	}
	if v := one(t, e, "aigw_tokens_in_total", nil); v != 4000/BytesPerToken {
		t.Errorf("tokens_in = %v вместо %d", v, 4000/BytesPerToken)
	}
	if v := one(t, e, "aigw_tokens_out_total", nil); v != 400/BytesPerToken {
		t.Errorf("tokens_out = %v вместо %d", v, 400/BytesPerToken)
	}
}

func TestStoreGaugesArePublished(t *testing.T) {
	// Состояние хранилища публикуется как gauge: значение может убывать.
	m := NewMetrics()
	m.Store(12, 34567, 8, 9)
	e := parseProm(t, expose(m))

	if e.typ[metricStoreEntries] != "gauge" {
		t.Errorf("aigw_store_entries объявлен как %q", e.typ[metricStoreEntries])
	}
	if v := one(t, e, metricStoreEntries, nil); v != 12 {
		t.Errorf("store_entries = %v вместо 12", v)
	}
	if v := one(t, e, "aigw_store_bytes", nil); v != 34567 {
		t.Errorf("store_bytes = %v вместо 34567", v)
	}
	if v := one(t, e, "aigw_store_evicted_total", nil); v != 8 {
		t.Errorf("store_evicted_total = %v вместо 8", v)
	}
	if v := one(t, e, "aigw_store_expired_total", nil); v != 9 {
		t.Errorf("store_expired_total = %v вместо 9", v)
	}
}

func TestEnumNamesAreUniqueAndNonEmpty(t *testing.T) {
	// Имена меток попадают в экспозицию как есть. Пустое или повторяющееся
	// имя склеило бы разные ряды в один и исказило показатели.
	for _, set := range [][]string{endpointNames[:], opNames[:], outcomeNames[:]} {
		seen := map[string]bool{}
		for _, n := range set {
			if n == "" {
				t.Errorf("пустое имя в наборе %v", set)
			}
			if seen[n] {
				t.Errorf("повторяющееся имя %q в наборе %v", n, set)
			}
			seen[n] = true
		}
	}
	if got := EndpointProcess.String(); got != endpointProcessName {
		t.Errorf("Endpoint.String() = %q", got)
	}
	if got := OpMaskRetry.String(); got != "mask_retry" {
		t.Errorf("Op.String() = %q", got)
	}
	if got := OutcomeOverloaded.String(); got != "overloaded" {
		t.Errorf("Outcome.String() = %q", got)
	}
}
