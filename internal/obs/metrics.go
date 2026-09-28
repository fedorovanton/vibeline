// Package obs — журналирование и метрики.
//
// Ни логи, ни метрики не содержат значений персональных данных, сырых payload
// и обратимых соответствий. Логируются этапы, имена типов, счётчики и
// длительности. Метки метрик перечислимы: неограниченная кардинальность
// исключена по построению, а не соглашением.
package obs

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"ai-gateway/internal/pii"
)

// Endpoint — перечислимая метка эндпоинта.
type Endpoint uint8

// Значения меток эндпоинтов.
const (
	EndpointProcess Endpoint = iota
	EndpointChat
	EndpointMask
	EndpointUnmask
	EndpointAnalyze
	// EndpointUI — эндпоинты наблюдаемости стенда (/api/v1/ui/*). В метриках
	// появляется только отказами доступа: чтение буферов запросом не считается.
	EndpointUI
	endpointCount
)

var endpointNames = [endpointCount]string{"process", "chat_completions", "mask", "unmask", "analyze", "ui"}

// String возвращает имя эндпоинта для экспозиции метрик.
func (e Endpoint) String() string { return endpointNames[e] }

// Op — перечислимая метка операции.
type Op uint8

// Значения меток операций.
const (
	// OpMask — прямой шаг: новый payload_id, текст маскируется.
	OpMask Op = iota
	// OpMaskRetry — повтор прямого шага с тем же payload_id и тем же текстом.
	OpMaskRetry
	// OpMaskConflict — известный payload_id с неожиданным текстом.
	OpMaskConflict
	// OpUnmask — обратный шаг: возвращается сохранённый оригинал.
	OpUnmask
	// OpProxy — проксирование запроса в модель.
	OpProxy
	// OpRead — чтение истории, трассировки или журнала стенда.
	OpRead
	opCount
)

var opNames = [opCount]string{"mask", "mask_retry", "mask_conflict", "unmask", "proxy", "read"}

// String возвращает имя операции для экспозиции метрик.
func (o Op) String() string { return opNames[o] }

// Outcome — перечислимая метка исхода запроса.
type Outcome uint8

// Значения меток исходов.
const (
	OutcomeOK Outcome = iota
	OutcomeBadRequest
	OutcomeOverloaded
	OutcomeFailClosed
	OutcomeDegraded
	OutcomeUpstreamError
	// OutcomeClientGone — клиент закрыл соединение раньше ответа. Отказом
	// защиты это не является и в fail_closed не смешивается.
	OutcomeClientGone
	// OutcomeUnauthorized — ключ не предъявлен, неизвестен или принадлежит
	// отключённому потребителю (401). Отдельно от bad_request: отказ доступа
	// — событие аудита, а не ошибка формата запроса.
	OutcomeUnauthorized
	// OutcomeForbidden — ключ действителен, но действие политикой запрещено
	// (403): восстановление без права demask, чужая или отключённая политика.
	OutcomeForbidden
	// OutcomeRateLimited — превышен лимит частоты обращений к модели по
	// ключу (429 с Retry-After). Отдельно от overloaded: это не перегрузка
	// сервиса, а ограничение конкретного потребителя.
	OutcomeRateLimited
	outcomeCount
)

var outcomeNames = [outcomeCount]string{"ok", "bad_request", "overloaded", "fail_closed", "degraded", "upstream_error", "client_gone",
	"unauthorized", "forbidden", "rate_limited"}

// String возвращает имя исхода для экспозиции метрик.
func (o Outcome) String() string { return outcomeNames[o] }

// buckets — верхние границы гистограмм задержки в секундах.
//
// Сетка сгущена вокруг целевых значений: 200 мс соответствует 1000 RPS в
// закрытом контуре на 200 коннектах, 1 с — ориентиру ТЗ.
//
// Нижние корзины от 50 мкс: короткий текст обрабатывается за десятки
// микросекунд, и при нижней границе 0,5 мс все перцентили сервиса сливались в
// одну корзину (O-2 нагрузочного прогона 23.09).
var buckets = [...]float64{
	0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
	0.2, 0.5, 1, 2.5, 5, 10,
}

// Histogram — гистограмма с фиксированными границами.
//
// Операции выполняются атомарными сложениями без блокировок и аллокаций:
// измерение не должно заметно влиять на измеряемое.
type Histogram struct {
	counts [len(buckets) + 1]atomic.Uint64
	sumNs  atomic.Uint64
	total  atomic.Uint64
}

// ObserveSeconds учитывает наблюдение, заданное в секундах.
func (h *Histogram) ObserveSeconds(v float64) {
	i := 0
	for i < len(buckets) && v > buckets[i] {
		i++
	}
	h.counts[i].Add(1)
	h.sumNs.Add(uint64(v * 1e9))
	h.total.Add(1)
}

// Metrics — все метрики сервиса.
//
// Все наборы меток разложены по массивам фиксированного размера: добавить
// произвольную метку невозможно, поэтому payload_id или текст запроса в метки
// попасть не могут.
type Metrics struct {
	requests [endpointCount][opCount][outcomeCount]atomic.Uint64
	latency  [endpointCount][opCount]Histogram

	piiDetected [pii.Count]atomic.Uint64
	piiMasked   [pii.Count]atomic.Uint64

	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
	tokensIn  atomic.Uint64
	tokensOut atomic.Uint64

	storeEntries atomic.Int64
	storeBytes   atomic.Int64
	storeEvicted atomic.Uint64
	storeExpired atomic.Uint64

	llmCalls   [outcomeCount]atomic.Uint64
	llmLatency Histogram

	// byConsumer — счётчики запросов по потребителю: идентификатор →
	// *consumerCounters. Идентификаторы берутся из конфигурации, а не из
	// запроса, и их число ограничено maxConsumerLabels, поэтому кардинальность
	// метки consumer ограничена так же, как у перечислимых меток.
	byConsumer sync.Map
	consumerN  atomic.Int32
}

// ConsumerAnonymous — значение метки consumer для запросов, не прошедших
// аутентификацию. Непринятый ключ в метку не попадает ни целиком, ни частью.
const ConsumerAnonymous = "anonymous"

// consumerOther — значение метки для потребителей сверх maxConsumerLabels.
const consumerOther = "other"

// maxConsumerLabels — предел различных значений метки consumer.
//
// Потребители заводятся в конфигурации, и на практике их единицы. Предел
// нужен на случай, если после череды перезагрузок идентификаторов наберётся
// больше: счётчики не удаляются, и без предела ряд метрик рос бы с каждой
// правкой config.yaml.
const maxConsumerLabels = 64

// consumerCounters — счётчики запросов одного потребителя.
type consumerCounters struct {
	n [endpointCount][outcomeCount]atomic.Uint64
}

// NewMetrics создаёт набор метрик.
func NewMetrics() *Metrics { return &Metrics{} }

// Request учитывает завершённый запрос.
func (m *Metrics) Request(e Endpoint, op Op, out Outcome, seconds float64) {
	m.requests[e][op][out].Add(1)
	m.latency[e][op].ObserveSeconds(seconds)
}

// ConsumerRequest учитывает завершённый запрос в разрезе потребителя.
//
// id — идентификатор потребителя из конфигурации либо ConsumerAnonymous;
// пустая строка тоже считается анонимным запросом. Горячий путь — одно
// чтение sync.Map без блокировки и одно атомарное сложение.
func (m *Metrics) ConsumerRequest(id string, e Endpoint, out Outcome) {
	if id == "" {
		id = ConsumerAnonymous
	}
	m.consumerCounters(id).n[e][out].Add(1)
}

func (m *Metrics) consumerCounters(id string) *consumerCounters {
	if v, ok := m.byConsumer.Load(id); ok {
		return asConsumerCounters(v)
	}
	if m.consumerN.Load() >= maxConsumerLabels && id != consumerOther {
		return m.consumerCounters(consumerOther)
	}
	v, loaded := m.byConsumer.LoadOrStore(id, &consumerCounters{})
	if !loaded {
		m.consumerN.Add(1)
	}
	return asConsumerCounters(v)
}

// asConsumerCounters приводит значение карты к счётчикам потребителя. В карту
// кладутся только *consumerCounters; запасной путь — отдельные счётчики, не
// попадающие в экспозицию: учёт метрики не должен ронять обработку запроса.
func asConsumerCounters(v any) *consumerCounters {
	if c, ok := v.(*consumerCounters); ok {
		return c
	}
	return &consumerCounters{}
}

// PII учитывает найденные и замаскированные значения по типам.
func (m *Metrics) PII(detected, masked *[pii.Count]uint16) {
	for t := 1; t < pii.Count; t++ {
		if n := detected[t]; n > 0 {
			m.piiDetected[t].Add(uint64(n))
		}
		if n := masked[t]; n > 0 {
			m.piiMasked[t].Add(uint64(n))
		}
	}
}

// Traffic учитывает объём обработанного текста.
//
// Токен здесь — единица измерения сервиса, а не токен модели: принимается
// четыре байта на токен. Метрика байтов приводится рядом, чтобы показатель
// можно было пересчитать под любой токенизатор.
func (m *Metrics) Traffic(bytesIn, bytesOut int) {
	m.bytesIn.Add(uint64(bytesIn))
	m.bytesOut.Add(uint64(bytesOut))
	m.tokensIn.Add(uint64(bytesIn / BytesPerToken))
	m.tokensOut.Add(uint64(bytesOut / BytesPerToken))
}

// BytesPerToken — принятое соответствие байтов и токенов для метрики TPS.
const BytesPerToken = 4

// Store публикует текущее состояние хранилища соответствий.
func (m *Metrics) Store(entries int, bytes int64, evicted, expired uint64) {
	m.storeEntries.Store(int64(entries))
	m.storeBytes.Store(bytes)
	m.storeEvicted.Store(evicted)
	m.storeExpired.Store(expired)
}

// LLM учитывает вызов downstream-модели.
func (m *Metrics) LLM(out Outcome, seconds float64) {
	m.llmCalls[out].Add(1)
	m.llmLatency.ObserveSeconds(seconds)
}

// Типы метрик в строке «# TYPE» текстового формата Prometheus.
const (
	promCounter   = "counter"
	promGauge     = "gauge"
	promHistogram = "histogram"
)

// labelsEnd закрывает значение последней метки, набор меток и отделяет
// значение ряда: `…="x"} 42`.
const labelsEnd = `"} `

// promScalar — метрика без меток: одна строка «имя значение».
type promScalar struct {
	name, typ, help string
	value           string
}

// WriteProm пишет метрики в текстовом формате Prometheus.
func (m *Metrics) WriteProm(b *strings.Builder) {
	m.writeRequests(b)
	m.writeConsumerRequests(b)
	m.writeLatency(b)

	writeHeader(b, "aigw_llm_duration_seconds", promHistogram, "Время ответа downstream-модели")
	if m.llmLatency.total.Load() > 0 {
		writeHistogram(b, "aigw_llm_duration_seconds", "", &m.llmLatency)
	}

	writePIIVector(b, "aigw_pii_detected_total", "Найденные значения ПД по типам", &m.piiDetected)
	writePIIVector(b, "aigw_pii_masked_total", "Замаскированные значения ПД по типам", &m.piiMasked)

	writeScalars(b, []promScalar{
		{"aigw_bytes_in_total", promCounter, "Объём входящего текста", fmtUint(m.bytesIn.Load())},
		{"aigw_bytes_out_total", promCounter, "Объём исходящего текста", fmtUint(m.bytesOut.Load())},
		{"aigw_tokens_in_total", promCounter, "Входящие токены, 4 байта на токен", fmtUint(m.tokensIn.Load())},
		{"aigw_tokens_out_total", promCounter, "Исходящие токены, 4 байта на токен", fmtUint(m.tokensOut.Load())},
		{"aigw_store_entries", promGauge, "Число сохранённых соответствий", fmtInt(m.storeEntries.Load())},
		{"aigw_store_bytes", promGauge, "Объём сохранённых соответствий", fmtInt(m.storeBytes.Load())},
		{"aigw_store_evicted_total", promCounter, "Вытесненные по лимиту соответствия", fmtUint(m.storeEvicted.Load())},
		{"aigw_store_expired_total", promCounter, "Удалённые по TTL соответствия", fmtUint(m.storeExpired.Load())},
	})

	writeRuntimeProm(b)
}

// writeRequests пишет aigw_requests_total: ненулевые ряды по эндпоинту,
// операции и исходу.
func (m *Metrics) writeRequests(b *strings.Builder) {
	writeHeader(b, "aigw_requests_total", promCounter, "Число обработанных запросов")
	for e := Endpoint(0); e < endpointCount; e++ {
		for op := Op(0); op < opCount; op++ {
			m.writeRequestRow(b, e, op)
		}
	}
}

func (m *Metrics) writeRequestRow(b *strings.Builder, e Endpoint, op Op) {
	for out := Outcome(0); out < outcomeCount; out++ {
		if v := m.requests[e][op][out].Load(); v > 0 {
			b.WriteString(`aigw_requests_total{endpoint="` + e.String() +
				`",op="` + op.String() + `",outcome="` + out.String() + labelsEnd)
			writeUint(b, v)
		}
	}
}

// writeConsumerRequests пишет aigw_consumer_requests_total: ненулевые ряды
// по потребителю, эндпоинту и исходу, потребители по алфавиту.
func (m *Metrics) writeConsumerRequests(b *strings.Builder) {
	writeHeader(b, "aigw_consumer_requests_total", promCounter, "Число запросов по потребителю")
	for _, id := range m.consumerIDs() {
		c := m.consumerCounters(id)
		label := escapeLabel(id)
		for e := Endpoint(0); e < endpointCount; e++ {
			c.writeRow(b, label, e)
		}
	}
}

func (c *consumerCounters) writeRow(b *strings.Builder, label string, e Endpoint) {
	for out := Outcome(0); out < outcomeCount; out++ {
		if v := c.n[e][out].Load(); v > 0 {
			b.WriteString(`aigw_consumer_requests_total{consumer="` + label +
				`",endpoint="` + e.String() + `",outcome="` + out.String() + labelsEnd)
			writeUint(b, v)
		}
	}
}

// writeLatency пишет гистограммы aigw_request_duration_seconds по эндпоинту
// и операции; пустые гистограммы пропускаются.
func (m *Metrics) writeLatency(b *strings.Builder) {
	writeHeader(b, "aigw_request_duration_seconds", promHistogram, "Время ответа сервиса без ожидания модели")
	for e := Endpoint(0); e < endpointCount; e++ {
		for op := Op(0); op < opCount; op++ {
			h := &m.latency[e][op]
			if h.total.Load() == 0 {
				continue
			}
			labels := `endpoint="` + e.String() + `",op="` + op.String() + `"`
			writeHistogram(b, "aigw_request_duration_seconds", labels, h)
		}
	}
}

// writePIIVector пишет счётчик по типам ПД: ненулевые ряды с меткой type.
func writePIIVector(b *strings.Builder, name, help string, v *[pii.Count]atomic.Uint64) {
	writeHeader(b, name, promCounter, help)
	for t := 1; t < pii.Count; t++ {
		if n := v[t].Load(); n > 0 {
			b.WriteString(name + `{type="` + pii.Type(t).Key() + labelsEnd)
			writeUint(b, n)
		}
	}
}

// writeScalars пишет метрики без меток: заголовок и строку значения каждой.
func writeScalars(b *strings.Builder, ms []promScalar) {
	for _, s := range ms {
		writeHeader(b, s.name, s.typ, s.help)
		b.WriteString(s.name + " " + s.value + "\n")
	}
}

func fmtUint(v uint64) string { return strconv.FormatUint(v, 10) }

func fmtInt(v int64) string { return strconv.FormatInt(v, 10) }

func fmtFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// consumerIDs возвращает известные идентификаторы потребителей по алфавиту:
// порядок рядов в экспозиции не должен зависеть от обхода карты.
func (m *Metrics) consumerIDs() []string {
	var ids []string
	m.byConsumer.Range(func(k, _ any) bool {
		if id, ok := k.(string); ok {
			ids = append(ids, id)
		}
		return true
	})
	sort.Strings(ids)
	return ids
}

// escapeLabel экранирует значение метки по правилам текстового формата
// Prometheus. Идентификаторы потребителей приходят из конфигурации, но
// кавычка или перевод строки в них не должны ломать экспозицию.
func escapeLabel(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

func writeHeader(b *strings.Builder, name, typ, help string) {
	b.WriteString("# HELP " + name + " " + help + "\n")
	b.WriteString("# TYPE " + name + " " + typ + "\n")
}

func writeHistogram(b *strings.Builder, name, labels string, h *Histogram) {
	sep := ""
	if labels != "" {
		sep = ","
	}
	var cum uint64
	for i, ub := range buckets {
		cum += h.counts[i].Load()
		b.WriteString(name + `_bucket{` + labels + sep + `le="` + strconv.FormatFloat(ub, 'g', -1, 64) + labelsEnd)
		writeUint(b, cum)
	}
	cum += h.counts[len(buckets)].Load()
	b.WriteString(name + `_bucket{` + labels + sep + `le="+Inf"} `)
	writeUint(b, cum)
	b.WriteString(name + `_sum{` + labels + `} `)
	b.WriteString(strconv.FormatFloat(float64(h.sumNs.Load())/1e9, 'f', 6, 64))
	b.WriteByte('\n')
	b.WriteString(name + `_count{` + labels + `} `)
	writeUint(b, h.total.Load())
}

func writeUint(b *strings.Builder, v uint64) {
	b.WriteString(strconv.FormatUint(v, 10))
	b.WriteByte('\n')
}
