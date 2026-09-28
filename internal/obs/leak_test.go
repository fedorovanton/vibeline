package obs_test

// Тест утечек (REQ-701, AC-600, AC-601). Единственное доказательство того, что
// персональные данные не попадают в журнал, метрики и тела ответов, — поиск по
// каждому размеченному значению во всём, что сервис выпускает наружу.
//
// Тест внешний (obs_test), потому что поднимает настоящий сервер: журнал и
// метрики проверяются в том виде, в каком их увидит оператор, а не в виде
// внутренних счётчиков.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/detect"
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/httpapi"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/store"
)

// markedValue — синтетическое значение ПД и его тип.
type markedValue struct {
	value string
	typ   pii.Type
}

// marked — размеченный набор значений всех типов реестра.
//
// Значения выдуманы специально для этого теста и не берутся из справочников
// детекции: тест проверяет инвариант приватности, а не готовность сканеров.
// Реальные персональные данные в репозиторий не попадают ни в каком виде.
var marked = []markedValue{
	{"Кузнецова Анфиса Валерьевна", pii.FullName},
	{"17.11.1983", pii.BirthDate},
	{"город Нововязники", pii.BirthPlace},
	{"Республика Молдова", pii.Citizenship},
	{"4519 673204", pii.PassportNumber},
	{"ОУФМС Заречного округа", pii.PassportAuthority},
	{"770-093", pii.PassportDeptCode},
	{"05.08.2011", pii.PassportIssueDate},
	{"77 УУ 315902", pii.DriverLicense},
	{"переулок Тихвинский, дом 14, квартира 3", pii.Address},
	{"anfisa.k@pochta.invalid", pii.Email},
	{"+7 902 774-31-08", pii.Phone},
	{"503118942677", pii.INN},
	{"5211 6702 4488 1093", pii.CardNumber},
	{"417", pii.CVV},
	{"8306", pii.PIN},
	{"ANFISA KUZNETSOVA", pii.CardHolder},
	{"112-233-445 95", pii.SNILS},
	{"75 8812340", pii.ForeignPassport},
	{"6398110245778312", pii.OMSPolicy},
	{"К486ТС 790", pii.VehicleReg},
	{"XTA21099052233445", pii.VIN},
	{"1157746123456", pii.OGRN},
	{"40817810277345109926", pii.BankAccount},
}

// leakPayload — текст запроса со всеми размеченными значениями.
const leakPayload = "Клиент Кузнецова Анфиса Валерьевна, дата рождения 17.11.1983, " +
	"место рождения город Нововязники, гражданство Республика Молдова. " +
	"Паспорт 4519 673204, выдан ОУФМС Заречного округа 05.08.2011, " +
	"код подразделения 770-093. Водительское удостоверение 77 УУ 315902. " +
	"Адрес: переулок Тихвинский, дом 14, квартира 3. " +
	"Почта anfisa.k@pochta.invalid, телефон +7 902 774-31-08. " +
	"ИНН 503118942677, карта 5211 6702 4488 1093, CVV 417, ПИН 8306, " +
	"держатель ANFISA KUZNETSOVA. СНИЛС 112-233-445 95, " +
	"загранпаспорт 75 8812340, полис ОМС 6398110245778312, " +
	"госномер К486ТС 790, VIN XTA21099052233445, ОГРН 1157746123456, счёт 40817810277345109926."

// Идентификаторы корреляции выбраны узнаваемыми: они обязаны быть в журнале и
// обязаны отсутствовать в метках метрик (REQ-703).
const (
	idMask     = "leak-mask-9f2c"
	idBroken   = "leak-broken-9f2c"
	idNoField  = "leak-nofield-9f2c"
	idOversize = "leak-oversize-9f2c"
)

// Пути, по которым тест обращается к серверу.
const (
	pathProcess = "/process"
	pathMetrics = "/metrics"
	pathHistory = "/api/v1/ui/history"
	pathJournal = "/api/v1/ui/journal"
	pathTraceR1 = "/api/v1/ui/trace?id=r1"
)

// fieldPayload — поле текста в запросе /process и запрещённая метка метрик.
const fieldPayload = "payload"

// markScanner размечает известные значения как ПД.
//
// Сканеры детекции разрабатываются в отдельных задачах; инвариант приватности
// обязан проверяться независимо от их готовности, поэтому разметка задаётся
// тестом, а не берётся из движка.
type markScanner struct{}

func (markScanner) Name() string { return "leak-mark" }

func (markScanner) Scan(doc *lex.Doc, _ *dict.Set, out *detect.Candidates) {
	for _, m := range marked {
		for i := 0; i < len(doc.Text); {
			j := strings.Index(doc.Text[i:], m.value)
			if j < 0 {
				break
			}
			at := i + j
			out.Add(at, at+len(m.value), m.typ, detect.Certain, "leak-mark")
			i = at + len(m.value)
		}
	}
}

// syncBuffer — журнал в памяти. Сервер пишет из нескольких горутин, поэтому
// буфер защищён мьютексом.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

const leakConfig = `
server:
  addr: "%s"
  max_body_bytes: 8KiB
  max_concurrent: 8
  read_timeout: 5s
store:
  ttl: 1h
llm:
  mode: stub
logging:
  level: debug
  format: json
consumers:
  - id: benchmark
    types: [all]
    demask: true
    mask:
      default: placeholder
  # Потребитель с ключом нужен, чтобы дотянуться до эндпоинтов наблюдаемости:
  # без ключа они отвечают 401, и проверить их на утечки было бы нечем.
  - id: viewer
    api_key: leak-viewer-key
    types: [all]
    demask: true
    mask:
      default: placeholder
`

// viewerKey — ключ доступа к истории, журналу и трассировке. Синтетический.
const viewerKey = "leak-viewer-key"

// probeKey — непринятый ключ: его не должно быть ни в журнале, ни в метриках.
const probeKey = "leak-probe-key-7f3a91"

// startServer поднимает сервер на свободном порту и возвращает его базовый
// адрес вместе с накопителем журнала.
func startServer(t *testing.T) (string, *syncBuffer) {
	t.Helper()

	log := &syncBuffer{}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		addr := freeAddr(t)
		srv := newServer(t, addr, log)

		errc := make(chan error, 1)
		go func() { errc <- srv.ListenAndServe() }()

		err := waitReady(t.Context(), addr, errc)
		if err == nil {
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(ctx)
				<-errc
			})
			return "http://" + addr, log
		}

		last = err
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
	t.Fatalf("сервер не поднялся: %v", last)
	return "", nil
}

func newServer(t *testing.T, addr string, log *syncBuffer) *httpapi.Server {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(leakConfig, addr)), 0o600); err != nil {
		t.Fatalf("запись конфигурации: %v", err)
	}
	holder, err := config.NewHolder(path)
	if err != nil {
		t.Fatalf("загрузка конфигурации: %v", err)
	}

	st := store.NewMemory(holder.Current().Store)
	t.Cleanup(func() { _ = st.Close() })

	// Уровень debug выбран намеренно: проверяется самый разговорчивый режим,
	// в котором утечка вероятнее всего.
	logger, err := obs.NewLogger(log, "debug", "json")
	if err != nil {
		t.Fatalf("сборка журнала: %v", err)
	}

	return httpapi.NewServer(httpapi.Deps{
		Config:    holder,
		Gateway:   gateway.New(detect.New(nil, markScanner{}), st),
		Metrics:   obs.NewMetrics(),
		Logger:    logger,
		Version:   "test",
		StartedAt: time.Now(),
	})
}

// freeAddr подбирает свободный порт на петле.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("выбор порта: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("освобождение порта: %v", err)
	}
	return addr
}

func waitReady(ctx context.Context, addr string, errc <-chan error) error {
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errc:
			return fmt.Errorf("сервер завершился: %w", err)
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
		if err != nil {
			return fmt.Errorf("сборка запроса /healthz: %w", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("сервер не ответил на /healthz за отведённое время")
}

// exchange — один выполненный обмен: как запрос назывался, что вернулось.
type exchange struct {
	name   string
	status int
	body   string
}

func do(t *testing.T, base, method, path, body string) exchange {
	t.Helper()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("запрос %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("чтение ответа %s %s: %v", method, path, err)
	}
	return exchange{name: method + " " + path, status: resp.StatusCode, body: buf.String()}
}

// doAuth выполняет запрос с ключом доступа потребителя.
func doAuth(t *testing.T, base, path, key string) exchange {
	t.Helper()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("запрос GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("чтение ответа GET %s: %v", path, err)
	}
	return exchange{name: "GET " + path, status: resp.StatusCode, body: buf.String()}
}

// directStep выполняет прямой шаг /process с полным размеченным текстом.
func directStep(t *testing.T, base string) exchange {
	t.Helper()
	direct := do(t, base, http.MethodPost, pathProcess, processBody(t, leakPayload, idMask))
	if direct.status != http.StatusOK {
		t.Fatalf("прямой шаг вернул %d: %s", direct.status, direct.body)
	}
	return direct
}

func processBody(t *testing.T, payload, id string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{fieldPayload: payload, "payload_id": id})
	if err != nil {
		t.Fatalf("сборка тела запроса: %v", err)
	}
	return string(body)
}

func TestMarkedValuesAreDistinguishable(t *testing.T) {
	// Фикстура проверяет сама себя: если одно значение окажется частью
	// другого или не попадёт в текст запроса, тест утечек начнёт молча
	// проверять не то, что заявлено.
	for i, m := range marked {
		if n := strings.Count(leakPayload, m.value); n != 1 {
			t.Errorf("значение %q (%s) встречается в запросе %d раз вместо одного", m.value, m.typ, n)
		}
		for j, other := range marked {
			if i == j {
				continue
			}
			if strings.Contains(other.value, m.value) {
				t.Errorf("значение %q (%s) входит в значение %q (%s)", m.value, m.typ, other.value, other.typ)
			}
		}
	}
	if len(marked) != pii.Count-1 {
		t.Errorf("размечено %d значений при %d типах в реестре", len(marked), pii.Count-1)
	}
}

func TestNoMarkedValueLeaks(t *testing.T) {
	// Ключевая проверка задачи: полный цикл обращений, затем поиск каждого
	// значения по отдельности в журнале, метриках и телах ответов.
	base, log := startServer(t)

	direct := maskedRoundTrip(t, base)
	broken, missing, oversize := rejectedRequests(t, base)
	metrics, history, pageJournal, trace := observabilitySurfaces(t, base)

	journal := log.String()
	assertJournalIsMeaningful(t, journal)
	assertMetricsAreMeaningful(t, metrics.body)
	assertHistoryIsMeaningful(t, history.body)
	assertPageJournalIsMeaningful(t, pageJournal.body)
	assertTraceIsMeaningful(t, trace.body)

	assertNoMarkedValues(t, []exchange{
		{name: "журнал", body: journal},
		{name: "экспозиция /metrics", body: metrics.body},
		{name: "тело ответа прямого шага", body: direct.body},
		{name: "тело ответа на битый JSON", body: broken.body},
		{name: "тело ответа без payload_id", body: missing.body},
		{name: "тело ответа на превышение размера", body: oversize.body},
		{name: "буфер истории запросов", body: history.body},
		{name: "поток журнала на странице", body: pageJournal.body},
		{name: "трассировка этапов", body: trace.body},
	})
}

// maskedRoundTrip выполняет прямой и обратный шаг и возвращает обмен прямого
// шага. Маскирование обязано сработать до проверки утечек: иначе отсутствие
// значений в ответе ничего не доказывало бы.
func maskedRoundTrip(t *testing.T, base string) exchange {
	t.Helper()
	// 1. Успешный прямой шаг.
	direct := directStep(t, base)
	masked := resultOf(t, direct.body)
	if masked == leakPayload {
		t.Fatal("ответ прямого шага совпал с запросом: маскирование не выполнено")
	}
	for _, m := range marked {
		if prefix := "[" + m.typ.Placeholder() + "_"; !strings.Contains(masked, prefix) {
			t.Errorf("в ответе нет плейсхолдера типа %s (%s)", m.typ, prefix)
		}
	}

	// 2. Обратный шаг: та же корреляция, на вход подаётся выданная маска.
	reverse := do(t, base, http.MethodPost, pathProcess, processBody(t, masked, idMask))
	if reverse.status != http.StatusOK {
		t.Fatalf("обратный шаг вернул %d: %s", reverse.status, reverse.body)
	}
	// Тело обратного шага — сохранённый оригинал: это и есть предмет
	// контракта (REQ-103), поэтому в поиск утечек оно не входит. Зато оно
	// обязано совпасть с исходным текстом побайтово.
	if got := resultOf(t, reverse.body); got != leakPayload {
		t.Errorf("обратный шаг вернул не исходный текст")
	}
	return direct
}

// rejectedRequests отправляет запросы, которые сервер обязан отклонить, со
// значениями в теле: битый JSON, без payload_id, сверх предела размера.
func rejectedRequests(t *testing.T, base string) (broken, missing, oversize exchange) {
	t.Helper()
	// 3. Битый JSON: тело обрывается на середине, значения в нём есть.
	full := processBody(t, leakPayload, idBroken)
	broken = do(t, base, http.MethodPost, pathProcess, strings.TrimSuffix(full, "}"))
	if broken.status != http.StatusBadRequest {
		t.Errorf("битый JSON вернул %d вместо 400: %s", broken.status, broken.body)
	}

	// 4. Запрос без payload_id.
	noField, err := json.Marshal(map[string]string{fieldPayload: leakPayload, "corr": idNoField})
	if err != nil {
		t.Fatalf("сборка тела запроса: %v", err)
	}
	missing = do(t, base, http.MethodPost, pathProcess, string(noField))
	if missing.status != http.StatusBadRequest {
		t.Errorf("запрос без payload_id вернул %d вместо 400: %s", missing.status, missing.body)
	}

	// 5. Тело сверх предела: значения идут первыми, добивка — в конец.
	oversize = do(t, base, http.MethodPost, pathProcess,
		processBody(t, leakPayload+strings.Repeat("a", 20000), idOversize))
	if oversize.status != http.StatusRequestEntityTooLarge {
		t.Errorf("тело сверх предела вернуло %d вместо 413: %s", oversize.status, oversize.body)
	}
	return broken, missing, oversize
}

// observabilitySurfaces снимает метрики и поверхности наблюдаемости стенда.
// Метрики снимаются после всех обращений: экспозиция накапливается. Буфер
// истории, поток журнала на странице и трассировка проверяются наравне с
// журналом и метриками — это новые места, куда значение могло бы просочиться.
func observabilitySurfaces(t *testing.T, base string) (metrics, history, pageJournal, trace exchange) {
	t.Helper()
	metrics = do(t, base, http.MethodGet, pathMetrics, "")
	if metrics.status != http.StatusOK {
		t.Fatalf("/metrics вернул %d", metrics.status)
	}
	history = doAuth(t, base, "/api/v1/ui/history?limit=200", viewerKey)
	if history.status != http.StatusOK {
		t.Fatalf("история вернула %d: %s", history.status, history.body)
	}
	pageJournal = doAuth(t, base, "/api/v1/ui/journal?limit=500", viewerKey)
	if pageJournal.status != http.StatusOK {
		t.Fatalf("поток журнала вернул %d: %s", pageJournal.status, pageJournal.body)
	}
	trace = doAuth(t, base,
		"/api/v1/ui/trace?id="+firstHistoryRequestID(t, history.body), viewerKey)
	if trace.status != http.StatusOK {
		t.Fatalf("трассировка вернула %d: %s", trace.status, trace.body)
	}
	return metrics, history, pageJournal, trace
}

// assertNoMarkedValues ищет каждое размеченное значение отдельно в каждом
// источнике. Сравнение целого payload пропустило бы частичную утечку —
// фрагмент текста с одним значением.
func assertNoMarkedValues(t *testing.T, sources []exchange) {
	t.Helper()
	for _, m := range marked {
		for _, src := range sources {
			if at := findValue(src.body, m.value); at >= 0 {
				t.Errorf("значение типа %s найдено в источнике «%s»: %s",
					m.typ, src.name, excerpt(src.body, at, len(m.value)))
			}
		}
	}
}

func TestMetricsLabelsCarryNoIdentifiers(t *testing.T) {
	// AC-5 и REQ-703: идентификаторы корреляции и текст запроса в метках
	// означали бы неограниченную кардинальность — метрики стали бы
	// непригодны, а нагрузочный прогон раздул бы память.
	base, _ := startServer(t)

	directStep(t, base)
	// Отказ доступа с непринятым ключом (T-68): метка consumer обязана
	// получить anonymous, а не предъявленную строку.
	if got := doAuth(t, base, pathHistory, probeKey); got.status != http.StatusUnauthorized {
		t.Fatalf("история с непринятым ключом вернула %d", got.status)
	}
	metrics := do(t, base, http.MethodGet, pathMetrics, "")
	assertNoIdentifiersInMetrics(t, metrics.body)

	allowed := allowedMetricLabels()
	for _, p := range metricLabelPairs(metrics.body) {
		checkMetricLabel(t, allowed, p)
	}
}

// assertNoIdentifiersInMetrics — в экспозиции нет ни непринятого ключа, ни
// идентификаторов корреляции, ни меток с идентификаторами и текстом.
func assertNoIdentifiersInMetrics(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, probeKey) || strings.Contains(body, probeKey[:10]) {
		t.Error("непринятый ключ или его префикс попал в экспозицию метрик")
	}
	for _, id := range []string{idMask, idBroken, idNoField, idOversize} {
		if strings.Contains(body, id) {
			t.Errorf("идентификатор корреляции %q попал в экспозицию метрик", id)
		}
	}
	for _, name := range []string{"payload_id", "request_id", fieldPayload, "consumer_key"} {
		if strings.Contains(body, name) {
			t.Errorf("метка %q присутствует в экспозиции метрик", name)
		}
	}
}

// allowedMetricLabels — перечень допустимых меток и их значений; nil —
// значения проверяются отдельно.
func allowedMetricLabels() map[string]map[string]bool {
	return map[string]map[string]bool{
		"endpoint": setOf("process", "chat_completions", "mask", "unmask", "analyze", "ui"),
		"op":       setOf("mask", "mask_retry", "mask_conflict", "unmask", "proxy", "read"),
		"outcome": setOf("ok", "bad_request", "overloaded", "fail_closed", "degraded", "upstream_error",
			"unauthorized", "forbidden", "rate_limited"),
		// Метка consumer — идентификатор из конфигурации (T-68): перечень
		// ограничен конфигурацией теста и значением для непрошедших
		// аутентификацию.
		"consumer": setOf("benchmark", "viewer", "anonymous"),
		"type":     piiKeySet(),
		"le":       nil, // границы гистограммы — числа, проверяются отдельно
	}
}

// metricLabel — одна пара «метка=значение» ряда экспозиции.
type metricLabel struct {
	line, name, value string
}

// metricLabelPairs разбирает метки всех рядов экспозиции Prometheus.
func metricLabelPairs(body string) []metricLabel {
	var out []metricLabel
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		openAt := strings.IndexByte(line, '{')
		closing := strings.LastIndexByte(line, '}')
		if openAt < 0 || closing < openAt {
			continue
		}
		for _, pair := range strings.Split(line[openAt+1:closing], ",") {
			if eq := strings.IndexByte(pair, '='); eq >= 0 {
				out = append(out, metricLabel{line: line, name: pair[:eq], value: strings.Trim(pair[eq+1:], `"`)})
			}
		}
	}
	return out
}

// checkMetricLabel — метка из перечня, значение — из её перечисления, а
// граница корзины — число или +Inf.
func checkMetricLabel(t *testing.T, allowed map[string]map[string]bool, p metricLabel) {
	t.Helper()
	values, ok := allowed[p.name]
	switch {
	case !ok:
		t.Errorf("метка вне перечня: %q в строке %q", p.name, p.line)
	case p.name == "le":
		if p.value != "+Inf" {
			if _, err := strconv.ParseFloat(p.value, 64); err != nil {
				t.Errorf("граница корзины не число: %q", p.line)
			}
		}
	case !values[p.value]:
		t.Errorf("значение метки вне перечисления: %s=%q", p.name, p.value)
	}
}

func setOf(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}

func piiKeySet() map[string]bool {
	out := make(map[string]bool, pii.Count)
	for _, t := range pii.All() {
		out[t.Key()] = true
	}
	return out
}

// assertJournalIsMeaningful защищает от пустой проверки: журнал, в который
// ничего не записалось, не содержит и утечек.
func assertJournalIsMeaningful(t *testing.T, journal string) {
	t.Helper()
	if len(journal) < 100 {
		t.Fatalf("журнал почти пуст, проверка утечек была бы бессодержательной: %q", journal)
	}
	if !strings.Contains(journal, idMask) {
		t.Error("в журнале нет идентификатора корреляции: REQ-700 требует его записи")
	}
	if !strings.Contains(journal, "request_id") {
		t.Error("в журнале нет идентификатора запроса")
	}
	// Типы ПД журналируются по требованию ТЗ §3.2.1 — именами, не значениями.
	if !strings.Contains(journal, pii.FullName.Key()) {
		t.Error("в журнале нет перечня выявленных типов ПД")
	}
}

// assertMetricsAreMeaningful защищает от пустой экспозиции по тем же причинам.
func assertMetricsAreMeaningful(t *testing.T, metrics string) {
	t.Helper()
	for _, want := range []string{"aigw_requests_total", "aigw_pii_detected_total", "aigw_request_duration_seconds_count"} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("экспозиция не содержит %s: проверка утечек была бы бессодержательной", want)
		}
	}
}

func resultOf(t *testing.T, body string) string {
	t.Helper()
	var resp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("ответ не является JSON: %v (%s)", err, body)
	}
	return resp.Result
}

// findValue ищет размеченное значение и возвращает смещение находки или -1.
//
// Короткие числовые значения (CVV, ПИН) ищутся с проверкой соседних байтов:
// три цифры подряд неизбежно встречаются внутри чисел метрик, и такое
// совпадение — не утечка, а ложная тревога. Для остальных значений поиск
// подстрочный, без послаблений.
func findValue(haystack, value string) int {
	if !shortNumeric(value) {
		return strings.Index(haystack, value)
	}
	for i := 0; i+len(value) <= len(haystack); {
		j := strings.Index(haystack[i:], value)
		if j < 0 {
			return -1
		}
		at := i + j
		var before, after byte
		if at > 0 {
			before = haystack[at-1]
		}
		if at+len(value) < len(haystack) {
			after = haystack[at+len(value)]
		}
		if !digit(before) && !digit(after) {
			return at
		}
		i = at + 1
	}
	return -1
}

func shortNumeric(value string) bool {
	if len(value) > 5 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !digit(value[i]) {
			return false
		}
	}
	return len(value) > 0
}

func digit(c byte) bool { return c >= '0' && c <= '9' }

// excerpt возвращает окрестность находки: значения синтетические, поэтому их
// можно печатать, и без окрестности разбираться в утечке неудобно.
func excerpt(text string, at, length int) string {
	from := at - 40
	if from < 0 {
		from = 0
	}
	to := at + length + 40
	if to > len(text) {
		to = len(text)
	}
	return "…" + text[from:to] + "…"
}

// firstHistoryRequestID возвращает идентификатор первого запроса истории.
func firstHistoryRequestID(t *testing.T, body string) string {
	t.Helper()
	var resp struct {
		Rows []struct {
			RequestID string `json:"request_id"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("история не является JSON: %v (%s)", err, body)
	}
	if len(resp.Rows) == 0 {
		t.Fatal("история пуста: проверка утечек в трассировке была бы бессодержательной")
	}
	return resp.Rows[0].RequestID
}

// assertHistoryIsMeaningful защищает от пустой проверки: история, в которую
// ничего не записалось, не содержит и утечек.
func assertHistoryIsMeaningful(t *testing.T, body string) {
	t.Helper()
	var resp struct {
		Enabled bool `json:"enabled"`
		Rows    []struct {
			RequestID string   `json:"request_id"`
			Consumer  string   `json:"consumer"`
			Op        string   `json:"op"`
			Types     []string `json:"types"`
			Detected  int      `json:"detected"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("история не является JSON: %v", err)
	}
	if !resp.Enabled || len(resp.Rows) == 0 {
		t.Fatalf("история пуста или выключена: проверка утечек была бы бессодержательной (%s)", body)
	}
	var withTypes int
	for _, row := range resp.Rows {
		if row.RequestID == "" || row.Consumer == "" || row.Op == "" {
			t.Errorf("запись истории неполна: %+v", row)
		}
		if len(row.Types) > 0 && row.Detected > 0 {
			withTypes++
		}
	}
	if withTypes == 0 {
		// REQ-700 требует перечня выявленных типов и счётчиков по ним.
		t.Error("ни в одной записи истории нет найденных типов ПД")
	}
}

func assertPageJournalIsMeaningful(t *testing.T, body string) {
	t.Helper()
	var resp struct {
		Enabled bool `json:"enabled"`
		Rows    []struct {
			Level      string   `json:"level"`
			Message    string   `json:"message"`
			Types      []string `json:"types"`
			TypeLabels []string `json:"type_labels"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("поток журнала не является JSON: %v", err)
	}
	if !resp.Enabled || len(resp.Rows) == 0 {
		t.Fatalf("поток журнала пуст: проверка утечек была бы бессодержательной (%s)", body)
	}
	var withTypes int
	for _, row := range resp.Rows {
		if row.Level == "" || row.Message == "" {
			t.Errorf("запись потока неполна: %+v", row)
		}
		if len(row.Types) > 0 {
			withTypes++
		}
	}
	if withTypes == 0 {
		t.Error("ни в одной записи потока журнала нет имён типов ПД")
	}
}

func assertTraceIsMeaningful(t *testing.T, body string) {
	t.Helper()
	var resp struct {
		Spans []struct {
			Stage   string  `json:"stage"`
			MS      float64 `json:"ms"`
			Service bool    `json:"service"`
		} `json:"spans"`
		TotalMS float64 `json:"total_ms"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("трассировка не является JSON: %v", err)
	}
	if len(resp.Spans) < 2 || resp.TotalMS <= 0 {
		t.Fatalf("трассировка пуста: проверка утечек была бы бессодержательной (%s)", body)
	}
	for _, sp := range resp.Spans {
		if sp.Stage == "llm" && sp.Service {
			t.Error("ожидание модели помечено как входящее во время сервиса")
		}
	}
}

func TestObservabilityEndpointsRequireKey(t *testing.T) {
	// AC-9: новые эндпоинты без ключа возвращают 401. Страница по GET /
	// остаётся единственным исключением.
	base, _ := startServer(t)

	for _, path := range []string{
		pathHistory,
		pathJournal,
		pathTraceR1,
	} {
		if got := doAuth(t, base, path, ""); got.status != http.StatusUnauthorized {
			t.Errorf("%s без ключа вернул %d вместо 401: %s", path, got.status, got.body)
		}
		if got := doAuth(t, base, path, "не-тот-ключ"); got.status != http.StatusUnauthorized {
			t.Errorf("%s с чужим ключом вернул %d вместо 401", path, got.status)
		}
	}
	if page := do(t, base, http.MethodGet, "/", ""); page.status != http.StatusOK {
		t.Errorf("страница стенда вернула %d вместо 200", page.status)
	}
}

func TestObservabilityBuffersSwitchOff(t *testing.T) {
	// AC-4: буфер и трассировка выключаются настройкой. При выключенных
	// буферах эндпоинты остаются доступными и честно сообщают, что записей нет.
	t.Setenv("AIGW_OBS_BUFFERS", "off")
	base, _ := startServer(t)

	directStep(t, base)

	history := doAuth(t, base, pathHistory, viewerKey)
	if history.status != http.StatusOK {
		t.Fatalf("история вернула %d", history.status)
	}
	if !strings.Contains(history.body, `"enabled":false`) {
		t.Errorf("история не сообщила о выключении: %s", history.body)
	}
	journal := doAuth(t, base, pathJournal, viewerKey)
	if !strings.Contains(journal.body, `"enabled":false`) {
		t.Errorf("журнал не сообщил о выключении: %s", journal.body)
	}
	trace := doAuth(t, base, pathTraceR1, viewerKey)
	if trace.status != http.StatusNotFound {
		t.Errorf("трассировка при выключенном буфере вернула %d вместо 404", trace.status)
	}
}

func TestAccessDeniedLeavesNoKey(t *testing.T) {
	// T-68, AC-3: отказ 401 пишется в журнал записью «доступ отклонён», но
	// ни сам непринятый ключ, ни его префикс не попадают ни в журнал сервиса,
	// ни в зеркало журнала на стенде, ни в метрики.
	base, log := startServer(t)

	for _, path := range []string{pathHistory, pathJournal, pathTraceR1} {
		if got := doAuth(t, base, path, probeKey); got.status != http.StatusUnauthorized {
			t.Fatalf("%s с непринятым ключом вернул %d", path, got.status)
		}
	}
	stand := doAuth(t, base, pathJournal, viewerKey)
	metrics := do(t, base, http.MethodGet, pathMetrics, "")

	if !strings.Contains(log.String(), "доступ отклонён") {
		t.Fatalf("отказ доступа не записан в журнал: %s", log.String())
	}
	if !strings.Contains(stand.body, "доступ отклонён") {
		t.Errorf("отказ доступа не виден в журнале стенда: %s", stand.body)
	}
	if !strings.Contains(metrics.body, `outcome="unauthorized"`) {
		t.Error("отказ доступа не учтён исходом unauthorized")
	}
	for where, text := range map[string]string{"журнал": log.String(), "стенд": stand.body, "метрики": metrics.body} {
		for _, part := range []string{probeKey, probeKey[:10], probeKey[len(probeKey)-6:]} {
			if strings.Contains(text, part) {
				t.Errorf("%s содержит часть непринятого ключа %q", where, part)
			}
		}
	}
}
