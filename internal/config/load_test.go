package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
)

// Фикстуры, общие для тестов загрузки: потребитель по умолчанию и стратегия
// маски по умолчанию.
const (
	benchmarkID     = "benchmark"
	placeholderName = "placeholder"
)

// Конфигурации в тестах синтетические: ключи доступа берутся из переменных
// окружения теста, персональных данных в файлах нет.

// minimalConfig — наименьшая корректная конфигурация: только обязательный
// потребитель benchmark, всё остальное подставляется по умолчанию.
const minimalConfig = `
consumers:
  - id: benchmark
    types: [all]
`

// writeConfig кладёт конфигурацию во временный файл и возвращает путь.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("запись конфигурации: %v", err)
	}
	return path
}

// loadString разбирает конфигурацию из строки.
func loadString(t *testing.T, body string) (*Snapshot, error) {
	t.Helper()
	return Load(writeConfig(t, body))
}

func mustLoad(t *testing.T, body string) *Snapshot {
	t.Helper()
	snap, err := loadString(t, body)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return snap
}

// mustFail проверяет, что конфигурация отклонена и сообщение содержит все
// части parts.
func mustFail(t *testing.T, body string, parts ...string) {
	t.Helper()
	_ = mustFailErr(t, body, parts...)
}

// mustFailErr — то же, что mustFail, но возвращает ошибку загрузки для
// дополнительных проверок её текста.
func mustFailErr(t *testing.T, body string, parts ...string) error {
	t.Helper()
	_, err := loadString(t, body)
	if err == nil {
		t.Fatal("некорректная конфигурация принята")
	}
	for _, p := range parts {
		if !strings.Contains(err.Error(), p) {
			t.Fatalf("сообщение %q не содержит %q", err, p)
		}
	}
	return err
}

// TestDefaultsApplied — пропущенные поля получают значения по умолчанию,
// иначе минимальный config.yaml поднимал бы сервис с нулевыми таймаутами.
func TestDefaultsApplied(t *testing.T) {
	snap := mustLoad(t, minimalConfig)

	if snap.Server.Addr != ":8080" {
		t.Errorf("server.addr = %q", snap.Server.Addr)
	}
	if snap.Server.MaxBodyBytes.Int64() != 8<<20 {
		t.Errorf("server.max_body_bytes = %d", snap.Server.MaxBodyBytes.Int64())
	}
	if snap.Server.MaxConcurrent != 1024 {
		t.Errorf("server.max_concurrent = %d", snap.Server.MaxConcurrent)
	}
	if snap.Server.ReadTimeout.Duration() != 5*time.Second {
		t.Errorf("server.read_timeout = %s", snap.Server.ReadTimeout)
	}
	if snap.Store.TTL != 30*time.Minute {
		t.Errorf("store.ttl = %s", snap.Store.TTL)
	}
	if snap.Store.MaxEntries != 2_000_000 {
		t.Errorf("store.max_entries = %d", snap.Store.MaxEntries)
	}
	if snap.LLM.Mode != "stub" {
		t.Errorf("llm.mode = %q", snap.LLM.Mode)
	}
	if snap.Detection.Profile != "balanced" || snap.Detection.MaxSpans != 20_000 {
		t.Errorf("detection = %+v", snap.Detection)
	}
	if snap.Logging.Level != "info" || snap.Logging.Format != "json" {
		t.Errorf("logging = %+v", snap.Logging)
	}
	if snap.LoadedAt.IsZero() {
		t.Error("LoadedAt не проставлен")
	}
}

// TestConsumerDefaults — умолчания потребителя: включён, демаскирование
// разрешено, маскирование включено. Отключение маскирования не может
// случиться из-за пропущенного поля (REQ-402).
func TestConsumerDefaults(t *testing.T) {
	snap := mustLoad(t, minimalConfig)

	c, ok := snap.Consumers.ByID(policy.DefaultConsumerID)
	if !ok {
		t.Fatal("потребитель benchmark не найден")
	}
	if !c.Enabled || !c.Demask || !c.MaskingEnabled {
		t.Fatalf("умолчания потребителя: enabled=%v demask=%v masking=%v", c.Enabled, c.Demask, c.MaskingEnabled)
	}
	if c.Profile != detect.Balanced {
		t.Errorf("профиль %v, ожидался balanced", c.Profile)
	}
	if c.MaxSpans != 20_000 {
		t.Errorf("max_spans = %d", c.MaxSpans)
	}
	if c.DefaultStrategyName() != placeholderName {
		t.Errorf("стратегия по умолчанию %q", c.DefaultStrategyName())
	}
}

// TestTypesAllExpands — `types: [all]` разворачивается в полный набор типов,
// а не остаётся строкой «all».
func TestTypesAllExpands(t *testing.T) {
	snap := mustLoad(t, minimalConfig)
	c, _ := snap.Consumers.ByID(policy.DefaultConsumerID)

	if c.Types != pii.FullSet() {
		t.Fatalf("types = %v, ожидался полный набор", c.Types)
	}
	if c.Types.Len() != pii.Count-1 {
		t.Fatalf("в наборе %d типов, зарегистрировано %d", c.Types.Len(), pii.Count-1)
	}
}

// TestTypesOmittedMeansAll — пропущенный список типов означает «все»:
// умолчание не должно оставлять часть данных без защиты.
func TestTypesOmittedMeansAll(t *testing.T) {
	snap := mustLoad(t, "consumers:\n  - id: benchmark\n")
	c, _ := snap.Consumers.ByID(policy.DefaultConsumerID)

	if c.Types != pii.FullSet() {
		t.Fatalf("types = %v, ожидался полный набор", c.Types)
	}
}

func TestTypesListParsed(t *testing.T) {
	snap := mustLoad(t, `
consumers:
  - id: benchmark
    types: [full_name, phone, card_number]
`)
	c, _ := snap.Consumers.ByID(policy.DefaultConsumerID)

	if c.Types != pii.NewSet(pii.FullName, pii.Phone, pii.CardNumber) {
		t.Fatalf("types = %v", c.Types)
	}
}

// TestUnknownPIIType — AC-7. Опечатка в ключе типа обязана назвать
// потребителя и поле, иначе её ищут перебором по файлу.
func TestUnknownPIIType(t *testing.T) {
	mustFail(t, `
consumers:
  - id: benchmark
    types: [full_name, telefon]
`, benchmarkID, "types", "telefon")
}

func TestUnknownPIITypeInCombo(t *testing.T) {
	mustFail(t, `
consumers:
  - id: benchmark
    combinations:
      - mask: [pin]
        only_with: [kard]
`, benchmarkID, "combinations[0].only_with", "kard")
}

func TestUnknownPIITypeInPerType(t *testing.T) {
	mustFail(t, `
consumers:
  - id: benchmark
    mask:
      per_type:
        kard: asterisks
`, benchmarkID, "mask.per_type", "kard")
}

// TestUnknownProfile — профиль проверяется и глобально, и у потребителя.
func TestUnknownProfile(t *testing.T) {
	mustFail(t, `
detection:
  profile: паранойя
consumers:
  - id: benchmark
`, "detection.profile", "паранойя")

	mustFail(t, `
consumers:
  - id: benchmark
    profile: паранойя
`, benchmarkID, "профиль", "паранойя")
}

func TestUnknownLLMMode(t *testing.T) {
	mustFail(t, `
llm:
  mode: телепатия
consumers:
  - id: benchmark
`, "llm.mode", "телепатия")
}

// TestUnknownStrategy — AC-7 для стратегий: сообщение называет потребителя,
// неизвестное имя и перечень доступных.
func TestUnknownStrategy(t *testing.T) {
	err := mustFailErr(t, `
consumers:
  - id: benchmark
    mask:
      default: невидимость
`, benchmarkID, "невидимость")
	for _, name := range []string{placeholderName, "asterisks", "token", "synthetic"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("сообщение %q не перечисляет стратегию %q", err, name)
		}
	}

	mustFail(t, `
consumers:
  - id: benchmark
    mask:
      per_type:
        phone: невидимость
`, benchmarkID, "phone", "невидимость")
}

// TestAllStrategiesAcceptedInConfig — AC-1 со стороны конфигурации: все
// четыре стратегии выбираются по имени из config.yaml.
func TestAllStrategiesAcceptedInConfig(t *testing.T) {
	snap := mustLoad(t, `
consumers:
  - id: benchmark
    mask:
      default: token
      per_type:
        full_name: synthetic
        card_number: asterisks
        phone: placeholder
`)
	c, _ := snap.Consumers.ByID(policy.DefaultConsumerID)

	want := map[pii.Type]string{
		pii.FullName:   "synthetic",
		pii.CardNumber: "asterisks",
		pii.Phone:      placeholderName,
		pii.Email:      "token", // без переопределения — стратегия по умолчанию
	}
	for tp, name := range want {
		if got := c.StrategyName(tp); got != name {
			t.Errorf("%s: стратегия %q, ожидалась %q", tp.Key(), got, name)
		}
	}
}

// TestDuplicateConsumerID — два потребителя с одним идентификатором делают
// область изоляции неоднозначной.
func TestDuplicateConsumerID(t *testing.T) {
	mustFail(t, `
consumers:
  - id: benchmark
  - id: benchmark
`, benchmarkID, "дважды")
}

// TestDuplicateAPIKey — один ключ у двух потребителей означает, что запрос
// нельзя отнести к области изоляции однозначно.
func TestDuplicateAPIKey(t *testing.T) {
	t.Setenv("TEST_SHARED_KEY", "synthetic-key-0001")

	mustFail(t, `
consumers:
  - id: benchmark
  - id: crm
    api_key_env: TEST_SHARED_KEY
  - id: billing
    api_key_env: TEST_SHARED_KEY
`, "crm", "billing", "ключ")
}

// TestMissingBenchmarkConsumer — без потребителя benchmark контракт /process
// не может выбрать политику, и запросы автопроверки остались бы без защиты.
func TestMissingBenchmarkConsumer(t *testing.T) {
	mustFail(t, `
consumers:
  - id: crm
`, policy.DefaultConsumerID)
}

// TestDurationsAsStrings — длительность читается строкой вида «30m».
func TestDurationsAsStrings(t *testing.T) {
	snap := mustLoad(t, `
store:
  ttl: 30m
  sweep_interval: 90s
consumers:
  - id: benchmark
`)

	if snap.Store.TTL != 30*time.Minute {
		t.Fatalf("ttl = %s", snap.Store.TTL)
	}
	if snap.Store.SweepInterval != 90*time.Second {
		t.Fatalf("sweep_interval = %s", snap.Store.SweepInterval)
	}
}

// TestDurationsAsSeconds — длительность читается числом секунд.
//
// Форма заявлена и комментарием к Duration.UnmarshalYAML, и текстом его
// собственной ошибки («строкой вида "30m" или числом секунд»), и списком
// проверок задачи T-11.
//
// БЛОКЕР T-11. Тест падает на internal/config/types.go — файле вне owns
// задачи, поэтому исправление оставлено оркестратору. Причина: yaml.v3
// успешно разбирает нетипизированный скаляр 1800 в string, поэтому первая
// же ветка UnmarshalYAML забирает значение себе и падает на
// time.ParseDuration, не дойдя до числовой ветки. Bytes.UnmarshalYAML
// разбирает формы в обратном порядке (сначала число, затем строка) и
// работает верно — Duration нужно привести к тому же порядку.
func TestDurationsAsSeconds(t *testing.T) {
	snap := mustLoad(t, `
store:
  ttl: 1800
  sweep_interval: 90
consumers:
  - id: benchmark
`)

	if snap.Store.TTL != 30*time.Minute {
		t.Fatalf("ttl = %s, ожидалось 30m", snap.Store.TTL)
	}
	if snap.Store.SweepInterval != 90*time.Second {
		t.Fatalf("sweep_interval = %s, ожидалось 1m30s", snap.Store.SweepInterval)
	}
}

// TestBytesInBothForms — размер читается строкой «8MiB» и числом байт.
func TestBytesInBothForms(t *testing.T) {
	text := mustLoad(t, `
server:
  max_body_bytes: 8MiB
store:
  max_bytes: 2GiB
consumers:
  - id: benchmark
`)
	number := mustLoad(t, `
server:
  max_body_bytes: 8388608
store:
  max_bytes: 2147483648
consumers:
  - id: benchmark
`)

	if text.Server.MaxBodyBytes.Int64() != 8<<20 || number.Server.MaxBodyBytes.Int64() != 8<<20 {
		t.Fatalf("max_body_bytes: строкой %d, числом %d",
			text.Server.MaxBodyBytes.Int64(), number.Server.MaxBodyBytes.Int64())
	}
	if text.Store.MaxBytes != 2<<30 || number.Store.MaxBytes != 2<<30 {
		t.Fatalf("max_bytes: строкой %d, числом %d", text.Store.MaxBytes, number.Store.MaxBytes)
	}
}

func TestInvalidDurationRejected(t *testing.T) {
	mustFail(t, `
store:
  ttl: полчаса
consumers:
  - id: benchmark
`, "полчаса")
}

// TestUnknownFieldRejected — незнакомое поле почти всегда опечатка в имени
// настройки. Молча проигнорировать её значит тихо потерять настройку.
func TestUnknownFieldRejected(t *testing.T) {
	mustFail(t, `
server:
  addres: ":9090"
consumers:
  - id: benchmark
`, "addres")
}

func TestMissingFileReportsPath(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "нет-такого.yaml"))
	if err == nil {
		t.Fatal("отсутствующий файл принят")
	}
	if !strings.Contains(err.Error(), "нет-такого.yaml") {
		t.Fatalf("сообщение %q не называет путь", err)
	}
}

// TestNewHolderRejectsBadInitialConfig — REQ-403: отсутствие корректной
// начальной конфигурации не должно приводить к обработке запросов без защиты.
// Сервис не поднимается вовсе.
func TestNewHolderRejectsBadInitialConfig(t *testing.T) {
	h, err := NewHolder(writeConfig(t, "consumers:\n  - id: crm\n"))
	if err == nil {
		t.Fatal("Holder построен на конфигурации без потребителя benchmark")
	}
	if h != nil {
		t.Fatal("Holder возвращён вместе с ошибкой")
	}
}

// TestReloadKeepsSnapshotOnBrokenFile — ключевой тест задачи и AC-6 (REQ-403).
//
// Невалидное обновление обязано быть отклонено с сохранением действующего
// снимка: перезагрузка конфигурации происходит на работающем сервисе, и
// опечатка в файле не должна ни ронять его, ни, тем более, оставлять
// запросы без маскирования.
func TestReloadKeepsSnapshotOnBrokenFile(t *testing.T) {
	path := writeConfig(t, `
store:
  ttl: 30m
consumers:
  - id: benchmark
    types: [full_name, phone]
`)
	h, err := NewHolder(path)
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	before := h.Current()

	broken := []struct {
		name string
		body string
	}{
		{"битый YAML", "consumers: [ - id: benchmark"},
		{"незнакомое поле", "consumers:\n  - id: benchmark\n    типы: [all]\n"},
		{"неизвестный тип ПД", "consumers:\n  - id: benchmark\n    types: [telefon]\n"},
		{"неизвестная стратегия", "consumers:\n  - id: benchmark\n    mask:\n      default: невидимость\n"},
		{"нет потребителя benchmark", "consumers:\n  - id: crm\n"},
	}
	for _, b := range broken {
		if err := os.WriteFile(path, []byte(b.body), 0o600); err != nil {
			t.Fatalf("перезапись конфигурации: %v", err)
		}

		if err := h.Reload(); err == nil {
			t.Fatalf("%s: Reload не вернул ошибку", b.name)
		}

		if got := h.Current(); got != before {
			t.Fatalf("%s: снимок заменён невалидным обновлением", b.name)
		}
	}

	// Действующий снимок остался пригодным к работе, а не просто уцелел
	// как указатель.
	c, ok := before.Consumers.ByID(policy.DefaultConsumerID)
	if !ok {
		t.Fatal("в действующем снимке нет потребителя benchmark")
	}
	if c.Types != pii.NewSet(pii.FullName, pii.Phone) {
		t.Fatalf("типы действующего снимка изменились: %v", c.Types)
	}
	if before.Store.TTL != 30*time.Minute {
		t.Fatalf("ttl действующего снимка изменился: %s", before.Store.TTL)
	}
}

// TestReloadPublishesValidUpdate — обратная сторона того же требования:
// корректное обновление обязано публиковаться целиком и сразу.
func TestReloadPublishesValidUpdate(t *testing.T) {
	path := writeConfig(t, "consumers:\n  - id: benchmark\n    types: [full_name]\n")
	h, err := NewHolder(path)
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	before := h.Current()

	if err := os.WriteFile(path,
		[]byte("consumers:\n  - id: benchmark\n    types: [full_name, phone]\n"), 0o600); err != nil {
		t.Fatalf("перезапись конфигурации: %v", err)
	}
	if err := h.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	after := h.Current()
	if after == before {
		t.Fatal("снимок не заменён корректным обновлением")
	}
	c, _ := after.Consumers.ByID(policy.DefaultConsumerID)
	if c.Types != pii.NewSet(pii.FullName, pii.Phone) {
		t.Fatalf("новый снимок содержит типы %v", c.Types)
	}
	// Прежний снимок продолжает быть согласованным: читатель, взявший его до
	// перезагрузки, доработает запрос на нём.
	old, _ := before.Consumers.ByID(policy.DefaultConsumerID)
	if old.Types != pii.NewSet(pii.FullName) {
		t.Fatalf("прежний снимок изменился: %v", old.Types)
	}
	if h.Path() != path {
		t.Fatalf("Path() = %q", h.Path())
	}
}

// TestCombosFromConfigSuppressPIN — сквозная проверка AC-5: правило из
// config.yaml доходит до policy.Filter в том виде, в каком записано.
func TestCombosFromConfigSuppressPIN(t *testing.T) {
	snap := mustLoad(t, `
consumers:
  - id: benchmark
    combinations:
      - mask: [pin]
        only_with: [card_number]
`)
	c, _ := snap.Consumers.ByID(policy.DefaultConsumerID)

	alone := &detect.Result{
		Spans: []detect.Span{{Start: 0, End: 4, Type: pii.PIN}},
		Found: pii.NewSet(pii.PIN),
	}
	if got := c.Filter(alone); len(got) != 0 {
		t.Fatalf("ПИН без номера карты замаскирован: %d спанов", len(got))
	}

	withCard := &detect.Result{
		Spans: []detect.Span{
			{Start: 0, End: 4, Type: pii.PIN},
			{Start: 10, End: 26, Type: pii.CardNumber},
		},
		Found: pii.NewSet(pii.PIN, pii.CardNumber),
	}
	if got := c.Filter(withCard); len(got) != 2 {
		t.Fatalf("ПИН вместе с номером карты: %d спанов из 2", len(got))
	}
}

// TestMaskingDisabledFromConfig — REQ-402: отключение маскирования возможно
// только явной настройкой и доезжает из файла до политики.
func TestMaskingDisabledFromConfig(t *testing.T) {
	snap := mustLoad(t, `
consumers:
  - id: benchmark
  - id: analytics
    masking: false
    demask: false
    enabled: false
`)
	c, ok := snap.Consumers.ByID("analytics")
	if !ok {
		t.Fatal("потребитель analytics не найден")
	}
	if c.MaskingEnabled || c.Demask || c.Enabled {
		t.Fatalf("явные false потеряны: masking=%v demask=%v enabled=%v", c.MaskingEnabled, c.Demask, c.Enabled)
	}

	res := &detect.Result{
		Spans: []detect.Span{{Start: 0, End: 11, Type: pii.FullName}},
		Found: pii.NewSet(pii.FullName),
	}
	if got := c.Filter(res); len(got) != 0 {
		t.Fatalf("маскирование отключено, но Filter вернул %d спанов", len(got))
	}
}

// TestDisabledConsumerNotReachableByKey — отключённый потребитель не
// возвращается по ключу: проверка допуска выполняется в реестре.
func TestDisabledConsumerNotReachableByKey(t *testing.T) {
	t.Setenv("TEST_ANALYTICS_KEY", "synthetic-key-0002")

	snap := mustLoad(t, `
consumers:
  - id: benchmark
  - id: analytics
    enabled: false
    api_key_env: TEST_ANALYTICS_KEY
`)

	if _, ok := snap.Consumers.ByKey("synthetic-key-0002"); ok {
		t.Fatal("отключённый потребитель доступен по ключу")
	}
	if _, ok := snap.Consumers.ByKey(""); ok {
		t.Fatal("пустой ключ подобрал потребителя")
	}
	if _, ok := snap.Consumers.ByID("analytics"); !ok {
		t.Fatal("отключённый потребитель не виден по идентификатору")
	}
}

// TestLoadDotEnvDoesNotOverrideExisting — ключ из окружения сильнее файла:
// в контейнере переменную задают снаружи, и .env не должен её перебивать.
func TestLoadDotEnvDoesNotOverrideExisting(t *testing.T) {
	t.Setenv("TEST_DOTENV_PRESET", "из-окружения")

	path := filepath.Join(t.TempDir(), ".env")
	body := "# комментарий\n\nTEST_DOTENV_PRESET=из-файла\nTEST_DOTENV_NEW=\"значение\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("запись .env: %v", err)
	}

	if err := LoadDotEnv(path); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}

	if got := os.Getenv("TEST_DOTENV_PRESET"); got != "из-окружения" {
		t.Fatalf("переменная окружения перезаписана файлом: %q", got)
	}
	if got := os.Getenv("TEST_DOTENV_NEW"); got != "значение" {
		t.Fatalf("новая переменная = %q", got)
	}
	t.Setenv("TEST_DOTENV_NEW", "") // вернуть окружение теста в исходное состояние

	// Отсутствующий файл — не ошибка: .env опционален.
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "нет.env")); err != nil {
		t.Fatalf("отсутствующий .env вернул ошибку: %v", err)
	}
}

// TestLimitsValidated — отрицательные пределы и write_timeout не длиннее
// ожидания модели отклоняются при загрузке, а не роняют процесс паникой и не
// рвут ответы прокси (С-8 проверки качества кода 23.09).
func TestLimitsValidated(t *testing.T) {
	bad := map[string]string{
		"max_concurrent":  "server:\n  max_concurrent: -1\n",
		"request_timeout": "server:\n  request_timeout: -1s\n",
		"max_spans":       "detection:\n  max_spans: -5\n",
		"store.max_bytes": "store:\n  max_bytes: -1\n",
		"write_timeout":   "server:\n  write_timeout: 30s\nllm:\n  mode: alfagen\n  timeout: 60s\n",
	}
	for name, head := range bad {
		if _, err := loadString(t, head+minimalConfig); err == nil {
			t.Errorf("%s: невалидная конфигурация принята", name)
		}
	}
	snap, err := loadString(t, "llm:\n  mode: alfagen\n  timeout: 60s\n"+minimalConfig)
	if err != nil {
		t.Fatalf("конфигурация без write_timeout отклонена: %v", err)
	}
	if snap.Server.WriteTimeout.Duration() <= snap.LLM.Timeout.Duration() {
		t.Fatalf("write_timeout по умолчанию %s не превышает llm.timeout %s",
			snap.Server.WriteTimeout, snap.LLM.Timeout)
	}
}

// TestRestartOnlyReportsFixedSections — перезагрузка сообщает о полях, которые
// применяются только при запуске.
func TestRestartOnlyReportsFixedSections(t *testing.T) {
	prev, err := loadString(t, minimalConfig)
	if err != nil {
		t.Fatal(err)
	}
	next, err := loadString(t, "server:\n  max_concurrent: 7\nstore:\n  max_entries: 10\n"+minimalConfig)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(RestartOnly(prev, next), ",")
	if !strings.Contains(got, "server.max_concurrent") || !strings.Contains(got, "store") {
		t.Fatalf("RestartOnly = %q", got)
	}
	if n := RestartOnly(prev, prev); len(n) != 0 {
		t.Fatalf("без изменений RestartOnly = %v", n)
	}
}

// TestTypesAllWithUnknownRejected — опечатка рядом с «all» не принимается молча.
func TestTypesAllWithUnknownRejected(t *testing.T) {
	body := "consumers:\n  - id: benchmark\n    types: [all, nonexistent_type]\n"
	if _, err := loadString(t, body); err == nil {
		t.Fatal("types: [all, nonexistent_type] принят")
	}
}

// TestModelRateParsed — лимит частоты к модели задаётся на потребителя,
// по умолчанию выключен, всплеск по умолчанию — округлённая вверх частота.
func TestModelRateParsed(t *testing.T) {
	snap := mustLoad(t, `
consumers:
  - id: benchmark
  - id: demo
    api_key: rate-test-key
    model_rate: {rps: 2, burst: 5}
  - id: half
    api_key: rate-test-key-2
    model_rate: {rps: 0.5}
  - id: off
    api_key: rate-test-key-3
    model_rate: {rps: 0}
  - id: none
    api_key: rate-test-key-4
`)
	if r, ok := snap.ModelRate("demo"); !ok || r.RPS != 2 || r.Burst != 5 {
		t.Fatalf("demo: %+v, %v", r, ok)
	}
	if r, ok := snap.ModelRate("half"); !ok || r.RPS != 0.5 || r.Burst != 1 {
		t.Fatalf("half: всплеск по умолчанию %+v, %v", r, ok)
	}
	for _, id := range []string{"off", "none", benchmarkID, "unknown"} {
		if r, ok := snap.ModelRate(id); ok {
			t.Fatalf("%s: лимит %+v, ожидалось «выключен»", id, r)
		}
	}
}

// TestModelRateValidated — отрицательные значения отклоняют файл целиком, а
// не снимают лимит молча.
func TestModelRateValidated(t *testing.T) {
	for name, rate := range map[string]string{
		"rps":   "{rps: -1}",
		"burst": "{rps: 1, burst: -2}",
		"inf":   "{rps: .inf}",
		"nan":   "{rps: .nan}",
	} {
		body := "consumers:\n  - id: benchmark\n  - id: demo\n    api_key: k\n    model_rate: " + rate + "\n"
		if _, err := loadString(t, body); err == nil {
			t.Errorf("%s: model_rate %s принят", name, rate)
		}
	}
}

// TestRepoConfigLimitsPublishedKeys — в поставляемом config.yaml лимит
// включён у потребителей с опубликованными ключами и выключен у benchmark:
// контракт /process ограничивать нельзя.
func TestRepoConfigLimitsPublishedKeys(t *testing.T) {
	snap, err := Load(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatalf("config.yaml: %v", err)
	}
	for _, id := range []string{"demo", "crm", "demo-token", "demo-synthetic"} {
		if _, ok := snap.ModelRate(id); !ok {
			t.Errorf("%s: лимит частоты к модели не включён", id)
		}
	}
	if _, ok := snap.ModelRate(benchmarkID); ok {
		t.Error("benchmark: лимит частоты включён, а /process ограничивать нельзя")
	}
}
