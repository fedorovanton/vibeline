package config

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/llm"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
	"ai-gateway/internal/store"
)

// Snapshot — согласованный неизменяемый снимок конфигурации.
type Snapshot struct {
	Server    ServerSection
	Store     store.Options
	LLM       LLMSection
	Detection DetectionSection
	Logging   LoggingSection
	Consumers *policy.Registry
	// ModelRates — лимиты частоты обращений к модели по идентификатору
	// потребителя. Потребителя без лимита в карте нет. Карта неизменяема
	// после сборки, как и весь снимок.
	ModelRates map[string]RateLimit
	// LoadedAt — момент публикации снимка; попадает в /readyz и логи.
	LoadedAt time.Time
}

// RateLimit — проверенные параметры token bucket одного потребителя.
type RateLimit struct {
	// RPS — частота восполнения корзины, запросов в секунду, больше нуля.
	RPS float64
	// Burst — ёмкость корзины, не меньше одного.
	Burst int
}

// ModelRate возвращает лимит частоты обращений к модели для потребителя.
// Второе значение ложно, если лимит не настроен.
func (s *Snapshot) ModelRate(consumerID string) (RateLimit, bool) {
	if s == nil {
		return RateLimit{}, false
	}
	r, ok := s.ModelRates[consumerID]
	return r, ok
}

// Holder держит текущий снимок конфигурации.
//
// Публикация выполняется атомарной заменой указателя: читатель горячего пути
// берёт снимок один раз за запрос и работает с согласованными настройками,
// даже если в этот момент выполняется перезагрузка.
type Holder struct {
	path string
	cur  atomic.Pointer[Snapshot]
}

// NewHolder читает конфигурацию и публикует первый снимок.
func NewHolder(path string) (*Holder, error) {
	h := &Holder{path: path}
	if err := h.Reload(); err != nil {
		return nil, err
	}
	return h, nil
}

// Current возвращает текущий снимок.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Path возвращает путь к файлу конфигурации.
func (h *Holder) Path() string { return h.path }

// Reload перечитывает файл и публикует новый снимок.
//
// При любой ошибке разбора или проверки снимок не заменяется: сервис
// продолжает работать на последней корректной конфигурации.
func (h *Holder) Reload() error {
	snap, err := Load(h.path)
	if err != nil {
		return err
	}
	h.cur.Store(snap)
	return nil
}

// Load читает и проверяет конфигурацию, возвращая готовый снимок.
func Load(path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение конфигурации %s: %w", path, err)
	}
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("разбор конфигурации %s: %w", path, err)
	}
	return build(&f)
}

func build(f *File) (*Snapshot, error) {
	applyDefaults(f)

	if err := validateLimits(f); err != nil {
		return nil, err
	}

	profile, ok := detect.ParseProfile(f.Detection.Profile)
	if !ok {
		return nil, fmt.Errorf("detection.profile: неизвестный профиль %q (доступны: balanced, strict, paranoid)", f.Detection.Profile)
	}
	switch f.LLM.Mode {
	case "alfagen", llm.ModeStub:
	default:
		return nil, fmt.Errorf("llm.mode: неизвестный режим %q (доступны: alfagen, stub)", f.LLM.Mode)
	}

	consumers := make([]*policy.Consumer, 0, len(f.Consumers))
	rates := make(map[string]RateLimit, len(f.Consumers))
	for i := range f.Consumers {
		c, err := buildConsumer(&f.Consumers[i], profile, f.Detection.MaxSpans)
		if err != nil {
			return nil, err
		}
		consumers = append(consumers, c)
		rate, on, err := buildRate(&f.Consumers[i])
		if err != nil {
			return nil, err
		}
		if on {
			rates[c.ID] = rate
		}
	}
	reg, err := policy.NewRegistry(consumers)
	if err != nil {
		return nil, fmt.Errorf("consumers: %w", err)
	}

	return &Snapshot{
		Server: f.Server,
		Store: store.Options{
			TTL:           f.Store.TTL.Duration(),
			MaxEntries:    f.Store.MaxEntries,
			MaxBytes:      f.Store.MaxBytes.Int64(),
			SweepInterval: f.Store.SweepInterval.Duration(),
		},
		LLM:        f.LLM,
		Detection:  f.Detection,
		Logging:    f.Logging,
		Consumers:  reg,
		ModelRates: rates,
		LoadedAt:   time.Now(),
	}, nil
}

func buildConsumer(s *ConsumerSection, defProfile detect.Profile, defMaxSpans int) (*policy.Consumer, error) {
	types, err := parseTypes(s.ID, s.Types)
	if err != nil {
		return nil, err
	}
	profile := defProfile
	if s.Profile != "" {
		p, ok := detect.ParseProfile(s.Profile)
		if !ok {
			return nil, fmt.Errorf("потребитель %q: неизвестный профиль %q", s.ID, s.Profile)
		}
		profile = p
	}
	perType := make(map[pii.Type]string, len(s.Mask.PerType))
	for key, strat := range s.Mask.PerType {
		t, ok := pii.ByKey(key)
		if !ok {
			return nil, fmt.Errorf("потребитель %q, mask.per_type: неизвестный тип ПД %q", s.ID, key)
		}
		perType[t] = strat
	}
	combos := make([]policy.Combo, 0, len(s.Combos))
	for i, cb := range s.Combos {
		m, err := parseTypeList(s.ID, fmt.Sprintf("combinations[%d].mask", i), cb.Mask)
		if err != nil {
			return nil, err
		}
		w, err := parseTypeList(s.ID, fmt.Sprintf("combinations[%d].only_with", i), cb.OnlyWith)
		if err != nil {
			return nil, err
		}
		combos = append(combos, policy.Combo{Mask: m, OnlyWith: w})
	}
	maxSpans := defMaxSpans
	if s.MaxSpans > 0 {
		maxSpans = s.MaxSpans
	}

	return policy.NewConsumer(policy.Consumer{
		ID:             s.ID,
		Enabled:        boolOr(s.Enabled, true),
		APIKey:         resolveKey(s.APIKeyEnv, s.APIKey),
		Types:          types,
		Demask:         boolOr(s.Demask, true),
		Profile:        profile,
		MaskingEnabled: boolOr(s.Masking, true),
		MaxSpans:       maxSpans,
	}, s.Mask.Default, perType, combos)
}

// buildRate проверяет лимит частоты обращений к модели.
//
// Отрицательные значения — ошибка настройки, а не «без лимита»: оператор,
// написавший rps: -1, явно чего-то хотел, и молча снять лимит с публичного
// ключа здесь хуже, чем отклонить файл. Нулевая частота выключает лимит.
func buildRate(s *ConsumerSection) (RateLimit, bool, error) {
	r := s.ModelRate
	if r == nil {
		return RateLimit{}, false, nil
	}
	switch {
	case r.RPS < 0 || math.IsNaN(r.RPS) || math.IsInf(r.RPS, 0):
		return RateLimit{}, false, fmt.Errorf("потребитель %q, model_rate.rps: ожидается неотрицательное число", s.ID)
	case r.Burst < 0:
		return RateLimit{}, false, fmt.Errorf("потребитель %q, model_rate.burst: всплеск не может быть отрицательным", s.ID)
	case r.RPS == 0:
		return RateLimit{}, false, nil
	}
	burst := r.Burst
	if burst == 0 {
		burst = max(1, int(math.Ceil(r.RPS)))
	}
	return RateLimit{RPS: r.RPS, Burst: burst}, true, nil
}

func parseTypes(consumer string, list []string) (pii.Set, error) {
	if len(list) == 0 {
		return pii.FullSet(), nil
	}
	if len(list) == 1 && list[0] == "all" {
		return pii.FullSet(), nil
	}
	return parseTypeList(consumer, "types", list)
}

func parseTypeList(consumer, field string, list []string) (pii.Set, error) {
	// Список проверяется целиком и тогда, когда в нём есть «all»: иначе
	// опечатка после «all» молча принималась бы (техническое жюри 23.09).
	var set pii.Set
	all := false
	for _, key := range list {
		if key == "all" {
			all = true
			continue
		}
		t, ok := pii.ByKey(key)
		if !ok {
			return 0, fmt.Errorf("потребитель %q, %s: неизвестный тип ПД %q", consumer, field, key)
		}
		set = set.Add(t)
	}
	if all {
		return pii.FullSet(), nil
	}
	return set, nil
}

// resolveKey выбирает ключ доступа потребителя.
//
// Переменная окружения имеет приоритет: она задаётся на конкретном стенде и
// не попадает ни в репозиторий, ни в архив. Значение из конфигурации —
// запасной путь для демонстрационного потребителя.
func resolveKey(envName, literal string) string {
	if envName != "" {
		if v := os.Getenv(envName); v != "" {
			return v
		}
	}
	return literal
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// validateLimits отклоняет числовые настройки, с которыми сервис не может
// работать: отрицательный предел одновременной обработки ронял процесс
// паникой при создании семафора, а write_timeout не длиннее ожидания модели
// рвал ответ прокси раньше, чем модель успевала ответить.
func validateLimits(f *File) error {
	switch {
	case f.Server.MaxConcurrent < 0:
		return fmt.Errorf("server.max_concurrent: %d — предел не может быть отрицательным", f.Server.MaxConcurrent)
	case f.Server.MaxBodyBytes < 0:
		return fmt.Errorf("server.max_body_bytes: предел не может быть отрицательным")
	case f.Server.ReadTimeout < 0, f.Server.WriteTimeout < 0, f.Server.IdleTimeout < 0,
		f.Server.RequestTimeout < 0, f.Server.ShutdownTimeout < 0, f.LLM.Timeout < 0:
		return fmt.Errorf("server.*_timeout, llm.timeout: таймаут не может быть отрицательным")
	case f.Store.MaxEntries < 0 || f.Store.MaxBytes < 0 || f.Store.TTL < 0:
		return fmt.Errorf("store: пределы и ttl не могут быть отрицательными")
	case f.Detection.MaxSpans < 0:
		return fmt.Errorf("detection.max_spans: предел не может быть отрицательным")
	case f.LLM.Mode == "alfagen" && f.Server.WriteTimeout <= f.LLM.Timeout:
		return fmt.Errorf("server.write_timeout (%s) должен превышать llm.timeout (%s): иначе ответ прокси обрывается раньше ответа модели",
			f.Server.WriteTimeout, f.LLM.Timeout)
	}
	return nil
}

// RestartOnly перечисляет настройки, которые изменились в next по сравнению с
// prev, но применяются только при запуске: адрес и таймауты HTTP-сервера,
// предел одновременной обработки, хранилище и журнал. Перезагрузка по SIGHUP
// публикует снимок целиком, но эти части уже встроены в работающие объекты,
// и молчать об этом нельзя — оператор решит, что правка вступила в силу.
func RestartOnly(prev, next *Snapshot) []string {
	var out []string
	ps, ns := prev.Server, next.Server
	if ps.Addr != ns.Addr {
		out = append(out, "server.addr")
	}
	if ps.MaxConcurrent != ns.MaxConcurrent {
		out = append(out, "server.max_concurrent")
	}
	if ps.ReadTimeout != ns.ReadTimeout || ps.WriteTimeout != ns.WriteTimeout || ps.IdleTimeout != ns.IdleTimeout {
		out = append(out, "server.read_timeout/write_timeout/idle_timeout")
	}
	pst, nst := prev.Store, next.Store
	if pst.TTL != nst.TTL || pst.MaxEntries != nst.MaxEntries || pst.MaxBytes != nst.MaxBytes || pst.SweepInterval != nst.SweepInterval {
		out = append(out, "store")
	}
	if prev.Logging != next.Logging {
		out = append(out, "logging")
	}
	return out
}

func applyDefaults(f *File) {
	setStr(&f.Server.Addr, ":8080")
	setBytes(&f.Server.MaxBodyBytes, 8<<20)
	setInt(&f.Server.MaxConcurrent, 1024)
	setDur(&f.Server.ReadTimeout, 5*time.Second)
	// write_timeout по умолчанию выводится из ожидания модели ниже: прежние
	// 15 с при llm.timeout 60 с рвали ответ прокси.
	setDur(&f.Server.IdleTimeout, 60*time.Second)
	setDur(&f.Server.RequestTimeout, 9*time.Second)
	setDur(&f.Server.ShutdownTimeout, 10*time.Second)

	setDur(&f.Store.TTL, 30*time.Minute)
	setInt(&f.Store.MaxEntries, 2_000_000)
	setBytes(&f.Store.MaxBytes, 2<<30)
	setDur(&f.Store.SweepInterval, time.Minute)

	setStr(&f.LLM.Mode, llm.ModeStub)
	setStr(&f.LLM.BaseURL, "https://alfagen.alfabank.ru/continue-dev/v1")
	setStr(&f.LLM.Model, "deepseek-ai/DeepSeek-V4-Flash-0731")
	setDur(&f.LLM.Timeout, 60*time.Second)
	setDur(&f.Server.WriteTimeout, f.LLM.Timeout.Duration()+f.Server.RequestTimeout.Duration()+5*time.Second)
	setStr(&f.LLM.APIKeyEnv, "ALFAGEN_API_KEY")

	setStr(&f.Detection.Profile, "balanced")
	setInt(&f.Detection.MaxSpans, 20_000)

	setStr(&f.Logging.Level, "info")
	setStr(&f.Logging.Format, "json")
}

func setStr(p *string, def string) {
	if *p == "" {
		*p = def
	}
}

func setInt(p *int, def int) {
	if *p == 0 {
		*p = def
	}
}

func setDur(p *Duration, def time.Duration) {
	if *p == 0 {
		*p = Duration(def)
	}
}

func setBytes(p *Bytes, def int64) {
	if *p == 0 {
		*p = Bytes(def)
	}
}

// LoadDotEnv подгружает переменные окружения из файла .env, не затирая уже
// заданные. Ключ AlfaGen хранится именно так: решение работает на любой машине
// без правки кода и глобальных переменных, а файл исключён из Git.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("чтение %s: %w", path, err)
	}
	// Файл открыт только на чтение: ошибка закрытия не влияет на уже
	// прочитанные значения, и вернуть её вместо результата разбора нечем.
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, val, ok := strings.Cut(text, "=")
		if !ok {
			return fmt.Errorf("%s, строка %d: ожидается KEY=VALUE", path, line)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, val); err != nil {
			return fmt.Errorf("установка переменной %s: %w", key, err)
		}
	}
	return sc.Err()
}
