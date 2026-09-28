package policy

import (
	"strings"
	"testing"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/pii"
)

// Все значения в тестах синтетические: спаны задаются смещениями, сами
// персональные данные в файл не попадают.

// Фикстуры тестов: идентификатор потребителя и имена стратегий.
const (
	testConsumerID      = "crm"
	strategyPlaceholder = "placeholder"
	strategyAsterisks   = "asterisks"
	strategySynthetic   = "synthetic"
	unknownStrategy     = "нет-такой"
	fmtNewConsumer      = "NewConsumer: %v"
)

// consumer собирает потребителя для теста и падает на ошибке сборки.
func consumer(t *testing.T, combos []Combo, opts ...func(*Consumer)) *Consumer {
	t.Helper()
	c := Consumer{
		ID:             testConsumerID,
		Enabled:        true,
		Types:          pii.FullSet(),
		MaskingEnabled: true,
		Profile:        detect.Balanced,
	}
	for _, o := range opts {
		o(&c)
	}
	built, err := NewConsumer(c, strategyPlaceholder, nil, combos)
	if err != nil {
		t.Fatalf(fmtNewConsumer, err)
	}
	return built
}

// result собирает итог детекции: спаны и множество найденных типов.
func result(types ...pii.Type) *detect.Result {
	r := &detect.Result{}
	for i, tp := range types {
		r.Spans = append(r.Spans, detect.Span{
			Start: int32(i * 10), End: int32(i*10 + 4), Type: tp,
		})
		r.Found = r.Found.Add(tp)
		r.Counts[tp]++
	}
	return r
}

func maskedTypes(spans []detect.Span) pii.Set {
	var s pii.Set
	for _, sp := range spans {
		s = s.Add(sp.Type)
	}
	return s
}

// TestComboPINRequiresCardNumber — AC-5 и REQ-401. Пин-код сам по себе
// четырёхзначное число и без номера карты персональными данными не является:
// маскировать каждое «1234» в тексте — это шум, за который снимают баллы за
// избыточность.
func TestComboPINRequiresCardNumber(t *testing.T) {
	c := consumer(t, []Combo{{
		Mask:     pii.NewSet(pii.PIN),
		OnlyWith: pii.NewSet(pii.CardNumber),
	}})

	alone := c.Filter(result(pii.PIN))
	if len(alone) != 0 {
		t.Fatalf("ПИН без номера карты замаскирован: %v", maskedTypes(alone))
	}

	withCard := c.Filter(result(pii.PIN, pii.CardNumber))
	got := maskedTypes(withCard)
	if !got.Has(pii.PIN) {
		t.Fatalf("ПИН вместе с номером карты не замаскирован: %v", got)
	}
	if !got.Has(pii.CardNumber) {
		t.Fatalf("номер карты не замаскирован: %v", got)
	}
}

// TestComboCVVRequiresCardNumber — то же правило для CVV.
func TestComboCVVRequiresCardNumber(t *testing.T) {
	c := consumer(t, []Combo{{
		Mask:     pii.NewSet(pii.CVV),
		OnlyWith: pii.NewSet(pii.CardNumber),
	}})

	if got := c.Filter(result(pii.CVV)); len(got) != 0 {
		t.Fatalf("CVV без номера карты замаскирован: %v", maskedTypes(got))
	}
	if got := maskedTypes(c.Filter(result(pii.CVV, pii.CardNumber))); !got.Has(pii.CVV) {
		t.Fatalf("CVV вместе с номером карты не замаскирован: %v", got)
	}
}

// TestCombosApplyIndependently — правила не влияют друг на друга: выполнение
// одного не снимает подавление, наложенное другим.
func TestCombosApplyIndependently(t *testing.T) {
	c := consumer(t, []Combo{
		{Mask: pii.NewSet(pii.PIN), OnlyWith: pii.NewSet(pii.CardNumber)},
		{Mask: pii.NewSet(pii.CVV), OnlyWith: pii.NewSet(pii.CardHolder)},
	})

	// Есть номер карты, но нет держателя: первое правило выполнено,
	// второе — нет.
	got := maskedTypes(c.Filter(result(pii.PIN, pii.CVV, pii.CardNumber)))

	if !got.Has(pii.PIN) {
		t.Fatalf("ПИН подавлен, хотя номер карты найден: %v", got)
	}
	if got.Has(pii.CVV) {
		t.Fatalf("CVV замаскирован без имени держателя: %v", got)
	}
	if !got.Has(pii.CardNumber) {
		t.Fatalf("номер карты не замаскирован: %v", got)
	}
}

// TestComboRequiresAllCompanions — правило требует все сопутствующие типы,
// а не любой из них.
func TestComboRequiresAllCompanions(t *testing.T) {
	c := consumer(t, []Combo{{
		Mask:     pii.NewSet(pii.PIN),
		OnlyWith: pii.NewSet(pii.CardNumber, pii.CardHolder),
	}})

	if got := c.Filter(result(pii.PIN, pii.CardNumber)); maskedTypes(got).Has(pii.PIN) {
		t.Fatal("ПИН замаскирован, хотя найден только один из двух требуемых типов")
	}
	got := maskedTypes(c.Filter(result(pii.PIN, pii.CardNumber, pii.CardHolder)))
	if !got.Has(pii.PIN) {
		t.Fatalf("ПИН не замаскирован при обоих требуемых типах: %v", got)
	}
}

// TestNoCombosKeepsAllSpans — без правил Filter не трогает результат детекции.
func TestNoCombosKeepsAllSpans(t *testing.T) {
	c := consumer(t, nil)
	res := result(pii.PIN, pii.FullName)

	got := c.Filter(res)

	if len(got) != len(res.Spans) {
		t.Fatalf("осталось %d спанов из %d", len(got), len(res.Spans))
	}
}

// TestMaskingDisabledSuppressesEverything — REQ-402. Отключение маскирования
// допускается только явной настройкой и видно в результате Filter.
func TestMaskingDisabledSuppressesEverything(t *testing.T) {
	c := consumer(t, nil, func(c *Consumer) { c.MaskingEnabled = false })

	got := c.Filter(result(pii.FullName, pii.CardNumber, pii.Phone))

	if len(got) != 0 {
		t.Fatalf("при отключённом маскировании осталось %d спанов: %v", len(got), maskedTypes(got))
	}
}

// TestTypesLimitDetection — перечень типов потребителя ограничивает поиск:
// тип вне списка не ищется движком и, значит, не маскируется. Ограничение
// применяется через Options.Types, а не в Filter: не найденный спан нечего
// фильтровать.
func TestTypesLimitDetection(t *testing.T) {
	c := consumer(t, nil, func(c *Consumer) {
		c.Types = pii.NewSet(pii.FullName, pii.Phone)
	})

	opts := c.DetectOptions()

	if !opts.Types.Has(pii.FullName) || !opts.Types.Has(pii.Phone) {
		t.Fatalf("перечисленные типы потеряны: %v", opts.Types)
	}
	if opts.Types.Has(pii.CardNumber) {
		t.Fatalf("тип вне списка потребителя попал в настройки детекции: %v", opts.Types)
	}
	if opts.Profile != c.Profile {
		t.Fatalf("профиль %v вместо %v", opts.Profile, c.Profile)
	}
}

// TestStrategyPerTypeOverridesDefault — REQ-302: стратегия выбирается на
// уровне потребителя и может переопределяться для отдельного типа.
func TestStrategyPerTypeOverridesDefault(t *testing.T) {
	c, err := NewConsumer(
		Consumer{ID: testConsumerID, Enabled: true, MaskingEnabled: true},
		strategyPlaceholder,
		map[pii.Type]string{pii.CardNumber: strategyAsterisks, pii.FullName: strategySynthetic},
		nil,
	)
	if err != nil {
		t.Fatalf(fmtNewConsumer, err)
	}

	if got := c.StrategyName(pii.CardNumber); got != strategyAsterisks {
		t.Fatalf("стратегия для номера карты %q, ожидалась \"asterisks\"", got)
	}
	if got := c.StrategyName(pii.FullName); got != strategySynthetic {
		t.Fatalf("стратегия для ФИО %q, ожидалась \"synthetic\"", got)
	}
	// Тип без переопределения получает стратегию по умолчанию.
	if got := c.StrategyName(pii.Phone); got != strategyPlaceholder {
		t.Fatalf("стратегия для телефона %q, ожидалась \"placeholder\"", got)
	}
	if got := c.DefaultStrategyName(); got != strategyPlaceholder {
		t.Fatalf("стратегия по умолчанию %q", got)
	}
}

// TestStrategyDefaultsToPlaceholder — пустое имя стратегии означает формат
// маски по умолчанию, а не отсутствие маскирования.
func TestStrategyDefaultsToPlaceholder(t *testing.T) {
	c, err := NewConsumer(Consumer{ID: testConsumerID}, "", nil, nil)
	if err != nil {
		t.Fatalf(fmtNewConsumer, err)
	}
	if got := c.DefaultStrategyName(); got != strategyPlaceholder {
		t.Fatalf("стратегия по умолчанию %q, ожидалась \"placeholder\"", got)
	}
}

// TestNewConsumerRejectsUnknownStrategy — опечатка в конфигурации обязана
// остановить загрузку, а не молча оставить потребителя без маскирования.
func TestNewConsumerRejectsUnknownStrategy(t *testing.T) {
	_, err := NewConsumer(Consumer{ID: testConsumerID}, unknownStrategy, nil, nil)
	if err == nil {
		t.Fatal("неизвестная стратегия по умолчанию принята")
	}
	requireMentions(t, err.Error(), testConsumerID, unknownStrategy)
	// Сообщение перечисляет доступные имена: без этого исправлять опечатку
	// приходится чтением исходников.
	for _, name := range []string{strategyPlaceholder, strategyAsterisks, "token", strategySynthetic} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("сообщение %q не перечисляет стратегию %q", err, name)
		}
	}

	_, err = NewConsumer(Consumer{ID: testConsumerID}, strategyPlaceholder,
		map[pii.Type]string{pii.CardNumber: unknownStrategy}, nil)
	if err == nil {
		t.Fatal("неизвестная стратегия для типа принята")
	}
	requireMentions(t, err.Error(), testConsumerID, pii.CardNumber.Key(), unknownStrategy)
}

// TestNewConsumerRejectsEmptyComboLists — пустой список в правиле комбинации
// читается двусмысленно: «маскировать всегда» или «не маскировать никогда».
// Такую конфигурацию надёжнее отклонить.
func TestNewConsumerRejectsEmptyComboLists(t *testing.T) {
	_, err := NewConsumer(Consumer{ID: testConsumerID}, strategyPlaceholder, nil,
		[]Combo{{OnlyWith: pii.NewSet(pii.CardNumber)}})
	if err == nil {
		t.Fatal("правило с пустым mask принято")
	}
	requireMentions(t, err.Error(), testConsumerID, "mask")

	_, err = NewConsumer(Consumer{ID: testConsumerID}, strategyPlaceholder, nil,
		[]Combo{{Mask: pii.NewSet(pii.PIN)}})
	if err == nil {
		t.Fatal("правило с пустым only_with принято")
	}
	requireMentions(t, err.Error(), testConsumerID, "only_with")
}

// TestNewConsumerRejectsEmptyID — потребитель без идентификатора не может
// быть областью изоляции: его нечем назвать ни в логах, ни в Store.
func TestNewConsumerRejectsEmptyID(t *testing.T) {
	if _, err := NewConsumer(Consumer{}, strategyPlaceholder, nil, nil); err == nil {
		t.Fatal("потребитель без идентификатора принят")
	}
}

// TestCombosExposed — правила доступны для README, демо-стенда и отчётов.
func TestCombosExposed(t *testing.T) {
	combos := []Combo{{Mask: pii.NewSet(pii.PIN), OnlyWith: pii.NewSet(pii.CardNumber)}}
	c := consumer(t, combos)

	got := c.Combos()

	if len(got) != 1 || !got[0].Mask.Has(pii.PIN) || !got[0].OnlyWith.Has(pii.CardNumber) {
		t.Fatalf("Combos() = %v", got)
	}
}

// requireMentions проверяет, что сообщение об ошибке называет всё, что нужно
// для её исправления без чтения кода.
func requireMentions(t *testing.T, msg string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(msg, p) {
			t.Fatalf("сообщение %q не содержит %q", msg, p)
		}
	}
}
