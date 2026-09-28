// Package policy — правила обработки для конкретной системы-потребителя.
//
// Политика отвечает на три вопроса: допущен ли потребитель к сервису, какие
// типы ПД для него маскируются и каким способом, разрешено ли ему
// демаскирование (ТЗ §3.2.4).
package policy

import (
	"fmt"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/mask"
	"ai-gateway/internal/pii"
)

// Combo — правило маскирования по комбинации типов (ТЗ §6).
//
// Типы из Mask маскируются только при условии, что в тексте найдены все типы
// из OnlyWith. Пример: пин-код сам по себе не маскируется, пин-код вместе с
// номером карты — маскируется.
type Combo struct {
	Mask     pii.Set
	OnlyWith pii.Set
}

// Consumer — настроенная система-потребитель.
//
// Значение неизменяемо после сборки конфигурации и безопасно для
// конкурентного чтения.
type Consumer struct {
	ID      string
	Enabled bool
	// APIKey — ключ доступа к продуктовым эндпоинтам. Пустой ключ означает,
	// что потребитель доступен только как потребитель по умолчанию.
	APIKey string
	// Types — типы ПД, которые маскируются для этого потребителя.
	Types pii.Set
	// Demask — разрешено ли потребителю обратное преобразование.
	Demask bool
	// Profile — режим отнесения кандидатов к ПД.
	Profile detect.Profile
	// MaskingEnabled позволяет полностью отключить маскирование для
	// потребителя. Отключение допускается только явной настройкой и никогда
	// не включается автоматически при отказе защитной обработки.
	MaskingEnabled bool
	// MaxSpans ограничивает число замен в одном запросе.
	MaxSpans int

	defaultStrategy mask.Strategy
	perType         map[pii.Type]mask.Strategy
	combos          []Combo
}

// NewConsumer собирает потребителя и проверяет согласованность настроек.
func NewConsumer(c Consumer, defaultName string, perTypeNames map[pii.Type]string, combos []Combo) (*Consumer, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("потребитель без идентификатора")
	}
	if defaultName == "" {
		defaultName = "placeholder"
	}
	def, ok := mask.ByName(defaultName)
	if !ok {
		return nil, fmt.Errorf("потребитель %q: неизвестная стратегия маскирования %q (доступны: %v)", c.ID, defaultName, mask.Names())
	}
	c.defaultStrategy = def

	if len(perTypeNames) > 0 {
		c.perType = make(map[pii.Type]mask.Strategy, len(perTypeNames))
		for t, name := range perTypeNames {
			s, ok := mask.ByName(name)
			if !ok {
				return nil, fmt.Errorf("потребитель %q, тип %s: неизвестная стратегия %q", c.ID, t.Key(), name)
			}
			c.perType[t] = s
		}
	}
	for i, cb := range combos {
		if cb.Mask.Empty() {
			return nil, fmt.Errorf("потребитель %q, правило комбинации %d: пустой список mask", c.ID, i+1)
		}
		if cb.OnlyWith.Empty() {
			return nil, fmt.Errorf("потребитель %q, правило комбинации %d: пустой список only_with", c.ID, i+1)
		}
	}
	c.combos = combos
	return &c, nil
}

// Strategy возвращает стратегию маскирования для типа.
func (c *Consumer) Strategy(t pii.Type) mask.Strategy {
	if s, ok := c.perType[t]; ok {
		return s
	}
	return c.defaultStrategy
}

// StrategyName возвращает имя стратегии для типа — для README, логов и UI.
func (c *Consumer) StrategyName(t pii.Type) string { return c.Strategy(t).Name() }

// DefaultStrategyName возвращает имя стратегии по умолчанию.
func (c *Consumer) DefaultStrategyName() string { return c.defaultStrategy.Name() }

// Combos возвращает правила комбинаций потребителя.
func (c *Consumer) Combos() []Combo { return c.combos }

// DetectOptions переводит политику в настройки движка детекции.
func (c *Consumer) DetectOptions() detect.Options {
	return detect.Options{Profile: c.Profile, Types: c.Types, MaxSpans: c.MaxSpans}
}

// Filter применяет правила комбинаций к результату детекции.
//
// Возвращается подмножество спанов, подлежащих маскированию. Исходный слайс
// не изменяется, если фильтровать нечего.
func (c *Consumer) Filter(res *detect.Result) []detect.Span {
	if !c.MaskingEnabled {
		return nil
	}
	if len(c.combos) == 0 || len(res.Spans) == 0 {
		return res.Spans
	}
	var suppressed pii.Set
	for _, cb := range c.combos {
		if satisfied(res.Found, cb.OnlyWith) {
			continue
		}
		for _, t := range cb.Mask.Types() {
			suppressed = suppressed.Add(t)
		}
	}
	if suppressed.Empty() {
		return res.Spans
	}
	out := make([]detect.Span, 0, len(res.Spans))
	for _, s := range res.Spans {
		if suppressed.Has(s.Type) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// satisfied сообщает, что в found присутствуют все типы из need.
func satisfied(found, need pii.Set) bool { return found&need == need }
