// Package gateway — ядро обработки: детекция, политика, маскирование,
// сохранение соответствия и обратное преобразование.
//
// Пакет не знает про HTTP. Транспорт вызывает его методы и переводит исходы в
// коды ответа; это позволяет проверять поведение ядра без сети.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/mask"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
	"ai-gateway/internal/store"
)

// ErrSpanLimit — в тексте больше значений к маскированию, чем разрешает
// предел замен потребителя (detection.max_spans или его переопределение).
//
// Это отказ защиты, а не повод отдать частичную маску: значения сверх
// предела остались бы в тексте открытыми. Исход по контурам (REQ-600):
// /process скрывает строку целиком с сохранением оригинала, прокси к модели
// и явный API маскирования отказывают без выпуска и без записи соответствия.
var ErrSpanLimit = errors.New("gateway: значений к маскированию больше предела замен")

// Service — ядро обработки.
//
// Экземпляр неизменяем и безопасен для конкурентного использования: всё
// изменяемое состояние запроса живёт в рабочей области из пула.
type Service struct {
	engine *detect.Engine
	store  store.Store
	pool   sync.Pool
	now    func() time.Time
}

// New создаёт ядро обработки.
func New(engine *detect.Engine, st store.Store) *Service {
	s := &Service{engine: engine, store: st, now: time.Now}
	s.pool.New = func() any { return &workspace{} }
	return s
}

// workspaceFromPool берёт рабочую область из пула. В пул кладутся только
// *workspace, поэтому запасной путь — лишь защита от паники приведения.
func (s *Service) workspaceFromPool() *workspace {
	if w, ok := s.pool.Get().(*workspace); ok {
		return w
	}
	return &workspace{}
}

// SetClock подменяет источник времени. Предназначено для тестов.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Store возвращает хранилище соответствий — для метрик и диагностики.
func (s *Service) Store() store.Store { return s.store }

// Engine возвращает движок детекции — для диагностики и README.
func (s *Service) Engine() *detect.Engine { return s.engine }

// workspace — переиспользуемые буферы одного запроса.
//
// Рабочая область возвращается в пул только после того, как все производные
// от неё данные скопированы: ссылки на её буферы не покидают обработку.
type workspace struct {
	doc  lex.Doc
	cand detect.Candidates
	res  detect.Result
	appl mask.Applier
}

// MaskResult — итог маскирования одного текста.
type MaskResult struct {
	// Text — защищённый текст. Собственная строка, не ссылается на буферы пула.
	Text string
	// Spans — применённые спаны в порядке появления. Копия.
	Spans []detect.Span
	// Applied — выполненные замены. Копия.
	Applied []mask.Applied
	// Detected — типы, найденные детекцией до применения политики.
	Detected pii.Set
	// Masked — типы, фактически замаскированные.
	Masked pii.Set
	// DetectedCounts и MaskedCounts — счётчики по типам для метрик и логов.
	DetectedCounts [pii.Count]uint16
	MaskedCounts   [pii.Count]uint16
	// Degraded отмечает, что сработал безопасный откат: текст скрыт целиком,
	// потому что штатную обработку завершить не удалось.
	Degraded bool
	// DetectNs, PolicyNs и MaskNs — длительности этапов в наносекундах.
	//
	// Измеряются всегда, а не по флагу трассировки: три обращения к
	// монотонным часам стоят около сотни наносекунд на запрос — тысячные доли
	// процента от девяти с половиной миллисекунд среднего ответа. Флаг,
	// протянутый через ядро ради этой экономии, обошёлся бы дороже в чтении
	// кода, чем сами измерения — в исполнении.
	DetectNs int64
	PolicyNs int64
	MaskNs   int64
}

// Mask находит и маскирует персональные данные согласно политике потребителя.
//
// Ошибка означает, что защиту завершить не удалось. Вызывающий код обязан
// трактовать её как отказ: передавать исходный или частично обработанный текст
// дальше запрещено. Превышение предела замен отличимо через ErrSpanLimit.
func (s *Service) Mask(ctx context.Context, text string, c *policy.Consumer) (MaskResult, error) {
	return s.mask(ctx, text, c, nil)
}

// mask — общая часть Mask и проксирования. Пустой num означает собственную
// нумерацию текста; непустой — нумерацию, общую для всех сообщений одного
// запроса к модели.
func (s *Service) mask(ctx context.Context, text string, c *policy.Consumer, num *mask.Numbering) (res MaskResult, err error) {
	w := s.workspaceFromPool()
	defer s.pool.Put(w)

	defer func() {
		if r := recover(); r != nil {
			res = MaskResult{}
			err = fmt.Errorf("паника при маскировании: %v", r)
		}
	}()

	detectStart := time.Now()
	lex.Tokenize(text, &w.doc)
	if _, err := s.engine.Detect(ctx, &w.doc, c.DetectOptions(), &w.cand, &w.res); err != nil {
		return MaskResult{}, fmt.Errorf("детекция не завершена: %w", err)
	}
	if w.res.LimitExceeded {
		// Разметка неполна: маска по ней оставила бы значения сверх предела
		// открытыми при внешне успешном ответе (T-52).
		return MaskResult{}, ErrSpanLimit
	}

	policyStart := time.Now()
	spans := c.Filter(&w.res)

	maskStart := time.Now()
	// Повторы отобранных значений, которые детекция не опознала, скрываются
	// той же заменой (С-4, T-56): иначе на /process они уходили открытыми, а
	// на продуктовом контуре VerifyReplaced отклонял весь запрос.
	spans = w.appl.CoverRepeats(text, spans)
	if c.MaxSpans > 0 && len(spans) > c.MaxSpans {
		// Повторы тоже замены: предел считается по итоговому списку.
		return MaskResult{}, ErrSpanLimit
	}
	var masked string
	var applied []mask.Applied
	if num == nil {
		masked, applied = w.appl.Apply(text, spans, c.Strategy)
	} else {
		masked, applied = w.appl.ApplyNumbered(text, spans, c.Strategy, num)
	}
	maskEnd := time.Now()

	res = MaskResult{
		Text:           masked,
		Spans:          append([]detect.Span(nil), spans...),
		Applied:        append([]mask.Applied(nil), applied...),
		Detected:       w.res.Found,
		DetectedCounts: w.res.Counts,
		DetectNs:       policyStart.Sub(detectStart).Nanoseconds(),
		PolicyNs:       maskStart.Sub(policyStart).Nanoseconds(),
		MaskNs:         maskEnd.Sub(maskStart).Nanoseconds(),
	}
	for _, sp := range spans {
		res.Masked = res.Masked.Add(sp.Type)
		res.MaskedCounts[sp.Type]++
		if sp.Rule == mask.RuleRepeat {
			// Повтор найден точным совпадением с найденным значением — для
			// счётчиков это тоже обнаружение: замаскированных не больше,
			// чем обнаруженных.
			res.DetectedCounts[sp.Type]++
		}
	}
	return res, nil
}

// MaskReserved — Mask для текста, маска которого потом восстанавливается по
// плейсхолдерам в изменённом тексте (явный API /api/v1/mask и unmask).
//
// Номер, чья замена или её метка без скобок уже буквально написаны во входе,
// не выдаётся — как на прокси к модели (D-3, T-47; С-6, T-56). Иначе
// восстановление не отличило бы выданный «[ФИО_1]» от написанного
// пользователем и подставило бы значение на место буквального текста.
//
// Функция по-прежнему чистая от (text, политика): повторный вызов на том же
// тексте даёт ту же маску, на этом держится восстановление изменённой маски.
func (s *Service) MaskReserved(ctx context.Context, text string, c *policy.Consumer) (MaskResult, error) {
	return s.mask(ctx, text, c, &mask.Numbering{Reserved: literalIn(text)})
}

// MaskFullText — безопасный откат: текст скрывается целиком одним
// плейсхолдером.
//
// Применяется только там, где отказ в обслуживании хуже избыточного
// маскирования. Утечки не происходит: наружу не уходит ни одного исходного
// символа. Цена — штраф за избыточность, а не риск раскрытия данных.
func MaskFullText(text string) MaskResult {
	if text == "" {
		return MaskResult{Text: text, Degraded: true}
	}
	return MaskResult{Text: protectedWhole, Degraded: true}
}

// protectedWhole — маска строки, скрытой целиком.
const protectedWhole = "[ЗАЩИЩЕНО]"
