// Package detect — детерминированная идентификация персональных данных.
//
// Конвейер состоит из трёх слоёв:
//
//  1. Кандидаты по форме. Сканеры работают по токенам lex.Doc и выделяют
//     фрагменты, похожие на значение своего типа.
//  2. Верификаторы. Контрольные суммы, длины, диапазоны и справочники
//     повышают или опровергают уверенность кандидата.
//  3. Контекст и связи. Маркеры вокруг кандидата и соседство с уже
//     достоверными значениями решают, относится ли кандидат к персональным
//     данным конкретного лица.
//
// Нейросети, эмбеддинги и обращения к внешним моделям здесь не используются:
// решение по каждому кандидату детерминировано и объяснимо правилом.
package detect

import (
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Confidence — уровень уверенности кандидата.
//
// Это не вероятность и не откалиброванный score, а перечисление условий,
// при которых кандидат был найден. Каждый уровень достижим ровно набором
// сработавших правил, поэтому решение воспроизводимо и объяснимо.
type Confidence uint8

const (
	// Denied — сработало контр-правило: кандидат не является персональными
	// данными в этом контексте (упоминание публичной персоны, адрес отделения).
	Denied Confidence = iota
	// Weak — совпала только форма. Одних десяти цифр подряд недостаточно.
	Weak
	// Strong — форма плюс явный маркер типа рядом («паспорт», «выдан», «cvv»).
	Strong
	// Certain — форма плюс контрольная сумма или самодостаточная грамматика.
	Certain
)

// String возвращает имя уровня для логов и отчётов.
func (c Confidence) String() string {
	switch c {
	case Denied:
		return "denied"
	case Weak:
		return "weak"
	case Strong:
		return "strong"
	case Certain:
		return "certain"
	default:
		return "unknown"
	}
}

// Profile — режим отнесения кандидатов к персональным данным.
type Profile uint8

const (
	// Balanced — режим по умолчанию: достоверные и сильные кандидаты
	// маскируются всегда, слабые — только внутри кластера других ПД.
	Balanced Profile = iota
	// Strict — маскируются только достоверные и сильные кандидаты.
	// Меньше ложных срабатываний ценой риска пропуска.
	Strict
	// Paranoid — маскируется всё, что совпало по форме.
	Paranoid
)

// ParseProfile разбирает имя профиля. Второе значение — признак успеха.
func ParseProfile(s string) (Profile, bool) {
	switch s {
	case "balanced", "":
		return Balanced, true
	case "strict":
		return Strict, true
	case "paranoid":
		return Paranoid, true
	default:
		return Balanced, false
	}
}

// String возвращает имя профиля.
func (p Profile) String() string {
	switch p {
	case Strict:
		return "strict"
	case Paranoid:
		return "paranoid"
	default:
		return "balanced"
	}
}

// Span — найденный фрагмент персональных данных.
//
// Start и End — смещения в байтах в исходном тексте. Границы держатся точно по
// значению: служебные слова («серия», «ул.», «года») в спан не включаются —
// избыточное маскирование штрафуется.
type Span struct {
	Start int32
	End   int32
	Type  pii.Type
	Conf  Confidence
	// Rule — имя сработавшего правила. Идёт в отладочные логи и отчёты
	// качества; в продуктовых логах значение ПД не сопровождает.
	Rule string
}

// Len возвращает длину спана в байтах.
func (s Span) Len() int { return int(s.End - s.Start) }

// Veto — запрет на отнесение фрагмента к персональным данным.
//
// Контр-правила выражаются вето, а не удалением кандидата: сканеры независимы
// и не знают друг о друге, а решение принимает движок.
type Veto struct {
	Start int32
	End   int32
	// Types — типы, к которым применяется запрет. Пустое множество означает
	// запрет для любых типов.
	Types pii.Set
	Rule  string
}

// Candidates — накопитель результатов работы сканеров.
//
// Накопитель переиспользуется между запросами: сканеры только дописывают
// в него, а движок разбирает содержимое.
type Candidates struct {
	Spans []Span
	Vetos []Veto

	// Рабочие области движка. Живут в накопителе, а не в локальных
	// переменных, именно потому, что накопитель переиспользуется между
	// запросами, а локальные — нет. На тексте в четыре килобайта они давали
	// две трети всех аллокаций запроса: границы предложений росли
	// последовательными удвоениями, а карта якорей и список принятых спанов
	// строились заново каждый раз.
	sentences []int32
	anchors   []pii.Set
	kept      []Span
}

// Reset очищает накопитель, сохраняя ёмкость слайсов.
func (c *Candidates) Reset() {
	c.Spans = c.Spans[:0]
	c.Vetos = c.Vetos[:0]
	c.sentences = c.sentences[:0]
	c.anchors = c.anchors[:0]
	c.kept = c.kept[:0]
}

// Add регистрирует кандидата.
func (c *Candidates) Add(start, end int, t pii.Type, conf Confidence, rule string) {
	if end <= start {
		return
	}
	c.Spans = append(c.Spans, Span{Start: int32(start), End: int32(end), Type: t, Conf: conf, Rule: rule})
}

// Deny регистрирует запрет на фрагмент. Пустое множество types запрещает
// отнесение фрагмента к любому типу ПД.
func (c *Candidates) Deny(start, end int, types pii.Set, rule string) {
	if end <= start {
		return
	}
	c.Vetos = append(c.Vetos, Veto{Start: int32(start), End: int32(end), Types: types, Rule: rule})
}

// Scanner — источник кандидатов одного класса типов ПД.
//
// Scan обязан быть чистой функцией от doc и dicts: сканер не хранит состояние
// между вызовами и безопасен для конкурентного использования. Все результаты
// дописываются в out; входной текст не изменяется.
type Scanner interface {
	Name() string
	Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates)
}

// Result — итог детекции: непересекающиеся спаны в порядке появления.
type Result struct {
	Spans  []Span
	Found  pii.Set
	Counts [pii.Count]uint16
	// LimitExceeded сообщает, что значений к маскированию в тексте больше,
	// чем разрешает Options.MaxSpans. Spans тогда неполон: в нём только
	// спаны в пределах предела, а остальные значения в разметку не вошли.
	// Выпускать текст по такому результату запрещено — вызывающий обязан
	// трактовать флаг как отказ защиты.
	//
	// Флаг, а не ошибка: частичная разметка остаётся доступной для
	// диагностики, а проверка поля не стоит аллокации в горячем пути.
	LimitExceeded bool
}

// Reset очищает результат, сохраняя ёмкость.
func (r *Result) Reset() {
	r.Spans = r.Spans[:0]
	r.Found = 0
	r.Counts = [pii.Count]uint16{}
	r.LimitExceeded = false
}

// Options — настройки движка.
type Options struct {
	// Profile — режим отнесения кандидатов к ПД.
	Profile Profile
	// Types — типы, которые требуется искать. Пустое множество означает все.
	Types pii.Set
	// MaxSpans ограничивает число замен в одном запросе. Ноль — без ограничения.
	// Превышение не обрезает маскирование молча: движок выставляет
	// Result.LimitExceeded, и текст по такому результату не выпускается.
	MaxSpans int
}
