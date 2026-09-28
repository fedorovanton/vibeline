// Package corpus строит независимый размеченный корпус для оценки качества
// детекции персональных данных.
//
// Корпус намеренно не переиспользует грамматики и справочники детектора:
// иначе измерение проверяло бы совпадение кода с самим собой, а не качество
// (docs/spec/ACCEPTANCE.md §4). Поэтому у пакета собственные словари значений
// (vocab.go), собственные форматтеры (format.go) и собственные шаблоны
// предложений (templates.go), и он не зависит от модуля ai-gateway.
package corpus

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Виды записей корпуса. Поле kind нужно отчёту: метрики по «чистым» записям и
// по ловушкам считаются отдельно от записей с ПД.
const (
	KindSingle   = "single"   // один тип ПД в естественном запросе
	KindMulti    = "multi"    // несколько типов ПД в одном запросе
	KindTrap     = "trap"     // есть похожие на ПД фрагменты, которые ПД не являются
	KindClean    = "clean"    // ни ПД, ни ловушек
	KindNamesake = "namesake" // однофамилец публичной персоны — это настоящие ПД
	KindLong     = "long"     // длинный текст (50 000 / 100 000 токенов)
)

// Span — размеченные персональные данные. Смещения байтовые и полуинтервальные:
// text[Start:End] равно Value. Границы идут ровно по значению — служебные слова
// («серия», «номер», «ул.», «года») в спан не включаются, потому что избыточное
// маскирование штрафуется (07-clarifications.md §7.1).
type Span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Trap — фрагмент, который похож на персональные данные, но ими не является:
// поэт Пушкин, улица Пушкина, адрес отделения банка, телефон горячей линии,
// номер договора. Ловушки не маскируются; по ним считаются ложные срабатывания,
// поэтому они живут в отдельном поле, а не в Spans.
type Trap struct {
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Type   string `json:"type"`   // тип, за который фрагмент можно ошибочно принять
	Reason string `json:"reason"` // почему это не ПД
	Value  string `json:"value"`
}

// Record — элемент корпуса: одна строка JSON Lines.
type Record struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Text  string `json:"text"`
	Spans []Span `json:"spans"`
	Traps []Trap `json:"traps"`
}

// piece — кусок собираемого текста: литерал, значение ПД или ловушка.
// Текст собирается только из кусков, поэтому смещения вычисляются по длине
// уже записанного буфера и разойтись с текстом не могут.
type piece struct {
	text   string
	typ    string // пусто — литерал
	reason string // непусто — ловушка, а не ПД
}

func lit(s string) piece { return piece{text: s} }

func val(typ, s string) piece { return piece{text: s, typ: typ} }

func trapVal(typ, reason, s string) piece { return piece{text: s, typ: typ, reason: reason} }

// builder накапливает текст записи вместе с разметкой.
type builder struct {
	sb    strings.Builder
	spans []Span
	traps []Trap
}

// add дописывает куски в текст, попутно запоминая байтовые границы значений.
func (b *builder) add(ps ...piece) {
	for _, p := range ps {
		start := b.sb.Len()
		b.sb.WriteString(p.text)
		end := b.sb.Len()
		switch {
		case p.typ == "":
			// литерал — разметке не подлежит
		case p.reason != "":
			b.traps = append(b.traps, Trap{Start: start, End: end, Type: p.typ, Reason: p.reason, Value: p.text})
		default:
			b.spans = append(b.spans, Span{Start: start, End: end, Type: p.typ, Value: p.text})
		}
	}
}

// addCounted дописывает группу кусков и возвращает число токенов в ней.
// Группы всегда разделяются пробелом, поэтому токен не расщепляется на границе
// групп и сумма по группам равна числу токенов всего текста.
func (b *builder) addCounted(ps []piece) int {
	start := b.sb.Len()
	b.add(ps...)
	return countTokens(b.sb.String()[start:])
}

// record завершает сборку. Пустые срезы не заменяются на nil: в JSON должно
// быть [], иначе потребитель корпуса вынужден различать null и пустой список.
func (b *builder) record(kind string) Record {
	r := Record{Kind: kind, Text: b.sb.String(), Spans: b.spans, Traps: b.traps}
	if r.Spans == nil {
		r.Spans = []Span{}
	}
	if r.Traps == nil {
		r.Traps = []Trap{}
	}
	return r
}

// countTokens считает токены как слова, разделённые пробельными символами.
// Определение зафиксировано здесь и проверяется тестом: без него «50 000
// токенов» в требованиях ничего не значит.
func countTokens(s string) int {
	n, in := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			in = false
		default:
			if !in {
				n++
				in = true
			}
		}
	}
	return n
}

// Write печатает корпус в формате JSON Lines: одна запись на строку.
func Write(w io.Writer, recs []Record) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // корпус читают люди, экранирование < > & мешает
	for i := range recs {
		if err := enc.Encode(&recs[i]); err != nil {
			return fmt.Errorf("запись %s: %w", recs[i].ID, err)
		}
	}
	return nil
}
