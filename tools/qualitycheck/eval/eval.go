// Package eval сверяет ответ сервиса с разметкой корпуса.
//
// Метрик две, и они принципиально разные.
//
// Сокрытие — главная метрика. Берётся размеченное значение и проверяется, что
// в ответе его нет. Проверка не зависит ни от границ спана, ни от стратегии
// замены: эталонной маски не существует (07-clarifications.md §7.1), важен сам
// факт, что значения в выдаче не осталось.
//
// Одного поиска целой строки для этого мало, и выяснилось это дорого. Если
// значение замаскировано частично — «двенадцатого марта 1987» превратилось в
// «двенадцатого ‹маска›», — то целой строки в ответе действительно нет, и
// прежняя проверка засчитывала значение скрытым. День при этом уходил в
// модель открытым, а отчёт показывал по датам рождения единицу. Поэтому
// сокрытие требует ещё и того, чтобы от значения не уцелело читаемого
// фрагмента: уцелевший помечается Partial и считается утечкой.
//
// Избыточность — вспомогательная метрика, и она от границ зависит напрямую.
// Автор корпуса предупредил, что его соглашение о границах может не совпадать
// с фактической разметкой детектора, поэтому высокая избыточность в первую
// очередь означает расхождение конвенций, а не дефект детектора.
package eval

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"qualitycheck/corpus"
)

// SpanOutcome — итог по одному размеченному значению.
// Value заполняется только при явном согласии вызывающего (флаг -verbose).
type SpanOutcome struct {
	RecordID string `json:"record_id"`
	Kind     string `json:"kind"`
	Type     string `json:"type"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Hidden   bool   `json:"hidden"`
	// Partial — целой строки значения в ответе нет, но часть его уцелела.
	// Это утечка: в модель ушёл читаемый кусок персональных данных.
	Partial bool `json:"partial,omitempty"`
	// Ambiguous — значение встречается в исходном тексте и вне разметки,
	// поэтому подсчёт вхождений не отличает уцелевшее значение спана от
	// обычного текста. Такой спан трактуется в худшую сторону, но помечается:
	// по пометке видна ширина неопределённости отчёта.
	Ambiguous bool   `json:"ambiguous,omitempty"`
	Value     string `json:"value,omitempty"`
}

// TrapOutcome — итог по одной ловушке. Masked означает ложное срабатывание:
// фрагмент не является персональными данными, а из ответа исчез.
type TrapOutcome struct {
	RecordID string `json:"record_id"`
	Type     string `json:"type"`
	Reason   string `json:"reason"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Masked   bool   `json:"masked"`
	Value    string `json:"value,omitempty"`
}

// RecordResult — итог по одной записи корпуса.
type RecordResult struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	TextBytes int    `json:"text_bytes"`
	SpanBytes int    `json:"span_bytes"`

	Spans []SpanOutcome `json:"spans"`
	Traps []TrapOutcome `json:"traps"`

	// MaskedBytes — байты оригинала, не сохранившиеся в ответе.
	MaskedBytes int `json:"masked_bytes"`
	// ExcessBytes — из них те, что лежат вне размеченных спанов.
	ExcessBytes int `json:"excess_bytes"`

	// Changed — ответ отличается от оригинала хоть чем-то.
	Changed bool `json:"changed"`
	// FullyMasked — изменён весь текст целиком. Избыточным это считается
	// только если текст не состоит из одного значения (A4.4).
	FullyMasked bool `json:"fully_masked"`
	// Restored — обратный шаг вернул оригинал побайтово.
	Restored bool `json:"restored"`

	// Ambiguous — число спанов, значение которых встречается в оригинале и
	// вне разметки. Для таких спанов подсчёт вхождений не может отличить
	// утечку от обычного текста, и результат трактуется в худшую сторону.
	Ambiguous int `json:"ambiguous_spans"`

	// Err — прогон записи не состоялся; метрики по ней не считаются.
	Err string `json:"error,omitempty"`
}

// Evaluate сверяет запись корпуса с ответами сервиса: masked — результат
// прямого шага, restored — результат обратного.
func Evaluate(rec *corpus.Record, masked, restored string) RecordResult {
	res := RecordResult{
		ID:        rec.ID,
		Kind:      rec.Kind,
		TextBytes: len(rec.Text),
		Changed:   masked != rec.Text,
		Restored:  restored == rec.Text,
	}

	spanRegions := make([]Region, 0, len(rec.Spans))
	for _, s := range rec.Spans {
		res.SpanBytes += s.Len()
		spanRegions = append(spanRegions, Region{Start: s.Start, End: s.End})
	}
	sort.Slice(spanRegions, func(i, j int) bool { return spanRegions[i].Start < spanRegions[j].Start })

	regions := MaskedRegions(rec.Text, masked)
	res.Spans = checkSpans(rec, masked, regions, &res.Ambiguous)
	res.Traps = checkTraps(rec, masked)

	for _, r := range regions {
		res.MaskedBytes += r.Len()
	}
	res.ExcessBytes = uncoveredBytes(regions, spanRegions)
	res.FullyMasked = len(regions) == 1 && regions[0].Start == 0 && regions[0].End == len(rec.Text)
	return res
}

// checkSpans определяет для каждого спана, скрыто ли значение.
//
// Одно и то же значение может стоять в записи дважды — это два спана. Поэтому
// считается не «есть ли значение в ответе», а сколько его вхождений там
// осталось: k спанов и m оставшихся вхождений дают k-m скрытых значений.
// Какой именно из одинаковых спанов объявлен утёкшим, значения не имеет:
// в отчёт идут количества, а позиции у одинаковых значений равноценны.
func checkSpans(rec *corpus.Record, masked string, regions []Region, ambiguous *int) []SpanOutcome {
	byValue := map[string][]int{}
	for i, s := range rec.Spans {
		byValue[s.Value] = append(byValue[s.Value], i)
	}

	out := make([]SpanOutcome, len(rec.Spans))
	for i, s := range rec.Spans {
		out[i] = SpanOutcome{
			RecordID: rec.ID, Kind: rec.Kind, Type: s.Type,
			Start: s.Start, End: s.End, Value: s.Value, Hidden: true,
		}
	}

	for value, idx := range byValue {
		if value != "" {
			markSpanValue(rec.Text, masked, value, idx, out, ambiguous)
		}
	}
	markPartialLeaks(rec, regions, out)
	return out
}

// markSpanValue размечает спаны с одинаковым значением value: idx — их номера.
func markSpanValue(text, masked, value string, idx []int, out []SpanOutcome, ambiguous *int) {
	// Значение может встречаться и вне разметки: короткое число или
	// обиходное слово попадается в длинном тексте случайно. Отличить уцелевший
	// спан от обычного текста подсчётом вхождений нельзя, поэтому такие
	// спаны трактуются в худшую сторону и помечаются Ambiguous.
	if strings.Count(text, value) > len(idx) {
		*ambiguous += len(idx)
		for _, i := range idx {
			out[i].Ambiguous = true
		}
	}
	leaked := min(strings.Count(masked, value), len(idx))
	for k := 0; k < leaked; k++ {
		out[idx[k]].Hidden = false
	}
}

// markPartialLeaks помечает частичные утечки: целой строки в ответе нет, но
// читаемый кусок значения уцелел. Определяется по выравниванию, а не поиском
// подстроки: важно именно то, что кусок остался на своём месте.
func markPartialLeaks(rec *corpus.Record, regions []Region, out []SpanOutcome) {
	for i, s := range rec.Spans {
		if !out[i].Hidden {
			continue
		}
		if spanSurvivedRunes(rec.Text, s.Start, s.End, regions) >= partialLeakMinRunes {
			out[i].Hidden = false
			out[i].Partial = true
		}
	}
}

// partialLeakMinRunes — сколько букв или цифр значения должно уцелеть, чтобы
// счесть утечку частичной.
//
// Выравнивание оригинала и ответа приблизительное по своей природе, поэтому
// одиночный уцелевший знак — скорее его артефакт, чем фрагмент значения. Два
// знака выравнивание так не теряет, а реальная частичная утечка их заведомо
// превышает: она оставляет слово или группу цифр целиком.
const partialLeakMinRunes = 2

// spanSurvivedRunes считает буквы и цифры участка [start, end), не попавшие ни
// в одну замаскированную область. Пробелы и знаки препинания не в счёт: сами
// по себе они ничего не раскрывают.
func spanSurvivedRunes(text string, start, end int, regions []Region) int {
	if start < 0 || end > len(text) || start >= end {
		return 0
	}
	n := 0
	for i := start; i < end; {
		r, size := utf8.DecodeRuneInString(text[i:])
		if (unicode.IsLetter(r) || unicode.IsDigit(r)) && !regionsCover(regions, i) {
			n++
		}
		i += size
	}
	return n
}

// regionsCover сообщает, лежит ли байт внутри одной из областей. Области
// отсортированы по началу и не пересекаются, поэтому достаточно поиска.
func regionsCover(regions []Region, off int) bool {
	i := sort.Search(len(regions), func(i int) bool { return regions[i].End > off })
	return i < len(regions) && regions[i].Start <= off
}

// checkTraps определяет для каждой ловушки, была ли она ошибочно замаскирована.
// Признак тот же, что и для сокрытия: значение исчезло из ответа. Частичное
// маскирование ловушки тоже считается ложным срабатыванием — фрагмент тронут.
func checkTraps(rec *corpus.Record, masked string) []TrapOutcome {
	byValue := map[string][]int{}
	for i, t := range rec.Traps {
		byValue[t.Value] = append(byValue[t.Value], i)
	}

	out := make([]TrapOutcome, len(rec.Traps))
	for i, t := range rec.Traps {
		out[i] = TrapOutcome{
			RecordID: rec.ID, Type: t.Type, Reason: t.Reason,
			Start: t.Start, End: t.End, Value: t.Value, Masked: true,
		}
	}
	for value, idx := range byValue {
		if value == "" {
			continue
		}
		survived := min(strings.Count(masked, value), len(idx))
		for k := 0; k < survived; k++ {
			out[idx[k]].Masked = false
		}
	}
	return out
}

// Failed строит итог записи, прогон которой не состоялся.
func Failed(rec *corpus.Record, err error) RecordResult {
	return RecordResult{ID: rec.ID, Kind: rec.Kind, TextBytes: len(rec.Text), Err: err.Error()}
}
