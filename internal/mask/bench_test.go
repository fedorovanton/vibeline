package mask

import (
	"strings"
	"testing"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/pii"
)

// Бенчмарк применения замен. Заведён для T-21: задача требует назвать B/op и
// allocs/op ядра, а измерить их было нечем — бенчмарков у пакета не было
// вовсе, и расход на маскирование оценивался только по профилю всего
// процесса под нагрузкой.
//
// Текст синтетический: реальные персональные данные в репозиторий не
// попадают (AGENTS.md, «Инварианты приватности»).

const benchSentence = "Клиент Иванов Иван Иванович, паспорт 4509 123456, ИНН 7707083893, " +
	"карта 4111 1111 1111 1111, телефон +7 916 123-45-67, почта ivan@example.org, " +
	"родился 12 мая 1990 года, проживает по адресу город Москва улица Ленина дом 5. "

// benchText — около четырёх килобайт, как у бенчмарков сканеров.
var benchText = strings.Repeat(benchSentence, 4096/len(benchSentence)+1)

// benchSpans размечает в каждом повторе предложения по одному значению
// каждого из восьми типов: расположение замен важнее их содержания.
func benchSpans() []detect.Span {
	var spans []detect.Span
	marks := []struct {
		text string
		typ  pii.Type
	}{
		{"Иванов Иван Иванович", pii.FullName},
		{"4509 123456", pii.PassportNumber},
		{"7707083893", pii.INN},
		{"4111 1111 1111 1111", pii.CardNumber},
		{phoneSample, pii.Phone},
		{"ivan@example.org", pii.Email},
		{"12 мая 1990", pii.BirthDate},
		{"город Москва улица Ленина дом 5", pii.Address},
	}
	for off := 0; off+len(benchSentence) <= len(benchText); off += len(benchSentence) {
		for _, m := range marks {
			at := strings.Index(benchText[off:off+len(benchSentence)], m.text)
			if at < 0 {
				continue
			}
			spans = append(spans, detect.Span{
				Start: int32(off + at), End: int32(off + at + len(m.text)), Type: m.typ,
			})
		}
	}
	return spans
}

func BenchmarkApply(b *testing.B) {
	spans := benchSpans()
	if len(spans) < 8 {
		b.Fatalf("размечено %d спанов, ожидалось хотя бы восемь", len(spans))
	}
	pick := func(pii.Type) Strategy { return Placeholder{} }

	var a Applier
	// Прогрев: буферы набирают ёмкость, чтобы в измерении осталась работа, а
	// не разовое выделение.
	if out, _ := a.Apply(benchText, spans, pick); out == "" {
		b.Fatal("маскирование вернуло пустую строку")
	}

	b.SetBytes(int64(len(benchText)))
	b.ReportAllocs()
	for b.Loop() {
		a.Apply(benchText, spans, pick)
	}
}
