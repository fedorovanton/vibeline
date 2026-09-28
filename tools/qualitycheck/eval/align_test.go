package eval

import (
	"strings"
	"testing"
)

// regionsText собирает текст областей: по нему видно, что именно алгоритм
// счёл замаскированным.
func regionsText(text string, regions []Region) []string {
	out := make([]string, 0, len(regions))
	for _, r := range regions {
		out = append(out, text[r.Start:r.End])
	}
	return out
}

func TestMaskedRegionsFindsReplacedValue(t *testing.T) {
	original := "Клиент Петров Пётр, телефон +7 900 000-00-00, спасибо."
	masked := "Клиент [ФИО_1], телефон [ТЕЛЕФОН_1], спасибо."

	got := regionsText(original, MaskedRegions(original, masked))
	want := []string{testName, "+7 900 000-00-00"}
	if len(got) != len(want) {
		t.Fatalf("области %q, ожидались %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("область %d: %q, ожидалась %q", i, got[i], want[i])
		}
	}
}

// Значение часто стоит вплотную к знаку препинания. Запятая после значения в
// маске сохранилась, и объявлять её замаскированной нельзя: избыточность
// оказалась бы завышенной на пустом месте.
func TestMaskedRegionsTrimsAdjacentPunctuation(t *testing.T) {
	original := "Паспорт 4509 123456, проверь."
	masked := "Паспорт [ПАСПОРТ_1], проверь."
	got := regionsText(original, MaskedRegions(original, masked))
	if len(got) != 1 || got[0] != "4509 123456" {
		t.Fatalf("области %q, ожидалась [\"4509 123456\"]", got)
	}
}

func TestMaskedRegionsEmptyWhenNothingChanged(t *testing.T) {
	s := "Как долго идёт перевод между банками?"
	if got := MaskedRegions(s, s); len(got) != 0 {
		t.Fatalf("области %v, ожидался пустой список", got)
	}
}

func TestMaskedRegionsWholeText(t *testing.T) {
	original := "Иванов Иван Иванович"
	masked := "[ФИО_1]"
	got := MaskedRegions(original, masked)
	if len(got) != 1 || got[0].Start != 0 || got[0].End != len(original) {
		t.Fatalf("области %v, ожидалась одна на весь текст", got)
	}
}

// Стратегия замены свободна: звёздочки не меняют число токенов, и выравнивание
// обязано работать и на них.
func TestMaskedRegionsWithAsterisks(t *testing.T) {
	original := "Карта 2200 0013 1881 8301 заблокирована."
	masked := "Карта **** **** **** **** заблокирована."
	got := regionsText(original, MaskedRegions(original, masked))
	joined := strings.Join(got, "|")
	if !strings.Contains(joined, "2200") || !strings.Contains(joined, "8301") {
		t.Fatalf("области %q не покрывают номер карты", got)
	}
	for _, r := range MaskedRegions(original, masked) {
		if r.Start < len("Карта ") || r.End > len(original)-len(" заблокирована.") {
			t.Errorf("область [%d;%d) выходит за пределы значения", r.Start, r.End)
		}
	}
}

// Кириллица: границы областей обязаны попадать на границы рун, иначе текст
// областей невозможно напечатать, а длины — сравнивать.
func TestMaskedRegionsRuneAligned(t *testing.T) {
	original := "Место рождения — Ирбит, уточни."
	masked := "Место рождения — [МЕСТО_РОЖДЕНИЯ_1], уточни."
	for _, r := range MaskedRegions(original, masked) {
		s := original[r.Start:r.End]
		if !isValidUTF8(s) {
			t.Fatalf("область [%d;%d) режет руну", r.Start, r.End)
		}
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// Вставка текста маской не должна порождать области: вставленные байты в
// оригинале не существуют и замаскированными не являются.
func TestMaskedRegionsIgnoresPureInsertion(t *testing.T) {
	original := "Телефон клиента записан."
	masked := "Телефон клиента записан. [ПРИМЕЧАНИЕ]"
	if got := MaskedRegions(original, masked); len(got) != 0 {
		t.Fatalf("области %v, ожидался пустой список", got)
	}
}

func TestUncoveredBytes(t *testing.T) {
	tests := []struct {
		name    string
		regions []Region
		cover   []Region
		want    int
	}{
		{"полностью внутри спана", []Region{{10, 20}}, []Region{{5, 25}}, 0},
		{"полностью вне спана", []Region{{10, 20}}, []Region{{30, 40}}, 10},
		{"частично", []Region{{10, 20}}, []Region{{15, 25}}, 5},
		{"два спана внутри области", []Region{{0, 30}}, []Region{{5, 10}, {20, 25}}, 20},
		{"без спанов", []Region{{0, 7}}, nil, 7},
		{"без областей", nil, []Region{{0, 7}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uncoveredBytes(tt.regions, tt.cover); got != tt.want {
				t.Fatalf("непокрытых байтов %d, ожидалось %d", got, tt.want)
			}
		})
	}
}

// Длинные записи корпуса доходят до 100 000 токенов: выравнивание обязано
// оставаться линейным, иначе прогон не завершится.
func TestMaskedRegionsHandlesLongText(t *testing.T) {
	var orig, mask strings.Builder
	for i := 0; i < 20000; i++ {
		orig.WriteString("обычный текст без персональных данных ")
		mask.WriteString("обычный текст без персональных данных ")
		if i%100 == 0 {
			orig.WriteString("Петров Пётр Петрович ")
			mask.WriteString("[ФИО_1] ")
		}
	}
	regions := MaskedRegions(orig.String(), mask.String())
	if len(regions) != 200 {
		t.Fatalf("областей %d, ожидалось 200", len(regions))
	}
	for _, r := range regions {
		if got := orig.String()[r.Start:r.End]; got != "Петров Пётр Петрович" {
			t.Fatalf("область содержит %q", got)
		}
	}
}
