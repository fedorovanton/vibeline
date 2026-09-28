package detect

import (
	"strings"
	"testing"

	"ai-gateway/internal/pii"
)

// Тесты T-83, раунд 5 технического жюри 23.09 (P5-5): адрес без точек после
// сокращений и квартира без маркера за номером дома. Адреса синтетические.

// addrR5Indexed — адрес жюри с индексом и квартирой без маркера.
const addrR5Indexed = "153002 Иваново Шереметевский 85 207"

// TestScanAddressUndotted — однобуквенные маркеры без точки внутри адреса и
// квартира без маркера: адрес маскируется целиком.
func TestScanAddressUndotted(t *testing.T) {
	tests := []struct {
		text string
		want addressWant
	}{
		// Фразы жюри.
		{"ул Лежневская д 120 кв 5", addressWant{"Лежневская д 120 кв 5", Strong}},
		{"г Иваново ул Лежневская д 120 кв 5", addressWant{"Иваново ул Лежневская д 120 кв 5", Strong}},
		{addrR5Indexed, addressWant{addrR5Indexed, Certain}},
		// Вариации: корпус без точки, дефисное сокращение, квартира перед
		// запятой, в конце предложения.
		{"г Кинешма ул Слободская д 7 к 2 кв 15", addressWant{"Кинешма ул Слободская д 7 к 2 кв 15", Strong}},
		{"пр-т Заводской д 12 кв 3", addressWant{"Заводской д 12 кв 3", Strong}},
		{addrR5Indexed + ", тел. уточнить", addressWant{addrR5Indexed, Certain}},
		{"Адрес: " + addrR5Indexed + ".", addressWant{addrR5Indexed, Certain}},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			spans := scanAddressText(t, tt.text)
			if !hasAddressSpan(tt.text, spans, tt.want) {
				t.Errorf("ожидался спан «%s» (%v), получено: %s", tt.want.text, tt.want.conf, formatAddressSpans(tt.text, spans))
			}
		})
	}
}

// TestScanAddressUndottedNoFalse — одна буква без точки маркером не
// становится без адресного контекста с обеих сторон, а число за домом не
// становится квартирой, если за ним идёт слово.
func TestScanAddressUndottedNoFalse(t *testing.T) {
	tests := []struct {
		text string
		// outside — фрагмент, который не должен попасть ни в один спан.
		outside string
	}{
		{"Казань, Тверская 5 12 лет назад", "12"},
		{"ул Ленина к 10 утра", "10"},
		{"Иваново, ул. Садовая, 5 2 раза звонил", " 2"},
		{"д 5 кв 3", "д 5"},
		{"Иванов И Петров пришёл", "Петров"},
		{"Москва, ул. Тверская, 12 12.03.1985", "12.03"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			at := strings.Index(tt.text, tt.outside)
			if at < 0 {
				t.Fatalf("фрагмент %q не найден", tt.outside)
			}
			end := at + len(tt.outside)
			for _, s := range scanAddressText(t, tt.text) {
				if int(s.Start) < end && int(s.End) > at {
					t.Errorf("спан «%s» захватил %q", tt.text[s.Start:s.End], tt.outside)
				}
			}
		})
	}
}

// r5Covered сообщает, что фрагмент value текста целиком лежит внутри спана
// типа typ, найденного полным движком.
func r5Covered(t *testing.T, e *Engine, text, value string, typ pii.Type) bool {
	t.Helper()
	at := strings.Index(text, value)
	if at < 0 {
		t.Fatalf("фрагмент %q не найден в %q", value, text)
	}
	for _, s := range runDetect(t, e, text, Options{}) {
		if s.Type == typ && int(s.Start) <= at && at+len(value) <= int(s.End) {
			return true
		}
	}
	return false
}

// TestAddressUndottedEngine — фразы P5-5 сквозь полный движок: каждое
// значение из разметки жюри скрыто внутри одного адреса.
func TestAddressUndottedEngine(t *testing.T) {
	e := newFullEngine(t)
	tests := []struct {
		text   string
		values []string
	}{
		{"ул Лежневская д 120 кв 5", []string{"Лежневская", "120", "кв 5"}},
		{"г Иваново ул Лежневская д 120 кв 5", []string{"Лежневская", "д 120", "кв 5"}},
		{addrR5Indexed, []string{"153002", "Шереметевский", "207"}},
	}
	for _, tt := range tests {
		for _, v := range tt.values {
			if !r5Covered(t, e, tt.text, v, pii.Address) {
				t.Errorf("%q не скрыто адресом в %q; найдено %q", v, tt.text, counterEngineMasked(t, e, tt.text))
			}
		}
	}
}
