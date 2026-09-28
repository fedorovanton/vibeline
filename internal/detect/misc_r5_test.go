package detect

import (
	"testing"

	"ai-gateway/internal/pii"
)

// Тесты T-83, раунд 5 технического жюри 23.09: гражданство полным
// официальным названием и его отсутствие (P5-3), сокращённый маркер места
// рождения (P5-4). Значения синтетические.

// TestMiscCitizenshipOfficialNames — официальное название с прилагательным
// впереди и «лицо без гражданства» маскируются целиком.
func TestMiscCitizenshipOfficialNames(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct{ text, span string }{
		// Фразы жюри.
		{"Гражданство: Кыргызская Республика", "Кыргызская Республика"},
		{"Гражданство: Азербайджанская Республика", "Азербайджанская Республика"},
		{"Гражданство: Китайская Народная Республика", "Китайская Народная Республика"},
		{"Гражданство: лицо без гражданства", "лицо без гражданства"},
		// Вариации: падеж, регистр, другие страны, составное через дефис.
		{"гражданин Кыргызской Республики", "Кыргызской Республики"},
		{"гражданка Китайской Народной Республики", "Китайской Народной Республики"},
		{"ГРАЖДАНСТВО: АЗЕРБАЙДЖАНСКАЯ РЕСПУБЛИКА", "АЗЕРБАЙДЖАНСКАЯ РЕСПУБЛИКА"},
		{"Гражданство — Киргизская Республика", "Киргизская Республика"},
		{"Гражданство: Социалистическая Республика Вьетнам", "Социалистическая Республика Вьетнам"},
		{"Гражданство: Корейская Народно-Демократическая Республика", "Корейская Народно-Демократическая Республика"},
		{"гражданин Федеративной Республики Германия", "Федеративной Республики Германия"},
		{"Гражданство: апатрид", "апатрид"},
		{"гражданство: без гражданства", "без гражданства"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			s := miscOnly(t, miscScan(t, dicts, tt.text), tt.text, pii.Citizenship)
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
			if s.Conf != Strong {
				t.Errorf(msgConfWant, s.Conf, Strong)
			}
		})
	}
}

// TestMiscCitizenshipAdjectiveAlone — прилагательное женского рода без
// родового слова гражданством не становится: «китайская кухня».
func TestMiscCitizenshipAdjectiveAlone(t *testing.T) {
	dicts := miscDicts(t)
	for _, text := range []string{
		"китайская кухня в меню ресторана",
		"Кыргызская кухня и азербайджанская музыка",
		"Великая Китайская стена",
	} {
		miscNone(t, miscScan(t, dicts, text), text, pii.Citizenship)
	}
}

// TestMiscBirthPlaceAbbrevMarker — «Место рожд.», «м. рожд.»: сокращённый
// маркер поля анкеты (P5-4).
func TestMiscBirthPlaceAbbrevMarker(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct{ text, span string }{
		{"Место рожд.: г. Орёл", "г. Орёл"},
		{"место рожд. г. Тула", "г. Тула"},
		{"м. рожд.: г. Казань", miscPlace},
		{"Место рожд.: Кинешма", "Кинешма"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			s := miscOnly(t, miscScan(t, dicts, tt.text), tt.text, pii.BirthPlace)
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
		})
	}
	// «Дата рожд.» — поле даты, а не места.
	for _, text := range []string{"Дата рожд.: 12.03.1985", "рожд. в анкете не указано"} {
		miscNone(t, miscScan(t, dicts, text), text, pii.BirthPlace)
	}
}

// TestMiscRound5Engine — фразы P5-3 и P5-4 сквозь полный движок.
func TestMiscRound5Engine(t *testing.T) {
	e := newFullEngine(t)
	tests := []struct {
		text, value string
		typ         pii.Type
	}{
		{"Гражданство: Кыргызская Республика", "Кыргызская Республика", pii.Citizenship},
		{"Гражданство: Азербайджанская Республика", "Азербайджанская Республика", pii.Citizenship},
		{"Гражданство: Китайская Народная Республика", "Китайская Народная Республика", pii.Citizenship},
		{"Гражданство: лицо без гражданства", "лицо без гражданства", pii.Citizenship},
		{"Место рожд.: г. Орёл", "Орёл", pii.BirthPlace},
	}
	for _, tt := range tests {
		if !r5Covered(t, e, tt.text, tt.value, tt.typ) {
			t.Errorf("%q не скрыто типом %s в %q; найдено %q", tt.value, tt.typ.Key(), tt.text, counterEngineMasked(t, e, tt.text))
		}
	}
}
