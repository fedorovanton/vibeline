package detect

import (
	"testing"

	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Номера в этом файле синтетические: реальные персональные данные в
// репозиторий не попадают (AGENTS.md, «Инварианты приватности»).

// Синтетические номера, которые повторяются в проверках файла.
const (
	// dmkDriver — водительское удостоверение серией и номером.
	dmkDriver = "7734 518206"
	// dmkPassportMasked — ожидаемая маска паспорта после маркера-опечатки.
	dmkPassportMasked = " [ПАСПОРТ]"
	// dmkTypoDrop, dmkTypoDouble — опечатки маркера «паспорт»: пропуск и
	// удвоение буквы.
	dmkTypoDrop   = "пасорт"
	dmkTypoDouble = "пасспорт"
)

// TestDigitsOneEdit — расстояние Левенштейна не больше одной правки по
// рунам: вставка, удаление, замена в начале, середине и конце слова.
func TestDigitsOneEdit(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{digitsPassportWord, digitsPassportWord, true},
		{dmkTypoDrop, digitsPassportWord, true},
		{dmkTypoDouble, digitsPassportWord, true},
		{"паспорд", digitsPassportWord, true},
		{"паспор", digitsPassportWord, true},
		{"ппаспорт", digitsPassportWord, true},
		{"аспорт", digitsPassportWord, true},
		{"пастор", digitsPassportWord, false},
		{"пасорд", digitsPassportWord, false},
		{"пас", digitsPassportWord, false},
		{"", "а", true},
		{"", "аб", false},
		{"abc", "abd", true},
		{"abc", "acb", false},
	}
	for _, c := range cases {
		if got := digitsOneEdit(c.a, c.b); got != c.want {
			t.Errorf("digitsOneEdit(%q, %q) = %v, ожидалось %v", c.a, c.b, got, c.want)
		}
		if got := digitsOneEdit(c.b, c.a); got != c.want {
			t.Errorf("digitsOneEdit(%q, %q) = %v, ожидалось %v", c.b, c.a, got, c.want)
		}
	}
}

// TestDigitsPassportTypo — опечатки маркера паспорта в словоформах и слова,
// которые на «паспорт» только похожи.
func TestDigitsPassportTypo(t *testing.T) {
	for _, w := range []string{dmkTypoDrop, dmkTypoDouble, "пасорта", "пасспорту", "пасортом", "пассорт"} {
		if !digitsPassportTypo(w) {
			t.Errorf("%q: опечатка «паспорт» не распознана", w)
		}
	}
	for _, w := range []string{"пастор", "пастора", "пасека", "пассаж", "пасьянс", "пас"} {
		if digitsPassportTypo(w) {
			t.Errorf("%q: принято за опечатку «паспорт»", w)
		}
	}
}

// TestDetectDigitsRound5 — пункты T-81 и T-83 (P5-2, P5-4) через весь
// конвейер. Ожидание — маска целиком, как колонка «Ожидается» таблиц задач.
func TestDetectDigitsRound5(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		// T-81-2: опечатка маркера паспорта перед серией и номером.
		{dmkTypoDrop, dmkTypoDrop + " " + dfxPassport, dmkTypoDrop + dmkPassportMasked},
		{dmkTypoDouble, dmkTypoDouble + " " + dfxPassport, dmkTypoDouble + dmkPassportMasked},
		{"пасорт в фразе", "Клиент потерял " + dmkTypoDrop + " " + dfxPassport + ".", "Клиент потерял " + dmkTypoDrop + " [ПАСПОРТ]."},
		{"пасорта парами", "копия пасорта 45 09 123456", "копия пасорта [ПАСПОРТ]"},
		{"паспот как раньше", "паспот " + dfxPassport, "паспот" + dmkPassportMasked},
		// T-81-3: «выдан» справа от серии и номера.
		{"выдан справа", "Данные клиента: " + dfxPassport + ", выдан в 2019 году.",
			"Данные клиента: [ПАСПОРТ], выдан в 2019 году."},
		{"выдан справа с органом", dfxPassport + " выдан ОВД района", "[ПАСПОРТ] выдан [ОРГАН_ВЫДАЧИ]"},
		// T-83 P5-2: номер паспорта двумя тройками.
		{"серия парами, номер тройками", "паспорт серии 45 21 номер 603 918",
			"паспорт серии [ПАСПОРТ] номер [ПАСПОРТ]"},
		{"серия и номер тройками", "паспорт 4521 603 918", "паспорт [ПАСПОРТ]"},
		{"серия, знак номера, тройки", "паспорт: серия 45 21, № 603 918",
			"паспорт: серия [ПАСПОРТ], № [ПАСПОРТ]"},
		{"серия четвёркой, номер тройками", "серия 4521 номер 603 918", "серия [ПАСПОРТ] номер [ПАСПОРТ]"},
		{"парами и тройками одной записью", "паспорт 45 21 603 918", "паспорт [ПАСПОРТ]"},
		// T-83 P5-4: сокращения водительского удостоверения.
		{"водит. удост.", "водит. удост. " + dmkDriver, "водит. удост. [ВОДИТЕЛЬСКОЕ_УДОСТОВЕРЕНИЕ]"},
		{"вод. уд.", "вод. уд. " + dmkDriver, "вод. уд. [ВОДИТЕЛЬСКОЕ_УДОСТОВЕРЕНИЕ]"},
		{"удост. водителя", "удост. " + dmkDriver, "удост. [ВОДИТЕЛЬСКОЕ_УДОСТОВЕРЕНИЕ]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := digitsMasked(t, c.text); got != c.want {
				t.Errorf(msgMaskWant, got, c.want)
			}
		})
	}
}

// TestDetectDigitsRound5Kept — ложные срабатывания рядом с новыми правилами:
// тексты остаются как есть.
func TestDetectDigitsRound5Kept(t *testing.T) {
	for _, text := range []string{
		"пастор пришёл",
		"пастор " + dfxPassport,
		"выдан чек № 1234 567890",
		"перевести на 5000 рублей",
		dmkTypoDrop + " " + dfxPassportRun,
		"число 4521 603 918 в отчёте",
		"серия 4521 номер 603 918 11",
		"уд. вес " + dmkDriver,
		"вода " + dmkDriver,
		"Трек-номер посылки 80085273452178",
	} {
		t.Run(text, func(t *testing.T) {
			if got := digitsMasked(t, text); got != text {
				t.Errorf(msgMaskWant, got, text)
			}
		})
	}
}

// TestScanDigitsRound5Markers — уверенность и тип кандидатов сканера по
// новым маркерам: опечатка даёт паспорт Strong только при записи группами,
// «уд.» без «вод.» маркером не служит.
func TestScanDigitsRound5Markers(t *testing.T) {
	cases := []struct {
		name string
		text string
		want digitsWant
	}{
		{"опечатка перед группами", dmkTypoDrop + " " + dfxPassport, digitsWant{pii.PassportNumber, dfxPassport, Strong}},
		{"опечатка перед слитной записью", dmkTypoDrop + " " + dfxPassportRun, digitsWant{pii.PassportNumber, dfxPassportRun, Weak}},
		{"вод. уд.", "вод. уд. " + dmkDriver, digitsWant{pii.DriverLicense, dmkDriver, Strong}},
		{"уд. без вод.", "уд. " + dmkDriver, digitsWant{pii.PassportNumber, dmkDriver, Weak}},
		{"выдан слева", "выдан " + dfxPassport, digitsWant{pii.PassportNumber, dfxPassport, Weak}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spans := scanDigitsText(t, c.text)
			if !hasDigitsSpan(c.text, spans, c.want) {
				t.Fatalf("нет кандидата %+v: %s", c.want, formatDigitsSpans(c.text, spans))
			}
		})
	}
}

// TestScanDigitsRound5NoAllocs — новые маркеры не добавляют аллокаций.
func TestScanDigitsRound5NoAllocs(t *testing.T) {
	const text = "пасорт 4509 123456, вод. уд. 7734 518206, паспорт серии 45 21 номер 603 918, " +
		"паспорт 4521 603 918, 4618 330291 выдан ОВД, пастор 4509 123456"
	doc := lex.Tokenize(text, nil)
	dicts := digitsTestDicts(t)
	var (
		s    digitsScanner
		cand Candidates
	)
	s.Scan(doc, dicts, &cand)
	if n := testing.AllocsPerRun(20, func() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}); n != 0 {
		t.Fatalf(msgScanAllocs, n)
	}
}
