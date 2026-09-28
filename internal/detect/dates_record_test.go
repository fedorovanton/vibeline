package detect

import (
	"testing"

	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Записи и даты в этом файле синтетические: реальные персональные данные в
// репозиторий не попадают (AGENTS.md, «Инварианты приватности»).

// Синтетические значения, которые повторяются в проверках файла.
const (
	// drcDate — дата рождения в записях анкеты.
	drcDate = "02.02.1979"
	// drcPhone — поле телефона в записи через точку с запятой.
	drcPhone = ";89031234567"
	// drcJournal — строка журнала операций: дата без имени.
	drcJournal = "12.03.2005;Оплата;500;Магазин"
	// drcYear, drcEvent — год рождения и дата события после него.
	drcYear  = "1981"
	drcEvent = "12.03.2026"
)

// TestDatesRecordField — дата в записи анкеты через разделитель: Strong
// дата рождения по форме строки (технический жюри 23.09, раунд 5, P5-1).
func TestDatesRecordField(t *testing.T) {
	dicts := datesDicts(t)
	for _, text := range []string{
		"Лысенко;Ольга;Петровна;" + drcDate + drcPhone,
		"Лысенко,Ольга,Петровна," + drcDate,
		"Лысенко Ольга Петровна;" + drcDate + drcPhone,
		"Фамилия;Имя;Отчество;Дата рождения\nЛысенко;Ольга;Петровна;" + drcDate,
		drcDate + ";Лысенко;Ольга;Москва",
		"Лысенко | Ольга | Петровна | " + drcDate,
		"Лысенко;Игорь;Сергеевич;" + drcDate + "\n12.03.2005;Оплата;500",
	} {
		t.Run(text, func(t *testing.T) {
			if !datesHasStrongBirth(text, datesScan(t, dicts, text), drcDate) {
				t.Fatalf("дата %q не размечена датой рождения Strong", drcDate)
			}
		})
	}
}

// TestDatesRecordFieldRejected — строки, которые записью анкеты не являются:
// нет личного имени, мало полей, запятая с пробелом, дата события.
func TestDatesRecordFieldRejected(t *testing.T) {
	dicts := datesDicts(t)
	for _, text := range []string{
		drcJournal,
		"Ольга, " + drcDate + ", Москва",
		"Ольга;" + drcDate,
		"ольга;петровна;" + drcDate + ";москва",
		"Лысенко;Ольга\n" + drcDate + ";500;120",
		"Лысенко;Ольга;Петровна;12.03.2024",
	} {
		t.Run(text, func(t *testing.T) {
			for _, s := range datesScan(t, dicts, text) {
				if s.Conf >= Strong {
					t.Errorf("кандидат %q %v %s, ожидался не выше Weak", text[s.Start:s.End], s.Conf, s.Rule)
				}
			}
		})
	}
}

// TestDatesBirthMarkerOwnedByYear — пометка «года рождения» после года
// относится к этому году, а не к следующей дате (P5-7).
func TestDatesBirthMarkerOwnedByYear(t *testing.T) {
	dicts := datesDicts(t)
	cases := []struct {
		name string
		text string
		// birth — значения, которые обязаны быть датой рождения Strong;
		// event — значения, которые не должны быть ею.
		birth, event string
	}{
		{"года рождения", "Клиент 1981 года рождения, 12.03.2026 подал жалобу", drcYear, drcEvent},
		{"г.р.", "Клиент 1981 г.р., 12.03.2026 подал жалобу", drcYear, drcEvent},
		{"г. рожд.", "Клиент 1981 г. рожд., 12.03.2026 обратился", drcYear, drcEvent},
		{"д.р. после телефона", "тел 89031234567 д.р. 12.03.1985", dateSample1985, ""},
		{"р. после имени", "Ершова Рита, р. 12.03.1985", dateSample1985, ""},
		{"дата рождения", "Клиент 1981 года, дата рождения 12.03.1985", dateSample1985, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spans := datesScan(t, dicts, c.text)
			if !datesHasStrongBirth(c.text, spans, c.birth) {
				t.Errorf("%q: нет даты рождения Strong; кандидаты %v", c.birth, spans)
			}
			if c.event != "" && datesHasStrongBirth(c.text, spans, c.event) {
				t.Errorf("%q размечено датой рождения", c.event)
			}
		})
	}
}

// datesHasStrongBirth сообщает, что среди кандидатов есть дата рождения не
// слабее Strong ровно по значению v.
func datesHasStrongBirth(text string, spans []Span, v string) bool {
	for _, s := range spans {
		if s.Type == pii.BirthDate && s.Conf >= Strong && text[s.Start:s.End] == v {
			return true
		}
	}
	return false
}

// TestDetectDatesRecord — P5-1 и P5-7 через весь конвейер.
func TestDetectDatesRecord(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"запись через точку с запятой", "Лысенко Ольга Петровна;" + drcDate + drcPhone,
			"[ФИО];[ДАТА_РОЖДЕНИЯ];[ТЕЛЕФОН]"},
		{"дата события после года рождения", "Клиент 1981 года рождения, 12.03.2026 подал жалобу",
			"Клиент [ДАТА_РОЖДЕНИЯ] года рождения, 12.03.2026 подал жалобу"},
		{"журнал операций", drcJournal, drcJournal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := digitsMasked(t, c.text); got != c.want {
				t.Errorf(msgMaskWant, got, c.want)
			}
		})
	}
}

// TestDatesRecordNoAllocs — разбор записи не аллоцирует.
func TestDatesRecordNoAllocs(t *testing.T) {
	const text = "Лысенко;Ольга;Петровна;02.02.1979;89031234567\nКлиент 1981 года рождения, 12.03.2026 подал жалобу"
	doc := lex.Tokenize(text, nil)
	dicts := datesDicts(t)
	var (
		s    datesScanner
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
