package detect

import (
	"fmt"
	"strings"
	"testing"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Все тексты в этом файле синтетические: реальные персональные данные в
// репозиторий не попадают (AGENTS.md, «Инварианты приватности»).

// Синтетические даты, которые повторяются в нескольких проверках файла.
const (
	dateSampleDMY  = "12.05.1990"
	dateSample1985 = "12.03.1985"
	dateSampleYMD  = "1990.05.12"
)

func datesDicts(tb testing.TB) *dict.Set {
	tb.Helper()
	set, err := dict.Load()
	if err != nil {
		tb.Fatalf(msgDictLoad, err)
	}
	return set
}

// datesScan прогоняет сканер дат по тексту и отдаёт найденных кандидатов.
func datesScan(tb testing.TB, dicts *dict.Set, text string) []Span {
	tb.Helper()
	var cand Candidates
	datesScanner{}.Scan(lex.Tokenize(text, nil), dicts, &cand)
	return cand.Spans
}

// requireOneDate требует ровно одного кандидата и возвращает его.
func requireOneDate(t *testing.T, spans []Span) Span {
	t.Helper()
	if len(spans) != 1 {
		t.Fatalf(msgOneCandidateGot, len(spans), spans)
	}
	return spans[0]
}

func TestDatesFormats(t *testing.T) {
	dicts := datesDicts(t)
	tests := []struct {
		name string
		text string
		span string
		typ  pii.Type
		conf Confidence
	}{
		{"точки", "дата рождения 12.05.1990", dateSampleDMY, pii.BirthDate, Strong},
		{"слэши", "дата рождения 12/05/1990", "12/05/1990", pii.BirthDate, Strong},
		{"дефисы", "дата рождения 12-05-1990", "12-05-1990", pii.BirthDate, Strong},
		{"пробелы", "дата рождения 12 05 1990", "12 05 1990", pii.BirthDate, Strong},
		{"двузначный год", "дата рождения 12.05.90", "12.05.90", pii.BirthDate, Strong},
		{"год первым", "дата рождения 1990.05.12", dateSampleYMD, pii.BirthDate, Strong},
		{"сокращение д.р.", "д.р. 12.05.1990", dateSampleDMY, pii.BirthDate, Strong},
		{"маркер справа", "12.05.1990 г.р.", dateSampleDMY, pii.BirthDate, Strong},
		{"словами с годом", "родился 12 мая 1990 года", "12 мая 1990", pii.BirthDate, Strong},
		{"словами без года", "дата рождения 15 марта", "15 марта", pii.BirthDate, Strong},
		{"месяц и год", "дата рождения май 1990", "май 1990", pii.BirthDate, Strong},
		{"месяц день год", "родилась мая 12, 1990", "мая 12, 1990", pii.BirthDate, Strong},
		{"только год", "1990 г.р.", "1990", pii.BirthDate, Strong},
		{"год после маркера", "родился в 1990 году", "1990", pii.BirthDate, Strong},
		{"выдан", "паспорт выдан 20.03.2015", "20.03.2015", pii.PassportIssueDate, Strong},
		{"дата выдачи", "дата выдачи: 20.03.2015", "20.03.2015", pii.PassportIssueDate, Strong},
		{"без маркера", "в анкете указано 12.05.1990", dateSampleDMY, pii.BirthDate, Weak},
		{"будущий год с маркером", "родился 12.05.2090", "12.05.2090", pii.BirthDate, Weak},

		// Дата словами целиком: день порядковым числительным и год словами
		// (ТЗ §2.2, REQ-202). До T-26 день и год словами оставались вне маски.
		{"день словом", "дата рождения шестнадцатое февраля 1959 года", "шестнадцатое февраля 1959", pii.BirthDate, Strong},
		{"день в родительном", "родился двенадцатого мая 1990 года", "двенадцатого мая 1990", pii.BirthDate, Strong},
		{"составной день", "дата рождения двадцать первого мая 1990", "двадцать первого мая 1990", pii.BirthDate, Strong},
		{"составной день именительный", "дата рождения тридцать первое марта 1985", "тридцать первое марта 1985", pii.BirthDate, Strong},
		{"день словом без года", "дата рождения пятнадцатое марта", "пятнадцатое марта", pii.BirthDate, Strong},
		{"год словами", "родился двенадцатого мая тысяча девятьсот девяностого года", "двенадцатого мая тысяча девятьсот девяностого", pii.BirthDate, Strong},
		{"год словами две тысячи", "дата рождения первое января две тысячи первого года", "первое января две тысячи первого", pii.BirthDate, Strong},
		{"цифровой день и год словами", "родился 12 мая тысяча девятьсот девяностого года", "12 мая тысяча девятьсот девяностого", pii.BirthDate, Strong},
		{"месяц и год словами", "дата рождения май тысяча девятьсот девяностого года", "май тысяча девятьсот девяностого", pii.BirthDate, Strong},
		{"год словами без месяца", "родился в тысяча девятьсот девяностом году", "тысяча девятьсот девяностом", pii.BirthDate, Strong},
		{"двухтысячный", "родилась в двухтысячном году", "двухтысячном", pii.BirthDate, Strong},
		{"выдан через орган", "паспорт выдан ГУ МВД России по Свердловской области 25.12.2007", "25.12.2007", pii.PassportIssueDate, Strong},
		{"выдан через орган словами", "паспорт выдан ГУ МВД России по Свердловской области двадцать пятого декабря две тысячи седьмого", "двадцать пятого декабря две тысячи седьмого", pii.PassportIssueDate, Strong},
		{"выдача словами", "паспорт выдан двадцатого марта две тысячи пятнадцатого года", "двадцатого марта две тысячи пятнадцатого", pii.PassportIssueDate, Strong},
		{"словами без маркера", "в анкете указано шестнадцатое февраля 1959", "шестнадцатое февраля 1959", pii.BirthDate, Weak},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := requireOneDate(t, datesScan(t, dicts, tt.text))
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
			if s.Type != tt.typ {
				t.Errorf("тип %v, ожидался %v", s.Type, tt.typ)
			}
			if s.Conf != tt.conf {
				t.Errorf(msgConfWant, s.Conf, tt.conf)
			}
		})
	}
}

// TestDatesIssueMarkerFarStops проверяет, что дальний поиск маркера выдачи
// обрывается на числе и на маркере рождения: «выдан» относится к ближайшему
// значению, а не ко всем датам текста.
func TestDatesIssueMarkerFarStops(t *testing.T) {
	dicts := datesDicts(t)
	tests := []struct {
		name, text, span string
	}{
		{"число по дороге", "паспорт выдан 20.03.2015, в анкете клиента указано 12.05.1990", dateSampleDMY},
		{"маркер рождения по дороге", "паспорт выдан, дата рождения указана в анкете отдельно от прочего 12.05.1990", dateSampleDMY},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, s := range datesScan(t, dicts, tt.text) {
				if tt.text[s.Start:s.End] == tt.span && s.Type == pii.PassportIssueDate {
					t.Errorf("дата %q отнесена к дате выдачи", tt.span)
				}
			}
		})
	}
}

// TestDatesEventNotBirth — дата события рядом с именем клиента не становится
// датой рождения: ни после слова платежа или операции, ни без маркера в
// текущем году (замечание технического жюри 23.09).
func TestDatesEventNotBirth(t *testing.T) {
	dicts := datesDicts(t)
	for _, text := range []string{
		"платёж от 03.03.2021 не прошёл",
		"перевод 12.05.1990 отклонён",
		"обращение от 14.02.2019 закрыто",
		fmt.Sprintf("в анкете указано 03.03.%d", dateNowYear),
	} {
		if spans := datesScan(t, dicts, text); len(spans) != 0 {
			t.Errorf("%q: дата события зарегистрирована: %v", text, spans)
		}
	}
	if spans := datesScan(t, dicts, fmt.Sprintf("дата рождения 03.03.%d", dateNowYear)); len(spans) != 1 {
		t.Errorf("дата рождения текущего года с маркером не найдена: %v", spans)
	}
}

// TestDatesExtendedForms — двузначный год, римский и английский месяц, «р.»
// перед датой (T-65, строки 3–5 и 13):
// значение целиком, без служебного слова «г.» в спане.
func TestDatesExtendedForms(t *testing.T) {
	dicts := datesDicts(t)
	tests := []struct {
		name, text, span string
		typ              pii.Type
	}{
		{"год двумя цифрами после месяца", "родилась 27 марта 88 г.", "27 марта 88", pii.BirthDate},
		{"год двумя цифрами перед года", "родился 5 июня 91 года", "5 июня 91", pii.BirthDate},
		{"римский месяц", "родилась 27.III.1988", "27.III.1988", pii.BirthDate},
		{"римский месяц дефисом и двузначный год", "дата рождения 5-XI-90", "5-XI-90", pii.BirthDate},
		{"римский месяц строчными", "д.р. 1.iv.1979", "1.iv.1979", pii.BirthDate},
		{"английский месяц", "born on 12 May 1990", "12 May 1990", pii.BirthDate},
		{"английский месяц первым", "DOB: May 12, 1990", "May 12, 1990", pii.BirthDate},
		{"английский месяц сокращением", "Date of birth 3 Sept 1985", "3 Sept 1985", pii.BirthDate},
		{"английский порядковый день", "born 1st June 1979", "1st June 1979", pii.BirthDate},
		{"р. перед датой", "Клиентка Ершова Рита, р. 12.03.1985, паспорт утерян.", dateSample1985, pii.BirthDate},
		{"р. перед датой словами", "Ершов Олег, р. 3 мая 1979", "3 мая 1979", pii.BirthDate},
		{"выдача с римским месяцем", "паспорт выдан 14.III.2019", "14.III.2019", pii.PassportIssueDate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := requireOneDate(t, datesScan(t, dicts, tt.text))
			if got := tt.text[s.Start:s.End]; got != tt.span || s.Type != tt.typ || s.Conf != Strong {
				t.Errorf("спан %q %v %v, ожидался %q %v Strong", got, s.Type, s.Conf, tt.span, tt.typ)
			}
		})
	}
}

// TestDatesExtendedFormsRejected — формы, похожие на новые, датой не становятся.
func TestDatesExtendedFormsRejected(t *testing.T) {
	dicts := datesDicts(t)
	for _, text := range []string{
		// Римская цифра через пробел — размер, а не месяц.
		"стол 5 X 10 1988 года выпуска",
		// Строчные английские месяцы — глаголы.
		"you may 12 times",
		// Двузначное число после месяца без «г.» — не год.
		"дата рождения 15 марта 20 человек",
		// Римского месяца XIII нет.
		"родился 12.XIII.1988",
	} {
		for _, s := range datesScan(t, dicts, text) {
			if got := text[s.Start:s.End]; strings.ContainsAny(got, "XxIi") || strings.Contains(got, "may") || strings.Contains(got, " 20") {
				t.Errorf("%q: лишний кандидат %q %v", text, got, s.Type)
			}
		}
	}
	// «р.» после числа — рубли, а не маркер рождения.
	for _, s := range datesScan(t, dicts, "Списано 500 р. 12.03.1985 по ошибке") {
		if s.Conf >= Strong {
			t.Errorf("дата после «500 р.» поднята до %v правилом %s", s.Conf, s.Rule)
		}
	}
}

// TestDatesEventWithoutBirthMarker — дата события без маркера рождения кандидата не
// получает (T-65, строка 1; P4-5, замечание T-64 о выписке за дату).
// Даты взяты и свежие, и старше четырнадцати лет: второе проверяет правило
// глагола и предлога, а не только правдоподобие года.
func TestDatesEventWithoutBirthMarker(t *testing.T) {
	dicts := datesDicts(t)
	for _, text := range []string{
		"Клиент Громов Антон Ильич оформил кредит 12.05.2024.",
		"Клиент Громов Антон Ильич оформил кредит 12.05.2004.",
		"Клиент Громов Антон Ильич обратился 01.02.2004 по поводу карты.",
		"12.05.2008 клиент Громов Антон Ильич закрыл вклад.",
		"Клиент Громов Антон Ильич, карта заблокирована 12 мая 2004 года.",
		"Выписка по счёту 40817810099910004312 за 01.01.2024 для Петрова Ивана Сергеевича.",
		"Выписка за 01.01.2005 для Петрова Ивана.",
		"Остаток по состоянию на 01.10.2008 — 500 рублей.",
		"Вклад открыт 03.03.2001, клиент Ершов Олег.",
		"Громов Антон Ильич, в период с 01.02.2003 по 01.03.2003 платежей не было.",
		// Год без маркера моложе четырнадцати лет — не дата рождения.
		"Клиент Громов Антон Ильич, 12.03.2015",
	} {
		if spans := datesScan(t, dicts, text); len(spans) != 0 {
			t.Errorf("%q: дата события зарегистрирована: %v", text, spans)
		}
	}
}

// TestDatesBirthNearEventWords — даты рождения рядом с теми же словами
// по-прежнему кандидаты: с маркером, с «г.р.», в анкете без маркера и когда
// между глаголом и датой стоит имя.
func TestDatesBirthNearEventWords(t *testing.T) {
	dicts := datesDicts(t)
	tests := []struct {
		text, span string
		conf       Confidence
	}{
		{"Громова Анна, дата рождения 03.04.1990, заявка подана 12.05.2024.", "03.04.1990", Strong},
		{"Клиент оформил кредит, 12.03.1985 г.р.", dateSample1985, Strong},
		{"Громов Антон Ильич, 12.03.1985 г.р.", dateSample1985, Strong},
		{"Громов Антон Ильич, 12.03.1985", dateSample1985, Weak},
		{"Вчера обратилась Иванова Анна 12.03.1985, просит выписку.", dateSample1985, Weak},
		{"12.03.1985 родился Громов Антон Ильич, клиент оформил кредит.", dateSample1985, Weak},
		{"Паспорт выдан ОВД Тверского района по 12.03.2015", "12.03.2015", Strong},
	}
	for _, tt := range tests {
		spans := datesScan(t, dicts, tt.text)
		found := false
		for _, s := range spans {
			if tt.text[s.Start:s.End] == tt.span && s.Conf == tt.conf {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: не найден кандидат %q (%v): %v", tt.text, tt.span, tt.conf, spans)
		}
	}
}

// TestDatesExtendedFormsNoAllocs — ветки T-65 (римский и английский месяц,
// двузначный год, глагол события, дата в начале предложения) не аллоцируют.
func TestDatesExtendedFormsNoAllocs(t *testing.T) {
	const text = "Клиент Громов Антон Ильич оформил кредит 12.05.2004. 12.05.2008 клиент закрыл вклад. " +
		"Родилась 27.III.1988, born on 12 May 1990, DOB: May 12, 1990, родилась 27 марта 88 г. " +
		"Ершова Рита, р. 12.03.1985. Выписка за 01.01.2005."
	doc := lex.Tokenize(text, nil)
	dicts := datesDicts(t)
	var cand Candidates
	s := datesScanner{}
	s.Scan(doc, dicts, &cand)
	if got := testing.AllocsPerRun(20, func() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}); got != 0 {
		t.Errorf(msgAllocsWant, got)
	}
}

func TestDatesRejected(t *testing.T) {
	dicts := datesDicts(t)
	tests := []struct {
		name string
		text string
	}{
		{"договор", "договор от 01.02.2024"},
		{"заказ", "заказ оформлен 01.02.2024"},
		{"заявка", "заявка принята 12.05.1990"},
		{"оплата", "оплата 01.02.2024"},
		{"срок", "срок действует до 01.02.2024"},
		{"сегодня", "сегодня 22.09.2026"},
		{"встреча", "встреча 15 марта"},
		{"день вне месяца", "31.02.2000"},
		{"месяц вне диапазона", "32.13.1990"},
		{"невалидная с маркером", "родился 31.02.2000"},
		{"год вне диапазона", "12.05.1850"},
		{"номер версии", "версия 1.2.3"},
		{"номер карты", "карта 1234 5678 9012 3456"},
		{"телефон", "телефон 8 916 123 45 67"},
		{"голый год без маркера", "сумма 1990 рублей"},
		{"время", "встретимся в 10:45"},

		// Числительные сами по себе датой не становятся: число завершает
		// только порядковое, а день засчитывается лишь перед словесным
		// месяцем.
		{"порядковое без месяца", "занял первое место"},
		{"количественное без порядкового", "сумма тысяча рублей"},
		{"число людей", "пришло двадцать человек"},
		{"век", "в двадцать первом веке"},
		{"год словами без маркера", "отчёт за две тысячи двадцатого года"},
		{"договор словами", "договор от первого февраля две тысячи двадцать четвёртого года"},
		{"год словами вне диапазона", "родился тысяча восемьсот пятидесятого года"},
		{"невалидный день словами", "родился тридцать первого февраля"},
		{"день и месяц через перенос", "родился первое\nмая"},
		{"улица словами", "улица Первого Мая"},
		{"улица цифрой", "улица 1 Мая"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if spans := datesScan(t, dicts, tt.text); len(spans) != 0 {
				t.Fatalf(msgNoCandidates, len(spans), tt.text[spans[0].Start:spans[0].End])
			}
		})
	}
}

// TestDatesBirthSuffixAndCompactForms — формы даты рождения из второго раунда технического
// жюри (N8, задача T-61): падежное окончание дня, год двумя цифрами словами,
// пометка «рождения» сразу за датой, английские маркеры и слитная запись.
func TestDatesBirthSuffixAndCompactForms(t *testing.T) {
	dicts := datesDicts(t)
	found := []struct {
		name, text, span string
		typ              pii.Type
	}{
		{"день с окончанием через дефис", "родилась 12-го мая 1990 года", "12-го мая 1990", pii.BirthDate},
		{"день с окончанием слитно", "родилась 12го мая 1990 года", "12го мая 1990", pii.BirthDate},
		{"первое число", "родился 1-е января 1985 года", "1-е января 1985", pii.BirthDate},
		{"год словами двумя цифрами", "родилась двенадцатое мая девяностого года", "двенадцатое мая девяностого", pii.BirthDate},
		{"год словами составной двузначный", "родился 12 мая девяносто пятого года", "12 мая девяносто пятого", pii.BirthDate},
		{"пометка рождения справа", "Клиентка Петрова А.С., 12.05.1990 рождения", dateSampleDMY, pii.BirthDate},
		{"DOB", "DOB 12.05.1990", dateSampleDMY, pii.BirthDate},
		{"date of birth", "Date of birth: 12.05.1990", dateSampleDMY, pii.BirthDate},
		{"born", "born 05/12/1990", "05/12/1990", pii.BirthDate},
		{"слитно гггг мм дд", "дата рождения 19851205", "19851205", pii.BirthDate},
		{"слитно дд мм гггг", "дата рождения 05121985", "05121985", pii.BirthDate},
		{"слитно дата выдачи", "дата выдачи 20150320", "20150320", pii.PassportIssueDate},
	}
	for _, tt := range found {
		t.Run(tt.name, func(t *testing.T) {
			s := requireOneDate(t, datesScan(t, dicts, tt.text))
			if got := tt.text[s.Start:s.End]; got != tt.span || s.Type != tt.typ || s.Conf != Strong {
				t.Errorf("спан %q %v %v, ожидался %q %v Strong", got, s.Type, s.Conf, tt.span, tt.typ)
			}
		})
	}
	// Даты событий и числа, похожие на новые формы, кандидатами не
	// становятся: слитная запись без маркера — номер, «-летний» — не день,
	// дата события текущего года и позже снимается, как и раньше.
	for _, text := range []string{
		"номер заявки 20240512",
		"договор 19851205 от 03.03.2021",
		"сумма 12051990 рублей",
		"12-летний стаж",
		"Платёж по графику 12-го мая 2027 года.",
		"Событие 12.05.2026 прошло успешно.",
		"Reborn 12.05.2026",
		"Он родился 5-го числа.",
		"пятого года выпуска",
	} {
		if spans := datesScan(t, dicts, text); len(spans) != 0 {
			t.Errorf("%q: кандидаты не ожидались: %q", text, text[spans[0].Start:spans[0].End])
		}
	}
}

// TestDatesOrderAmbiguity фиксирует правило разбора неоднозначного порядка
// компонентов: год определяется первым, оставшиеся два читаются как «день,
// месяц», если только один из них не больше 12.
func TestDatesOrderAmbiguity(t *testing.T) {
	tests := []struct {
		name string
		text string
		want dateValue
	}{
		{"дд.мм.гггг", dateSampleDMY, dateValue{day: 12, month: 5, year: 1990}},
		{"мм.дд.гггг", "05.25.1990", dateValue{day: 25, month: 5, year: 1990}},
		{"гггг.мм.дд", "1990.05.25", dateValue{day: 25, month: 5, year: 1990}},
		{"гггг.дд.мм", "1990.25.05", dateValue{day: 25, month: 5, year: 1990}},
		{"год первым по умолчанию", dateSampleYMD, dateValue{day: 5, month: 12, year: 1990}},
		{"год последним по умолчанию", "05.12.1990", dateValue{day: 5, month: 12, year: 1990}},
		{"двузначный год в прошлом веке", "12.05.90", dateValue{day: 12, month: 5, year: 1990}},
		{"двузначный год в текущем веке", "01.02.24", dateValue{day: 1, month: 2, year: 2024}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, last, ok := matchNumericDate(lex.Tokenize(tt.text, nil), 0)
			if !ok {
				t.Fatalf("дата %q не разобрана", tt.text)
			}
			if v != tt.want {
				t.Errorf("разобрано %+v, ожидалось %+v", v, tt.want)
			}
			if last != 4 {
				t.Errorf("последний токен %d, ожидался 4", last)
			}
		})
	}

	// AC-6: обе записи дают одну и ту же дату.
	direct, _, _ := matchNumericDate(lex.Tokenize("05.12.1990", nil), 0)
	reversed, _, _ := matchNumericDate(lex.Tokenize(dateSampleYMD, nil), 0)
	if direct != reversed {
		t.Errorf("«05.12.1990» разобрано как %+v, «1990.05.12» — как %+v", direct, reversed)
	}
}

func TestDatesCalendarValidation(t *testing.T) {
	tests := []struct {
		name string
		v    dateValue
		want bool
	}{
		{"29 февраля високосного", dateValue{day: 29, month: 2, year: 2000}, true},
		{"29 февраля невисокосного", dateValue{day: 29, month: 2, year: 1900}, false},
		{"29 февраля 2024", dateValue{day: 29, month: 2, year: 2024}, true},
		{"31 апреля", dateValue{day: 31, month: 4, year: 1990}, false},
		{"31 марта", dateValue{day: 31, month: 3, year: 1990}, true},
		{"месяц 13", dateValue{day: 1, month: 13, year: 1990}, false},
		{"месяц 0", dateValue{day: 1, month: 0, year: 1990}, false},
		{"год ниже границы", dateValue{day: 1, month: 1, year: 1899}, false},
		{"год выше границы", dateValue{day: 1, month: 1, year: 2101}, false},
		{"год не указан", dateValue{day: 29, month: 2}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.valid(); got != tt.want {
				t.Errorf("valid(%+v) = %v, ожидалось %v", tt.v, got, tt.want)
			}
		})
	}
}

// TestDatesWordNumber проверяет накопитель числа, записанного словами, в
// изоляции от остального разбора: сложение разрядов, множитель тысяч и
// требование порядкового числительного в конце.
func TestDatesWordNumber(t *testing.T) {
	nums := datesDicts(t).Table(dateNumeralsTable)
	tests := []dateWordNumCase{
		{"день", "шестнадцатое", 16, true},
		{"составной день", "двадцать первого", 21, true},
		{"составной день именительный", "тридцать первое", 31, true},
		{"год", "тысяча девятьсот девяностого", 1990, true},
		{"год с десятками", "тысяча девятьсот восемьдесят пятого", 1985, true},
		{"две тысячи", "две тысячи первого", 2001, true},
		{"двухтысячный", "двухтысячного", 2000, true},
		{"одна тысяча", "одна тысяча девятьсот семнадцатого", 1917, true},
		{"без порядкового", "тысяча", 0, false},
		{"сотни без порядкового", "девятьсот", 0, false},
		{"десятки без порядкового", "двадцать", 0, false},
		{"не числительное", "рублей", 0, false},
		{"пусто", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkDateWordNum(t, nums, tt) })
	}
}

// dateWordNumCase — текст числа словами и ожидаемый разбор.
type dateWordNumCase struct {
	name  string
	text  string
	value int
	ok    bool
}

// checkDateWordNum — один случай TestDatesWordNumber.
func checkDateWordNum(t *testing.T, nums *dict.Table, tt dateWordNumCase) {
	t.Helper()
	doc := lex.Tokenize(tt.text, nil)
	if len(doc.Tokens) == 0 {
		if tt.ok {
			t.Fatalf("текст %q не дал ни одного токена", tt.text)
		}
		return
	}
	v, last, ok := dateWordNum(doc, nums, 0)
	if ok != tt.ok {
		t.Fatalf("признак разбора %v, ожидался %v", ok, tt.ok)
	}
	if !tt.ok {
		return
	}
	if v != tt.value {
		t.Errorf("значение %d, ожидалось %d", v, tt.value)
	}
	if last != len(doc.Tokens)-1 {
		t.Errorf("последний токен %d, ожидался %d", last, len(doc.Tokens)-1)
	}
}

// TestDatesNumeralsTable ловит опечатку в справочнике числительных на стадии
// теста, а не на прогоне: каждая метка обязана нести роль и разбираемое
// значение.
func TestDatesNumeralsTable(t *testing.T) {
	nums := datesDicts(t).Table(dateNumeralsTable)
	if nums.Len() < 100 {
		t.Fatalf("в справочнике %d записей, ожидалось не меньше 100", nums.Len())
	}
	for _, w := range []string{"тысяча", "девятьсот", "двадцать", "шестнадцатое", "девяностого", "двухтысячном"} {
		doc := lex.Tokenize(w, nil)
		if _, _, ok := dateNumeral(doc, nums, 0); !ok {
			t.Errorf("числительное %q не читается из справочника", w)
		}
	}
}

// TestDatesSpanByteOffsets проверяет, что смещения спана байтовые: кириллица
// слева от даты занимает по два байта на букву.
func TestDatesSpanByteOffsets(t *testing.T) {
	const text = "родился 12 мая 1990 года"
	spans := datesScan(t, datesDicts(t), text)
	if len(spans) != 1 {
		t.Fatalf(msgOneCandidate, len(spans))
	}
	const want = "12 мая 1990"
	// «родился » — восемь символов, из них семь кириллических: 15 байт.
	if spans[0].Start != 15 {
		t.Errorf("начало спана %d, ожидалось 15", spans[0].Start)
	}
	if int(spans[0].Start) != strings.Index(text, want) {
		t.Errorf(msgSpanStartWant, spans[0].Start, strings.Index(text, want))
	}
	if int(spans[0].End) != strings.Index(text, want)+len(want) {
		t.Errorf(msgSpanEndWant, spans[0].End, strings.Index(text, want)+len(want))
	}
}

// datesBenchBlock — синтетический фрагмент со всеми ветками разбора.
const datesBenchBlock = "Анкета клиента: дата рождения 12.05.1990, паспорт выдан 20.03.2015. " +
	"Второй заявитель родился 7 августа 1985 года, третий — 1978 г.р. " +
	"Договор от 01.02.2024 и встреча 15 марта к персональным данным не относятся. " +
	"Четвёртый заявитель родился двадцать первого мая тысяча девятьсот восемьдесят пятого года. " +
	"Пятая анкета: дата рождения шестнадцатое февраля 1959 года, сумма тысяча рублей не в счёт. " +
	"Запасные записи: 12/05/1990, 12-05-1990, 12 05 1990, 1990.05.12, 05.25.1990, 12.05.90. " +
	"Невалидные строки 32.13.1990 и 31.02.2000 отбрасываются проверкой календаря. " +
	"Версия документа 1.2.3, счёт 1234 5678 9012 3456, время 10:45.\n"

var datesBenchText = strings.Repeat(datesBenchBlock, 4096/len(datesBenchBlock)+1)

func BenchmarkScanDates(b *testing.B) {
	if len(datesBenchText) < 4096 || len(datesBenchText) > 8192 {
		b.Fatalf(msgBenchTextSize, len(datesBenchText))
	}
	doc := lex.Tokenize(datesBenchText, nil)
	dicts := datesDicts(b)
	var cand Candidates
	s := datesScanner{}
	// Прогрев: накопитель набирает ёмкость, чтобы в измерении остался только
	// разбор. Аллокаций в Scan быть не должно.
	s.Scan(doc, dicts, &cand)
	if len(cand.Spans) == 0 {
		b.Fatal("в тексте бенчмарка не найдено ни одной даты")
	}
	b.SetBytes(int64(len(datesBenchText)))
	b.ReportAllocs()
	for b.Loop() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}
}
