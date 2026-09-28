package detect

import (
	"context"
	"strings"
	"testing"

	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Тесты голого значения (T-63). Все значения синтетические: имена, номера и
// учреждения вымышлены (AGENTS.md, «Инварианты приватности»). Пробы таблицы
// задачи повторяют прогон технического жюри, раунд 4, P4-3.

// Синтетические голые значения, которые повторяются в нескольких пробах.
const (
	bareSurname  = "Корнеева"
	barePassport = "4618 507329"
	bareCVV      = "314"
)

// bareProbe — голый payload и ожидаемое значение внутри него.
type bareProbe struct {
	text string
	typ  pii.Type
	// value — замаскированная часть, если она уже всей строки: служебное
	// слово «года» за датой в значение не входит. Пусто — вся строка.
	value string
}

// bareTableProbes — голые пробы таблицы задачи. Тип у голой даты выдачи и у
// водительского удостоверения из десяти цифр подряд совпадает с типом их
// двойников — даты рождения и паспорта: по одной форме их не различить, а
// сокрытие от типа не зависит.
var bareTableProbes = []bareProbe{
	{text: bareSurname, typ: pii.FullName},
	{text: "Д. Н. Шаповалова", typ: pii.FullName},
	{text: "27.03.1988", typ: pii.BirthDate},
	{text: "27 марта 1988 года", typ: pii.BirthDate, value: "27 марта 1988"},
	{text: "Москва", typ: pii.BirthPlace},
	{text: "г. Жуковский Московской области", typ: pii.BirthPlace},
	{text: "Российская Федерация", typ: pii.Citizenship},
	{text: "РФ", typ: pii.Citizenship},
	{text: barePassport, typ: pii.PassportNumber},
	{text: "4618507329", typ: pii.PassportNumber},
	{text: "ГУ МВД России по Московской области", typ: pii.PassportAuthority},
	{text: "Отделом УФМС России по г. Москве", typ: pii.PassportAuthority},
	{text: "500-137", typ: pii.PassportDeptCode},
	{text: "14.03.2019", typ: pii.BirthDate},
	{text: "50 23 118406", typ: pii.DriverLicense},
	{text: "5023118406", typ: pii.PassportNumber},
	{text: "9264071835", typ: pii.Phone},
	{text: bareCVV, typ: pii.CVV},
	{text: "0582", typ: pii.PIN},
	{text: "DARIA SHAPOVALOVA", typ: pii.CardHolder},
	{text: "Daria Shapovalova", typ: pii.CardHolder},
}

// bareMoreProbes — другие формы тех же типов: падежи, составные названия,
// транслитерация по разным схемам, обрамление и концевая пунктуация.
var bareMoreProbes = []bareProbe{
	{text: "Дарья", typ: pii.FullName},
	{text: "Никитична", typ: pii.FullName},
	{text: "КОРНЕЕВА", typ: pii.FullName},
	{text: "Корнеева.", typ: pii.FullName, value: bareSurname},
	{text: "«Корнеева»", typ: pii.FullName, value: bareSurname},
	{text: "  4618 507329\r\n", typ: pii.PassportNumber, value: barePassport},
	{text: "№ 4618 507329", typ: pii.PassportNumber, value: barePassport},
	{text: "12.05.2025", typ: pii.BirthDate},
	{text: "19880327", typ: pii.BirthDate},
	{text: "15 марта", typ: pii.BirthDate},
	{text: "27.03.1988 г.", typ: pii.BirthDate, value: "27.03.1988"},
	{text: "двенадцатого марта тысяча девятьсот восемьдесят седьмого", typ: pii.BirthDate},
	{text: "Россия", typ: pii.Citizenship},
	{text: "Республики Казахстан", typ: pii.Citizenship},
	{text: "Санкт-Петербург", typ: pii.BirthPlace},
	{text: "Ростов-на-Дону", typ: pii.BirthPlace},
	{text: "Великие Луки", typ: pii.BirthPlace},
	{text: "Ленинградская область", typ: pii.BirthPlace},
	{text: "г. Москва", typ: pii.BirthPlace},
	{text: "пос. Заречный", typ: pii.BirthPlace},
	{text: "ОВД Заречного района г. Ирбита", typ: pii.PassportAuthority},
	{text: "ТП УФМС России по Курганской области в г. Шадринске", typ: pii.PassportAuthority},
	{text: "Жук Герман", typ: pii.FullName},
	{text: "Герман Жук", typ: pii.FullName},
	{text: "Мельник Марина Олеговна", typ: pii.FullName},
	{text: "IVAN PETROV", typ: pii.CardHolder},
	{text: "Ivan Petrov", typ: pii.CardHolder},
	{text: "MARINA KOVAL", typ: pii.CardHolder},
	{text: "Ksenia Melnik", typ: pii.CardHolder},
	{text: "OLGA TSOI", typ: pii.CardHolder},
	{text: "IGOR MOROZ", typ: pii.CardHolder},
	{text: "SERGEY KOVAL", typ: pii.CardHolder},
	{text: "IURII MELNIK", typ: pii.CardHolder},
}

// TestBareValueMaskedWhole — AC-1: голое значение маскируется одним спаном на
// всё значение, и тип у него ожидаемый.
func TestBareValueMaskedWhole(t *testing.T) {
	e := newFullEngine(t)
	probes := append(append([]bareProbe{}, bareTableProbes...), bareMoreProbes...)
	for _, p := range probes {
		t.Run(p.text, func(t *testing.T) { checkBareMaskedWhole(t, e, p) })
	}
}

// checkBareMaskedWhole — одна проба TestBareValueMaskedWhole: ровно один
// спан ожидаемого типа на всё значение, не слабее Strong.
func checkBareMaskedWhole(t *testing.T, e *Engine, p bareProbe) {
	t.Helper()
	value := p.value
	if value == "" {
		value = p.text
	}
	off := strings.Index(p.text, value)
	if off < 0 {
		t.Fatalf("значение %q не входит в пробу", value)
	}
	spans := detectSpans(t, e, p.text, Options{})
	if len(spans) != 1 {
		t.Fatalf(msgOneSpanGot, len(spans), formatSpans(spans))
	}
	s := spans[0]
	if int(s.Start) != off || int(s.End) != off+len(value) || s.Type != p.typ {
		t.Fatalf("получено %s [%d,%d) %q, ожидалось %s [%d,%d) %q",
			s.Type.Key(), s.Start, s.End, p.text[s.Start:s.End],
			p.typ.Key(), off, off+len(value), value)
	}
	if s.Conf < Strong {
		t.Fatalf("уверенность %s ниже Strong: до маски такой спан не дойдёт", s.Conf)
	}
}

// bareCleanTexts — короткие строки без ПД. Первые пять названы в AC-2
// задачи, дальше — формы, на которых классификатор ошибался бы, будь он
// шире: слова с заглавной, названия ведомств без территории, латиница без
// сходства с именем, публичные персоны и короткий номер организации.
var bareCleanTexts = []string{
	"Добрый день",
	"Спасибо",
	"Москва — столица России",
	"поэт Пушкин",
	"ул. Пушкина",
	"Спасибо!",
	"Хорошо, спасибо",
	"Здравствуйте",
	"Добрый День",
	"Итого",
	"Новости",
	"Отлично",
	"Готово",
	"Ок",
	"Да",
	"Нет",
	"Альфа-Банк",
	"ПАО Сбербанк",
	"МВД",
	"МВД России",
	"ГУ МВД России",
	"HELLO WORLD",
	"Visa Classic",
	"Пушкин",
	"Гагарин",
	"Жуковский",
	"*0582",
	"Спасибо? 314",
	"Код: 314",
	"Номер\n314",
}

// TestBareCleanTextUnchanged — AC-2: короткая строка без ПД не маскируется.
func TestBareCleanTextUnchanged(t *testing.T) {
	e := newFullEngine(t)
	for _, text := range bareCleanTexts {
		if spans := detectSpans(t, e, text, Options{}); len(spans) != 0 {
			t.Errorf("%q: ожидалось без изменений, получено %s", text, formatSpans(spans))
		}
	}
}

// TestBareRespectsVeto — контр-правило сильнее голой формы: фамилия
// публичной персоны целиком строки остаётся открытой, а тот же город с
// обозначением типа — место.
func TestBareRespectsVeto(t *testing.T) {
	e := newFullEngine(t)
	for _, text := range []string{"Пушкин", "Жуковский", "Гагарин"} {
		if spans := detectSpans(t, e, text, Options{}); len(spans) != 0 {
			t.Errorf("%q: вето публичной персоны не сработало: %s", text, formatSpans(spans))
		}
	}
	spans := detectSpans(t, e, "г. Жуковский", Options{})
	if len(spans) != 1 || spans[0].Type != pii.BirthPlace || spans[0].Start != 0 {
		t.Errorf("«г. Жуковский»: ожидалось место рождения на всю строку, получено %s", formatSpans(spans))
	}
}

// TestBareNameWithoutSuffixNeedsSurnameShape — слово без роли рядом с
// именем становится фамилией, только если проходит отсев сканера ФИО и имя
// стоит в именительном падеже: приветствие, обращение-прилагательное и месяц
// фамилией не бывают, а имя в косвенном падеже — «Спроси Олега» — значит,
// что рядом глагол. Строка целиком под маску ФИО не уходит.
func TestBareNameWithoutSuffixNeedsSurnameShape(t *testing.T) {
	e := newFullEngine(t)
	for _, text := range []string{
		"Привет Марина", "Дорогая Марина", "Спасибо Марина", "Январь Марина",
		"Напиши Ивану", "Спроси Олега", "Передай Анне",
	} {
		for _, s := range detectSpans(t, e, text, Options{}) {
			if s.Start == 0 {
				t.Errorf("%q: первое слово попало под маску %s", text, formatSpans([]Span{s}))
			}
		}
	}
}

// TestBarePlaceNeedsEveryWordConfirmed — без обозначения места каждое слово
// строки обязано входить в город, регион или страну из справочников: имя
// рядом с городом местом рождения не становится.
func TestBarePlaceNeedsEveryWordConfirmed(t *testing.T) {
	e := newFullEngine(t)
	for _, s := range detectSpans(t, e, "Иван Грозный", Options{}) {
		if s.Type == pii.BirthPlace {
			t.Errorf("«Иван Грозный» принят за место рождения: %s", formatSpans([]Span{s}))
		}
	}
}

// TestBareProfiles — шаг работает под balanced и paranoid; strict голое
// значение не трогает.
func TestBareProfiles(t *testing.T) {
	e := newFullEngine(t)
	for _, p := range bareTableProbes {
		strict := detectSpans(t, e, p.text, Options{Profile: Strict})
		for _, s := range strict {
			if strings.HasPrefix(s.Rule, "bare/") || strings.HasSuffix(s.Rule, bareSuffix) {
				t.Errorf("%q: под strict сработало правило голого значения %s", p.text, formatSpans(strict))
			}
		}
		paranoid := detectSpans(t, e, p.text, Options{Profile: Paranoid})
		if len(paranoid) != 1 || paranoid[0].Type != p.typ {
			t.Errorf("%q под paranoid: ожидался один спан %s, получено %s", p.text, p.typ.Key(), formatSpans(paranoid))
		}
	}
	// Три цифры сами по себе под strict — не CVV.
	if spans := detectSpans(t, e, bareCVV, Options{Profile: Strict}); len(spans) != 0 {
		t.Errorf("«314» под strict: ожидалось без изменений, получено %s", formatSpans(spans))
	}
}

// TestBareLiftWeakCandidate — слабый кандидат, накрывающий всю строку,
// поднимается с пометкой правила: у шести цифр подряд своей формы в
// классификаторе нет, но сканер адреса видит в них индекс.
func TestBareLiftWeakCandidate(t *testing.T) {
	e := newFullEngine(t)
	spans := detectSpans(t, e, "500137", Options{})
	if len(spans) != 1 || spans[0].Start != 0 || spans[0].End != 6 {
		t.Fatalf("ожидался один спан на всю строку, получено %s", formatSpans(spans))
	}
	if !strings.HasSuffix(spans[0].Rule, bareSuffix) || spans[0].Conf != Strong {
		t.Fatalf("ожидался поднятый слабый кандидат с пометкой %q, получено %s", bareSuffix, formatSpans(spans))
	}
}

// TestBareNotInsideText — внутри предложения голая форма не действует:
// «314» в тексте без маркера и без соседних ПД остаётся открытым, как и до
// T-63. Иначе классификатор формы превратился бы в маскирование любых цифр.
func TestBareNotInsideText(t *testing.T) {
	e := newFullEngine(t)
	for _, text := range []string{
		"Заказ 314 будет готов завтра",
		"Москва приняла делегацию",
		"Встреча назначена на 12.05.2025, приходите вовремя",
		"Корнеева просит перезвонить",
	} {
		for _, s := range detectSpans(t, e, text, Options{}) {
			if strings.HasPrefix(s.Rule, "bare/") || strings.HasSuffix(s.Rule, bareSuffix) {
				t.Errorf("%q: правило голого значения сработало внутри текста: %s", text, formatSpans([]Span{s}))
			}
		}
	}
}

// TestBareCore — границы голого значения: обрамление и концевые знаки
// отбрасываются, второе предложение, поле формы и перевод строки делают
// строку не голой.
func TestBareCore(t *testing.T) {
	tests := []struct {
		text  string
		value string // пусто — строка не голая
	}{
		{bareCVV, bareCVV},
		{" (314). ", bareCVV},
		{"— Корнеева…", bareSurname},
		{"г. Москва.", "г. Москва"},
		{"", ""},
		{" .,; ", ""},
		{"*314", ""},
		{"+314", ""},
		{"CVV: 314", ""},
		{"Корнеева? Да", ""},
		{"Корнеева; Дарья", ""},
		{"Корнеева\nДарья", ""},
		{strings.Repeat("слово ", bareMaxWords+1), ""},
	}
	for _, tt := range tests {
		doc := lex.Tokenize(tt.text, nil)
		lo, hi, ok := bareCore(doc)
		got := ""
		if ok {
			got = tt.text[doc.Tokens[lo].Start:doc.Tokens[hi].End]
		}
		if got != tt.value {
			t.Errorf("bareCore(%q) = %q, ожидалось %q", tt.text, got, tt.value)
		}
	}
}

// TestBareLatinGiven — обратная транслитерация находит имя из справочника
// по записи любой из схем, а на английских словах молчит.
func TestBareLatinGiven(t *testing.T) {
	given := engineTestDicts(t).Table(nameDictGiven)
	for _, w := range []string{
		"daria", "darya", "maria", "sergei", "sergey", "dmitrii", "dmitry",
		"iurii", "yuri", "olga", "igor", "kseniia", "ksenia", "natalia",
		"tatiana", "aleksandr", "alexander", "mikhail", "elvira", "ilya",
	} {
		if !bareLatinGiven(given, w) {
			t.Errorf("%q: имя из справочника не найдено", w)
		}
	}
	for _, w := range []string{"hello", "world", "visa", "classic", "gold", "platinum"} {
		if bareLatinGiven(given, w) {
			t.Errorf("%q: английское слово принято за имя", w)
		}
	}
	// Предел перебора: длинное слово из одних «i» и «y» не зависает.
	if bareLatinGiven(given, strings.Repeat("iy", 16)) {
		t.Error("слово из повторов «iy» принято за имя")
	}
}

// TestBareZeroAllocs — голое значение не добавляет аллокаций: накопитель
// переиспользуется, имена правил берутся из кеша, ключ транслитерации
// собирается на стеке.
func TestBareZeroAllocs(t *testing.T) {
	e := newFullEngine(t)
	texts := []string{
		bareCVV, "9264071835", bareSurname, "Москва", "500137",
		"ГУ МВД России по Московской области", "Daria Shapovalova",
	}
	docs := make([]*lex.Doc, len(texts))
	for i, text := range texts {
		docs[i] = lex.Tokenize(text, nil)
	}
	var (
		cand Candidates
		res  Result
	)
	run := func() {
		for _, doc := range docs {
			if _, err := e.Detect(context.Background(), doc, Options{}, &cand, &res); err != nil {
				t.Fatalf(msgDetectFailed, err)
			}
		}
	}
	run() // прогрев: ёмкость накопителей и кеш имён правил
	if n := testing.AllocsPerRun(50, run); n != 0 {
		t.Fatalf("аллокаций на прогон: %v, ожидалось 0", n)
	}
}

// BenchmarkDetectBare — стоимость шага на коротком входе, где он работает.
// Длинный вход меряет BenchmarkDetect: там шаг стоит одного сравнения длины.
func BenchmarkDetectBare(b *testing.B) {
	e := newFullEngine(b)
	docs := make([]*lex.Doc, 0, len(bareTableProbes))
	for _, p := range bareTableProbes {
		docs = append(docs, lex.Tokenize(p.text, nil))
	}
	var (
		cand Candidates
		res  Result
	)
	b.ReportAllocs()
	for b.Loop() {
		for _, doc := range docs {
			if _, err := e.Detect(context.Background(), doc, Options{}, &cand, &res); err != nil {
				b.Fatalf(msgDetectFailed, err)
			}
		}
	}
}
