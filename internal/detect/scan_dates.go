package detect

import (
	"strings"
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

func init() { Register(datesScanner{}) }

// datesScanner — даты рождения и даты выдачи паспорта во всех употребимых
// написаниях (ТЗ §2.2).
//
// Разбор идёт по токенам lex.Doc: regexp в горячем пути запрещён, а работа по
// токенам вдобавок даёт точную границу значения — «года», «г.р.» и маркер слева
// в спан не попадают.
//
// Тип даты задаёт ближайший маркер слева: в русском тексте реквизит следует за
// своим названием («дата рождения 12.05.1990», «паспорт выдан 20.03.2015»).
// Даты событий снимаются стоп-маркерами: срок договора и время встречи
// персональными данными субъекта не являются.
type datesScanner struct{}

// Name реализует Scanner.
func (datesScanner) Name() string { return "dates" }

// Имена справочников сканера дат.
const (
	dateMonthsTable   = "months"
	dateNumeralsTable = "numerals"
)

// dateTables — справочники, прочитанные один раз за Scan. Поиск таблицы по
// имени — обращение к карте; в горячем пути оно не повторяется на каждый токен.
type dateTables struct {
	months   *dict.Table
	numerals *dict.Table
	// given — справочник личных имён: по нему опознаётся запись анкеты
	// через разделитель, см. datesRecordField.
	given *dict.Table
}

const (
	// dateNowYear — опорный год для оценки правдоподобия возраста. Константа,
	// а не time.Now: результат детекции обязан быть воспроизводимым и не
	// зависеть от системных часов при прогоне тестов и бенчмарков.
	dateNowYear = 2026
	// dateMaxAge — предельный правдоподобный возраст живущего человека.
	dateMaxAge = 120
	// dateMinAge — младший правдоподобный возраст клиента для даты без
	// маркера рождения: с четырнадцати лет выдаётся паспорт. Опорный год —
	// та же константа dateNowYear, а не time.Now: маскирование остаётся
	// чистой функцией от (payload, policy), и повтор запроса через год даёт
	// ту же маску, что и сегодня (решение T-65).
	dateMinAge = 14
	// dateMinYear, dateMaxYear — допустимый диапазон года.
	dateMinYear = 1900
	dateMaxYear = 2100
	// dateWordNumParts — предел числа компонентов в числе, записанном
	// словами: «одна тысяча девятьсот восемьдесят пятого» — пять. Граница
	// делает разбор константным по времени и не даёт неудачной попытке уйти
	// далеко по тексту.
	dateWordNumParts = 6
	// dateLeapRef — опорный год для проверки дня, когда год не указан.
	// Високосный: «29 февраля» без года отбраковывать нельзя.
	dateLeapRef = 2000
)

// dateValue — разобранная дата. Нулевой день означает «день не указан»
// («май 1990»), нулевой месяц — что найден только год («1990 г.р.»),
// нулевой год — что год не указан («15 марта»).
type dateValue struct {
	day   int
	month int
	year  int
	// compact — дата записана слитно восемью цифрами («19851205»). Такое
	// число без маркера ничем не отличается от номера заявки или суммы,
	// поэтому регистрируется только при маркере рождения или выдачи.
	compact bool
}

// Scan реализует Scanner.
func (datesScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	tabs := dateTables{
		months:   dicts.Table(dateMonthsTable),
		numerals: dicts.Table(dateNumeralsTable),
		given:    dicts.Table(datesGivenTable),
	}
	for i := 0; i < len(doc.Tokens); {
		v, last, ok := matchDate(doc, tabs, i)
		if !ok {
			i++
			continue
		}
		registerDate(doc, out, tabs, v, i, last)
		// Разобранная дата не пересматривается со сдвигом на компонент:
		// «01.02.2024» не должна дать второго кандидата с «02.2024».
		i = last + 1
	}
}

// matchDate пробует прочитать дату, начинающуюся с токена i. Второе значение —
// индекс последнего токена даты, третье — признак успеха.
func matchDate(doc *lex.Doc, tabs dateTables, i int) (dateValue, int, bool) {
	if v, last, ok := matchNumericDate(doc, i); ok {
		return v, last, true
	}
	if v, last, ok := matchRomanDate(doc, i); ok {
		return v, last, true
	}
	// Словесная дата: «12 мая 1990», «май 1990». Разбор по виду первого
	// токена идёт прямо здесь, а не отдельной функцией: matchDate вызывается
	// на каждом токене, и лишний уровень вызова был заметен в бенчмарке.
	switch doc.Tokens[i].Kind {
	case lex.KindDigits:
		if v, last, ok := matchWordDateDayFirst(doc, tabs, i); ok {
			return v, last, true
		}
	case lex.KindWord:
		if v, last, ok := matchWordDateMonthFirst(doc, tabs, i); ok {
			return v, last, true
		}
	}
	// Проверка длины — до вызова: слитная запись — редкая форма, и цена
	// её разбора не должна ложиться на каждый токен документа.
	if t := doc.Tokens[i]; t.Kind == lex.KindDigits && t.Len() == dateCompactLen {
		if v, ok := matchCompactDate(doc, i); ok {
			return v, i, true
		}
		return dateValue{}, 0, false
	}
	return matchYearOnly(doc, i)
}

// registerDate относит найденную дату к типу по ближайшему маркеру.
func registerDate(doc *lex.Doc, out *Candidates, tabs dateTables, v dateValue, first, last int) {
	mk := dateMarkerFor(doc, first, last)
	// Дата события — «оформил кредит 12.05.2024», «выписка за 01.01.2024»,
	// «12.05.2024 клиент закрыл вклад» — реквизит операции, а не человека.
	// Без маркера рождения кандидата она не получает: рядом с ФИО клиента
	// подъём по кластеру делал её «датой рождения» (замечание технического
	// жюри 23.09, раунд 4, P4-5). Пометка «г.р.» после даты сильнее — её
	// учитывает dateMarkerFor.
	if mk == dateMarkerStop || mk == dateMarkerEvent {
		return
	}
	start, end := int(doc.Tokens[first].Start), int(doc.Tokens[last].End)

	// Слитная запись без маркера — просто восьмизначное число.
	if v.compact && mk != dateMarkerBirth && mk != dateMarkerIssue {
		return
	}

	// Голый год — слишком слабая форма, чтобы регистрировать её по одному лишь
	// совпадению: любое четырёхзначное число попало бы в кандидаты. Поэтому
	// год без дня и месяца берётся только с явным маркером рождения.
	if v.month == 0 {
		if mk == dateMarkerBirth && datePlausibleBirth(v.year) {
			out.Add(start, end, pii.BirthDate, Strong, "date_birth_year")
		}
		return
	}

	switch mk {
	case dateMarkerIssue:
		out.Add(start, end, pii.PassportIssueDate, Strong, "date_issue")
	case dateMarkerBirth:
		// Маркер рождения рядом с датой из будущего — скорее всего не дата
		// рождения, поэтому уверенность до Strong не поднимается.
		conf := Strong
		if !datePlausibleBirth(v.year) {
			conf = Weak
		}
		out.Add(start, end, pii.BirthDate, conf, "date_birth")
	default:
		// Совпала только форма. Движок поднимет кандидата до Strong, если
		// в том же предложении найдутся другие персональные данные.
		//
		// Без маркера рождения дата должна давать правдоподобный возраст
		// взрослого клиента. Дата последних лет — почти всегда событие:
		// платёж, обращение, звонок, оформление кредита. Рядом с именем
		// клиента подъём по кластеру делал её «датой рождения» (замечания
		// технического жюри 23.09: «платёж от 03.03.2026», раунд 4 —
		// «оформил кредит 12.05.2024»). С маркером рождения такая дата
		// по-прежнему регистрируется — ветка выше.
		if !datePlausibleClient(v.year) {
			return
		}
		// Поле записи анкеты через разделитель — «Лысенко;Ольга;Петровна;
		// 02.02.1979;…»: точка с запятой рвёт предложение, и подъёма по
		// кластеру у такой даты нет (технический жюри 23.09, раунд 5, P5-1).
		if datesRecordField(doc, tabs.given, first, last) {
			out.Add(start, end, pii.BirthDate, Strong, ruleDatesRecord)
			return
		}
		out.Add(start, end, pii.BirthDate, Weak, "date_form")
	}
}

// dateMarkerFor выбирает класс маркера даты first..last: ближайший маркер
// слева, затем предложение-событие без маркера, затем пометка рождения
// справа («1990 г.р.»), которая сильнее всего, кроме маркера выдачи.
// Стоп-маркер возвращается сразу: ни событие, ни пометка его не отменяют.
func dateMarkerFor(doc *lex.Doc, first, last int) dateMarker {
	mk := dateMarkerBefore(doc, first)
	if mk == dateMarkerStop {
		return mk
	}
	if mk == dateMarkerNone && dateSentenceEvent(doc, first, last) {
		mk = dateMarkerEvent
	}
	if mk != dateMarkerIssue && dateBirthSuffix(doc, last) {
		mk = dateMarkerBirth
	}
	return mk
}

// datePlausibleBirth сообщает, что год даёт правдоподобный возраст: от нуля до
// dateMaxAge лет на опорный год. Неуказанный год правдоподобию не мешает.
func datePlausibleBirth(year int) bool {
	if year == 0 {
		return true
	}
	age := dateNowYear - year
	return age >= 0 && age <= dateMaxAge
}

// datePlausibleClient — правдоподобие даты рождения без маркера: возраст от
// dateMinAge до dateMaxAge лет на опорный год. Неуказанный год («15 марта»)
// правдоподобию не мешает, как и в datePlausibleBirth.
//
// Нижняя граница — возраст, с которого клиент сам обращается в банк и
// получает паспорт. Дата ребёнка младше без маркера неотличима от даты
// операции; с маркером («дата рождения 03.03.2020») она маскируется.
func datePlausibleClient(year int) bool {
	if year == 0 {
		return true
	}
	age := dateNowYear - year
	return age >= dateMinAge && age <= dateMaxAge
}

// matchNumericDate читает три числа, разделённых одинаковым разделителем:
// «12.05.1990», «12/05/1990», «12-05-1990», «12 05 1990».
func matchNumericDate(doc *lex.Doc, i int) (dateValue, int, bool) {
	toks := doc.Tokens
	if toks[i].Kind != lex.KindDigits || dateContinues(doc, i) {
		return dateValue{}, 0, false
	}
	j, sep, ok := dateNextPart(doc, i, 0)
	if !ok {
		return dateValue{}, 0, false
	}
	k, _, ok := dateNextPart(doc, j, sep)
	if !ok {
		return dateValue{}, 0, false
	}
	vals := [3]int{dateNum(doc, i), dateNum(doc, j), dateNum(doc, k)}
	lens := [3]int{toks[i].Len(), toks[j].Len(), toks[k].Len()}
	v, ok := resolveDateOrder(vals, lens)
	if !ok || v.day < 1 || !v.valid() {
		return dateValue{}, 0, false
	}
	return v, k, true
}

// matchRomanDate читает дату с месяцем римской цифрой: «27.III.1988»,
// «5-XI-90», «1/IV/1990». Порядок только «день, месяц, год»: другого в
// обиходе нет. Раньше такая запись разбиралась как голый год, и «27.III.»
// оставалось открытым (замечание технического жюри 23.09, раунд 4, P4-7).
//
// Разделители обязаны совпадать, как и в matchNumericDate, и стоять вплотную.
// Запись через пробел не принимается: «5 x 10» — размер, а не 5 октября.
func matchRomanDate(doc *lex.Doc, i int) (dateValue, int, bool) {
	toks := doc.Tokens
	// Сначала самая дешёвая и самая избирательная проверка: слово латиницей
	// через токен. Функция вызывается на каждом числе документа.
	if i+4 >= len(toks) || toks[i+2].Kind != lex.KindWord || !toks[i+2].Flags.Has(lex.FlagLatin) ||
		toks[i].Kind != lex.KindDigits || toks[i].Len() > 2 || dateContinues(doc, i) {
		return dateValue{}, 0, false
	}
	m, sep, ok := dateRomanPart(doc, i, 0)
	if !ok {
		return dateValue{}, 0, false
	}
	month := dateRomanMonth(doc, m)
	if month == 0 {
		return dateValue{}, 0, false
	}
	y, _, ok := dateRomanPart(doc, m, sep)
	if !ok || toks[y].Kind != lex.KindDigits {
		return dateValue{}, 0, false
	}
	n := toks[y].Len()
	if n != 2 && n != 4 {
		return dateValue{}, 0, false
	}
	// Год не должен продолжаться числовой группой: «27.III.1988.5» — не дата.
	if _, _, more := dateNextPart(doc, y, 0); more {
		return dateValue{}, 0, false
	}
	v := dateValue{day: dateNum(doc, i), month: month, year: dateExpandYear(dateNum(doc, y), n)}
	if v.day < 1 || !v.valid() {
		return dateValue{}, 0, false
	}
	return v, y, true
}

// dateRomanPart находит следующий компонент римской даты за токеном i через
// знак-разделитель вплотную. Аргумент want задаёт требуемый разделитель;
// ноль означает «любой».
func dateRomanPart(doc *lex.Doc, i int, want byte) (next int, sep byte, ok bool) {
	toks := doc.Tokens
	if i+2 < len(toks) && toks[i+1].Kind == lex.KindPunct && toks[i+2].Kind != lex.KindPunct &&
		doc.Adjacent(i) && doc.Adjacent(i+1) {
		c := doc.Text[toks[i+1].Start]
		if !dateIsSep(c) || (want != 0 && want != c) {
			return 0, 0, false
		}
		return i + 2, c, true
	}
	return 0, 0, false
}

// dateRomanMonth читает номер месяца, записанный римской цифрой латиницей.
// Для прочего слова возвращает ноль.
func dateRomanMonth(doc *lex.Doc, i int) int {
	t := doc.Tokens[i]
	if t.Kind != lex.KindWord || !t.Flags.Has(lex.FlagLatin) || t.Len() > 4 {
		return 0
	}
	switch doc.NormOf(i) {
	case "i":
		return 1
	case "ii":
		return 2
	case "iii":
		return 3
	case "iv":
		return 4
	case "v":
		return 5
	case "vi":
		return 6
	case "vii":
		return 7
	case "viii":
		return 8
	case "ix":
		return 9
	case "x":
		return 10
	case "xi":
		return 11
	case "xii":
		return 12
	}
	return 0
}

// resolveDateOrder распределяет три числовых компонента по дню, месяцу и году.
//
// ТЗ §2.2 требует принимать «дд.мм.гггг», «мм.дд.гггг», «гггг.мм.дд» и
// «гггг.дд.мм» одновременно, то есть запись неоднозначна в принципе. Принято
// такое правило:
//
//  1. Год — компонент из четырёх цифр; если такого нет, компонент со значением
//     больше 31; если нет и такого — последний компонент. Год в середине
//     («05.1990.12») не поддерживается: такой записи нет в обиходе.
//  2. Из двух оставшихся днём считается тот, что больше 12.
//  3. Если оба не больше 12, порядок читается как «день, месяц» — принятый по
//     умолчанию для русского текста дд.мм.гггг.
//
// Правило 3 применяется одинаково независимо от позиции года, поэтому
// «1990.05.12» и «05.12.1990» дают одну и ту же дату: порядок дня и месяца от
// позиции года не зависит. Двусмысленность устраняется в пользу русского
// порядка, а не ISO, потому что вход сервиса — обращения на русском языке.
func resolveDateOrder(vals, lens [3]int) (dateValue, bool) {
	yi, found := dateYearIndex(vals, lens)
	if found > 1 || yi == 1 {
		return dateValue{}, false
	}
	// Год записывается двумя или четырьмя цифрами. Отсечка снимает номера
	// версий вида «1.2.3» и прочие числовые группы.
	if lens[yi] != 2 && lens[yi] != 4 {
		return dateValue{}, false
	}
	p, q := 0, 1
	if yi == 0 {
		p, q = 1, 2
	}
	if lens[p] > 2 || lens[q] > 2 {
		return dateValue{}, false
	}
	day, month := vals[p], vals[q]
	if vals[q] > 12 && vals[p] <= 12 {
		day, month = vals[q], vals[p]
	}
	return dateValue{day: day, month: month, year: dateExpandYear(vals[yi], lens[yi])}, true
}

// dateYearIndex выбирает компонент года по правилу 1 resolveDateOrder и
// возвращает его индекс и число претендентов: больше одного — запись
// неоднозначна и датой не считается.
func dateYearIndex(vals, lens [3]int) (yi, found int) {
	yi = -1
	for i := 0; i < 3; i++ {
		if lens[i] == 4 {
			yi, found = i, found+1
		}
	}
	if found != 0 {
		return yi, found
	}
	for i := 0; i < 3; i++ {
		if vals[i] > 31 {
			yi, found = i, found+1
		}
	}
	if found == 0 {
		yi, found = 2, 1
	}
	return yi, found
}

// dateExpandYear раскрывает двузначный год. Граница — опорный год: «12.05.90»
// читается как 1990, «01.02.24» — как 2024. Век выбирается в прошлое, потому
// что дат рождения и выдачи документов из будущего не бывает.
func dateExpandYear(v, digits int) int {
	if digits != 2 {
		return v
	}
	if v <= dateNowYear%100 {
		return 2000 + v
	}
	return 1900 + v
}

// valid проверяет календарную корректность: месяц 1–12, день не больше числа
// дней в месяце с учётом високосного года, год в допустимом диапазоне.
func (v dateValue) valid() bool {
	if v.month < 1 || v.month > 12 {
		return false
	}
	if v.year != 0 && (v.year < dateMinYear || v.year > dateMaxYear) {
		return false
	}
	y := v.year
	if y == 0 {
		y = dateLeapRef
	}
	return v.day >= 0 && v.day <= dateDaysInMonth(v.month, y)
}

func dateDaysInMonth(month, year int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if dateIsLeap(year) {
			return 29
		}
		return 28
	}
	return 0
}

func dateIsLeap(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

// matchWordDateDayFirst читает словесную дату, начинающуюся с числа дня:
// «12 мая 1990», «12-го мая», «15 марта».
//
// Словесная дата — месяц записан словом. Год здесь требуется
// четырёхзначный: «15 марта 20 человек» не должно превращаться в дату, а
// двузначный год в записи словами не употребляется. Разбор делится по виду
// первого токена, выбор делает matchDate; порядок «месяц первым» разбирает
// matchWordDateMonthFirst.
func matchWordDateDayFirst(doc *lex.Doc, tabs dateTables, i int) (dateValue, int, bool) {
	day, ok := dateDayNum(doc, i)
	if !ok {
		return dateValue{}, 0, false
	}
	// «12-го мая», «1-е мая»: падежное окончание дня — часть значения.
	// Без него в спан попадал только «мая 1990», а «12-го» оставалось
	// открытым (замечание технического жюри 23.09, раунд 2, N8).
	dayEnd := i
	if doc.Adjacent(i) {
		dayEnd = dateDaySuffix(doc, i)
	}
	if !dateSpaceGap(doc.Gap(dayEnd)) {
		return dateValue{}, 0, false
	}
	month, ok := dateMonthOf(doc, tabs.months, dayEnd+1)
	if !ok {
		return dateValue{}, 0, false
	}
	return dateWithYear(doc, tabs, dateValue{day: day, month: month}, dayEnd+1, dayEnd+1)
}

// matchWordDateMonthFirst читает словесную дату, начинающуюся с месяца:
// «май 1990», «мая 12, 1990». Слово, которое месяцем не является, может
// начинать дату числительным — это разбирает matchWordNumberDate.
func matchWordDateMonthFirst(doc *lex.Doc, tabs dateTables, i int) (dateValue, int, bool) {
	toks := doc.Tokens
	month, ok := dateMonthOf(doc, tabs.months, i)
	if !ok {
		// Дата может начинаться и с числительного, записанного словом:
		// «шестнадцатое февраля 1959», «тысяча девятьсот девяностом».
		return matchWordNumberDate(doc, tabs, i)
	}
	// «май 1990» — месяц и год без дня.
	if y, yi, ok := dateYearOf(doc, tabs, i); ok {
		return dateChecked(dateValue{month: month, year: y}, yi)
	}
	// «мая 12, 1990» — порядок «месяц день год».
	if !dateSpaceGap(doc.Gap(i)) || i+1 >= len(toks) {
		return dateValue{}, 0, false
	}
	day, ok := dateDayNum(doc, i+1)
	if !ok {
		return dateValue{}, 0, false
	}
	after := i + 1
	if after+1 < len(toks) && toks[after+1].Kind == lex.KindPunct &&
		doc.Text[toks[after+1].Start] == ',' && doc.Adjacent(after) {
		after++
	}
	return dateWithYear(doc, tabs, dateValue{day: day, month: month}, i+1, after)
}

// dateWithYear дополняет дату годом, стоящим сразу за токеном from, и
// проверяет её календарную корректность. Без года последним токеном даты
// остаётся last.
func dateWithYear(doc *lex.Doc, tabs dateTables, v dateValue, last, from int) (dateValue, int, bool) {
	if y, yi, ok := dateYearOf(doc, tabs, from); ok {
		v.year, last = y, yi
	}
	return dateChecked(v, last)
}

// dateChecked возвращает дату, оканчивающуюся токеном last, если она
// календарно корректна.
func dateChecked(v dateValue, last int) (dateValue, int, bool) {
	if !v.valid() {
		return dateValue{}, 0, false
	}
	return v, last, true
}

// matchWordNumberDate читает дату, которая начинается с числительного,
// записанного словом: день порядковым числительным перед словесным месяцем
// («шестнадцатое февраля 1959») либо год словами без месяца
// («тысяча девятьсот девяностом»). ТЗ §2.2 требует и то, и другое.
//
// Диапазоны дня (1…31) и года (dateMinYear…dateMaxYear) не пересекаются,
// поэтому разобранное число однозначно относится к своему месту, и порядок
// проверок на результат не влияет.
func matchWordNumberDate(doc *lex.Doc, tabs dateTables, i int) (dateValue, int, bool) {
	// Сначала разбор, потом проверка продолжения: dateWordNum отсекает не
	// числительное первым же обращением к справочнику, а таких токенов в
	// тексте подавляющее большинство. Обратный порядок стоил бы лишнего
	// поиска по словарю на каждое слово документа.
	n, last, ok := dateWordNum(doc, tabs.numerals, i)
	if !ok {
		return dateValue{}, 0, false
	}
	if dateWordContinues(doc, tabs.numerals, i) {
		return dateValue{}, 0, false
	}

	// День засчитывается только непосредственно перед словесным месяцем.
	// Без этого «занял первое место» стало бы датой.
	if n >= 1 && n <= 31 {
		if !dateSpaceGap(doc.Gap(last)) {
			return dateValue{}, 0, false
		}
		month, ok := dateMonthOf(doc, tabs.months, last+1)
		if !ok {
			return dateValue{}, 0, false
		}
		return dateWithYear(doc, tabs, dateValue{day: n, month: month}, last+1, last+1)
	}

	// Голый год словами. Регистрировать его или нет — решает registerDate:
	// для года без дня и месяца он требует явного маркера рождения.
	if n >= dateMinYear && n <= dateMaxYear {
		return dateValue{year: n}, last, true
	}
	return dateValue{}, 0, false
}

// dateCompactLen — длина слитной записи даты: «гггг мм дд» или «дд мм гггг»
// без разделителей.
const dateCompactLen = 8

// matchCompactDate читает дату, записанную слитно восемью цифрами:
// «19851205» (гггг мм дд) или «05121985» (дд мм гггг). Регистрировать её
// или нет, решает registerDate: без маркера рождения или выдачи такое
// число не отличить от номера заявки.
func matchCompactDate(doc *lex.Doc, i int) (dateValue, bool) {
	t := doc.Tokens[i]
	if t.Kind != lex.KindDigits || t.Len() != dateCompactLen || dateContinues(doc, i) {
		return dateValue{}, false
	}
	if _, _, ok := dateNextPart(doc, i, 0); ok {
		return dateValue{}, false
	}
	s := doc.Text[t.Start:t.End]
	// Сначала гггг мм дд: у этой записи первые четыре цифры — правдоподобный
	// год, и спутать её с дд мм гггг можно только при годе 01…31, которого в
	// допустимом диапазоне нет.
	if v := (dateValue{year: dateAtoi(s[:4]), month: dateAtoi(s[4:6]), day: dateAtoi(s[6:]), compact: true}); v.year >= dateMinYear && v.day >= 1 && v.valid() {
		return v, true
	}
	if v := (dateValue{day: dateAtoi(s[:2]), month: dateAtoi(s[2:4]), year: dateAtoi(s[4:]), compact: true}); v.year >= dateMinYear && v.day >= 1 && v.valid() {
		return v, true
	}
	return dateValue{}, false
}

// matchYearOnly читает одиночный год. Такой кандидат регистрируется только при
// явном маркере рождения — решение принимает registerDate.
func matchYearOnly(doc *lex.Doc, i int) (dateValue, int, bool) {
	t := doc.Tokens[i]
	if t.Kind != lex.KindDigits || t.Len() != 4 {
		return dateValue{}, 0, false
	}
	// Число внутри числовой группы отдельной датой не считается: разбор такой
	// группы — дело matchNumericDate, и если он её отверг («31.02.2000»),
	// значит дата невалидна и год из неё брать нельзя.
	if dateContinues(doc, i) {
		return dateValue{}, 0, false
	}
	if _, _, ok := dateNextPart(doc, i, 0); ok {
		return dateValue{}, 0, false
	}
	y := dateNum(doc, i)
	if y < dateMinYear || y > dateMaxYear {
		return dateValue{}, 0, false
	}
	return dateValue{year: y}, i, true
}

// dateNextPart находит следующий числовой компонент за токеном i.
// Аргумент want задаёт требуемый разделитель; ноль означает «любой».
func dateNextPart(doc *lex.Doc, i int, want byte) (next int, sep byte, ok bool) {
	toks := doc.Tokens
	if i+1 < len(toks) && toks[i+1].Kind == lex.KindDigits && dateSpaceGap(doc.Gap(i)) {
		if want != 0 && want != ' ' {
			return 0, 0, false
		}
		return i + 1, ' ', true
	}
	if i+2 < len(toks) && toks[i+1].Kind == lex.KindPunct && toks[i+2].Kind == lex.KindDigits &&
		doc.Adjacent(i) && doc.Adjacent(i+1) {
		c := doc.Text[toks[i+1].Start]
		if !dateIsSep(c) || (want != 0 && want != c) {
			return 0, 0, false
		}
		return i + 2, c, true
	}
	return 0, 0, false
}

// dateContinues сообщает, что токен i — продолжение числовой группы слева.
func dateContinues(doc *lex.Doc, i int) bool {
	toks := doc.Tokens
	if i >= 1 && toks[i-1].Kind == lex.KindDigits && dateSpaceGap(doc.Gap(i-1)) {
		return true
	}
	return i >= 2 && toks[i-1].Kind == lex.KindPunct && dateIsSep(doc.Text[toks[i-1].Start]) &&
		toks[i-2].Kind == lex.KindDigits && doc.Adjacent(i-2) && doc.Adjacent(i-1)
}

func dateIsSep(c byte) bool { return c == '.' || c == '/' || c == '-' }

// dateSpaceGap сообщает, что между токенами стоит только горизонтальный
// пробел. Перевод строки разделителем даты не считается: дата не переносится.
func dateSpaceGap(gap string) bool {
	if gap == "" {
		return false
	}
	for i := 0; i < len(gap); i++ {
		switch gap[i] {
		case ' ', '\t', 0xC2, 0xA0: // 0xC2 0xA0 — неразрывный пробел U+00A0
		default:
			return false
		}
	}
	return true
}

// dateMonthOf читает номер месяца из словаря по нормализованному токену.
func dateMonthOf(doc *lex.Doc, months *dict.Table, i int) (int, bool) {
	if i >= len(doc.Tokens) || doc.Tokens[i].Kind != lex.KindWord {
		return 0, false
	}
	if t := doc.Tokens[i]; t.Flags.Has(lex.FlagLatin) {
		return dateEnglishMonth(doc, i)
	}
	label, ok := months.Get(doc.NormOf(i))
	if !ok {
		return 0, false
	}
	m := dateAtoi(label)
	if m < 1 || m > 12 {
		return 0, false
	}
	return m, true
}

// dateEnglishMonth читает английское название месяца: «12 May 1990», «May 12,
// 1990», «DOB: 3 Sept 1985». Раньше в спан шёл только год, а «12 May»
// оставалось открытым (замечание технического жюри 23.09, раунд 4, P4-7).
//
// Название требуется с заглавной: в английском месяц всегда пишут так, а
// строчные «may» и «march» — обычные глаголы. Список закрытый и живёт в коде,
// а не в справочнике months: справочник ведёт русские формы с падежами, а
// английских форм двенадцать и они не склоняются.
func dateEnglishMonth(doc *lex.Doc, i int) (int, bool) {
	if !doc.Tokens[i].Flags.Has(lex.FlagFirstUpper) {
		return 0, false
	}
	var m int
	switch doc.NormOf(i) {
	case "january", "jan":
		m = 1
	case "february", "feb":
		m = 2
	case "march", "mar":
		m = 3
	case "april", "apr":
		m = 4
	case "may":
		m = 5
	case "june", "jun":
		m = 6
	case "july", "jul":
		m = 7
	case "august", "aug":
		m = 8
	case "september", "sep", "sept":
		m = 9
	case "october", "oct":
		m = 10
	case "november", "nov":
		m = 11
	case "december", "dec":
		m = 12
	}
	return m, m != 0
}

// dateDayNum читает число дня: одна или две цифры, значение 1–31.
func dateDayNum(doc *lex.Doc, i int) (int, bool) {
	if i >= len(doc.Tokens) || doc.Tokens[i].Kind != lex.KindDigits || doc.Tokens[i].Len() > 2 {
		return 0, false
	}
	d := dateNum(doc, i)
	if d < 1 || d > 31 {
		return 0, false
	}
	return d, true
}

// dateDaySuffix возвращает последний токен дня с падежным окончанием:
// «12-го», «1-е», «12го». Без окончания возвращается сам токен i.
//
// Окончание берётся только вплотную к числу и только из короткого закрытого
// списка: «12-летний» и «5-комнатная» датой не становятся.
func dateDaySuffix(doc *lex.Doc, i int) int {
	toks := doc.Tokens
	j := i + 1
	if j >= len(toks) || !doc.Adjacent(i) {
		return i
	}
	if toks[j].Kind == lex.KindPunct {
		if toks[j].Len() != 1 || doc.Text[toks[j].Start] != '-' || !doc.Adjacent(j) {
			return i
		}
		j++
	}
	if j < len(toks) && toks[j].Kind == lex.KindWord && dateIsDayEnding(doc.NormOf(j)) {
		return j
	}
	return i
}

// dateIsDayEnding — падежные окончания порядкового числительного дня.
func dateIsDayEnding(w string) bool {
	switch w {
	case "го", "ого", wordHis, "е", "ое", "ье",
		// Английские порядковые: «12th May 1990», «1st of May» не
		// разбирается, но «1st May» — да.
		"st", "nd", "rd", "th":
		return true
	}
	return false
}

// dateYearAfter читает четырёхзначный год сразу за токеном i.
func dateYearAfter(doc *lex.Doc, i int) (year, last int, ok bool) {
	toks := doc.Tokens
	if i+1 >= len(toks) || toks[i+1].Kind != lex.KindDigits || toks[i+1].Len() != 4 {
		return 0, 0, false
	}
	if !dateSpaceGap(doc.Gap(i)) {
		return 0, 0, false
	}
	y := dateNum(doc, i+1)
	if y < dateMinYear || y > dateMaxYear {
		return 0, 0, false
	}
	return y, i + 1, true
}

// dateYearOf читает год сразу за токеном i — цифрами («1959») или словами
// («тысяча девятьсот девяностого»).
func dateYearOf(doc *lex.Doc, tabs dateTables, i int) (year, last int, ok bool) {
	if y, yi, found := dateYearAfter(doc, i); found {
		return y, yi, true
	}
	if !dateSpaceGap(doc.Gap(i)) {
		return 0, 0, false
	}
	// Год двумя цифрами после словесного месяца — «27 марта 88 г.» —
	// принимается только перед «г.» или «года»: без пометки «15 марта 20
	// человек» стало бы датой. Раньше в спан шло «27 марта», а «88» оставалось
	// открытым (замечание технического жюри 23.09, раунд 4, P4-7).
	if j := i + 1; j < len(doc.Tokens) && doc.Tokens[j].Kind == lex.KindDigits && doc.Tokens[j].Len() == 2 {
		if dateYearWordAfter(doc, j) {
			return dateExpandYear(dateNum(doc, j), 2), j, true
		}
		return 0, 0, false
	}
	y, yi, found := dateWordNum(doc, tabs.numerals, i+1)
	if !found {
		return 0, 0, false
	}
	// Год двумя последними цифрами словами — «двенадцатое мая девяностого
	// года» — читается как двузначный год цифрами, но только перед словом
	// «год»: без него «пятого» после месяца значит что угодно.
	if y >= 1 && y <= 99 && dateYearWordAfter(doc, yi) {
		return dateExpandYear(y, 2), yi, true
	}
	if y < dateMinYear || y > dateMaxYear {
		return 0, 0, false
	}
	return y, yi, true
}

// dateYearWordAfter сообщает, что за токеном i через пробел стоит слово
// «год» в любом падеже или сокращение «г.».
func dateYearWordAfter(doc *lex.Doc, i int) bool {
	j := i + 1
	if j >= len(doc.Tokens) || doc.Tokens[j].Kind != lex.KindWord || !dateSpaceGap(doc.Gap(i)) {
		return false
	}
	switch doc.NormOf(j) {
	case wordYear, wordOfYear, "году", "г":
		return true
	}
	return false
}

// dateWordNum читает число, записанное словами, начиная с токена i. Второе
// значение — индекс последнего токена числа.
//
// Грамматика: ноль или более количественных компонентов, затем обязательное
// порядковое. Требование порядкового и есть защита от избыточного
// маскирования: в «сумма тысяча рублей» и «пришло двадцать человек»
// порядкового нет, поэтому числа нет вовсе и кандидат не рождается.
//
// Значение набирается как в устном счёте: компонент от тысячи умножает уже
// набранную группу и закрывает её, остальные складываются. Аллокаций нет:
// справочник читается по подстроке нормализованного текста.
func dateWordNum(doc *lex.Doc, nums *dict.Table, i int) (int, int, bool) {
	acc, cur := 0, 0
	for k := i; k < len(doc.Tokens) && k-i < dateWordNumParts; k++ {
		// Перенос строки и знак препинания рвут число: «двадцать, первого»
		// перечисление, а не дата.
		if k > i && !dateSpaceGap(doc.Gap(k-1)) {
			return 0, 0, false
		}
		v, ordinal, found := dateNumeral(doc, nums, k)
		if !found {
			return 0, 0, false
		}
		if ordinal {
			n := acc + cur + v
			if n > dateMaxYear {
				return 0, 0, false
			}
			return n, k, true
		}
		acc, cur = dateWordAdd(acc, cur, v)
		if acc+cur > dateMaxYear {
			return 0, 0, false
		}
	}
	return 0, 0, false
}

// dateWordAdd добавляет количественный компонент v к числу словами: acc —
// закрытые группы, cur — набираемая. Компонент от тысячи умножает набранную
// группу («две тысячи») или единицу («тысяча») и закрывает её.
func dateWordAdd(acc, cur, v int) (int, int) {
	if v < 1000 {
		return acc, cur + v
	}
	if cur == 0 {
		cur = 1
	}
	return acc + cur*v, 0
}

// dateNumeral читает числительное из справочника по нормализованному токену.
// Метка справочника составная: первый байт — роль («c» количественное,
// «o» порядковое), остальное — значение разряда.
func dateNumeral(doc *lex.Doc, nums *dict.Table, i int) (value int, ordinal, ok bool) {
	if i >= len(doc.Tokens) || doc.Tokens[i].Kind != lex.KindWord {
		return 0, false, false
	}
	label, found := nums.Get(doc.NormOf(i))
	if !found || len(label) < 2 {
		return 0, false, false
	}
	v := dateAtoi(label[1:])
	if v < 1 {
		return 0, false, false
	}
	switch label[0] {
	case 'c':
		return v, false, true
	case 'o':
		return v, true, true
	}
	return 0, false, false
}

// dateWordContinues сообщает, что токен i — продолжение числа словами,
// начатого левее. Разбор такого числа — дело попытки с его начала: если она
// число отвергла («тридцать первого февраля» — такого дня нет), то брать из
// него кусок нельзя. Зеркало dateContinues для числовых групп.
func dateWordContinues(doc *lex.Doc, nums *dict.Table, i int) bool {
	if i == 0 || !dateSpaceGap(doc.Gap(i-1)) {
		return false
	}
	_, _, ok := dateNumeral(doc, nums, i-1)
	return ok
}

func dateNum(doc *lex.Doc, i int) int {
	t := doc.Tokens[i]
	return dateAtoi(doc.Text[t.Start:t.End])
}

// dateAtoi читает неотрицательное десятичное число длиной до четырёх цифр.
// Для нечисловой или слишком длинной строки возвращается -1. Временных строк
// не создаётся: разбор не аллоцирует.
func dateAtoi(s string) int {
	if s == "" || len(s) > 4 {
		return -1
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// dateMarker — класс маркера рядом с датой.
type dateMarker uint8

const (
	dateMarkerNone dateMarker = iota
	dateMarkerBirth
	dateMarkerIssue
	dateMarkerStop
	// dateMarkerEvent — дата события: рядом глагол операции («оформил»,
	// «обратился», «заблокирована») или предлог срока («за», «по состоянию
	// на»). В отличие от стоп-маркера уступает пометке «г.р.» после даты.
	dateMarkerEvent
)

// dateMarkerWindow — сколько значимых токенов слева просматривается.
const dateMarkerWindow = 4

// dateMarkerBefore ищет ближайший маркер типа слева от даты.
//
// Знаки препинания в окно не считаются: «дата рождения:» и «д.р.» должны
// читаться одинаково. Граница предложения здесь намеренно не проверяется —
// точка в сокращениях «д.р.», «г.», «ул.» делает её ненадёжной, а окно в
// четыре значимых токена и так не даёт уйти далеко.
//
// Побеждает ближайший маркер: в «дата рождения по договору 12.05.1990»
// ближе стоит стоп-слово, и дата не регистрируется.
//
// Глагол события засчитывается, только пока между ним и датой нет слова с
// заглавной: в «оформил кредит 12.05.2024» дата относится к операции, а в
// «обратилась Иванова Анна 12.03.1985» — к человеку, названному между ними.
func dateMarkerBefore(doc *lex.Doc, at int) dateMarker {
	seen := 0
	// afterR — предыдущий (правее) значимый токен был «р»: так распознаются
	// сокращения «д.р.» и «г.р.», разбитые лексером на отдельные токены.
	afterR := false
	// named — между датой и текущим словом встретилось слово с заглавной.
	named := false
	for i := at - 1; i >= 0 && seen < dateMarkerWindow; i-- {
		t := doc.Tokens[i]
		if t.Kind == lex.KindPunct {
			continue
		}
		seen++
		if t.Kind != lex.KindWord {
			afterR = false
			continue
		}
		w := doc.NormOf(i)
		// Ближние маркеры проверяются только у первого значимого слова, а
		// afterR у него всегда ложно, поэтому их порядок с «д.р.» и «г.р.»
		// ниже на результат не влияет.
		if mk := dateMarkerFirst(doc, at, i, w, seen); mk != dateMarkerNone {
			return mk
		}
		switch {
		case afterR && (w == "д" || w == "г"), dateIsBirthWord(w):
			return datesBirthMarkerOf(doc, i)
		case dateIsIssueWord(w):
			return dateMarkerIssue
		case dateIsStopWord(w):
			return dateMarkerStop
		case !named && dateIsEventWord(w):
			return dateMarkerEvent
		}
		afterR = w == "р"
		named = named || t.Flags.Has(lex.FlagFirstUpper)
	}
	return dateIssueMarkerFar(doc, at)
}

// dateMarkerFirst — ближний маркер dateMarkerNear, если слово w в позиции i
// первое значимое слева от даты at (seen == 1); иначе dateMarkerNone.
// Проверка seen встраивается в место вызова, и на остальных словах окна
// лишнего вызова нет.
func dateMarkerFirst(doc *lex.Doc, at, i int, w string, seen int) dateMarker {
	if seen != 1 {
		return dateMarkerNone
	}
	return dateMarkerNear(doc, at, i, w)
}

// dateMarkerNear распознаёт маркеры, которые действуют только вплотную перед
// датой at: слово w в позиции i — первое значимое слева от неё.
func dateMarkerNear(doc *lex.Doc, at, i int, w string) dateMarker {
	// «Ершова Рита, р. 12.03.1985»: одиночное «р.» вплотную перед
	// датой — сокращение «рождения» (бизнес-жюри 23.09, раунд 4,
	// Б4-7). После числа это рубли: «500 р. 12.03.2024 списано».
	// «1981 г.р., 12.03.2026» — «р.» из пометки года, а не подпись этой
	// даты, см. datesBirthMarkerOf.
	if w == "р" && dateDotAfter(doc, i) && (i <= 0 || doc.Tokens[i-1].Kind != lex.KindDigits) {
		return datesBirthMarkerOf(doc, i)
	}
	// «Выписка за 01.01.2024», «по состоянию на 01.10.2025»: предлог
	// срока вплотную перед датой. Дальний маркер выдачи сильнее:
	// «выдан ОВД района по 12.03.2015» так и остаётся датой выдачи.
	if !dateIsPeriodWord(w) {
		return dateMarkerNone
	}
	if dateIssueMarkerFar(doc, at) == dateMarkerIssue {
		return dateMarkerIssue
	}
	return dateMarkerEvent
}

// dateDotAfter сообщает, что сразу за словом i вплотную стоит точка.
func dateDotAfter(doc *lex.Doc, i int) bool {
	j := i + 1
	return j < len(doc.Tokens) && doc.Adjacent(i) && doc.Tokens[j].Kind == lex.KindPunct &&
		doc.Text[doc.Tokens[j].Start] == '.'
}

// dateEventWindow — сколько значимых токенов справа от даты, стоящей в начале
// предложения, просматривается в поисках глагола события.
const dateEventWindow = 8

// dateSentenceEvent сообщает, что дата открывает предложение-событие:
// «12.05.2024 клиент Громов Антон Ильич закрыл вклад». Так пишут журнал
// обращений и выписку: дата, затем кто и что сделал. Анкетная дата рождения
// предложение не открывает — она идёт после имени или после маркера.
//
// Маркер рождения справа («12.03.1985 родился …») отменяет вывод.
//
// Границы предложения ищутся от даты, а не через SentenceBounds: тот проходит
// предложение целиком в обе стороны, и на тексте с десятком дат в одном
// предложении разбор становился заметно дороже.
func dateSentenceEvent(doc *lex.Doc, first, last int) bool {
	// Слева от даты до начала предложения — только знаки: кавычка, тире.
	for i := first - 1; i >= 0 && !doc.IsSentenceBreak(i); i-- {
		if doc.Tokens[i].Kind != lex.KindPunct {
			return false
		}
	}
	seen := 0
	for i := last + 1; i < len(doc.Tokens) && seen < dateEventWindow; i++ {
		if doc.IsSentenceBreak(i - 1) {
			return false
		}
		t := doc.Tokens[i]
		if t.Kind == lex.KindPunct {
			continue
		}
		seen++
		if t.Kind != lex.KindWord {
			continue
		}
		w := doc.NormOf(i)
		switch {
		case dateIsBirthWord(w):
			return false
		case dateIsEventWord(w):
			return true
		}
	}
	return false
}

// dateEventStems — основы глаголов и причастий операции. Дата рядом с ними —
// дата события, а не дата рождения. Сравнение по префиксу покрывает род, число
// и причастия: «оформил», «оформила», «оформлен».
//
// «Получил» и «выдан» сюда не входят намеренно: «получил паспорт 12.03.2015»
// — это дата выдачи, и снимать её нельзя; «выдан» — маркер выдачи.
var dateEventStems = [...]string{
	"оформ", "обратил", "обращал", "заблокир", "разблокир", "блокир",
	"открыл", "открыт", "закрыл", "закрыт", "подал", "подан", "поступил",
	"поступл", "оплатил", "списал", "списан", "зачисл", "подписал",
	"подписан", "совершил", "совершен", "звонил", "позвонил", "заключ",
	"расторг", "одобр", "погас", "погаш", "внес", "перевел", "перечисл",
	"пополн", "выпущен", "перевыпущ", "перевыпуст", "активир", "провел",
	"проведен", "отправил", "отправлен", "пришел", "пришла", "пришло",
	"прошел", "прошла", "прошло", "произош", "продл", "начисл", "вернул",
}

// dateIsEventWord сообщает, что слово — глагол или причастие операции.
//
// Основы разложены по первой букве один раз при старте: проверка идёт на
// каждом слове в окне каждой даты, и полный перебор списка был заметен в
// профиле сканера.
func dateIsEventWord(w string) bool {
	_, size := utf8.DecodeRuneInString(w)
	for _, s := range dateEventByLead[w[:size]] {
		if strings.HasPrefix(w, s) {
			return true
		}
	}
	return false
}

// dateEventByLead — основы dateEventStems по первой букве. Строится в init и
// дальше только читается.
var dateEventByLead = func() map[string][]string {
	m := make(map[string][]string)
	for _, s := range dateEventStems {
		_, size := utf8.DecodeRuneInString(s)
		m[s[:size]] = append(m[s[:size]], s)
	}
	return m
}()

// dateIsPeriodWord — предлоги и слова срока, после которых дата описывает
// период или отчётную точку: «за 01.01.2024», «по состоянию на …», «период
// 01.01–31.01», «с … по …». «От» сюда не входит: «паспорт 4618 507329 от
// 12.03.2015» — это дата выдачи документа.
func dateIsPeriodWord(w string) bool {
	switch w {
	case "за", "на", "до", "по", "с", "со", "состоянию",
		"период", "периода", "периоде", "периодом":
		return true
	}
	return false
}

// dateIssueWindow — насколько далеко слева ищется маркер выдачи, если в
// ближнем окне маркера нет.
//
// Между «выдан» и датой обычно стоит название органа выдачи: «паспорт выдан
// ГУ МВД России по Свердловской области 25.12.2007». В ближнее окно из четырёх
// слов маркер не попадает, и без дальнего поиска дата выдачи получала подпись
// даты рождения. Ищется только маркер выдачи: дальний маркер рождения значил бы
// слишком мало, а стоп-слово и так видно в ближнем окне.
const dateIssueWindow = 12

// dateIssueMarkerFar ищет маркер выдачи за пределами ближнего окна. Число
// или другая дата по дороге обрывают поиск: «выдан» тогда относится к ним, а
// не к этой дате.
func dateIssueMarkerFar(doc *lex.Doc, at int) dateMarker {
	seen := 0
	for i := at - 1; i >= 0 && seen < dateIssueWindow; i-- {
		t := doc.Tokens[i]
		if t.Kind == lex.KindPunct {
			continue
		}
		seen++
		if t.Kind != lex.KindWord {
			return dateMarkerNone
		}
		w := doc.NormOf(i)
		switch {
		case dateIsIssueWord(w):
			return dateMarkerIssue
		case dateIsBirthWord(w), dateIsStopWord(w):
			return dateMarkerNone
		}
	}
	return dateMarkerNone
}

// dateBirthSuffix сообщает, что сразу за датой стоит пометка рождения:
// «1990 г.р.», «12.05.1990 года рождения».
func dateBirthSuffix(doc *lex.Doc, last int) bool {
	toks := doc.Tokens
	i := last + 1
	if i >= len(toks) || toks[i].Kind != lex.KindWord {
		return false
	}
	gap := doc.Gap(last)
	if gap != "" && !dateSpaceGap(gap) {
		return false
	}
	switch w := doc.NormOf(i); {
	case w == "г":
		// «г.р.» и «г. рожд.»: между «г» и следующим словом стоит точка.
		return i+2 < len(toks) && toks[i+1].Kind == lex.KindPunct &&
			doc.Text[toks[i+1].Start] == '.' && dateIsBirthShort(doc.NormOf(i+2))
	case w == wordOfYear || w == wordYear:
		return i+1 < len(toks) && dateIsBirthShort(doc.NormOf(i+1))
	case strings.HasPrefix(w, wordBirthStem):
		// «Петрова А.С., 12.05.1990 рождения» — без «года» между ними.
		return true
	}
	return false
}

// dateIsBirthWord — маркеры рождения: «дата рождения», «родился», «родилась»,
// «рожд», «др», а также английские «DOB», «date of birth», «birthday»,
// «born» — их пишут в анкетах и переписке с иностранными сервисами.
func dateIsBirthWord(w string) bool {
	return strings.HasPrefix(w, wordBirthStem) || strings.HasPrefix(w, wordBornStem) || w == "др" ||
		w == "dob" || w == "born" || strings.HasPrefix(w, "birth")
}

// dateIsBirthShort — вторая половина сокращения «г.р.»: либо одиночное «р»,
// либо «рожд». Отдельно от dateIsBirthWord, потому что одиночная буква
// маркером сама по себе не является — она значима только после «г.» или «д.».
func dateIsBirthShort(w string) bool { return w == "р" || strings.HasPrefix(w, wordBirthStem) }

// dateIsIssueWord — маркеры выдачи документа: «выдан», «выдано», «дата
// выдачи», «выдачи».
func dateIsIssueWord(w string) bool { return strings.HasPrefix(w, "выда") }

// dateIsStopWord — слова, после которых дата описывает событие или место, а не
// человека. Такая дата персональными данными не является и не регистрируется
// вовсе.
//
// Топонимы стоят здесь по той же причине: «улица Первого Мая» и «улица 1 Мая»
// — адрес, а не дата рождения. Сокращения сверяются точным равенством, иначе
// префикс «ул» поймал бы «улучшение».
func dateIsStopWord(w string) bool {
	switch {
	case strings.HasPrefix(w, "договор"), strings.HasPrefix(w, "заказ"),
		strings.HasPrefix(w, "заявк"), strings.HasPrefix(w, "оплат"),
		strings.HasPrefix(w, "срок"), strings.HasPrefix(w, "действ"),
		strings.HasPrefix(w, "встреч"), w == wordToday,
		strings.HasPrefix(w, "платеж"), strings.HasPrefix(w, "перевод"),
		strings.HasPrefix(w, "списан"), strings.HasPrefix(w, "зачисл"),
		strings.HasPrefix(w, "операц"), strings.HasPrefix(w, "транзакц"),
		strings.HasPrefix(w, "обращени"):
		return true
	case strings.HasPrefix(w, "улиц"), strings.HasPrefix(w, "проспект"),
		strings.HasPrefix(w, "переул"), strings.HasPrefix(w, "площад"),
		strings.HasPrefix(w, "бульвар"), strings.HasPrefix(w, "набережн"),
		w == "ул", w == "пр", w == "пер", w == "пл", w == "наб":
		return true
	}
	return false
}
