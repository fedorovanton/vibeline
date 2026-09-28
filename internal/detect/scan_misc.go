package detect

import (
	"strings"
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

func init() { Register(miscScanner{}) }

// miscScanner — типы ПД, у которых нет самодостаточной формы: гражданство,
// место рождения, орган выдачи паспорта и имя держателя карты.
//
// Ни одно из четырёх значений нельзя опознать по одному лишь виду. «Казань» —
// это город, пока слева не появилось «родился в»; «ГУ МВД России по г. Москве»
// — это учреждение, пока слева нет «выдан»; «IVAN IVANOV» — это два слова
// латиницей, пока рядом нет ни маркера держателя, ни номера карты. Поэтому у
// трёх типов маркер решает, заводить ли кандидата вообще, а не только с какой
// уверенностью. Исключение — гражданство: словарное совпадение регистрируется
// всегда, но без маркера остаётся Weak, и судьбу его решает движок.
//
// Regexp здесь не используется: разбор идёт по токенам lex.Doc, а словарные
// фразы сравниваются срезом Doc.Norm, который побайтово выровнен с Text.
// Временных строк не собирается, поэтому Scan не аллоцирует.
type miscScanner struct{}

// Name реализует Scanner.
func (miscScanner) Name() string { return "misc" }

// Имена справочников. geo_cities ведёт отдельная задача и его может ещё не
// быть в сборке — Table и Has корректно работают на nil-приёмнике.
const (
	miscCitizenshipTable = "citizenship"
	miscAuthorityTable   = "passport_authority"
	miscGeoCitiesTable   = "geo_cities"
	// Справочники дат нужны сканеру органа выдачи, чтобы вовремя
	// остановиться: дата, записанная словами, стоит сразу за названием и
	// состоит из обычных слов. Их ведёт сканер дат, здесь они только читаются.
	miscNumeralsTable = "numerals"
	miscMonthsTable   = "months"
)

// Имена правил. Идут в отладочные отчёты рядом с типом и уверенностью,
// значение ПД при этом не сопровождают.
const (
	ruleMiscCitizenshipForm   = "misc/citizenship_form"
	ruleMiscCitizenshipMarker = "misc/citizenship_marker"
	ruleMiscBirthPlace        = "misc/birth_place"
	ruleMiscAuthority         = "misc/passport_authority"
	ruleMiscHolderForm        = "misc/card_holder_form"
	ruleMiscHolderMarker      = "misc/card_holder_marker"
	ruleMiscHolderCard        = "misc/card_holder_near_card"
)

const (
	// miscMarkerWindow — сколько значимых токенов слева просматривается в
	// поисках маркера. Знаки препинания окно не расходуют: «гражданство:» —
	// это одно значимое слово, а не два токена.
	miscMarkerWindow = 3
	// miscPhraseTokens — предел длины словарной фразы в токенах. «Отделение
	// по вопросам миграции» — четыре слова, «паспортно-визовая служба» —
	// четыре токена вместе с дефисом.
	miscPhraseTokens = 6
	// miscAuthorityLead — окно поиска словарной аббревиатуры после «выдан».
	// Между маркером и названием органа может стоять дата выдачи или слово
	// «отделом», которого в справочнике нет.
	miscAuthorityLead = 4
	// miscDateTokens — сколько токенов даты между маркером и значением
	// пропускается: «выдан 14 марта 2019 г. ГУ МВД …» — четыре, «родилась
	// двенадцатого января тысяча девятьсот семьдесят третьего г. в …» — семь.
	miscDateTokens = 10
	// miscAuthorityWords — предел длины хвоста названия органа в словах.
	// «ГУ МВД России по г. Москве» — пять слов после аббревиатуры.
	miscAuthorityWords = 8
	// miscAbbrevRunes — длина слова, после которого точка считается знаком
	// сокращения, а не концом конструкции: «по г. Москве» рвать нельзя.
	miscAbbrevRunes = 4
	// miscToponymWords и miscToponymSegments ограничивают топоним: не больше
	// четырёх капитализированных слов и не больше трёх частей через запятую.
	miscToponymWords    = 4
	miscToponymSegments = 3
	// miscHolderMinLetters — минимальная длина слова в имени держателя.
	miscHolderMinLetters = 2
	// miscHolderMaxWords — предел длины имени держателя. Более длинный ряд
	// слов в верхнем регистре — это заголовок или англоязычная фраза, а не
	// имя: на карте печатают имя и фамилию, реже отчество.
	miscHolderMaxWords = 3
	// miscCardMinDigits и miscCardMaxDigits — длина номера карты в цифрах.
	miscCardMinDigits = 13
	miscCardMaxDigits = 19
)

// Scan реализует Scanner.
func (miscScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	miscScanCitizenship(doc, dicts.Table(miscCitizenshipTable), out)
	// Справочник городов принадлежит соседней задаче и может отсутствовать.
	// Топоним распознаётся и по капитализации, поэтому отсутствие справочника
	// уменьшает охват, но не теряет тип и не ломает разбор.
	dates := miscDateTables{months: dicts.Table(miscMonthsTable), numerals: dicts.Table(miscNumeralsTable)}
	miscScanBirthPlace(doc, dicts.Table(miscGeoCitiesTable), dates, out)
	miscScanAuthority(doc, dicts, out)
	miscScanCardHolder(doc, out)
}

// miscScanCitizenship находит названия стран и производные от них слова.
//
// Кандидат заводится на каждом словарном совпадении, потому что пропуск
// штрафуется сильнее лишней маски. Отсутствие маркера слева оставляет его
// слабым: «перевод в РФ» маской не станет, а «гражданин РФ» — станет.
func miscScanCitizenship(doc *lex.Doc, tab *dict.Table, out *Candidates) {
	if tab == nil {
		return
	}
	for i := 0; i < len(doc.Tokens); {
		last, ok := miscMatchPhrase(doc, tab, i)
		if !ok {
			i++
			continue
		}
		first := miscCountryLeadLeft(doc, i)
		switch {
		case miscCitizenshipMarkerBefore(doc, first):
			// Спан покрывает только значение: маркер «гражданство:» стоит
			// левее первого токена фразы и в границы не попадает.
			out.Add(int(doc.Tokens[first].Start), int(doc.Tokens[last].End),
				pii.Citizenship, Strong, ruleMiscCitizenshipMarker)
		case !miscOrgContextLeft(doc, first):
			out.Add(int(doc.Tokens[first].Start), int(doc.Tokens[last].End),
				pii.Citizenship, Weak, ruleMiscCitizenshipForm)
		}
		i = last + 1
	}
}

// miscCountryLeadWords — родовые слова официального названия страны во всех
// падежах.
//
// Справочник хранит название в именительном падеже — «Республика Казахстан»,
// — а в тексте склоняется всё название целиком: «гражданство Республики
// Казахстан». Словарное совпадение при этом находится только на «Казахстан»,
// и родовое слово оставалось за границей спана: значение маскировалось не
// целиком. Персональных данных в слове «Республики» нет, но соглашение о
// границах у корпуса и у детектора расходилось, и метрика строгого сокрытия
// считала это утечкой — все десять утечек гражданства были ровно этой формы.
//
// Падежи перечислены явно, а не сравниваются по префиксу: «республиканский»
// под префикс «республик» подходит, а родовым словом не является.
var miscCountryLeadWords = [...]string{
	"республика", "республики", "республику", "республикой", "республике",
	"королевство", "королевства", "королевству", "королевством", "королевстве",
	"княжество", "княжества", "княжеству", "княжеством", "княжестве",
}

// miscCountryLeadLeft расширяет словарную фразу влево на родовое слово
// названия страны и возвращает первый токен значения.
func miscCountryLeadLeft(doc *lex.Doc, first int) int {
	k := first - 1
	if k < 0 || doc.Tokens[k].Kind != lex.KindWord || !onlySpaces(doc.Gap(k), 1) {
		return first
	}
	w := doc.NormOf(k)
	for _, s := range miscCountryLeadWords {
		if w == s {
			return k
		}
	}
	return first
}

// miscCitizenshipMarkers — маркеры слева от значения гражданства.
//
// Сравнение по префиксу покрывает падежи. Префиксы намеренно длиннее корня:
// «гражданский иск» и «гражданская оборона» маркером не являются, и
// «граждански…» ни под один из них не подходит.
var miscCitizenshipMarkers = [...]string{"гражданств", "граждани", "гражданк", "поддан"}

// miscCitizenshipMarkerBefore ищет маркер гражданства слева от токена at.
func miscCitizenshipMarkerBefore(doc *lex.Doc, at int) bool {
	for i, seen := at-1, 0; i >= 0 && seen < miscMarkerWindow; i-- {
		// Перевод строки разрывает связь слова со значением: заголовок
		// строкой выше маркером соседней строки не является.
		if hasLineBreak(doc.Gap(i)) {
			return false
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		if doc.Tokens[i].Kind != lex.KindWord {
			continue
		}
		w := doc.NormOf(i)
		for _, m := range miscCitizenshipMarkers {
			if strings.HasPrefix(w, m) {
				return true
			}
		}
	}
	return false
}

// miscOrgWordsLeft — слова, после которых название страны обозначает
// организацию, территорию или вид документа, а не гражданство человека.
//
// Название документа — «Паспорт РФ №», «загранпаспорт России» — вид бланка,
// а не отметка о гражданстве: без маркера «гражданина» слово «РФ» становилось
// [ГРАЖДАНСТВО] посреди названия документа (замечание технического жюри
// 23.09, раунд 4, P4-11). «Паспорт гражданина РФ» по-прежнему гражданство —
// маркер проверяется раньше этого списка.
var miscOrgWordsLeft = [...]string{
	"по", wordBank, "банка", "банке", "правительство", "правительства",
	"президент", "президента", "территории", "территория", "почта", "почты",
	"паспорт", "паспорта", "паспорте", "паспортом", "пасп",
	"загранпаспорт", "загранпаспорта", "загранпаспорте", "загранпаспортом",
}

// miscOrgContextLeft сообщает, что слева от названия страны стоит признак
// организации или территории.
//
// «МВД России», «ЦБ России», «по России» — это учреждение и география, а не
// гражданство: заводить по ним даже слабого кандидата вредно, потому что
// движок поднимет его до Strong рядом с любыми другими ПД в предложении.
// Аббревиатура слева опознаётся не списком, а признаком разметки: слово из
// заглавных кириллических букв перед названием страны — это её ведомство.
// Проверка применяется только в отсутствие маркера гражданства: «гражданство:
// РОССИЙСКАЯ ФЕДЕРАЦИЯ» заглавными буквами остаётся гражданством.
func miscOrgContextLeft(doc *lex.Doc, at int) bool {
	for i := at - 1; i >= 0 && at-i <= miscMarkerWindow; i-- {
		t := doc.Tokens[i]
		if t.Kind == lex.KindPunct {
			continue
		}
		if t.Kind != lex.KindWord {
			return false
		}
		if t.Flags.Has(lex.FlagAllUpper | lex.FlagCyrillic) {
			return true
		}
		w := doc.NormOf(i)
		for _, s := range miscOrgWordsLeft {
			if s == w {
				return true
			}
		}
		return false
	}
	return false
}

// miscScanBirthPlace находит место рождения.
//
// Без маркера тип не регистрируется вовсе: иначе любой город в тексте стал бы
// местом рождения, а город сам по себе персональными данными не является.
func miscScanBirthPlace(doc *lex.Doc, cities *dict.Table, dates miscDateTables, out *Candidates) {
	for i := range doc.Tokens {
		if !miscBirthMarkerAt(doc, dates, i) {
			continue
		}
		start, end, ok := miscToponymAfter(doc, cities, i+1)
		if !ok && miscPlaceOfBirthAt(doc, i) {
			if j, found := miscSkipBirthFiller(doc, i+1); found {
				start, end, ok = miscToponymAfter(doc, cities, j)
			}
		}
		if !ok {
			continue
		}
		out.Add(start, end, pii.BirthPlace, Strong, ruleMiscBirthPlace)
	}
}

// miscBirthMarkerAt сообщает, что маркер места рождения заканчивается
// токеном i: «место рождения», «м.р.», «родился в», «родилась в»,
// «уроженец», «уроженка».
//
// Маркер опознаётся по последнему слову, а не по первому, потому что топоним
// начинается сразу за ним: «родился» без «в» маркером не является.
//
// Между «родился» и «в» может стоять дата рождения: «Родился 27.03.1988 в
// Новосибирске», «родилась 3 мая 1988 года в г. Туле». Её токены при поиске
// глагола пропускаются — раньше город после даты оставался открытым
// (замечание технического жюри 23.09, раунд 4, P4-7).
func miscBirthMarkerAt(doc *lex.Doc, dates miscDateTables, i int) bool {
	if doc.Tokens[i].Kind != lex.KindWord {
		return false
	}
	switch w := doc.NormOf(i); {
	case strings.HasPrefix(w, "урожен"):
		return true
	case w == "в" || w == "во":
		return miscPrevWordHasPrefix(doc, i, wordBornStem) || miscBornBeforeDate(doc, dates, i)
	case miscIsBirthWord(w):
		// «Место рождения», «Место рожд.:», «м. рожд.» — поле анкеты, в том
		// числе сокращённое (техническое жюри 23.09, раунд 5, P5-4).
		prev := miscPrevWord(doc, i)
		return strings.HasPrefix(prev, "мест") || prev == "м"
	case w == "р":
		// Сокращение «м.р.» приходит четырьмя токенами: буква, точка,
		// буква, точка.
		return i >= 2 && doc.Tokens[i-1].Kind == lex.KindPunct &&
			doc.Text[doc.Tokens[i-1].Start] == '.' && doc.NormOf(i-2) == "м"
	}
	return false
}

// miscBirthFillerWords — сколько строчных слов между «место рождения» и
// топонимом пропускается: «в заявлении», «заполнена как», «клиента».
const miscBirthFillerWords = 3

// miscPlaceOfBirthAt сообщает, что маркер, оканчивающийся токеном i, —
// «место рождения»: только после него значение стоит не вплотную.
func miscPlaceOfBirthAt(doc *lex.Doc, i int) bool {
	return miscIsBirthWord(doc.NormOf(i))
}

// miscIsBirthWord сообщает, что слово — «рождения» или его сокращение
// «рожд» во второй части маркера «место рождения».
func miscIsBirthWord(w string) bool {
	return strings.HasPrefix(w, "рожден") || w == wordBirthStem
}

// miscSkipBirthFiller пропускает короткую вставку между «место рождения» и
// значением и возвращает токен, с которого начинается топоним: «Место
// рождения в заявлении — Тверь», «графа «место рождения» заполнена как
// Ливны». Раньше значение после вставки оставалось открытым, а на длинном
// тексте его прикрывал только слабый адресный кандидат одинокого города.
//
// Вставка — не больше miscBirthFillerWords строчных слов и знаки «—», «:»,
// кавычки, запятая. Отрицание («место рождения не указано») и число
// обрывают поиск: значения там нет.
func miscSkipBirthFiller(doc *lex.Doc, from int) (int, bool) {
	words := 0
	for j := from; j < len(doc.Tokens); j++ {
		if j > from && hasLineBreak(doc.Gap(j-1)) {
			return 0, false
		}
		switch miscFillerStep(doc, j, words) {
		case miscFillerValue:
			return j, words > 0 || j > from
		case miscFillerWord:
			words++
		case miscFillerStop:
			return 0, false
		}
	}
	return 0, false
}

// miscFillerAction — что miscSkipBirthFiller делает с очередным токеном.
type miscFillerAction uint8

const (
	// miscFillerSkip — знак вставки: пропускается, слов не расходует.
	miscFillerSkip miscFillerAction = iota
	// miscFillerWord — строчное слово вставки.
	miscFillerWord
	// miscFillerValue — с токена начинается топоним.
	miscFillerValue
	// miscFillerStop — значения нет: отрицание, число, посторонний знак или
	// слишком длинная вставка.
	miscFillerStop
)

// miscFillerStep классифицирует токен j вставки, перед которым набрано words
// строчных слов.
func miscFillerStep(doc *lex.Doc, j, words int) miscFillerAction {
	t := doc.Tokens[j]
	switch t.Kind {
	case lex.KindPunct:
		if miscIsFillerPunct(doc.Raw(j)) {
			return miscFillerSkip
		}
		return miscFillerStop
	case lex.KindWord:
		w := doc.NormOf(j)
		if t.Flags.Has(lex.FlagFirstUpper) || miscIsPlaceWord(w) {
			return miscFillerValue
		}
		if w == "не" || w == "нет" || words+1 > miscBirthFillerWords {
			return miscFillerStop
		}
		return miscFillerWord
	}
	return miscFillerStop
}

// miscIsFillerPunct — знаки, допустимые во вставке после «место рождения»:
// тире, двоеточие, кавычки, запятая.
func miscIsFillerPunct(raw string) bool {
	switch raw {
	case "—", "–", "-", ":", "«", "»", "\"", ",":
		return true
	}
	return false
}

// miscBornBeforeDate сообщает, что слева от предлога at стоит дата, а перед
// ней — глагол «родился»: «Родился 27.03.1988 в …», «родилась двенадцатого
// января тысяча девятьсот семьдесят третьего в …». Пропускается не больше
// miscDateTokens токенов даты и хотя бы один обязателен, иначе проверка
// повторяла бы miscPrevWordHasPrefix.
func miscBornBeforeDate(doc *lex.Doc, dates miscDateTables, at int) bool {
	skipped := 0
	for i := at - 1; i >= 0; i-- {
		if hasLineBreak(doc.Gap(i)) {
			return false
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		if miscIsDatePart(doc, dates, i) {
			if skipped++; skipped > miscDateTokens {
				return false
			}
			continue
		}
		return skipped > 0 && doc.Tokens[i].Kind == lex.KindWord && strings.HasPrefix(doc.NormOf(i), wordBornStem)
	}
	return false
}

// miscPrevWordHasPrefix проверяет ближайшее значимое слово слева от токена at.
func miscPrevWordHasPrefix(doc *lex.Doc, at int, prefix string) bool {
	return strings.HasPrefix(miscPrevWord(doc, at), prefix)
}

// miscPrevWord возвращает нормализованное ближайшее значимое слово слева от
// токена at, пропуская знаки препинания в пределах miscMarkerWindow токенов.
// Число или конец окна дают пустую строку.
func miscPrevWord(doc *lex.Doc, at int) string {
	for i := at - 1; i >= 0 && at-i <= miscMarkerWindow; i-- {
		switch doc.Tokens[i].Kind {
		case lex.KindPunct:
			continue
		case lex.KindWord:
			return doc.NormOf(i)
		default:
			return ""
		}
	}
	return ""
}

// miscToponymAfter читает топоним, стоящий за маркером рождения, и возвращает
// его границы в байтах.
//
// Топоним — капитализированная цепочка, возможно с обозначениями населённого
// пункта («г. Казань») и с уточнением через запятую («г. Казань, Республика
// Татарстан»). Обозначение типа пункта входит в спан: «г.» здесь не служебное
// слово при значении, а часть самого топонима.
//
// Часть после запятой принимается только если начинается обозначением
// населённого пункта или региона. Иначе «родился в Москве, Иван Петров
// подписал» затянуло бы в место рождения чужое имя.
func miscToponymAfter(doc *lex.Doc, cities *dict.Table, from int) (int, int, bool) {
	t := miscToponym{start: -1, last: -1, segments: 1}
	for i := from; i < len(doc.Tokens); i++ {
		// Перевод строки и лишние пробелы рвут топоним: следующая строка
		// анкеты к месту рождения уже не относится.
		if i > from && !onlySpaces(doc.Gap(i-1), 2) {
			break
		}
		tok := doc.Tokens[i]
		if tok.Kind == lex.KindDigits {
			break
		}
		if tok.Kind == lex.KindPunct {
			if !t.punct(doc, i) {
				break
			}
			continue
		}
		if !t.word(doc, cities, i) {
			break
		}
	}
	return t.bounds(doc)
}

// miscToponym — состояние разбора топонима. Живёт на стеке одного вызова:
// сканер не хранит состояния между вызовами и не аллоцирует.
type miscToponym struct {
	start int // смещение первого токена в байтах, -1 до начала топонима
	last  int // индекс последнего токена значения, -1 пока значения нет
	// words и segments считают набранные капитализированные слова и части,
	// разделённые запятой.
	words    int
	segments int
	// afterComma и segHasPlace: после запятой ожидается новая часть, и она
	// обязана начаться обозначением пункта или региона.
	afterComma  bool
	segHasPlace bool
	// afterHyphen: предыдущий токен — дефис внутри составного названия.
	afterHyphen bool
}

// word обрабатывает слово топонима. Возвращает false, если слово завершает
// разбор.
func (t *miscToponym) word(doc *lex.Doc, cities *dict.Table, i int) bool {
	tok := doc.Tokens[i]
	w := doc.NormOf(i)
	switch {
	case t.afterHyphen:
		// Середина составного названия пишется строчными: «Комсомольск-
		// на-Амуре», «Ростов-на-Дону». Регистр здесь не требуется.
		t.afterHyphen = false
		t.last = i
		return true

	case miscIsPlaceWord(w):
		t.placeWord(int(tok.Start), i)
		return true

	case tok.Flags.Has(lex.FlagFirstUpper) || cities.Has(w):
		return t.nameWord(doc, int(tok.Start), i)
	}
	// Строчное слово вне списка обозначений завершает топоним.
	return false
}

// placeWord учитывает обозначение пункта или региона — слово i, которое
// начинается со смещения start.
func (t *miscToponym) placeWord(start, i int) {
	if t.start < 0 {
		t.start = start
	}
	switch {
	case t.afterComma:
		t.segHasPlace = true
	case t.last >= 0:
		// «Московской области»: уточнение после названия входит
		// в значение, одиночное «г.» в конце — нет.
		t.last = i
	}
}

// nameWord учитывает слово названия — слово i с заглавной или город из
// справочника, которое начинается со смещения start. Возвращает false, если
// слово завершает разбор.
func (t *miscToponym) nameWord(doc *lex.Doc, start, i int) bool {
	if t.afterComma {
		// «ст. Лесная, Ростовская область»: регион после запятой
		// начинается названием, а обозначение стоит за ним. Без этого
		// уточнение оставалось за спаном, и значение маскировалось не
		// целиком: «ст.» и «Лесная» уходили в разные спаны.
		if !t.segHasPlace && !miscPlaceWordNext(doc, i) {
			return false
		}
		t.afterComma = false
	}
	if t.words >= miscToponymWords {
		return false
	}
	if t.start < 0 {
		t.start = start
	}
	t.last = i
	t.words++
	return true
}

// punct обрабатывает знак препинания. Возвращает false, если знак завершает
// разбор.
func (t *miscToponym) punct(doc *lex.Doc, i int) bool {
	c := doc.Raw(i)
	if t.start < 0 {
		// Топоним ещё не начался: знаки после маркера («место рождения: …»,
		// «м.р. — …») пропускаются.
		switch c {
		case ":", "-", ".", ",", "—", "–":
			return true
		}
		return false
	}
	switch c {
	case ".":
		// Точка сокращения («г.») стоит вплотную к своему слову; точка после
		// самого значения — конец топонима.
		return t.last < i-1 && doc.Adjacent(i-1)
	case "-":
		if t.last < 0 || !doc.Adjacent(i-1) || !doc.Adjacent(i) {
			return false
		}
		t.afterHyphen = true
		return true
	case ",":
		if t.segments >= miscToponymSegments {
			return false
		}
		t.segments++
		t.afterComma = true
		t.segHasPlace = false
		return true
	}
	return false
}

// bounds переводит найденные токены в границы значения.
func (t *miscToponym) bounds(doc *lex.Doc) (int, int, bool) {
	if t.start < 0 || t.last < 0 {
		return 0, 0, false
	}
	return t.start, int(doc.Tokens[t.last].End), true
}

// miscPlaceWordNext сообщает, что за словом i через один пробел стоит
// обозначение региона: «Ростовская область», «Пермский край».
func miscPlaceWordNext(doc *lex.Doc, i int) bool {
	j := i + 1
	if j >= len(doc.Tokens) || doc.Tokens[j].Kind != lex.KindWord || doc.Gap(i) != " " {
		return false
	}
	switch doc.NormOf(j) {
	case "обл", "область", wordRegion, "край", "края", "район", "района", "округ", "округа", "ао":
		return true
	}
	return false
}

// miscIsPlaceWord сообщает, что слово обозначает тип населённого пункта или
// региона. Такое слово топоним не заканчивает и, в отличие от прочих
// строчных слов, входит в его состав.
func miscIsPlaceWord(w string) bool {
	switch w {
	case "г", "гор", "город", "города", "городе",
		"с", "село", "села", "п", "пос", "пгт", "поселок", "поселка",
		"д", "дер", "деревня", "деревни", "ст", "станица", "станицы",
		"х", "хутор", "аул", wordNamed, "им":
		return true
	case "обл", "область", wordRegion, "кр", "край", "края",
		"респ", "республика", "республики", "район", "района",
		"округ", "округа", "ао", "сср", "рсфср", "ссср":
		return true
	}
	return false
}

// miscScanAuthority находит орган, выдавший паспорт.
//
// Конструкция начинается маркером «выдан», продолжается аббревиатурой из
// справочника и тянется до конца названия: до точки, запятой или цифровой
// группы (кода подразделения или даты выдачи). Само слово «выдан» в спан не
// входит — это служебное слово при значении.
func miscScanAuthority(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	tab := dicts.Table(miscAuthorityTable)
	if tab == nil {
		return
	}
	numerals, months := dicts.Table(miscNumeralsTable), dicts.Table(miscMonthsTable)
	for i := range doc.Tokens {
		if doc.Tokens[i].Kind != lex.KindWord || !miscIsIssueMarker(doc.NormOf(i)) {
			continue
		}
		first, last, ok := miscAuthorityPhrase(doc, tab, miscDateTables{months: months, numerals: numerals}, i+1)
		if !ok {
			continue
		}
		end := miscAuthorityTail(doc, numerals, months, last)
		out.Add(int(doc.Tokens[first].Start), int(doc.Tokens[end].End),
			pii.PassportAuthority, Strong, ruleMiscAuthority)
	}
}

// miscIsIssueMarker — маркеры выдачи документа: «выдан», «выдано», «выдана».
// Начало конструкции «кем выдан» распознаётся по тому же слову.
//
// «Подразделение УМВД России по Псковской области» — тот же орган, названный
// родовым словом: без маркера выдачи он оставался открытым. Ложных срабатываний
// слово не даёт: значение подтверждает словарная аббревиатура органа, а в
// «код подразделения 770-001» и «подразделение банка» её нет.
func miscIsIssueMarker(w string) bool {
	return strings.HasPrefix(w, "выдан") || strings.HasPrefix(w, "подразделени")
}

// miscAuthorityPhrase ищет словарную аббревиатуру органа в окне после
// маркера. Возвращает первый и последний токены найденной фразы.
//
// Дата выдачи между маркером и органом окно не расходует: «выдан 14 марта
// 2019 г. ГУ МВД России по Республике Татарстан» и «выдан 01.02.2015 отделом
// УФМС …» — орган стоит после даты, и окно из четырёх слов кончалось на ней
// (замечания жюри 23.09, раунд 4: P4-7, Б4-16). Токенов даты пропускается не
// больше miscDateTokens, поэтому окно остаётся ограниченным.
func miscAuthorityPhrase(doc *lex.Doc, tab *dict.Table, dates miscDateTables, from int) (int, int, bool) {
	skipped := 0
	for i, seen := from, 0; i < len(doc.Tokens) && seen < miscAuthorityLead; i++ {
		if i > from && hasLineBreak(doc.Gap(i-1)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		if skipped < miscDateTokens && miscIsDatePart(doc, dates, i) {
			skipped++
			continue
		}
		seen++
		if last, ok := miscMatchPhrase(doc, tab, i); ok {
			return i, last, true
		}
	}
	return 0, 0, false
}

// miscDateTables — справочники сканера дат, нужные здесь, чтобы узнать дату
// между маркером и значением. Их ведёт сканер дат, здесь они только читаются.
type miscDateTables struct {
	months   *dict.Table
	numerals *dict.Table
}

// miscIsDatePart сообщает, что токен i может быть частью даты: число до
// четырёх цифр, название месяца, числительное словами или пометка года «г.»,
// «года».
func miscIsDatePart(doc *lex.Doc, dates miscDateTables, i int) bool {
	t := doc.Tokens[i]
	switch t.Kind {
	case lex.KindDigits:
		return t.Len() <= 4
	case lex.KindWord:
		return miscIsDateWord(dates, doc.NormOf(i))
	}
	return false
}

// miscIsDateWord сообщает, что слово w может быть частью даты: пометка года
// «г.», «года», название месяца или числительное словами.
func miscIsDateWord(dates miscDateTables, w string) bool {
	switch w {
	case "г", wordOfYear, wordYear, "гг":
		return true
	}
	return dates.months.Has(w) || dates.numerals.Has(w)
}

// miscAuthorityTail добирает название органа после словарной аббревиатуры и
// возвращает индекс последнего токена значения.
func miscAuthorityTail(doc *lex.Doc, numerals, months *dict.Table, last int) int {
	end, words := last, 0
	for i := last + 1; i < len(doc.Tokens) && words < miscAuthorityWords; i++ {
		if !onlySpaces(doc.Gap(i-1), 2) {
			return end
		}
		t := doc.Tokens[i]
		switch t.Kind {
		case lex.KindDigits:
			// Цифровая группа — код подразделения или дата выдачи:
			// название органа кончилось.
			return end
		case lex.KindWord:
			// Дата выдачи, записанная словами, стоит сразу за названием
			// органа, и цифровой группы, на которой разбор останавливался,
			// в ней нет. Без этой проверки название тянулось по словам даты
			// и упиралось в предел длины: «…по Свердловской области двадцать
			// пятого декабря две тысячи» уходило в спан органа, который
			// выигрывал перекрытие у спана даты по длине, а «седьмого»
			// оставалось снаружи и уезжало в модель открытым.
			if w := doc.NormOf(i); numerals.Has(w) || months.Has(w) {
				return end
			}
			end = i
			words++
		case lex.KindPunct:
			if !miscAuthorityPunct(doc, i) {
				return end
			}
		}
	}
	return end
}

// miscAuthorityPunct сообщает, что знак i не рвёт название органа: точка
// сокращения, дефис вплотную или кавычки.
func miscAuthorityPunct(doc *lex.Doc, i int) bool {
	switch doc.Raw(i) {
	case ".":
		// Точка после сокращения конструкцию не рвёт: в «по
		// г. Москве» название продолжается после «г.».
		return miscIsAbbrevDot(doc, i)
	case "-":
		return doc.Adjacent(i-1) && doc.Adjacent(i)
	case "\"", "«", "»":
		// Кавычки в названии учреждения.
		return true
	}
	return false
}

// miscIsAbbrevDot сообщает, что точка в позиции i — знак сокращения: она
// стоит вплотную к короткому слову («г.», «обл.», «респ.»).
func miscIsAbbrevDot(doc *lex.Doc, i int) bool {
	if i == 0 || !doc.Adjacent(i-1) || doc.Tokens[i-1].Kind != lex.KindWord {
		return false
	}
	return utf8.RuneCountInString(doc.NormOf(i-1)) <= miscAbbrevRunes
}

// miscScanCardHolder находит имя держателя карты — два или три подряд
// латинских слова в верхнем регистре.
//
// Верхний регистр здесь не случайность разметки, а признак: на карте имя
// эмбоссируется заглавными, и именно в таком виде его переносят в обращения.
// Поэтому регистр для этого типа значим, в отличие от остальных трёх.
//
// Имя в обычном регистре — «Имя на карте Daria Shapovalova» — принимается
// только при маркере держателя слева: без него два слова с заглавной латиницей
// — это что угодно, от названия продукта до адреса сайта. Раньше такое имя
// оставалось открытым даже рядом с маркером (замечание технического жюри
// 23.09, раунд 4, P4-7).
func miscScanCardHolder(doc *lex.Doc, out *Candidates) {
	var card miscCardMemo
	for i := 0; i < len(doc.Tokens); {
		if !miscHolderWord(doc, i) {
			if miscHolderTitleWord(doc, i) {
				i = miscTitleHolder(doc, i, out) + 1
				continue
			}
			i++
			continue
		}
		j := i
		for j+1 < len(doc.Tokens) && miscHolderWord(doc, j+1) && onlySpaces(doc.Gap(j), 2) {
			j++
		}
		if n := j - i + 1; n >= 2 && n <= miscHolderMaxWords {
			conf, rule := Weak, ruleMiscHolderForm
			switch {
			case miscHolderMarkerBefore(doc, i):
				conf, rule = Strong, ruleMiscHolderMarker
			case card.nearby(doc, i):
				conf, rule = Strong, ruleMiscHolderCard
			}
			out.Add(int(doc.Tokens[i].Start), int(doc.Tokens[j].End), pii.CardHolder, conf, rule)
		}
		i = j + 1
	}
}

// miscHolderStopWords — слова, которые именем держателя не являются.
//
// Аббревиатуры реквизитов, технические сокращения и платёжные системы
// набираются заглавными латиницей ровно так же, как имя на карте, и без
// этого списка «CVV PIN» или «VISA CLASSIC» стали бы держателем. Слово из
// списка не просто пропускается, а разрывает ряд: в «CARD HOLDER IVAN
// IVANOV» именем остаётся только «IVAN IVANOV».
//
// Записи в нижнем регистре: сравнение идёт с нормализованным токеном.
var miscHolderStopWords = [...]string{
	"amex", "api", "atm", "bank", "bic", "card", "cash", "classic", "credit",
	"csv", "cvc", "cvp", "cvv", "debit", "demo", "eur", "exp", "expires",
	"faq", "gold", "gps", "gsm", "guid", "holder", "html", "http", "https",
	"iban", "id", "imei", "inn", "json", "jwt", "kyc", "maestro", "mastercard",
	"mir", "name", "null", "ok", "otp", "pan", "pdf", "pin", "platinum", "png",
	"pos", "rub", "sample", "sim", "sms", "sql", "ssl", "swift", "test",
	"thru", "unionpay", "url", "usb", "usd", "uuid", "valid", "vin", "vip",
	"visa", "xml", "zip",
	// Названия продуктов и кошельков пишут с заглавной латиницей, как имя
	// в обычном регистре: «на карте Apple Pay», «картой Visa Signature».
	"apple", "black", "business", "cashback", "digital", "google", "infinite",
	"online", "pay", "premium", "samsung", "signature", "standard", "travel",
	"virtual", "wallet", "world",
}

// miscHolderWord сообщает, что токен i годится в слово имени держателя.
func miscHolderWord(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	if t.Kind != lex.KindWord || !t.Flags.Has(lex.FlagLatin|lex.FlagAllUpper) {
		return false
	}
	w := doc.NormOf(i)
	if utf8.RuneCountInString(w) < miscHolderMinLetters {
		return false
	}
	head := w[0]
	for _, s := range miscHolderStopWords {
		// Отсев по первому байту: список перебирается на каждом слове
		// в верхнем регистре, и сравнение строк здесь дороже всего.
		if s[0] == head && s == w {
			return false
		}
	}
	return true
}

// miscHolderTitleWord сообщает, что токен i — слово латиницей в обычном
// регистре: заглавная и строчные, «Daria». Стоп-слова отсеиваются тем же
// списком, что и в верхнем регистре: «Visa Classic», «Apple Pay».
func miscHolderTitleWord(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	if t.Kind != lex.KindWord || !t.Flags.Has(lex.FlagLatin|lex.FlagFirstUpper) || t.Flags.Has(lex.FlagAllUpper) {
		return false
	}
	w := doc.NormOf(i)
	if utf8.RuneCountInString(w) < miscHolderMinLetters {
		return false
	}
	head := w[0]
	for _, s := range miscHolderStopWords {
		if s[0] == head && s == w {
			return false
		}
	}
	return true
}

// miscTitleHolder читает ряд слов в обычном регистре, начатый токеном i, и
// регистрирует держателя, если ряд длиной с имя и слева стоит маркер.
// Возвращает последний токен ряда: проход продолжается за ним.
func miscTitleHolder(doc *lex.Doc, i int, out *Candidates) int {
	j := i
	for j+1 < len(doc.Tokens) && miscHolderTitleWord(doc, j+1) && onlySpaces(doc.Gap(j), 2) {
		j++
	}
	if n := j - i + 1; n >= 2 && n <= miscHolderMaxWords && miscHolderMarkerBefore(doc, i) {
		out.Add(int(doc.Tokens[i].Start), int(doc.Tokens[j].End), pii.CardHolder, Strong, ruleMiscHolderMarker)
	}
	return j
}

// miscHolderMarkers — маркеры имени держателя карты.
var miscHolderMarkers = [...]string{"держател", "владел", "cardholder", "holder", "card", "карт", "name", "имя", "фио"}

// miscHolderMarkerBefore ищет маркер держателя слева от имени.
func miscHolderMarkerBefore(doc *lex.Doc, at int) bool {
	for i, seen := at-1, 0; i >= 0 && seen < miscMarkerWindow+1; i-- {
		if hasLineBreak(doc.Gap(i)) {
			return false
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		if doc.Tokens[i].Kind != lex.KindWord {
			continue
		}
		w := doc.NormOf(i)
		for _, m := range miscHolderMarkers {
			if strings.HasPrefix(w, m) {
				return true
			}
		}
	}
	return false
}

// miscCardMemo запоминает ответ miscCardInRange для последнего разобранного
// предложения.
//
// Кандидаты в держатели идут слева направо, и в одном предложении их может
// быть сколько угодно: без запоминания каждый заново проходил предложение
// целиком, и строка из повторов «IVAN PETROV» разбиралась за квадратичное
// время (замечание проверки качества кода 23.09, С-2).
type miscCardMemo struct {
	hi    int
	ok    bool
	valid bool
}

func (m *miscCardMemo) nearby(doc *lex.Doc, at int) bool {
	if m.valid && at <= m.hi {
		return m.ok
	}
	lo, hi := doc.SentenceBounds(at)
	m.hi, m.ok, m.valid = hi, miscCardInRange(doc, lo, hi), true
	return m.ok
}

// miscCardInRange сообщает, что в предложении [lo, hi] стоит число длиной с
// номер карты.
//
// Сканер не видит кандидатов других сканеров, поэтому считает цифры сам:
// достаточно факта, что рядом записан номер карты, а его проверкой по Луну
// занимается сканер цифр. Любое слово между группами цифр обнуляет счёт —
// две несвязанные суммы в номер карты не складываются.
func miscCardInRange(doc *lex.Doc, lo, hi int) bool {
	total := 0
	for i := lo; i <= hi; i++ {
		t := doc.Tokens[i]
		switch {
		case t.Kind == lex.KindDigits:
			total += t.Len()
		case t.Kind == lex.KindPunct && doc.Text[t.Start] == '-':
			// Дефис между группами цифр номер не разрывает.
		default:
			total = 0
			continue
		}
		if total >= miscCardMinDigits && total <= miscCardMaxDigits {
			return true
		}
	}
	return false
}

// miscMatchPhrase ищет самое длинное словарное совпадение, начинающееся с
// токена i, и возвращает индекс последнего токена фразы.
//
// Сравнение идёт срезом Doc.Norm: нормализованная копия выровнена с
// исходником побайтово, поэтому многословная запись справочника проверяется
// без сборки временной строки и без единой аллокации.
func miscMatchPhrase(doc *lex.Doc, tab *dict.Table, i int) (int, bool) {
	if tab == nil || doc.Tokens[i].Kind != lex.KindWord {
		return 0, false
	}
	start := int(doc.Tokens[i].Start)
	last, found := 0, false
	limit := i + miscPhraseTokens
	if limit > len(doc.Tokens) {
		limit = len(doc.Tokens)
	}
	for j := i; j < limit; j++ {
		// Запись справочника отделяется от следующей ровно одним пробелом
		// или пишется слитно через дефис: «Гвинея-Бисау», «ГУ МВД».
		if j > i && !onlySpaces(doc.Gap(j-1), 1) {
			break
		}
		t := doc.Tokens[j]
		if t.Kind == lex.KindDigits {
			break
		}
		if t.Kind != lex.KindWord {
			continue
		}
		if tab.Has(doc.Norm[start:int(t.End)]) {
			last, found = j, true
		}
	}
	return last, found
}
