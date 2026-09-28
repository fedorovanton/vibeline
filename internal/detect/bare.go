package detect

import (
	"strings"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Голое значение (T-63): payload целиком состоит из одного значения ПД —
// «Корнеева», «27.03.1988», «4618 507329», «DARIA SHAPOVALOVA».
//
// Проверяющая система шлёт такие записи наравне с фразами и предложениями
// (A2.1), и полное маскирование строки из одного значения избыточным не
// считается (A4.4). Сканеры же устроены под текст: форма без маркера типа даёт
// слабого кандидата, а слабый доходит до маски только внутри кластера других
// ПД. У голого значения кластера нет, и 20 проб из 27 уходили открытыми
// (технический раунд 4, P4-3), хотя с маркером те же значения скрыты.
//
// Голый payload сам и есть контекст: вся строка — одно значение. Поэтому шагов
// два, и оба срабатывают только на строке, похожей на одно значение
// (bareCore):
//
//  1. Классификатор формы целиком строки: группы цифр по длине, дата любой
//     поддерживаемой формы, фраза справочника гражданства, орган выдачи с
//     территорией, населённый пункт, одно–три слова ФИО, два–три слова
//     латиницей. Совпадение даёт Strong-кандидата на всё значение.
//  2. Подъём слабых кандидатов: если кандидаты одного типа накрывают все слова
//     и числа строки, они поднимаются до Strong с пометкой правила «+bare» —
//     так же, как это делает подъём по кластеру.
//
// Что не подошло ни под одну форму, остаётся без изменений: обычный текст без
// ПД не маскируется, и mask(T) == T для него не нарушается.
//
// Контр-правила сильнее голой формы. Вето типа снимает классификацию в этот
// тип: «Пушкин» целиком строки остаётся открытым так же, как в «поэт Пушкин».
// При любом вето внутри строки слабые кандидаты не поднимаются.
//
// На длинном тексте шаг стоит одного сравнения длины: всё остальное считается
// только на входе короче bareMaxBytes.

const (
	// bareMaxBytes — предел длины голого payload в байтах. Самое длинное
	// голое значение — орган выдачи: «Отделением УФМС России по Московской
	// области в Одинцовском районе» занимает около 130 байт.
	bareMaxBytes = 256
	// bareMaxTokens — предел числа токенов строки вместе со знаками.
	bareMaxTokens = 32
	// bareMaxWords — предел числа слов и чисел в значении.
	bareMaxWords = 12

	// bareNameWords — предел длины ФИО в словах; части двойной фамилии через
	// дефис считаются одним словом.
	bareNameWords = 3
	// bareHolderWords — предел длины имени держателя: на карте печатают имя и
	// фамилию, реже отчество.
	bareHolderWords = 3
	// bareAuthorityLead — сколько слов-обозначений подразделения может стоять
	// перед аббревиатурой органа: «Отделом УФМС», «Территориальным пунктом
	// УФМС».
	bareAuthorityLead = 2
	// bareAuthorityWords — предел длины продолжения названия органа в словах.
	bareAuthorityWords = 10
	// bareToponymWords — предел числа слов с заглавной в названии места:
	// «Великие Луки, Псковская область» — четыре.
	bareToponymWords = 6
	// bareTranslitBudget — предел числа шагов обратной транслитерации одного
	// слова. Варианты ветвятся на «i», «y», «l» и сочетаниях гласных, и без
	// предела длинное латинское слово перебиралось бы экспоненциально.
	bareTranslitBudget = 2048
)

// geo_regions ведёт сканер адреса; здесь справочник только читается —
// «Московская область» целиком строки подтверждает место.
const bareGeoRegionsTable = "geo_regions"

// Имена правил. Классификатор выдаёт собственные, подъём слабого кандидата
// дописывает к правилу сканера bareSuffix.
const (
	bareSuffix          = "+bare"
	ruleBareCVV         = "bare/cvv"
	ruleBarePIN         = "bare/pin"
	ruleBareDeptCode    = "bare/dept_code"
	ruleBarePassport    = "bare/passport"
	ruleBareLicense     = "bare/driver_license"
	ruleBarePhone       = "bare/phone"
	ruleBareDate        = "bare/date"
	ruleBareCitizenship = "bare/citizenship"
	ruleBareAuthority   = "bare/passport_authority"
	ruleBareBirthPlace  = "bare/birth_place"
	ruleBareName        = "bare/full_name"
	ruleBareHolder      = "bare/card_holder"
)

// bareValue — значение, опознанное классификатором.
type bareValue struct {
	start, end int32
	typ        pii.Type
	rule       string
}

// promoteBare — шаг движка для голого payload.
//
// Вызывается после вето и подъёма по кластеру. Вето нужны, чтобы контр-правила
// сняли классификацию. Кластер — чтобы голое значение не стало якорем: у
// строки из одного значения соседей нет, а слабый кандидат на тех же байтах,
// поднятый до той же силы, выиграл бы перекрытие порядком типа.
func promoteBare(doc *lex.Doc, dicts *dict.Set, cand *Candidates) {
	if len(doc.Text) > bareMaxBytes {
		return
	}
	lo, hi, ok := bareCore(doc)
	if !ok {
		return
	}
	start, end := doc.Tokens[lo].Start, doc.Tokens[hi].End
	for _, s := range cand.Spans {
		// Достоверное значение сканер уже нашёл: строка либо разобрана
		// целиком, либо в ней больше одного значения, и судьбу остальных
		// решает подъём по кластеру. Голая форма тут ничего не добавит,
		// а поверх разобранного значения могла бы только навредить.
		if s.Conf >= Strong && s.Start < end && start < s.End {
			return
		}
	}
	if v, ok := bareClassify(doc, dicts, cand.Vetos, lo, hi); ok {
		cand.Add(int(v.start), int(v.end), v.typ, Strong, v.rule)
		return
	}
	bareLiftWeak(doc, cand, lo, hi)
}

// bareCore возвращает первый и последний значимые токены строки — слово или
// число — и сообщает, похожа ли строка на одно значение.
//
// Концевые знаки отбрасываются: «4618 507329.», «Корнеева?». Слева — только
// обрамление: скобки, кавычки, тире и знак номера. Прочий знак в начале
// строки значим — «*0582» это короткий номер, а не ПИН, — и такая строка
// голым значением не считается.
//
// Внутри значения не бывает перевода строки, вопросительного и
// восклицательного знаков, точки с запятой и двоеточия: это либо второе
// предложение, либо поле формы «Паспорт: …», которое сканеры разбирают по
// маркеру.
func bareCore(doc *lex.Doc) (lo, hi int, ok bool) {
	n := len(doc.Tokens)
	if n == 0 || n > bareMaxTokens {
		return 0, 0, false
	}
	if lo, hi, ok = bareTrim(doc, n); !ok {
		return 0, 0, false
	}
	words, ok := bareInterior(doc, lo, hi)
	if !ok {
		return 0, 0, false
	}
	return lo, hi, words <= bareMaxWords
}

// bareTrim отбрасывает знаки по краям строки из n токенов и возвращает первый
// и последний значимые токены. Слева допускается только обрамление значения;
// строка из одних знаков значения не содержит.
func bareTrim(doc *lex.Doc, n int) (lo, hi int, ok bool) {
	lo, hi = 0, n-1
	for lo <= hi && doc.Tokens[lo].Kind == lex.KindPunct {
		if !bareLeadingWrap(doc.Raw(lo)) {
			return 0, 0, false
		}
		lo++
	}
	for hi >= lo && doc.Tokens[hi].Kind == lex.KindPunct {
		hi--
	}
	if lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

// bareInterior считает слова и числа строки [lo, hi] и сообщает, что внутри
// нет перевода строки и знаков, которых в одном значении не бывает.
func bareInterior(doc *lex.Doc, lo, hi int) (words int, ok bool) {
	for i := lo; i <= hi; i++ {
		if i > lo && lex.HasLineBreak(doc.Gap(i-1)) {
			return 0, false
		}
		t := doc.Tokens[i]
		if t.Kind != lex.KindPunct {
			words++
			continue
		}
		switch doc.Text[t.Start] {
		case '!', '?', ';', ':':
			return 0, false
		}
	}
	return words, true
}

// bareLeadingWrap сообщает, что знак в начале строки — обрамление значения.
func bareLeadingWrap(c string) bool {
	switch c {
	case "(", "[", "«", "\"", "'", "„", "“", "№", "—", "–", "-":
		return true
	}
	return false
}

// bareClassify опознаёт значение по форме всей строки [lo, hi].
//
// Порядок проверок — от самых узких форм к самым широким: цифры и даты не
// спутать ни с чем, гражданство и орган выдачи — фразы справочников, а место
// рождения, ФИО и держатель опознаются по словам с заглавной буквы, и первым
// среди них идёт то, у чего есть справочное подтверждение.
func bareClassify(doc *lex.Doc, dicts *dict.Set, vetos []Veto, lo, hi int) (bareValue, bool) {
	start, end := doc.Tokens[lo].Start, doc.Tokens[hi].End
	whole := bareValue{start: start, end: end}

	if last, ok := bareDate(doc, dicts, lo, hi); ok {
		// Голая дата выдачи от даты рождения ничем не отличается. Тип
		// берётся тот, что чаще, — пропуск стоит дороже неточного типа.
		v := bareValue{start: start, end: doc.Tokens[last].End, typ: pii.BirthDate, rule: ruleBareDate}
		if !bareVetoed(vetos, v.start, v.end, v.typ) {
			return v, true
		}
	}
	if t, rule, ok := bareDigits(doc, lo, hi); ok && !bareVetoed(vetos, start, end, t) {
		whole.typ, whole.rule = t, rule
		return whole, true
	}
	if bareCitizenship(doc, dicts.Table(miscCitizenshipTable), lo, hi) &&
		!bareVetoed(vetos, start, end, pii.Citizenship) {
		whole.typ, whole.rule = pii.Citizenship, ruleBareCitizenship
		return whole, true
	}
	if bareAuthority(doc, dicts.Table(miscAuthorityTable), lo, hi) &&
		!bareVetoed(vetos, start, end, pii.PassportAuthority) {
		whole.typ, whole.rule = pii.PassportAuthority, ruleBareAuthority
		return whole, true
	}
	if barePlaceAllowed(doc, dicts, vetos, lo, hi) {
		whole.typ, whole.rule = pii.BirthPlace, ruleBareBirthPlace
		return whole, true
	}
	if bareFullName(doc, dicts, lo, hi) && !bareVetoed(vetos, start, end, pii.FullName) {
		whole.typ, whole.rule = pii.FullName, ruleBareName
		return whole, true
	}
	if bareHolder(doc, dicts.Table(nameDictGiven), lo, hi) && !bareVetoed(vetos, start, end, pii.CardHolder) {
		whole.typ, whole.rule = pii.CardHolder, ruleBareHolder
		return whole, true
	}
	return bareValue{}, false
}

// barePlaceAllowed сообщает, что строка [lo, hi] — место рождения и вето его
// не снимают.
//
// Город без обозначения типа бывает и фамилией: «Королёв», «Жуковский».
// Контр-правило на такую фамилию — признак, что строка про публичную персону,
// и тогда она остаётся открытой. С «г.» или «области» строка — место, и
// снимает её только вето на сам тип.
func barePlaceAllowed(doc *lex.Doc, dicts *dict.Set, vetos []Veto, lo, hi int) bool {
	marked, ok := bareBirthPlace(doc, dicts, lo, hi)
	if !ok {
		return false
	}
	start, end := doc.Tokens[lo].Start, doc.Tokens[hi].End
	if marked {
		return !bareVetoed(vetos, start, end, pii.BirthPlace)
	}
	return !bareAnyVeto(vetos, start, end)
}

// bareVetoed сообщает, что вето на участке [start, end) запрещает тип t.
func bareVetoed(vetos []Veto, start, end int32, t pii.Type) bool {
	for _, v := range vetos {
		if v.Start < end && start < v.End && (v.Types.Empty() || v.Types.Has(t)) {
			return true
		}
	}
	return false
}

// bareAnyVeto сообщает, что на участке [start, end) есть вето на любой тип.
func bareAnyVeto(vetos []Veto, start, end int32) bool {
	for _, v := range vetos {
		if v.Start < end && start < v.End {
			return true
		}
	}
	return false
}

// bareDate читает дату, занимающую всю строку, и возвращает её последний
// токен. Слово «года» или «г.» после даты допускается, но в значение не
// входит: это служебное слово, и граница держится по значению.
//
// Голый год («1988») датой здесь не считается: без дня и месяца это любое
// четырёхзначное число, и форму решает bareDigits.
func bareDate(doc *lex.Doc, dicts *dict.Set, lo, hi int) (int, bool) {
	tabs := dateTables{months: dicts.Table(dateMonthsTable), numerals: dicts.Table(dateNumeralsTable)}
	v, last, ok := matchDate(doc, tabs, lo)
	if !ok || v.month == 0 {
		return 0, false
	}
	switch {
	case last == hi:
	case last+1 == hi && doc.Tokens[hi].Kind == lex.KindWord && bareYearWord(doc.NormOf(hi)):
	default:
		return 0, false
	}
	return last, true
}

// bareYearWord — служебное слово года после даты.
func bareYearWord(w string) bool {
	switch w {
	case wordOfYear, wordYear, "г", "гг":
		return true
	}
	return false
}

// bareDigits опознаёт строку из групп цифр по их длине.
//
// Формы — ровно те, что пишут в анкете без маркера: CVV из трёх цифр, ПИН из
// четырёх, код подразделения «ddd-ddd», серия и номер паспорта «dddd dddddd»
// или десять цифр подряд, водительское удостоверение «dd dd dddddd». Десять
// цифр с девятки — мобильный номер без кода страны: серий паспорта с «9»
// немного, мобильные номера начинаются с неё все.
//
// «dddd-dddddd» формой паспорта не считается: так пишут номер договора.
func bareDigits(doc *lex.Doc, lo, hi int) (pii.Type, string, bool) {
	toks := doc.Tokens[lo : hi+1]
	for _, t := range toks {
		if t.Kind == lex.KindWord {
			return 0, "", false
		}
	}
	// Цифры — ASCII, поэтому длина токена в байтах и есть число цифр. Края
	// строки — всегда значимые токены (bareCore), то есть числа.
	switch len(toks) {
	case 1:
		return bareDigitsSingle(doc, toks[0])
	case 2:
		if toks[0].Len() == 4 && toks[1].Len() == 6 {
			return pii.PassportNumber, ruleBarePassport, true
		}
	case 3:
		return bareDigitsTriple(doc, lo, toks)
	}
	return 0, "", false
}

// bareDigitsSingle опознаёт строку из одного числа по числу цифр.
func bareDigitsSingle(doc *lex.Doc, t lex.Token) (pii.Type, string, bool) {
	switch t.Len() {
	case 3:
		return pii.CVV, ruleBareCVV, true
	case 4:
		return pii.PIN, ruleBarePIN, true
	case 10:
		if doc.Text[t.Start] == '9' {
			return pii.Phone, ruleBarePhone, true
		}
		return pii.PassportNumber, ruleBarePassport, true
	}
	return 0, "", false
}

// bareDigitsTriple опознаёт строку из трёх токенов toks, начиная с токена lo:
// код подразделения «ddd-ddd» или водительское удостоверение «dd dd dddddd».
func bareDigitsTriple(doc *lex.Doc, lo int, toks []lex.Token) (pii.Type, string, bool) {
	mid := toks[1]
	if mid.Kind == lex.KindPunct {
		if doc.Text[mid.Start] == '-' && doc.Adjacent(lo) && doc.Adjacent(lo+1) &&
			toks[0].Len() == 3 && toks[2].Len() == 3 {
			return pii.PassportDeptCode, ruleBareDeptCode, true
		}
		return 0, "", false
	}
	if toks[0].Len() == 2 && mid.Len() == 2 && toks[2].Len() == 6 {
		return pii.DriverLicense, ruleBareLicense, true
	}
	return 0, "", false
}

// bareCitizenship сообщает, что вся строка — фраза справочника гражданства:
// «Российская Федерация», «РФ», «Республики Беларусь».
func bareCitizenship(doc *lex.Doc, tab *dict.Table, lo, hi int) bool {
	if last, ok := miscMatchPhrase(doc, tab, lo); ok && last == hi {
		return true
	}
	// Родовое слово в косвенном падеже справочником не покрыто:
	// «Республики Казахстан» — это «республики» и словарное «казахстан».
	if lo < hi && doc.Tokens[lo].Kind == lex.KindWord && bareCountryLead(doc.NormOf(lo)) {
		if last, ok := miscMatchPhrase(doc, tab, lo+1); ok && last == hi {
			return true
		}
	}
	return false
}

// bareCountryLead сообщает, что слово — родовое слово названия страны.
func bareCountryLead(w string) bool {
	for _, s := range miscCountryLeadWords {
		if w == s {
			return true
		}
	}
	return false
}

// bareAuthority сообщает, что строка — название органа, выдавшего паспорт:
// аббревиатура из справочника, перед ней не больше bareAuthorityLead слов
// подразделения («Отделом», «Территориальным пунктом»), после неё —
// территория.
//
// Территория обязательна. «МВД», «УФМС России» и «ГУ МВД России» — названия
// ведомств, а не реквизит паспорта: реквизитом орган становится вместе с
// регионом или районом, где он выдал документ.
func bareAuthority(doc *lex.Doc, tab *dict.Table, lo, hi int) bool {
	if tab == nil {
		return false
	}
	for k := lo; k <= hi && k-lo <= bareAuthorityLead; k++ {
		if doc.Tokens[k].Kind != lex.KindWord {
			return false
		}
		if last, ok := miscMatchPhrase(doc, tab, k); ok {
			return last < hi && bareAuthorityTail(doc, last+1, hi)
		}
		if !bareUnitWord(doc.NormOf(k)) {
			return false
		}
	}
	return false
}

// bareUnitPrefixes — основы слов, обозначающих подразделение перед
// аббревиатурой органа, во всех падежах: «отделом», «отделением»,
// «управлением», «территориальным пунктом».
var bareUnitPrefixes = [...]string{
	"отдел", "управлен", "территориальн", "пункт", "подразделен",
	"межрайон", "главн", "миграцион", "паспортн",
}

func bareUnitWord(w string) bool {
	for _, p := range bareUnitPrefixes {
		if strings.HasPrefix(w, p) {
			return true
		}
	}
	return false
}

// bareAuthorityTail проверяет продолжение названия органа [from, hi]: слова,
// точки сокращений, дефисы, запятые и кавычки, и среди слов — территория:
// «по …», «в …» или обозначение места («области», «района», «г.»).
func bareAuthorityTail(doc *lex.Doc, from, hi int) bool {
	words, territory := 0, false
	for i := from; i <= hi; i++ {
		switch doc.Tokens[i].Kind {
		case lex.KindDigits:
			return false
		case lex.KindPunct:
			switch doc.Raw(i) {
			case ".", "-", ",", "\"", "«", "»":
			default:
				return false
			}
		default:
			words++
			switch w := doc.NormOf(i); {
			case w == "по" || w == "в" || w == "во":
				territory = true
			case w != "им" && w != wordNamed && miscIsPlaceWord(w):
				territory = true
			}
		}
	}
	return territory && words <= bareAuthorityWords
}

// bareBirthPlace сообщает, что строка — населённый пункт или регион без
// улицы и дома: «Москва», «г. Жуковский Московской области», «Санкт-
// Петербург», «с. Верхние Ключи, Тверская область».
//
// Форма — слова с заглавной, обозначения места («г.», «обл.», «области»),
// дефисы составных названий и запятые между частями. Подтверждение
// обязательно: либо обозначение места, либо каждое слово входит в город,
// регион или страну из справочников. Без подтверждения любое слово с
// заглавной — «Спасибо» — стало бы местом рождения, а при подтверждении
// одним словом из нескольких — и «Иван Грозный».
//
// Первое значение сообщает, что в строке есть обозначение места: такая строка
// заведомо про место, а не про человека. Однобуквенное обозначение с
// заглавной — «Д.» — таким признаком не считается: это и инициал.
func bareBirthPlace(doc *lex.Doc, dicts *dict.Set, lo, hi int) (marked, ok bool) {
	st := barePlaceScan{
		tabs: [...]*dict.Table{
			dicts.Table(miscGeoCitiesTable),
			dicts.Table(bareGeoRegionsTable),
			dicts.Table(miscCitizenshipTable),
		},
		covered: -1,
	}
	for i := lo; i <= hi; i++ {
		if !st.step(doc, lo, i) {
			return false, false
		}
	}
	return st.marked, st.words > 0 && (st.marked || !st.uncovered)
}

// barePlaceScan — состояние разбора места рождения слева направо.
type barePlaceScan struct {
	// tabs — справочники городов, регионов и стран.
	tabs [3]*dict.Table
	// words — число слов названия, covered — последний токен, накрытый
	// словарной фразой, uncovered — нашлось слово вне справочников, marked —
	// в строке есть обозначение места.
	words, covered    int
	uncovered, marked bool
}

// step разбирает токен i строки, начатой токеном lo, и сообщает, что строка
// всё ещё может быть местом рождения.
func (st *barePlaceScan) step(doc *lex.Doc, lo, i int) bool {
	t := doc.Tokens[i]
	switch t.Kind {
	case lex.KindDigits:
		return false
	case lex.KindPunct:
		return bareJoinerOK(doc, i, false)
	}
	if !t.Flags.Has(lex.FlagCyrillic) {
		return false
	}
	w := doc.NormOf(i)
	if miscIsPlaceWord(w) {
		if barePlaceMark(t, w) {
			st.marked = true
		}
		return true
	}
	// Строчное слово допустимо только внутри составного названия:
	// «Ростов-на-Дону».
	afterHyphen := i > lo && doc.Adjacent(i-1) && doc.Raw(i-1) == "-"
	if !t.Flags.Has(lex.FlagFirstUpper) && !afterHyphen {
		return false
	}
	if st.words++; st.words > bareToponymWords {
		return false
	}
	if i <= st.covered {
		return true
	}
	hit := st.lookup(doc, i)
	st.uncovered = st.uncovered || !hit
	return true
}

// barePlaceMark сообщает, что обозначение места w (токен t) подтверждает
// место: «им.» и «имени» — часть названия, а однобуквенное обозначение с
// заглавной — «Д.» — это и инициал.
func barePlaceMark(t lex.Token, w string) bool {
	return w != "им" && w != wordNamed && (t.Len() > 2 || !t.Flags.Has(lex.FlagFirstUpper))
}

// lookup ищет словарную фразу, начатую словом i, и запоминает её последний
// токен.
func (st *barePlaceScan) lookup(doc *lex.Doc, i int) bool {
	for _, tab := range st.tabs {
		if last, ok := miscMatchPhrase(doc, tab, i); ok {
			st.covered = last
			return true
		}
	}
	return false
}

// bareJoinerOK сообщает, что знак i допустим внутри голого названия или ФИО.
//
// Точка сокращения стоит вплотную к своему слову: «г.». Дефис составного
// названия и двойной фамилии — вплотную с обеих сторон: «Санкт-Петербург»,
// «Римская-Корсакова». С initialDot разбирается ФИО: точка допускается только
// после однобуквенного слова — инициала, — а запятая не допускается вовсе.
func bareJoinerOK(doc *lex.Doc, i int, initialDot bool) bool {
	switch doc.Raw(i) {
	case ".":
		return doc.Adjacent(i-1) && doc.Tokens[i-1].Kind == lex.KindWord &&
			(!initialDot || nameRunes(doc.Tokens[i-1]) == 1)
	case "-":
		return doc.Adjacent(i-1) && doc.Adjacent(i)
	case ",":
		return !initialDot
	}
	return false
}

// bareFullName сообщает, что строка — ФИО: одно–три слова кириллицей с
// заглавной буквы, каждое из которых — имя, отчество, фамилия или инициал, и
// хотя бы одно — не инициал. Роли слов определяет тот же разбор, что и у
// сканера ФИО, — справочник имён и морфология отчеств и фамилий.
//
// Одно слово без роли допускается рядом с именем или отчеством: это фамилия
// без русского суффикса — «Жук Герман», «Мельник Марина Олеговна». Её
// проверяет тот же отсев, что у сканера ФИО: служебные слова, глаголы,
// прилагательные, месяцы и города фамилией не становятся, поэтому «Привет
// Марина» или «Дорогая Марина» ФИО целиком строки не считаются.
func bareFullName(doc *lex.Doc, dicts *dict.Set, lo, hi int) bool {
	tb := bareNameTables(dicts)
	st := bareNameScan{bare: -1, first: -1, patr: -1}
	for i := lo; i <= hi; i++ {
		if !st.step(doc, &tb, lo, i) {
			return false
		}
	}
	return st.accept(doc, &tb)
}

// bareNameTables собирает справочники разбора ФИО, нужные голому значению.
func bareNameTables(dicts *dict.Set) nameTables {
	return nameTables{
		given:   dicts.Table(nameDictGiven),
		markers: dicts.Table(nameDictMarkers),
		months:  dicts.Table(nameDictMonths),
		cities:  dicts.Table(nameDictCities),
		banking: dicts.Table(counterDictBanking),
	}
}

// bareNameScan — состояние разбора голого ФИО слева направо.
type bareNameScan struct {
	// words — число слов, named — есть слово с ролью, кроме инициала,
	// nominative — есть имя или отчество в именительном падеже.
	words             int
	named, nominative bool
	// bare — слово без роли, first — первое слово с ролью имени или
	// отчества, patr — отчество: по ним проверяется фамилия без суффикса.
	bare, first, patr int
}

// step разбирает токен i строки, начатой токеном lo, и сообщает, что строка
// всё ещё может быть ФИО.
func (st *bareNameScan) step(doc *lex.Doc, tb *nameTables, lo, i int) bool {
	t := doc.Tokens[i]
	switch t.Kind {
	case lex.KindDigits:
		return false
	case lex.KindPunct:
		return bareJoinerOK(doc, i, true)
	}
	if !t.Flags.Has(lex.FlagCyrillic | lex.FlagFirstUpper) {
		return false
	}
	if i == lo || doc.Raw(i-1) != "-" {
		st.words++
	}
	role := nameClassify(doc, tb.given, tb.markers, i)
	if role == 0 {
		if st.bare >= 0 {
			return false
		}
		st.bare = i
		return true
	}
	st.note(doc, tb.given, i, role)
	return true
}

// note учитывает слово i с ролью role.
func (st *bareNameScan) note(doc *lex.Doc, given *dict.Table, i int, role nameRole) {
	if role&(nameRoleGiven|nameRolePatronymic) != 0 && st.first < 0 {
		st.first = i
	}
	if role&nameRolePatronymic != 0 && role&nameRoleGiven == 0 {
		st.patr = i
	}
	if !st.nominative {
		st.nominative = bareNominativeName(given, doc.NormOf(i), role)
	}
	if role&^nameRoleInitial != 0 {
		st.named = true
	}
}

// accept решает по разобранной строке, ФИО ли она.
func (st *bareNameScan) accept(doc *lex.Doc, tb *nameTables) bool {
	if !st.named || st.words > bareNameWords {
		return false
	}
	if st.bare < 0 {
		return true
	}
	// Голое ФИО пишут в именительном падеже. Имя в косвенном — «Позвони
	// Марине», «Спроси Олега» — значит, что рядом не фамилия, а глагол.
	if st.first < 0 || st.words < 2 || !st.nominative {
		return false
	}
	ok, _ := nameBareSurname(doc, tb, st.bare, st.patr, st.bare < st.first)
	return ok
}

// bareNominativeName сообщает, что слово — имя или отчество в именительном
// падеже: имя — ровно запись справочника, отчество — на «-ич» или «-на».
func bareNominativeName(given *dict.Table, w string, role nameRole) bool {
	switch {
	case role&nameRoleGiven != 0 && given.Has(w):
		return true
	case role&nameRolePatronymic != 0:
		return strings.HasSuffix(w, "ич") || strings.HasSuffix(w, "на")
	}
	return false
}

// bareHolder сообщает, что строка — имя держателя карты: два–три слова
// латиницей с заглавной буквы, похожие на имя и фамилию.
//
// Сходство проверяется дёшево и без списков латинских имён: либо у слова
// суффикс русской фамилии в транслитерации («SHAPOVALOVA», «PETROV»), либо
// слово — транслитерация имени из справочника («DARIA» → «дарья»). Два слова
// латиницей без этого — «HELLO WORLD», «Visa Classic» — держателем не
// считаются.
func bareHolder(doc *lex.Doc, given *dict.Table, lo, hi int) bool {
	words, named := 0, false
	for i := lo; i <= hi; i++ {
		t := doc.Tokens[i]
		if t.Kind != lex.KindWord || !t.Flags.Has(lex.FlagLatin|lex.FlagFirstUpper) {
			return false
		}
		w := doc.NormOf(i)
		if len(w) < miscHolderMinLetters || bareHolderStop(w) {
			return false
		}
		words++
		if !named && (bareLatinSurname(w) || bareLatinGiven(given, w)) {
			named = true
		}
	}
	return named && words >= 2 && words <= bareHolderWords
}

// bareHolderStop — слово из стоп-списка держателя: реквизит, платёжная
// система или техническое сокращение.
func bareHolderStop(w string) bool {
	for _, s := range miscHolderStopWords {
		if s == w {
			return true
		}
	}
	return false
}

// bareLatinSuffix — суффикс русской фамилии в транслитерации и минимальная
// длина слова в буквах, с которой он принимается.
type bareLatinSuffix struct {
	end string
	min int
}

// bareLatinSurnames — суффиксы фамилий латиницей. Минимальная длина отсекает
// короткие английские слова: «cabin», «rich» под суффиксы не проходят.
var bareLatinSurnames = [...]bareLatinSuffix{
	{"skaya", 8}, {"skaia", 8}, {"skiy", 7}, {"skii", 7}, {"sky", 6},
	{"shvili", 8}, {"enko", 6}, {"dze", 6},
	{"ova", 6}, {"eva", 6}, {"ina", 6}, {"yna", 6},
	{"ov", 5}, {"ev", 5}, {"in", 6}, {"yn", 5},
	{"chuk", 6}, {"yuk", 5}, {"iuk", 5}, {"uk", 4},
	{"yan", 5}, {"ian", 6}, {"vich", 6}, {"ykh", 5}, {"ikh", 5},
	{"aya", 7}, {"aia", 7}, {"oi", 6}, {"oy", 6}, {"ko", 6},
}

func bareLatinSurname(w string) bool {
	for _, s := range bareLatinSurnames {
		if len(w) >= s.min && strings.HasSuffix(w, s.end) {
			return true
		}
	}
	return false
}

// bareLatinAlt — вариант обратной транслитерации: латинская запись и
// кириллица, которую она может передавать, с ограничением на позицию.
type bareLatinAlt struct {
	lat, cyr string
	pos      uint8
}

const (
	barePosAny   uint8 = iota
	barePosFirst       // только в начале слова: «Elvira» → «э»
	barePosLast        // только в конце слова: «Igor» → «рь»
)

// bareLatinAlts — таблица обратной транслитерации.
//
// На карте имя печатают по правилам загранпаспорта, и одна кириллическая
// буква даёт одну запись: «я» → «IA», «й» → «I», «ь» пропадает. Обратно
// однозначности нет, поэтому у сочетаний несколько вариантов, а перебор
// сверяет каждый со справочником имён. Устаревшие схемы («YA», «Y»,
// «SERGEY») тоже в таблице: на картах разных лет встречаются обе.
var bareLatinAlts = [...]bareLatinAlt{
	{"shch", "щ", barePosAny}, {"sch", "щ", barePosAny},
	{"zh", "ж", barePosAny}, {"kh", "х", barePosAny}, {"ch", "ч", barePosAny},
	{"sh", "ш", barePosAny}, {"ts", "ц", barePosAny},
	{"iu", "ю", barePosAny}, {"yu", "ю", barePosAny},
	{"ia", "я", barePosAny}, {"ia", "ья", barePosAny}, {"ia", "ия", barePosAny},
	{"ya", "я", barePosAny}, {"ya", "ья", barePosAny},
	{"ye", "е", barePosAny}, {"ye", "ье", barePosAny}, {"ie", "ье", barePosAny},
	{"yo", "е", barePosAny}, {"ii", "ий", barePosAny}, {"iy", "ий", barePosAny},
	{"er", "р", barePosLast},
	{"x", "кс", barePosAny},
	{"a", "а", barePosAny}, {"b", "б", barePosAny}, {"c", "к", barePosAny},
	{"d", "д", barePosAny}, {"e", "е", barePosAny}, {"e", "э", barePosFirst},
	{"f", "ф", barePosAny}, {"g", "г", barePosAny}, {"h", "х", barePosAny},
	{"i", "и", barePosAny}, {"i", "й", barePosAny}, {"i", "ий", barePosLast},
	{"j", "й", barePosAny}, {"k", "к", barePosAny},
	{"l", "л", barePosAny}, {"l", "ль", barePosAny},
	{"m", "м", barePosAny}, {"n", "н", barePosAny}, {"o", "о", barePosAny},
	{"p", "п", barePosAny}, {"q", "к", barePosAny},
	{"r", "р", barePosAny}, {"r", "рь", barePosLast},
	{"s", "с", barePosAny}, {"t", "т", barePosAny}, {"u", "у", barePosAny},
	{"v", "в", barePosAny}, {"w", "в", barePosAny},
	{"y", "ы", barePosAny}, {"y", "й", barePosAny}, {"y", "ий", barePosLast},
	{"z", "з", barePosAny},
}

// bareLatinGiven сообщает, что латинское слово w (в нижнем регистре) — одна
// из транслитераций имени из справочника.
//
// Ключ собирается в буфере на стеке: nameKeyMax байт хватает на любое имя
// справочника, более длинный вариант отбрасывается.
func bareLatinGiven(given *dict.Table, w string) bool {
	if given == nil || len(w) > nameKeyMax {
		return false
	}
	tr := bareTranslit{given: given, src: w, budget: bareTranslitBudget}
	return tr.walk(0, 0)
}

// bareTranslit — состояние перебора вариантов обратной транслитерации.
type bareTranslit struct {
	given  *dict.Table
	src    string
	buf    [nameKeyMax]byte
	budget int
}

// walk продолжает вариант, у которого разобрано i байт латиницы и собрано
// n байт кириллицы.
func (t *bareTranslit) walk(i, n int) bool {
	if t.budget--; t.budget < 0 {
		return false
	}
	if i == len(t.src) {
		return t.given.Has(string(t.buf[:n]))
	}
	for k := range bareLatinAlts {
		a := &bareLatinAlts[k]
		if a.lat[0] != t.src[i] {
			continue
		}
		next, ok := t.fits(a, i, n)
		if !ok {
			continue
		}
		copy(t.buf[n:], a.cyr)
		if t.walk(next, n+len(a.cyr)) {
			return true
		}
		if t.budget < 0 {
			return false
		}
	}
	return false
}

// fits сообщает, что вариант a продолжает разбор с байта i латиницы при n
// собранных байтах кириллицы, и возвращает, сколько латиницы разобрано после
// него. Вариант не подходит, если его запись не совпадает с текстом, он стоит
// не на своей позиции или ключ перерос буфер.
func (t *bareTranslit) fits(a *bareLatinAlt, i, n int) (int, bool) {
	if !strings.HasPrefix(t.src[i:], a.lat) {
		return 0, false
	}
	next := i + len(a.lat)
	if a.pos == barePosFirst && i != 0 {
		return 0, false
	}
	if a.pos == barePosLast && next != len(t.src) {
		return 0, false
	}
	if n+len(a.cyr) > len(t.buf) {
		return 0, false
	}
	return next, true
}

// bareLiftWeak поднимает до Strong слабых кандидатов одного типа, если они
// вместе накрывают все слова и числа строки [lo, hi].
//
// Тип выбирается в порядке объявления, чтобы результат не зависел от порядка
// работы сканеров. Держатель карты не поднимается: два слова латиницей
// заглавными — ещё не имя, и его решает только классификатор, проверяющий
// сходство с именем.
func bareLiftWeak(doc *lex.Doc, cand *Candidates, lo, hi int) {
	start, end := doc.Tokens[lo].Start, doc.Tokens[hi].End
	if bareAnyVeto(cand.Vetos, start, end) {
		return
	}
	var types pii.Set
	for _, s := range cand.Spans {
		if s.Conf == Weak && s.Type != pii.CardHolder && s.Start < end && start < s.End {
			types = types.Add(s.Type)
		}
	}
	if types.Empty() {
		return
	}
	for t := pii.Type(1); int(t) < pii.Count; t++ {
		if !types.Has(t) || !bareCovered(doc, cand.Spans, lo, hi, t) {
			continue
		}
		barePromote(cand.Spans, t, start, end)
		return
	}
}

// barePromote поднимает до Strong слабых кандидатов типа t, пересекающих
// участок [start, end), с пометкой правила «+bare».
func barePromote(spans []Span, t pii.Type, start, end int32) {
	for i := range spans {
		s := &spans[i]
		if s.Type == t && s.Conf == Weak && s.Start < end && start < s.End {
			s.Conf = Strong
			s.Rule = bareRules.of(s.Rule)
		}
	}
}

// bareCovered сообщает, что каждое слово и число строки [lo, hi] лежит внутри
// слабого кандидата типа t.
func bareCovered(doc *lex.Doc, spans []Span, lo, hi int, t pii.Type) bool {
	for i := lo; i <= hi; i++ {
		tok := doc.Tokens[i]
		if tok.Kind == lex.KindPunct {
			continue
		}
		covered := false
		for _, s := range spans {
			if s.Type == t && s.Conf == Weak && s.Start <= tok.Start && tok.End <= s.End {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}
