package detect

import (
	"strings"
	"unicode/utf8"

	"ai-gateway/internal/lex"
)

// --- Раунд 5 жюри (T-80, ФИО-часть T-83) ------------------------------------
//
// Классы утечек, и каждый — класс, а не фраза:
//
//  1. фамилия капсом после метки поля с маркером лица: «Держатель карты:
//     ГОЛУБ СВЕТЛАНА», «Имя на карте: МАЗУР ОЛЕГ» (nameLabelAnchored);
//  2. общая фамилия после слова группы: «Супруги Мазур: Олег и Алла»,
//     «Братья Литвин — Ярослав и Остап» (nameFamilySurname), и имена того
//     же предложения — люди этой семьи;
//  3. имя вне справочника рядом с фамилией с суффиксом: «Шахзод Турсунов»,
//     «Гелашвили Тамази» (nameGivenPosWord), вьетнамские и корейские слоги
//     («Ким Со Ён», nameScan.extendSyllables), тюркское «оглы»/«кызы»;
//  4. второе значение пары полей: «Прежняя фамилия — Литвин, текущая —
//     Голуб», «Была Дорош, стала Гринь», «Литвин → Лемеш» (name_fields.go);
//  5. строчная пара «имя фамилия-слово» в позиции лица: «звонил олег мазур,
//     просил…», «полина гринь не получила код», «клиент олег мельник,
//     паспорт …» (nameLowerSubject);
//  6. латинская буква-двойник внутри слова — сводится лексером;
//  7. фамилия-слово перед именем в начале предложения: «Кит Анна оформила
//     карту», «Бабий Зоя открыла вклад» (nameAdjLeadsPredicate,
//     nameBareVerbLike);
//  8. запись через разделитель без пробела: «Лысенко;Ольга;Петровна»
//     (nameCSVNext) и латинские метки полей «surname=», «first_name:»;
//  9. одиночная фамилия с суффиксом перед сказуемым лица: «Сидорчук просит
//     перевыпустить карту» (nameSubjectSlot), «Орёл Сергей Петрович
//     оформил…» — фамилия-глагол перед парой со сказуемым.
//
// Ложное срабатывание «получил Нобелевскую премию» снимает согласование
// прилагательного с существительным справа (nameAdjModifiesNext).

// Имена правил раунда 5.
const (
	// Общая фамилия после слова группы и имена той же семьи.
	nameRuleFamily       = "name.surname+family"
	nameRuleFamilyMember = "name.given+family"

	// Фамилия-прилагательное перед именем при сказуемом лица: «Бабий Роман
	// сообщил о краже».
	nameRuleAdjGivenPredicate = "name.surname_adj+given/predicate"

	// Одиночная фамилия с суффиксом перед сказуемым: «Сидорчук просит…».
	nameRuleSubject = "name.surname+predicate"

	// Слово вне справочника на месте имени рядом с фамилией: «Шахзод
	// Турсунов», «Гелашвили Тамази».
	nameRuleGivenPosSurname       = "name.given_pos+surname"
	nameRuleSurnameGivenPos       = "name.surname+given_pos"
	nameRuleGivenPosSurnameMarker = "name.given_pos+surname+marker"
	nameRuleSurnameGivenPosMarker = "name.surname+given_pos+marker"
)

const (
	// nameDictGroups — слова, которые вводят нескольких людей с общей
	// фамилией: «супруги», «семья», «братья».
	nameDictGroups = "name_groups"

	// nameDictPlaces — адресные слова сканера адреса («улица», «площадь»):
	// здесь только читаются, как отсев слова на месте имени.
	nameDictPlaces = "address_markers"

	// nameDictRequisites — названия реквизитов, которые идут через запятую
	// за ФИО: «олег мельник, паспорт …».
	nameDictRequisites = "name_requisites"

	// Вторая половина оборота «была X, стала Y».
	nameWordBecame    = "стал"
	nameWordBecameFem = "стала"

	// nameFamilyReach — сколько токенов справа от общей фамилии ищется имя
	// из справочника: «Супруги Мазур: Олег и Алла», «У семьи Голуб два
	// кредита: у Светланы…». Предел держит проход линейным.
	nameFamilyReach = 12

	// nameSyllableMax — длина слога восточноазиатского имени в буквах:
	// «Ким Со Ён», «Нгуен Ван Ба».
	nameSyllableMax = 3

	// nameHeadReach — сколько служебных слов допускается перед конструкцией
	// в начале предложения: «Вчера полина гринь не получила код».
	nameHeadReach = 3
)

// nameLabelAnchored сообщает, что слово k стоит сразу за двоеточием метки
// поля, в которой есть маркер лица: «Держатель карты: ГОЛУБ СВЕТЛАНА», «Имя
// на карте: МАЗУР ОЛЕГ». Метка поля — та же опора, что маркер вплотную:
// значение поля с маркером лица — человек, в каком бы регистре его ни
// записали.
func nameLabelAnchored(doc *lex.Doc, tb *nameTables, k int) bool {
	if k == 0 {
		return false
	}
	p := doc.Tokens[k-1]
	if p.Kind != lex.KindPunct || doc.Text[p.Start] != ':' {
		return false
	}
	return nameMarkerLeft(doc, tb.markers, k)
}

// nameFamilySurname сообщает, что слово i с заглавной стоит вплотную за
// словом группы («Супруги», «Семья», «Братья») и в том же предложении дальше
// есть имя из справочника: «Супруги Мазур: Олег и Алла». Без имени слово не
// принимается — «Братья Карамазовы — роман», «Семья Ивановых» без имён
// могут быть названием.
func nameFamilySurname(doc *lex.Doc, tb *nameTables, i int) bool {
	if i == 0 || !nameTitle(doc.Tokens[i]) || doc.Tokens[i-1].Kind != lex.KindWord ||
		doc.IsSentenceBreak(i-1) || !tb.groups.Has(doc.NormOf(i-1)) {
		return false
	}
	w := doc.NormOf(i)
	if _, ok := nameLookupGiven(tb.given, w); ok {
		return false
	}
	if nameNotNamePart(tb.markers, w) || nameLeadStop(tb, w) || tb.cities.Has(w) || tb.months.Has(w) {
		return false
	}
	return nameGivenAhead(doc, tb, i)
}

// nameGivenAhead сообщает, что справа от слова i в том же предложении, не
// дальше nameFamilyReach токенов, стоит имя из справочника с заглавной.
func nameGivenAhead(doc *lex.Doc, tb *nameTables, i int) bool {
	for k := i + 1; k < len(doc.Tokens) && k <= i+nameFamilyReach; k++ {
		if doc.IsSentenceBreak(k - 1) {
			return false
		}
		if nameFamilyGiven(doc, tb, k) {
			return true
		}
	}
	return false
}

// nameFamilyGiven сообщает, что слово k — имя из справочника с заглавной
// буквы в любом падеже: «Олег», «у Светланы».
func nameFamilyGiven(doc *lex.Doc, tb *nameTables, k int) bool {
	if !nameEligible(doc, k) || !nameTitle(doc.Tokens[k]) {
		return false
	}
	_, ok := nameLookupGiven(tb.given, doc.NormOf(k))
	return ok
}

// noteFamily запоминает конец предложения, в котором найдена общая фамилия:
// имена до этой границы — люди этой семьи.
func (s *nameScan) noteFamily(rule string, i int) {
	if rule != nameRuleFamily {
		return
	}
	_, s.familyHi = s.doc.SentenceBounds(i)
}

// liftFamily поднимает одиночное имя в предложении с общей фамилией:
// «Супруги Мазур: Олег и Алла» — Олег и Алла Мазур.
func (s *nameScan) liftFamily(c *nameCons) bool {
	if c.conf >= Strong || !c.single || c.first > s.familyHi || !nameFamilyGiven(s.doc, &s.tb, c.first) {
		return false
	}
	c.conf, c.rule = Strong, nameRuleFamilyMember
	return true
}

// nameAdjGenderFits сообщает, что окончание прилагательного w допустимо для
// фамилии перед именем рода label. Мужская форма на «-ий», «-ый», «-ой»
// рядом с женским именем — несклоняемая фамилия («Бабий Зоя»): определением
// к женскому имени она быть не может.
func nameAdjGenderFits(w, label string) bool {
	masc := strings.HasSuffix(w, "ий") || strings.HasSuffix(w, "ый") || strings.HasSuffix(w, "ой")
	switch label {
	case "m":
		return masc
	case "f":
		return masc || strings.HasSuffix(w, "ая") || strings.HasSuffix(w, "яя")
	}
	return false
}

// nameAdjLeadsPredicate сообщает, что фамилия-прилагательное k стоит перед
// именем first в именительном падеже, а за именем — сказуемое лица: «Бабий
// Роман сообщил о краже», «Бабий Зоя открыла вклад». Слово в начале
// предложения свидетельства регистра не имеет, и nameAdjWithGiven его не
// берёт; сказуемое показывает, что подлежащее — пара целиком, а оценку и
// обращение («Милый Олег», «Старший Иван») снимает nameAdjStopped.
func nameAdjLeadsPredicate(doc *lex.Doc, tb *nameTables, k, first int) bool {
	t := doc.Tokens[k]
	if !nameTitle(t) || !nameTitle(doc.Tokens[first]) || nameRunes(t) < nameAdjMinLen || nameQuoted(doc, k) {
		return false
	}
	w := doc.NormOf(k)
	label, ok := tb.given.Get(doc.NormOf(first))
	if !ok || !nameAdjGenderFits(w, label) {
		return false
	}
	if nameNotNamePart(tb.markers, w) || nameLeadStop(tb, w) || nameAdjStopped(w) {
		return false
	}
	return namePredicateAfter(doc, first)
}

// nameShortNoun сообщает, что трёхбуквенное слово на «-ит», «-ет», «-ут»,
// «-ют», «-ат», «-ят» — существительное, а не глагол: «Кит», «Щит», «Шут».
// Глаголы настоящего времени короче четырёх букв не бывают («спит», «бдит»),
// а трёхбуквенные глаголы прошедшего времени («был», «дал») этим правилом не
// задеты.
func nameShortNoun(w string) bool {
	if utf8.RuneCountInString(w) != 3 {
		return false
	}
	switch w[len(w)-4:] {
	case "ит", "ет", "ут", "ют", "ат", "ят":
		return true
	}
	return false
}

// nameSubjectSlot сообщает, что одиночная фамилия с суффиксом i стоит перед
// сказуемым лица: «Сидорчук просит перевыпустить карту», «Ковальчук звонил
// дважды». Суффикс и сказуемое вместе — два независимых признака; заглавная
// буква в начале предложения свидетельством не служит, поэтому отсевы те же,
// что у позиции лица: имя из справочника, город, стоп-слова, организация.
func nameSubjectSlot(doc *lex.Doc, tb *nameTables, i int) bool {
	t := doc.Tokens[i]
	if !t.Flags.Has(lex.FlagFirstUpper) || nameQuoted(doc, i) || !namePredicateAfter(doc, i) {
		return false
	}
	// «поэт Пушкин написал»: публичную персону снимает контр-правило, и
	// сканер оставляет её на уровне одиночного слова.
	if p, ok := namePrevWord(doc, i); ok && tb.roles.Has(doc.NormOf(p)) {
		return false
	}
	w := doc.NormOf(i)
	if _, ok := nameLookupGiven(tb.given, w); ok {
		return false
	}
	if nameNotNamePart(tb.markers, w) || nameLeadStop(tb, w) || strings.Contains(w, wordBank) || nameDemonym(w) {
		return false
	}
	if _, city := nameLookupGiven(tb.cities, w); city {
		return false
	}
	return i == 0 || !nameToponymPrep(doc, i-1)
}

// nameIntroducedAs сообщает, что слово p — «как» после глагола
// самопредставления: «представился как Цой», «назвалась как Кох».
func nameIntroducedAs(doc *lex.Doc, p int) bool {
	if doc.NormOf(p) != "как" {
		return false
	}
	v, ok := namePrevWord(doc, p)
	if !ok {
		return false
	}
	switch doc.NormOf(v) {
	case "представился", "представилась", "назвался", "назвалась", "подписался", "подписалась":
		return true
	}
	return false
}

// nameDemonym сообщает, что слово на «-анин»/«-янин» называет жителя или
// сословие, а не фамилию: «Горожанин просит», «Россиянин звонил».
func nameDemonym(w string) bool {
	return strings.HasSuffix(w, "анин") || strings.HasSuffix(w, "янин")
}

// nameAdjAgreement — окончание фамилии-прилагательного после «-ск-»/«-цк-»
// и окончания существительного в том же роде и падеже.
var nameAdjAgreement = [...]struct {
	tail  string
	nouns [6]string
}{
	{"ую", [6]string{"у", "ю", "ь"}},
	{"ая", [6]string{"а", "я", "ь"}},
	{"ого", [6]string{"а", "я", "о", "е"}},
	{"ому", [6]string{"у", "ю"}},
	{"им", [6]string{"ом", "ем", "ам", "ям"}},
	{"ом", [6]string{"е", "и"}},
	{"ой", [6]string{"ы", "и", "е", "ой", "ей", "ью"}},
}

// nameAdjModifiesNext сообщает, что слово i с окончанием прилагательного на
// «-ск-»/«-цк-» — определение к строчному существительному справа в том же
// роде и падеже: «получил Нобелевскую премию», «от Российской федерации».
// Такое слово — прилагательное, а не фамилия в позиции лица: у фамилии за
// ней стоит граница или сказуемое, а не согласованное существительное.
func nameAdjModifiesNext(doc *lex.Doc, tb *nameTables, i int) bool {
	j := i + 1
	if j >= len(doc.Tokens) || !nameJoinable(doc, i) || doc.IsSentenceBreak(i) || !nameEligible(doc, j) ||
		doc.Tokens[j].Flags.Has(lex.FlagFirstUpper) || nameRunes(doc.Tokens[j]) < nameBareBlindMinLen {
		return false
	}
	noun := doc.NormOf(j)
	// Служебное слово после фамилии («Звонил Достоевский опять») —
	// не определяемое; «банк» из стоп-списка — существительное.
	if (nameBareStopWord(noun) || tb.stop.Has(noun)) && !strings.Contains(noun, wordBank) ||
		namePredicateWord(noun) || nameBareVerbLike(noun) {
		return false
	}
	w := doc.NormOf(i)
	// «Московский банк»: мужской род, именительный падеж — существительное
	// на согласную.
	if nameSkTail(w, "ий") {
		return nameConsonantEnd(noun)
	}
	for _, a := range nameAdjAgreement {
		if nameSkTail(w, a.tail) {
			return nameEndsWithAny(noun, a.nouns[:])
		}
	}
	return false
}

// nameSkTail сообщает, что слово кончается на «-ск-» или «-цк-» с окончанием
// tail: «нобелевскую» — «ск» + «ую».
func nameSkTail(w, tail string) bool {
	if !strings.HasSuffix(w, tail) {
		return false
	}
	stem := w[:len(w)-len(tail)]
	return strings.HasSuffix(stem, "ск") || strings.HasSuffix(stem, "цк")
}

// nameEndsWithAny сообщает, что слово кончается одним из непустых окончаний.
func nameEndsWithAny(w string, ends []string) bool {
	for _, e := range ends {
		if e != "" && strings.HasSuffix(w, e) {
			return true
		}
	}
	return false
}

// nameSentenceHead сообщает, что слово first начинает предложение: слева до
// границы предложения нет слов, кроме служебных вроде «вчера», «срочно»
// (nameFillerWord), не больше nameHeadReach.
func nameSentenceHead(doc *lex.Doc, first int) bool {
	words := 0
	for k := first - 1; k >= 0; k-- {
		if doc.IsSentenceBreak(k) {
			return true
		}
		t := doc.Tokens[k]
		if t.Kind == lex.KindPunct {
			continue
		}
		words++
		if t.Kind != lex.KindWord || words > nameHeadReach || !nameFillerWord(doc.NormOf(k)) {
			return false
		}
	}
	return true
}

// nameClauseEnd сообщает, что за словом j кончается именная группа: конец
// текста или строки, запятая, точка, скобка — но не дефис составного слова.
func nameClauseEnd(doc *lex.Doc, j int) bool {
	k := j + 1
	if k >= len(doc.Tokens) || lex.HasLineBreak(doc.Gap(j)) {
		return true
	}
	t := doc.Tokens[k]
	if t.Kind != lex.KindPunct || nameHyphenAt(doc, k) {
		return false
	}
	switch doc.Text[t.Start] {
	case ',', '.', ';', ':', '!', '?', ')':
		return true
	}
	return false
}

// nameShortAdjTail сообщает, что слово похоже на краткое прилагательное или
// причастие — «доволен», «согласна», «занят»: после имени оно сказуемое, а
// не фамилия («клиент иван доволен»).
func nameShortAdjTail(w string) bool {
	return strings.HasSuffix(w, "ен") || strings.HasSuffix(w, "ан") || strings.HasSuffix(w, "ян") ||
		strings.HasSuffix(w, "на") || strings.HasSuffix(w, "ны") || strings.HasSuffix(w, "но") ||
		strings.HasSuffix(w, "ат") || strings.HasSuffix(w, "ят")
}

// nameRequisiteAfter сообщает, что за словом j через запятую стоит название
// реквизита из справочника name_requisites: «олег мельник, паспорт …»,
// «анна кузнец, телефон …».
func nameRequisiteAfter(doc *lex.Doc, tb *nameTables, j int) bool {
	p := j + 1
	if p+1 >= len(doc.Tokens) || doc.Tokens[p].Kind != lex.KindPunct || doc.Text[doc.Tokens[p].Start] != ',' {
		return false
	}
	return doc.Tokens[p+1].Kind == lex.KindWord && tb.requisites.Has(doc.NormOf(p+1))
}

// nameLowerSubject решает, делает ли позиция фамилией слово j без суффикса
// справа от имени first в именительном падеже, когда у слова нет
// свидетельства регистра (строчные, капс): «звонил олег мазур, просил
// перезвонить», «полина гринь не получила код», «клиент олег мельник,
// паспорт …», «Держатель карты: СВЕТЛАНА ГОЛУБ».
//
// Одной опоры мало: «клиент иван доволен». Поэтому нужна рамка —
// сказуемое лица сразу за парой при опоре слева или в начале предложения,
// либо конец именной группы при опоре слева или перед реквизитом через
// запятую. Имя в косвенном падеже правило не берёт: «спросите у олега
// пароль», «передайте олегу карту».
func nameLowerSubject(doc *lex.Doc, tb *nameTables, first, j int) bool {
	w := doc.NormOf(j)
	if !tb.given.Has(doc.NormOf(first)) || tb.stop.Has(w) || namePredicateWord(w) || nameIntroWord(w) {
		return false
	}
	if namePredicateAfter(doc, j) {
		return nameBareAnchored(doc, tb, first) || nameSentenceHead(doc, first)
	}
	if !nameClauseEnd(doc, j) || nameShortAdjTail(w) {
		return false
	}
	return nameBareAnchored(doc, tb, first) || nameRequisiteAfter(doc, tb, j)
}

// nameEthnicSurname сообщает, что слово — фамилия с суффиксом, рядом с
// которой слово вне справочника стоит на месте имени, и есть ли у суффикса
// собственное свидетельство (strong): «-швили», «-дзе», «-ян», «-янц»,
// «-зода», «-заде» обычными словами не бывают, а «-ов», «-ин» бывают.
func nameEthnicSurname(w string, runes int) (strong, ok bool) {
	if !nameSurname(w, runes) {
		return false, false
	}
	for _, e := range [...]string{"швили", "дзе", "янц", "ян", "зода", "заде"} {
		if strings.HasSuffix(w, e) {
			return true, true
		}
	}
	for _, e := range [...]string{"ов", "ев", "ин", "ын", "ова", "ева", "ина", "ына"} {
		if strings.HasSuffix(w, e) {
			return false, true
		}
	}
	return false, false
}

// nameGivenPosAgrees проверяет согласование в роде слова w на месте имени с
// фамилией sur на «-ов»/«-ин»: «Шахзод Турсунов», «Толкын Жаксыбекова».
// Женская фамилия на «-ова» совпадает с родительным падежом мужской («Музей
// Пушкина»), поэтому рядом с ней нужно женское имя на «-а»/«-я»; рядом с
// мужской — слово не на «-а»/«-я». У «-швили», «-ян» род не виден, и
// согласование не проверяется.
func nameGivenPosAgrees(w, sur string, strong bool) bool {
	if strong {
		return true
	}
	fem := strings.HasSuffix(w, "а") || strings.HasSuffix(w, "я")
	if strings.HasSuffix(sur, "а") {
		return fem
	}
	return !fem
}

// nameGivenPosWord сообщает, что слово k вне справочника годится на место
// имени рядом с фамилией sur: оба с заглавной (не капсом), у слова нет роли,
// оно проходит отсевы фамилии без суффикса (глаголы, стоп-слова, города,
// месяцы, прилагательные), не адресное слово, не роль и не организация, и
// согласовано с фамилией в роде.
func nameGivenPosWord(doc *lex.Doc, tb *nameTables, k, sur int, left, strong bool) bool {
	// Дешёвые проверки — раньше: их не проходит почти ни одно слово текста.
	w := doc.NormOf(k)
	if !nameTitle(doc.Tokens[k]) || !nameTitle(doc.Tokens[sur]) || !nameGivenPosAgrees(w, doc.NormOf(sur), strong) ||
		nameQuoted(doc, min(k, sur)) || nameClassify(doc, tb.given, tb.markers, k) != 0 {
		return false
	}
	if ok, _ := nameBareSurname(doc, tb, k, -1, left); !ok {
		return false
	}
	return !nameLeadStop(tb, w) && !tb.places.Has(w) && !nameOrgStem(w) && !nameRoleNoun(w) && !nameCountry(tb, w)
}

// nameEthnicConf — уровень пары «имя по позиции + фамилия»: Strong у
// суффикса со своим свидетельством, иначе Weak — пару поднимает маркер,
// слово-ввод или сказуемое, но не банковское предложение.
func nameEthnicConf(strong bool) Confidence {
	if strong {
		return Strong
	}
	return Weak
}

// nameExtendLeftEthnic достраивает одиночную фамилию first — не имя из
// справочника, это проверил вызывающий, — словом k слева на месте имени:
// «Шахзод Турсунов просит увеличить лимит».
func nameExtendLeftEthnic(doc *lex.Doc, tb *nameTables, k, first int) (int, Confidence, string, bool) {
	if !nameTitle(doc.Tokens[k]) || !nameTitle(doc.Tokens[first]) {
		return 0, 0, "", false
	}
	strong, ok := nameEthnicSurname(doc.NormOf(first), nameRunes(doc.Tokens[first]))
	if !ok || !nameGivenPosWord(doc, tb, k, first, true, strong) {
		return 0, 0, "", false
	}
	return k, nameEthnicConf(strong), nameRuleGivenPosSurname, true
}

// nameExtendRightEthnic достраивает одиночную фамилию first — не имя из
// справочника — словом справа на месте имени: «Гелашвили Тамази», «Турсунов
// Шахзод».
func nameExtendRightEthnic(doc *lex.Doc, tb *nameTables, first int) (int, Confidence, string, bool) {
	if !nameTitle(doc.Tokens[first]) {
		return 0, 0, "", false
	}
	j, ok := nameNextPart(doc, first, first)
	if !ok || !nameTitle(doc.Tokens[j]) || doc.IsSentenceBreak(first) {
		return 0, 0, "", false
	}
	strong, ok := nameEthnicSurname(doc.NormOf(first), nameRunes(doc.Tokens[first]))
	if !ok || !nameGivenPosWord(doc, tb, j, first, false, strong) || nameStartsNext(doc, tb, first, j) {
		return 0, 0, "", false
	}
	return j, nameEthnicConf(strong), nameRuleSurnameGivenPos, true
}

// nameGivenPosRule — правила пары, в которой имя принято по позиции рядом с
// фамилией на «-ов»/«-ин»: банковское предложение их не поднимает («Банк
// спонсирует Музей Пушкина»).
func nameGivenPosRule(rule string) bool {
	return rule == nameRuleGivenPosSurname || rule == nameRuleSurnameGivenPos
}

// nameSyllableBase — правила конструкций, которые продолжаются слогом
// восточноазиатского имени: пары и тройки из коротких слов без суффикса.
func nameSyllableBase(rule string) bool {
	switch rule {
	case nameRuleGivenBare, nameRuleBareGiven, nameRuleGivenGiven, nameRuleBareGivenGiven,
		nameRuleGivenBareTitle, nameRuleBareLead, nameRuleBareLeadStart:
		return true
	}
	return false
}

// nameSyllable сообщает, что слово j — слог восточноазиатского имени: с
// заглавной, две-три буквы, не служебное слово и не маркер.
func nameSyllable(doc *lex.Doc, tb *nameTables, j int) bool {
	t := doc.Tokens[j]
	if !nameTitle(t) {
		return false
	}
	n := nameRunes(t)
	if n < nameBareMinLen || n > nameSyllableMax {
		return false
	}
	w := doc.NormOf(j)
	return !nameNotNamePart(tb.markers, w) && !nameLeadStop(tb, w) && !tb.months.Has(w)
}

// nameShortWords сообщает, что все слова конструкции [first, last] не длиннее
// nameSyllableMax+1 букв: «Ким Со», «Пак Мин».
func nameShortWords(doc *lex.Doc, first, last int) bool {
	for k := first; k <= last; k++ {
		if t := doc.Tokens[k]; t.Kind == lex.KindWord && nameRunes(t) > nameSyllableMax+1 {
			return false
		}
	}
	return true
}

// extendSyllables достраивает конструкцию из коротких слов слогами справа:
// «Клиентка Ким Со Ён» — до T-80 последний слог «Ён» уходил открытым.
func (s *nameScan) extendSyllables(c *nameCons) {
	doc := s.doc
	if !nameSyllableBase(c.base) || !nameShortWords(doc, c.first, c.last) {
		return
	}
	for n := 0; n < 2; n++ {
		j, ok := nameNextPart(doc, c.first, c.last)
		if !ok || doc.IsSentenceBreak(c.last) || !nameSyllable(doc, &s.tb, j) {
			return
		}
		c.last = j
	}
}

// nameTurkicParticle — тюркские слова отчества: «Эльчин Гусейн оглы»,
// «Лейла Рашид кызы».
func nameTurkicParticle(w string) bool {
	switch w {
	case "оглы", "огли", "кызы", "гызы", "кизи", "улы", "уулу":
		return true
	}
	return false
}

// nameTurkicTail возвращает конец конструкции с тюркским отчеством: слово
// «оглы» сразу за ней или имя отца и «оглы» — «Мамедов Эльчин Гусейн оглы».
func nameTurkicTail(doc *lex.Doc, last int) int {
	j := last + 1
	if j >= len(doc.Tokens) || doc.IsSentenceBreak(last) || !nameJoinable(doc, last) || !nameEligible(doc, j) {
		return last
	}
	if nameTurkicParticle(doc.NormOf(j)) {
		return j
	}
	k := j + 1
	if k < len(doc.Tokens) && nameTitle(doc.Tokens[j]) && nameJoinable(doc, j) && nameEligible(doc, k) &&
		nameTurkicParticle(doc.NormOf(k)) {
		return k
	}
	return last
}

// nameCSVSep сообщает, что токен p — разделитель поля записи без пробелов
// вокруг: «Лысенко;Ольга;Петровна», «Лысенко,Ольга». Между двумя частями
// имени такой знак — то же, что пробел: запись одна, человек один.
func nameCSVSep(doc *lex.Doc, p int) bool {
	t := doc.Tokens[p]
	if t.Kind != lex.KindPunct || t.Len() != 1 || p == 0 || !doc.Adjacent(p-1) || !doc.Adjacent(p) {
		return false
	}
	switch doc.Text[t.Start] {
	case ';', ',', '|':
		return doc.Tokens[p-1].Kind == lex.KindWord
	}
	return false
}

// nameCSVNext возвращает токен за разделителем записи p или p, если p не
// разделитель.
func nameCSVNext(doc *lex.Doc, p int) int {
	if p+1 < len(doc.Tokens) && nameCSVSep(doc, p) {
		return p + 1
	}
	return p
}

// nameCSVPrev возвращает токен перед разделителем записи слева от first или
// first-1.
func nameCSVPrev(doc *lex.Doc, first int) int {
	k := first - 1
	if k > 0 && nameCSVSep(doc, k) {
		return k - 1
	}
	return k
}
