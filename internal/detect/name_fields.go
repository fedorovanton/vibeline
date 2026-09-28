package detect

import (
	"strings"
	"unicode/utf8"

	"ai-gateway/internal/lex"
)

// nameFieldSlot сообщает, что слово i стоит на месте значения поля анкеты,
// и возвращает поле и признак разделителя между маркером и значением.
//
// Разбор идёт справа налево на ограниченное число токенов: знаки поля
// («:», тире, кавычки, косая черта), затем до трёх уточняющих слов, затем
// маркер поля. Перевод строки допустим один раз — между меткой поля,
// стоящей в начале строки, и значением: «Фамилия⏎Черныш». Две конструкции
// смены фамилии разбираются отдельно: «фамилию с Корнеевой на Шаповалову» и
// «фамилию: была Коваленко, стала Шульга».
func nameFieldSlot(doc *lex.Doc, tb *nameTables, i int) (nameFieldKind, bool, bool) {
	return nameFieldSlotAt(doc, tb, i, nameFieldCarryDepth)
}

// nameFieldCarryDepth — сколько раз значение поля может опереться на
// значение слева через запятую или стрелку: «Фамилия до брака — Литвин,
// после брака — Мазур», «Смена фамилии: Литвин → Лемеш» (T-80). Предел
// держит разбор линейным.
const nameFieldCarryDepth = 2

// nameFieldSlotAt — nameFieldSlot с пределом опор на значение слева.
func nameFieldSlotAt(doc *lex.Doc, tb *nameTables, i, depth int) (nameFieldKind, bool, bool) {
	k, sep, newline, ok := nameFieldPunctLeft(doc, i)
	if !ok || k < 0 || doc.Tokens[k].Kind != lex.KindWord {
		return 0, false, false
	}
	if newline, ok = nameFieldLineBreak(doc, k, newline); !ok {
		return 0, false, false
	}
	if sep && nameFIOAbbrevEnd(doc, k) {
		return nameFieldFIO, true, true
	}
	w := doc.NormOf(k)
	if kind := nameFieldWord(w); kind != nameFieldNone {
		return nameFieldLabel(doc, k, kind, sep, newline)
	}
	// «surname=Лысенко», «first_name: Ольга» (T-83, P5-4).
	if kind := nameFieldLatinAt(doc, k); kind != nameFieldNone {
		return nameFieldLabel(doc, k, kind, sep, newline)
	}
	if newline {
		return 0, false, false
	}
	if sep && nameFieldEllipsis(w) {
		return nameFieldSurname, true, true
	}
	switch w {
	case "на", "с", "со", nameWordBecameFem, nameWordBecame, wordNow, wordWasFem, wordWas:
		return nameFieldChangeWord(doc, tb, k, w)
	}
	return nameFieldQualified(doc, tb, i, k, depth, sep)
}

// nameFieldLatinAt возвращает поле, которое называет латинская метка k:
// «surname», «patronymic», «last_name», «first-name». Одиночное «name» —
// имя; «name» после другого слова через подчёркивание — по этому слову, а
// незнакомое («file_name», «user_name») полем ФИО не считается.
func nameFieldLatinAt(doc *lex.Doc, k int) nameFieldKind {
	if !doc.Tokens[k].Flags.Has(lex.FlagLatin) {
		return nameFieldNone
	}
	switch doc.NormOf(k) {
	case "surname", "lastname", "familyname":
		return nameFieldSurname
	case "firstname", "givenname", "forename":
		return nameFieldGiven
	case "patronymic", "middlename":
		return nameFieldPatronymic
	case "fio", "fullname":
		return nameFieldFIO
	case "name":
		return nameFieldLatinName(doc, k)
	}
	return nameFieldNone
}

// nameFieldLatinName разбирает метку «name» с приставкой через подчёркивание
// или дефис: «last_name», «first-name», «full_name».
func nameFieldLatinName(doc *lex.Doc, k int) nameFieldKind {
	if k < 2 || !doc.Adjacent(k-1) || !doc.Adjacent(k-2) || doc.Tokens[k-1].Kind != lex.KindPunct {
		return nameFieldGiven
	}
	if c := doc.Text[doc.Tokens[k-1].Start]; c != '_' && c != '-' {
		return nameFieldGiven
	}
	switch doc.NormOf(k - 2) {
	case "last", "family", "sur":
		return nameFieldSurname
	case "first", "given":
		return nameFieldGiven
	case "middle":
		return nameFieldPatronymic
	case "full":
		return nameFieldFIO
	}
	return nameFieldNone
}

// nameFieldPunctLeft пропускает знаки поля непосредственно слева от
// значения i и возвращает первый токен перед ними, признак разделителя и
// признак перевода строки. ok = false — знак недопустим или перевод строки
// встретился второй раз.
func nameFieldPunctLeft(doc *lex.Doc, i int) (k int, sep, newline, ok bool) {
	k = i - 1
	for ; k >= 0 && doc.Tokens[k].Kind == lex.KindPunct; k-- {
		s, ok := nameFieldPunct(doc, k)
		if !ok {
			return k, false, false, false
		}
		sep = sep || s
		if newline, ok = nameFieldLineBreak(doc, k, newline); !ok {
			return k, false, false, false
		}
	}
	return k, sep, newline, true
}

// nameFieldLineBreak учитывает перевод строки за токеном k: возвращает
// новый признак перевода строки и false, если перевод строки уже был.
func nameFieldLineBreak(doc *lex.Doc, k int, newline bool) (bool, bool) {
	if !lex.HasLineBreak(doc.Gap(k)) {
		return newline, true
	}
	return true, !newline
}

// nameFieldLabel принимает метку поля kind в токене k. Метка поля на
// отдельной строке: «Фамилия⏎Черныш», «Имя:⏎Денис». Перевод строки после
// метки в такой форме и есть разделитель.
func nameFieldLabel(doc *lex.Doc, k int, kind nameFieldKind, sep, newline bool) (nameFieldKind, bool, bool) {
	if !newline {
		return kind, sep, true
	}
	if !nameLineStart(doc, k) {
		return 0, false, false
	}
	return kind, true, true
}

// nameFieldChangeWord разбирает оборот смены фамилии, в котором слово k (w)
// стоит вплотную перед значением: «на», «с», «стала», «была».
func nameFieldChangeWord(doc *lex.Doc, tb *nameTables, k int, w string) (nameFieldKind, bool, bool) {
	switch w {
	case "на":
		return nameFieldChangeTo(doc, k)
	case "с", "со":
		if nameFieldSurnameBefore(doc, k) {
			return nameFieldChange, false, true
		}
	case nameWordBecameFem, nameWordBecame, wordNow:
		return nameFieldChangeBecame(doc, tb, k)
	case wordWasFem, wordWas:
		return nameFieldAfterWas(doc, tb, k)
	}
	return 0, false, false
}

// nameFieldChangeTo разбирает «сменил фамилию на Грин» и «сменил фамилию с
// Корнеевой на Шаповалову»: слева от «на» (k) — маркер поля или прежнее
// значение, а перед ним «с» и маркер поля.
func nameFieldChangeTo(doc *lex.Doc, k int) (nameFieldKind, bool, bool) {
	x, ok := namePrevWord(doc, k)
	if !ok {
		return 0, false, false
	}
	if nameFieldWord(doc.NormOf(x)) == nameFieldSurname {
		return nameFieldChange, false, true
	}
	c, ok := namePrevWord(doc, x)
	if !ok || (doc.NormOf(c) != "с" && doc.NormOf(c) != "со") {
		return 0, false, false
	}
	if nameFieldSurnameBefore(doc, c) {
		return nameFieldChange, false, true
	}
	return 0, false, false
}

// nameFieldChangeBecame разбирает «фамилию: была Коваленко, стала Шульга»:
// новое значение после прежнего; маркер поля ищется перед «была».
func nameFieldChangeBecame(doc *lex.Doc, tb *nameTables, k int) (nameFieldKind, bool, bool) {
	for p, n := k, 0; n < 4; n++ {
		q, ok := namePrevWord(doc, p)
		if !ok {
			return 0, false, false
		}
		if v := doc.NormOf(q); v == wordWasFem || v == wordWas {
			if kind, sep, ok := nameFieldAfterWas(doc, tb, q); ok {
				return kind, sep, ok
			}
			// «Была Дорош, стала Гринь»: без маркера поля оборот держат оба
			// значения с заглавной (T-80, класс 4).
			if nameFieldWasValue(doc, tb, q+1) {
				return nameFieldChange, false, true
			}
			return 0, false, false
		}
		p = q
	}
	return 0, false, false
}

// nameFieldAfterWas разбирает «фамилию: была Коваленко»: слева от «была»
// через знаки поля стоит маркер фамилии. Без маркера значение принимается,
// если за ним идёт вторая половина оборота: «Была Дорош, стала Гринь».
func nameFieldAfterWas(doc *lex.Doc, tb *nameTables, was int) (nameFieldKind, bool, bool) {
	if nameFieldSurnameBefore(doc, was) {
		return nameFieldChange, false, true
	}
	v := was + 1
	if v+3 < len(doc.Tokens) && nameFieldWasValue(doc, tb, v) && doc.Tokens[v+1].Kind == lex.KindPunct &&
		doc.Text[doc.Tokens[v+1].Start] == ',' && doc.Tokens[v+2].Kind == lex.KindWord &&
		nameFieldBecameWord(doc.NormOf(v+2)) && nameFieldWasValue(doc, tb, v+3) {
		return nameFieldChange, false, true
	}
	return 0, false, false
}

// nameFieldBecameWord — вторая половина оборота «была X, стала Y».
func nameFieldBecameWord(w string) bool {
	return w == nameWordBecameFem || w == nameWordBecame || w == wordNow
}

// nameFieldWasValue сообщает, что слово v годится значением оборота «была X,
// стала Y» без маркера поля: слово с заглавной, не город, не месяц и не
// государство — «Была Москва, стала Казань» фамилий не содержит.
func nameFieldWasValue(doc *lex.Doc, tb *nameTables, v int) bool {
	if v >= len(doc.Tokens) || !nameEligible(doc, v) || !nameTitle(doc.Tokens[v]) {
		return false
	}
	w := doc.NormOf(v)
	_, city := nameLookupGiven(tb.cities, w)
	return !city && !tb.months.Has(w) && !nameCountry(tb, w)
}

// nameFieldSurnameBefore сообщает, что слово перед k — маркер поля фамилии,
// в том числе через глагол смены: «Фамилия изменена с Мороз на Прус» (T-80).
func nameFieldSurnameBefore(doc *lex.Doc, k int) bool {
	f, ok := namePrevWord(doc, k)
	if !ok {
		return false
	}
	w := doc.NormOf(f)
	if nameFieldWord(w) == nameFieldSurname {
		return true
	}
	if !nameChangeVerb(w) {
		return false
	}
	g, ok := namePrevWord(doc, f)
	return ok && nameFieldWord(doc.NormOf(g)) == nameFieldSurname
}

// nameChangeVerb — глагол или причастие смены: «изменена», «сменила»,
// «поменял».
func nameChangeVerb(w string) bool {
	return strings.HasPrefix(w, "измен") || strings.HasPrefix(w, "смен") || strings.HasPrefix(w, "помен") ||
		strings.HasPrefix(w, "перемен")
}

// nameFieldQualified разбирает уточняющие слова между маркером поля и
// значением i: слово k и до nameFieldQualMax слов слева от него. Если цепочку
// прерывает слово, за которым стоит запятая или стрелка, и это слово само
// значение поля, значение i — второе в паре: «Фамилия до брака — Литвин,
// после брака — Мазур», «Литвин → Лемеш» (nameFieldCarry).
func nameFieldQualified(doc *lex.Doc, tb *nameTables, i, k, depth int, sep bool) (nameFieldKind, bool, bool) {
	w := doc.NormOf(k)
	for q := 0; q < nameFieldQualMax; q++ {
		if kind := nameFieldWord(w); kind != nameFieldNone {
			return kind, sep, true
		}
		if !nameFieldQualifier(tb.markers, w) {
			return nameFieldCarry(doc, tb, k, depth, sep)
		}
		p, ok := namePrevWord(doc, k)
		if !ok || p < i-nameFieldReach {
			return 0, false, false
		}
		k, w = p, doc.NormOf(p)
	}
	if kind := nameFieldWord(w); kind != nameFieldNone {
		return kind, sep, true
	}
	return 0, false, false
}

// nameFieldCarry принимает поле значения слева: слово p — значение поля, и
// за ним стоит запятая или стрелка.
func nameFieldCarry(doc *lex.Doc, tb *nameTables, p, depth int, sep bool) (nameFieldKind, bool, bool) {
	if depth == 0 || p+1 >= len(doc.Tokens) || doc.Tokens[p+1].Kind != lex.KindPunct {
		return 0, false, false
	}
	if r, _ := utf8.DecodeRuneInString(doc.Text[doc.Tokens[p+1].Start:]); r != ',' && r != '→' {
		return 0, false, false
	}
	kind, psep, ok := nameFieldSlotAt(doc, tb, p, depth-1)
	if !ok || !nameFieldValue(doc, tb, p, kind, psep) {
		return 0, false, false
	}
	return kind, sep, true
}

// nameFieldFeat — признаки слова-кандидата на значение поля анкеты.
type nameFieldFeat struct {
	sep, upper, surname, patronymic, given bool
	// plain — не глагол и не наречие и, если слово строчное, не
	// прилагательное.
	plain bool
	// adj — окончание прилагательного при длине от nameBareAdjMinLen.
	adj bool
	// city — город из справочника: «name=Москва» — не имя (T-83, P5-4).
	city bool
}

// nameFieldValue решает, годится ли слово i значением поля kind.
//
// Поле — сильное свидетельство, но не безусловное: «Фамилия не указана»,
// «Подпись: Отсутствует», «Укажите фамилию полностью» значения не содержат.
// Поэтому стоп-слова, глаголы и наречия отсеиваются всегда, кроме слов с
// морфологией фамилии или отчества. Без разделителя поля слово принимается
// только с заглавной буквы или с морфологией: «Моя фамилия Заяц», но не
// «фамилия указана неверно». Подпись — не фамилия, если это
// прилагательное: «Подпись: Электронная».
func nameFieldValue(doc *lex.Doc, tb *nameTables, i int, kind nameFieldKind, sep bool) bool {
	if !nameEligible(doc, i) {
		return false
	}
	t := doc.Tokens[i]
	runes := nameRunes(t)
	if runes < nameBareMinLen || runes > nameBareMaxLen {
		return false
	}
	w := doc.NormOf(i)
	if nameFieldValueStop(tb, w) {
		return false
	}
	f := nameFieldFeat{
		sep:        sep,
		upper:      t.Flags.Has(lex.FlagFirstUpper),
		surname:    nameSurname(w, runes),
		patronymic: namePatronymic(tb.given, w, runes),
		adj:        runes >= nameBareAdjMinLen && nameBareAdjEnding(w),
	}
	_, f.given = nameLookupGiven(tb.given, w)
	f.plain = !nameBareVerbLike(w) && (!f.adj || f.upper)
	if kind == nameFieldGiven && !f.given {
		_, f.city = nameLookupGiven(tb.cities, w)
	}
	return f.accepts(kind)
}

// nameFieldValueStop сообщает, что слово значением поля не бывает: маркер,
// метка поля, стоп-слово.
func nameFieldValueStop(tb *nameTables, w string) bool {
	return nameNotNamePart(tb.markers, w) || nameFieldWord(w) != nameFieldNone ||
		nameBareStopWord(w) || tb.stop.Has(w) || nameFieldEllipsis(w)
}

// accepts решает по признакам слова, годится ли оно значением поля kind.
func (f nameFieldFeat) accepts(kind nameFieldKind) bool {
	switch kind {
	case nameFieldGiven:
		// Без разделителя имя поднимает маркер «имя» (name_markers): здесь
		// только значение после «Имя:», в том числе вне справочника.
		return f.sep && (f.given || (f.upper && f.plain && !f.city))
	case nameFieldPatronymic:
		return f.patronymic || (f.sep && f.upper && f.plain)
	case nameFieldChange:
		return f.upper && (f.surname || f.plain)
	case nameFieldSign:
		return !f.adj && (f.sep || f.upper) && (f.surname || f.plain)
	default:
		return f.anyValue()
	}
}

// anyValue — значение поля фамилии или ФИО.
func (f nameFieldFeat) anyValue() bool {
	if f.sep {
		return f.surname || f.patronymic || f.plain
	}
	return f.surname || (f.upper && (f.plain || f.given))
}
