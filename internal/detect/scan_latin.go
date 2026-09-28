package detect

import (
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

func init() { Register(latinScanner{}) }

// latinScanner — ФИО латиницей в свободном тексте: «Клиент Ivan Ivanov»,
// «Client Oleg Melnik», «Получатель: IVANOVA ELENA».
//
// Сканер ФИО (scan_name.go) читает только кириллицу, а сканер держателя карты
// (scan_misc.go) — латиницу только рядом с картой или маркером держателя.
// Имя латиницей в обращении, в переводе или в англоязычном письме между ними
// оставалось открытым (замечание жюри 23.09, T-98).
//
// Правило: ряд из двух–четырёх слов латиницей с заглавной буквы (или
// ПРОПИСНЫМИ), в котором хотя бы одно слово — имя из справочника
// latin_given_names, в любом порядке: «Ivan Ivanov», «IVANOVA ELENA».
// Внутри ряда допустимы инициал «I.», составная фамилия через дефис или
// апостроф и строчная частица «van», «de». Уверенность:
//
//   - маркер лица слева («клиент», «перевод от», «Client», «Mr.») — Strong;
//   - транслитерация в скобках сразу за кириллическим ФИО — Strong;
//   - без маркера — Weak: движок поднимает кандидата до маски, только если
//     в том же предложении есть достоверный реквизит (телефон, паспорт,
//     email) — подъём по кластеру, см. promoteByCluster.
//
// Одно имя без фамилии не маскируется. Контр-правила (без маски): фраза из
// справочника брендов и персонажей («Hugo Boss»), объект по имени рядом
// («Victoria Station»), произведение рядом («роман Anna Karenina»), ряд в
// кавычках, латиница, склеенная с email или URL.
//
// Имя держателя карты — зона scan_misc.go: если сканер держателя сам
// накрывает ряд, этот сканер кандидата не регистрирует. Иначе на тех же
// байтах сошлись бы два кандидата одной силы, и тип маски зависел бы от
// порядка типов, а не от смысла.
type latinScanner struct{}

// Name реализует Scanner.
func (latinScanner) Name() string { return "latin" }

// Справочники сканера.
const (
	latinDictGiven   = "latin_given_names"
	latinDictContext = "latin_context"
)

// Метки справочника latin_context. Подробное описание — в самом справочнике.
const (
	latinLabelMarker   = "marker"
	latinLabelTitle    = "title"
	latinLabelWork     = "work"
	latinLabelPlace    = "place"
	latinLabelParticle = "particle"
	latinLabelPhrase   = "phrase"
)

// Имена правил. Константы: Scan не аллоцирует.
const (
	latinRuleMarker   = "latin/marker"
	latinRuleHolder   = "latin/holder"
	latinRuleTranslit = "latin/translit"
	latinRuleForm     = "latin/form"
)

const (
	// latinMaxWords — предел полных слов в ряду. Больше четырёх слов с
	// заглавной подряд — заголовок или название, а не ФИО.
	latinMaxWords = 4
	// latinMinLetters — минимальная длина слова ряда в буквах: «Li», «Wu».
	latinMinLetters = 2
	// latinWindow — сколько слов просматривается в поиске маркера и
	// произведения: «Получатель SWIFT-перевода: IVANOVA ELENA».
	latinWindow = 3
	// latinGapSpaces — предел пробелов между словами ряда.
	latinGapSpaces = 2
)

// latinTables — справочники сканера, прочитанные один раз на запрос.
type latinTables struct {
	given *dict.Table
	ctx   *dict.Table
}

// label возвращает метку слова или фразы в latin_context, пустую — если
// записи нет.
func (tb *latinTables) label(w string) string {
	l, _ := tb.ctx.Get(w)
	return l
}

// latinElem — вид элемента ряда.
type latinElem uint8

const (
	latinNone     latinElem = iota // не элемент: ряд здесь заканчивается
	latinWord                      // слово, не имя из справочника
	latinGiven                     // имя из справочника
	latinInitial                   // инициал с точкой: «I.»
	latinParticle                  // строчная частица: «van», «de»
)

// latinSeg — прочитанный ряд: токены [lo, hi] и его состав.
type latinSeg struct {
	lo, hi int
	words  int // полных слов
	given  int // из них имён из справочника
	// upper — все полные слова набраны ПРОПИСНЫМИ.
	upper bool
	// plain — ряд из одних простых слов: без инициалов, частиц и составных
	// фамилий. Только такой ряд накрывает сканер держателя карты.
	plain bool
}

// Scan реализует Scanner.
func (latinScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	tb := latinTables{given: dicts.Table(latinDictGiven), ctx: dicts.Table(latinDictContext)}
	if tb.given.Len() == 0 {
		return
	}
	var memo miscCardMemo
	for i := 0; i < len(doc.Tokens); {
		if !latinCapWord(doc, i) {
			i++
			continue
		}
		seg := latinReadSeg(doc, &tb, i)
		latinConsider(doc, &tb, &memo, seg, out)
		i = max(seg.hi+1, i+1)
	}
}

// latinCapWord сообщает, что токен i — слово латиницей с заглавной буквы.
func latinCapWord(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	return t.Kind == lex.KindWord && t.Flags.Has(lex.FlagLatin|lex.FlagFirstUpper)
}

// latinReadSeg читает ряд, начатый токеном i. Слова ряда разделены только
// пробелами в пределах строки; частица в ряд входит, только если за ней
// идёт слово.
func latinReadSeg(doc *lex.Doc, tb *latinTables, i int) latinSeg {
	seg := latinSeg{lo: i, hi: -1, upper: true, plain: true}
	for j := i; j < len(doc.Tokens); {
		kind, end := latinElementAt(doc, tb, j)
		if kind == latinNone || (kind == latinParticle && seg.hi < 0) {
			break
		}
		seg.take(doc, kind, j, end)
		if end+1 >= len(doc.Tokens) || !latinSpaced(doc.Gap(end)) {
			break
		}
		j = end + 1
	}
	return seg
}

// latinSpaced сообщает, что промежуток между словами ряда — пробелы без
// перевода строки. Пустой промежуток означает, что слова склеены знаком.
func latinSpaced(gap string) bool {
	return gap != "" && onlySpaces(gap, latinGapSpaces)
}

// take добавляет в ряд элемент вида kind, занимающий токены [j, end].
func (s *latinSeg) take(doc *lex.Doc, kind latinElem, j, end int) {
	if (kind != latinWord && kind != latinGiven) || end != j {
		s.plain = false
	}
	if kind == latinParticle {
		return
	}
	s.hi = end
	if kind == latinInitial {
		return
	}
	s.words++
	if kind == latinGiven {
		s.given++
	}
	if !doc.Tokens[j].Flags.Has(lex.FlagAllUpper) {
		s.upper = false
	}
}

// latinElementAt определяет вид элемента ряда, начатого токеном i, и
// возвращает его последний токен.
//
// Слово с меткой latin_context (маркер, обращение, служебное слово, объект)
// элементом не является: «Client Ivan Petrov» — ряд «Ivan Petrov».
func latinElementAt(doc *lex.Doc, tb *latinTables, i int) (latinElem, int) {
	t := doc.Tokens[i]
	if t.Kind != lex.KindWord || !t.Flags.Has(lex.FlagLatin) {
		return latinNone, i
	}
	w := doc.NormOf(i)
	label := tb.label(w)
	switch {
	case label == latinLabelParticle:
		return latinParticle, i
	case !t.Flags.Has(lex.FlagFirstUpper):
		return latinNone, i
	case latinIsInitial(doc, i):
		return latinInitial, i + 1
	case label != "":
		return latinNone, i
	}
	end := latinCompoundEnd(doc, i)
	if end == i && utf8.RuneCountInString(w) < latinMinLetters {
		return latinNone, i
	}
	if tb.given.Has(w) {
		return latinGiven, end
	}
	return latinWord, end
}

// latinIsInitial сообщает, что токен i — инициал: одна заглавная буква и
// точка вплотную.
func latinIsInitial(doc *lex.Doc, i int) bool {
	if utf8.RuneCountInString(doc.NormOf(i)) != 1 || !doc.Adjacent(i) {
		return false
	}
	t := doc.Tokens[i+1]
	return t.Kind == lex.KindPunct && doc.Text[t.Start] == '.'
}

// latinCompoundEnd возвращает последний токен составного слова, начатого
// токеном i: «Smith-Jones», «O'Brien». Для простого слова — сам i.
func latinCompoundEnd(doc *lex.Doc, i int) int {
	j := i
	for j+2 < len(doc.Tokens) && doc.Adjacent(j) && doc.Adjacent(j+1) &&
		latinJoiner(doc.Raw(j+1)) && latinCapWord(doc, j+2) {
		j += 2
	}
	return j
}

// latinJoiner сообщает, что знак соединяет части составной фамилии.
func latinJoiner(s string) bool {
	return s == "-" || s == "'" || s == "’"
}

// latinConsider решает судьбу ряда и регистрирует кандидата.
func latinConsider(doc *lex.Doc, tb *latinTables, memo *miscCardMemo, seg latinSeg, out *Candidates) {
	if seg.given == 0 || seg.words < 2 || seg.words > latinMaxWords {
		return
	}
	// Контр-правила действуют и при маркере лица: «made by Hugo Boss»,
	// «клиент читает роман Anna Karenina».
	if latinGlued(doc, tb, seg) || latinPhrase(doc, tb, seg) || latinNearPlace(doc, tb, seg) ||
		latinNearWork(doc, tb, seg) {
		return
	}
	conf, rule, ok := latinJudge(doc, tb, memo, seg)
	if !ok {
		return
	}
	out.Add(int(doc.Tokens[seg.lo].Start), int(doc.Tokens[seg.hi].End), pii.FullName, conf, rule)
}

// latinJudge выбирает уверенность кандидата по контексту ряда. Третье
// значение ложно, если кандидата регистрировать не нужно.
func latinJudge(doc *lex.Doc, tb *latinTables, memo *miscCardMemo, seg latinSeg) (Confidence, string, bool) {
	holder := latinHolderContext(doc, memo, seg)
	switch {
	case holder && seg.plain && seg.words <= miscHolderMaxWords:
		// Ряд накрывает сканер держателя карты — его зона.
		return Denied, "", false
	case holder:
		// Маркер держателя есть, но ряд сканеру держателя не по форме:
		// «Имя: Ivan I. Petrov». Маркер держателя — тоже маркер лица.
		return Strong, latinRuleHolder, true
	case latinLeftHas(doc, tb, seg.lo, latinLabelMarker, latinLabelTitle):
		return Strong, latinRuleMarker, true
	case latinTranslitParen(doc, seg):
		return Strong, latinRuleTranslit, true
	case seg.upper, seg.given == seg.words, latinQuoted(doc, seg):
		// ПРОПИСНЫЕ без маркера — форма имени на карте, их решает сканер
		// держателя; два имени без фамилии — не ФИО; ряд в кавычках —
		// название.
		return Denied, "", false
	}
	return Weak, latinRuleForm, true
}

// latinHolderContext сообщает, что ряд стоит там, где его ищет сканер
// держателя карты: за маркером держателя, а ПРОПИСНЫЕ — ещё и в
// предложении с номером карты.
func latinHolderContext(doc *lex.Doc, memo *miscCardMemo, seg latinSeg) bool {
	if miscHolderMarkerBefore(doc, seg.lo) {
		return true
	}
	return seg.upper && memo.nearby(doc, seg.lo)
}

// latinLeftHas ищет слева от токена lo, в пределах предложения и строки,
// слово с меткой a или b.
//
// Точка после обращения предложение не завершает: «Mr. Oleg Melnik».
func latinLeftHas(doc *lex.Doc, tb *latinTables, lo int, a, b string) bool {
	seen := 0
	for k := lo - 1; k >= 0 && seen < latinWindow; k-- {
		if hasLineBreak(doc.Gap(k)) {
			return false
		}
		t := doc.Tokens[k]
		if t.Kind == lex.KindPunct {
			if doc.IsSentenceBreak(k) && !latinTitleDot(doc, tb, k) {
				return false
			}
			continue
		}
		seen++
		if l := tb.label(doc.NormOf(k)); l == a || l == b {
			return true
		}
	}
	return false
}

// latinRightHas ищет справа от токена hi, в пределах предложения и строки,
// слово с меткой want.
func latinRightHas(doc *lex.Doc, tb *latinTables, hi int, want string) bool {
	seen := 0
	for k := hi + 1; k < len(doc.Tokens) && seen < latinWindow; k++ {
		if hasLineBreak(doc.Gap(k - 1)) {
			return false
		}
		if doc.Tokens[k].Kind == lex.KindPunct {
			if doc.IsSentenceBreak(k) {
				return false
			}
			continue
		}
		seen++
		if tb.label(doc.NormOf(k)) == want {
			return true
		}
	}
	return false
}

// latinTitleDot сообщает, что знак k — точка сразу после обращения.
func latinTitleDot(doc *lex.Doc, tb *latinTables, k int) bool {
	return doc.Text[doc.Tokens[k].Start] == '.' && k > 0 && doc.Adjacent(k-1) &&
		doc.Tokens[k-1].Kind == lex.KindWord && tb.label(doc.NormOf(k-1)) == latinLabelTitle
}

// latinNearWork — контр-правило произведения: «роман Anna Karenina»,
// «Anna Karenina is a novel». Имя рядом со словом-произведением — название.
func latinNearWork(doc *lex.Doc, tb *latinTables, seg latinSeg) bool {
	return latinLeftHas(doc, tb, seg.lo, latinLabelWork, latinLabelWork) ||
		latinRightHas(doc, tb, seg.hi, latinLabelWork)
}

// latinNearPlace — контр-правило объекта: ряд вплотную к слову «Street»,
// «Station», «Hotel» — название места или организации: «Victoria Station»,
// «Ivan Petrov Street».
func latinNearPlace(doc *lex.Doc, tb *latinTables, seg latinSeg) bool {
	if seg.hi+1 < len(doc.Tokens) && latinSpaced(doc.Gap(seg.hi)) && latinPlaceWord(doc, tb, seg.hi+1) {
		return true
	}
	return seg.lo > 0 && latinSpaced(doc.Gap(seg.lo-1)) && latinPlaceWord(doc, tb, seg.lo-1)
}

// latinPlaceWord сообщает, что токен k — слово латиницей с меткой place.
func latinPlaceWord(doc *lex.Doc, tb *latinTables, k int) bool {
	t := doc.Tokens[k]
	return t.Kind == lex.KindWord && t.Flags.Has(lex.FlagLatin) && tb.label(doc.NormOf(k)) == latinLabelPlace
}

// latinGlued сообщает, что ряд склеен с соседним токеном без пробела: это
// часть email, URL или идентификатора — «Anna.Schmidt@Example.com». Такую
// латиницу разбирает сканер email, а не сканер ФИО.
func latinGlued(doc *lex.Doc, tb *latinTables, seg latinSeg) bool {
	if seg.lo > 0 && doc.Adjacent(seg.lo-1) && latinGlueBefore(doc, tb, seg.lo-1) {
		return true
	}
	return seg.hi+1 < len(doc.Tokens) && doc.Adjacent(seg.hi) && latinGlueAfter(doc, seg.hi+1)
}

// latinGlueBefore сообщает, что токен k, стоящий вплотную перед рядом,
// приклеивает ряд к адресу: слово, число или знак адреса. Точка после
// обращения не приклеивает: «Mr.Oleg Melnik».
func latinGlueBefore(doc *lex.Doc, tb *latinTables, k int) bool {
	t := doc.Tokens[k]
	if t.Kind != lex.KindPunct {
		return true
	}
	c := doc.Text[t.Start]
	if c == '.' {
		return !latinTitleDot(doc, tb, k)
	}
	return latinAddressPunct(c)
}

// latinGlueAfter сообщает, что токен k, стоящий вплотную за рядом,
// приклеивает ряд к адресу. Точка приклеивает, только если за ней вплотную
// продолжается домен: «Ivan.Petrov.com», но не «… Ivan Petrov.».
func latinGlueAfter(doc *lex.Doc, k int) bool {
	t := doc.Tokens[k]
	if t.Kind != lex.KindPunct {
		return true
	}
	c := doc.Text[t.Start]
	if c == '.' {
		return k+1 < len(doc.Tokens) && doc.Adjacent(k) && doc.Tokens[k+1].Kind != lex.KindPunct
	}
	return latinAddressPunct(c)
}

// latinAddressPunct сообщает, что знак бывает внутри email, URL или
// идентификатора.
func latinAddressPunct(c byte) bool {
	switch c {
	case '@', '_', '/', '\\', '#', '=', '&', '%', '+', '~':
		return true
	}
	return false
}

// latinTranslitParen сообщает, что ряд — транслитерация в скобках сразу за
// кириллическим словом с заглавной: «Шульце Томасом (Thomas Schulze)».
func latinTranslitParen(doc *lex.Doc, seg latinSeg) bool {
	if seg.lo < 2 || seg.hi+1 >= len(doc.Tokens) || doc.Raw(seg.lo-1) != "(" || doc.Raw(seg.hi+1) != ")" {
		return false
	}
	t := doc.Tokens[seg.lo-2]
	return t.Kind == lex.KindWord && t.Flags.Has(lex.FlagCyrillic|lex.FlagFirstUpper)
}

// latinQuoted сообщает, что ряд стоит в кавычках вплотную: «"Anna Karenina"».
func latinQuoted(doc *lex.Doc, seg latinSeg) bool {
	return seg.lo > 0 && seg.hi+1 < len(doc.Tokens) && doc.Adjacent(seg.lo-1) && doc.Adjacent(seg.hi) &&
		latinQuote(doc.Raw(seg.lo-1)) && latinQuote(doc.Raw(seg.hi+1))
}

// latinQuote сообщает, что знак — кавычка.
func latinQuote(s string) bool {
	switch s {
	case "\"", "«", "»", "“", "”", "„":
		return true
	}
	return false
}

// latinPhrase сообщает, что ряд или его начало — фраза из справочника
// брендов и персонажей: «Hugo Boss», «Calvin Klein Jeans».
//
// Сравнение идёт срезом Doc.Norm: нормализованная копия выровнена с
// исходником, и многословная запись проверяется без сборки строки.
func latinPhrase(doc *lex.Doc, tb *latinTables, seg latinSeg) bool {
	start := doc.Tokens[seg.lo].Start
	for k := seg.lo + 1; k <= seg.hi; k++ {
		if tb.label(doc.Norm[start:doc.Tokens[k].End]) == latinLabelPhrase {
			return true
		}
	}
	return false
}
