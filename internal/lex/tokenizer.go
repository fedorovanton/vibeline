package lex

import (
	"unicode"
	"unicode/utf8"
)

// tokenizer — состояние одного прохода Tokenize.
//
// Живёт локальной переменной Tokenize и в кучу не уходит: методы получают
// указатель на неё, но нигде его не сохраняют. Раньше то же состояние было
// набором локальных переменных, захваченных замыканием closeToken; поля
// структуры — те же переменные, только с именем владельца.
type tokenizer struct {
	text string
	buf  []byte
	d    *Doc

	cur      Token
	open     bool
	letters  int
	uppers   int
	cyrillic int
	latin    int
	// glueEnd и glueOK — решение для текущей серии невидимых символов:
	// до байта glueEnd серия уже просмотрена, и glueOK говорит, стоит ли
	// за ней буква. Без запоминания каждый символ длинной серии заново
	// просматривал бы её до конца, и разбор стал бы квадратичным.
	glueEnd int
	glueOK  bool
	// hidden — байт невидимых символов в текущем слове.
	hidden int
	// lastUpper — последняя буква текущего слова заглавная.
	lastUpper bool
}

// closeToken завершает открытый токен: выставляет признаки регистра и
// алфавита, собирает невидимые символы в начало нормы и дописывает токен.
func (t *tokenizer) closeToken() {
	if !t.open {
		return
	}
	if t.cur.Kind == KindWord && t.letters > 0 {
		if t.uppers > 0 && t.letters == t.uppers && t.letters > 1 {
			t.cur.Flags |= FlagAllUpper
		}
		if t.cyrillic == t.letters {
			t.cur.Flags |= FlagCyrillic
		}
		if t.latin == t.letters {
			t.cur.Flags |= FlagLatin
		}
	}
	if t.cur.Flags&FlagInvisible != 0 {
		hideInvisible(t.buf, t.text, int(t.cur.Start), int(t.cur.End))
		t.cur.Hidden = uint16(t.hidden)
	}
	if t.foldable() {
		t.fold()
	}
	t.d.Tokens = append(t.d.Tokens, t.cur)
	t.open = false
	t.letters, t.uppers, t.cyrillic, t.latin, t.hidden = 0, 0, 0, 0, 0
}

// openToken закрывает текущий токен и открывает новый рода kind с байта i.
func (t *tokenizer) openToken(i int, kind Kind) {
	t.closeToken()
	t.cur = Token{Start: int32(i), Kind: kind}
	t.open = true
}

// count учитывает руну открытого токена в счётчиках букв. Не буква — ничего
// не меняет.
func (t *tokenizer) count(info runeInfo) {
	if info.kind != KindWord {
		return
	}
	t.letters++
	t.lastUpper = info.upper
	if info.upper {
		t.uppers++
		if t.letters == 1 {
			t.cur.Flags |= FlagFirstUpper
		}
	}
	switch {
	case info.cyr:
		t.cyrillic++
	case info.lat:
		t.latin++
	}
}

// slowRune разбирает руну с байта i вне быстрого пути: нормализует её в buf
// и возвращает её класс. Второе значение истинно, если руна уже разобрана
// целиком — некорректный байт или невидимый символ — и разбор продолжается
// с байта i+info.size.
func (t *tokenizer) slowRune(i int) (runeInfo, bool) {
	r, size := utf8.DecodeRuneInString(t.text[i:])
	if r == utf8.RuneError && size == 1 {
		// Некорректный UTF-8: байт переносится как есть и трактуется
		// как знак.
		t.closeToken()
		t.buf[i] = t.text[i]
		t.d.Tokens = append(t.d.Tokens, Token{Start: int32(i), End: int32(i + 1), Kind: KindPunct})
		return runeInfo{size: 1}, true
	}
	kind, isKind := classify(r)
	info := runeInfo{
		size:   size,
		kind:   kind,
		isKind: isKind,
		upper:  isKind && kind == KindWord && unicode.IsUpper(r),
		cyr:    isCyrillic(r),
	}
	info.lat = !info.cyr && (r < utf8.RuneSelf || isLatinExt(r))
	foldSlow(t.buf[i:i+size], t.text[i:i+size], r, size)

	// Невидимые символы разбираются только здесь: на быстром пути их
	// не бывает, и обычный текст за них не платит ни одной проверкой.
	// Категория смотрится только у знаков, а кавычки «» и прочие
	// руны ниже U+0300 отсекаются в isInvisible сравнением.
	if isKind && kind == KindPunct && isInvisible(r) && t.invisible(i, r, size) {
		return runeInfo{size: size}, true
	}
	return info, false
}

// invisible разбирает невидимый символ r длины size в позиции i. Истина —
// символ разобран: вошёл в слово или сыграл роль пробела. Ложь —
// комбинируемый знак вне слова, он разбирается как обычный знак.
func (t *tokenizer) invisible(i int, r rune, size int) bool {
	mark := unicode.Is(unicode.M, r)
	switch {
	case t.open && t.cur.Kind == KindWord && t.hidden+size <= maxHidden &&
		(mark || (glueAt(t.text, i, &t.glueEnd, &t.glueOK) && !caseBreakAt(t.text, t.glueEnd, t.lastUpper))):
		// Символ продолжает слово: «Ива́нов», «Ива­нов» —
		// один токен. Комбинируемый знак относится к букве перед
		// ним и входит в слово всегда, форматирующий — только
		// внутри слова: «ivanov@example.test‍» заканчивается
		// на «test». Буквой символ не считается и на признаки
		// регистра и алфавита не влияет.
		t.cur.Flags |= FlagInvisible
		t.cur.End = int32(i + size)
		t.hidden += size
		return true
	case !mark:
		// Форматирующий символ вне слова разбирается как пробел.
		t.closeToken()
		return true
	}
	return false
}
