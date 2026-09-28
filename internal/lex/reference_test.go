package lex

import (
	"math/rand/v2"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Эталонный разбор и сверка с ним.
//
// Быстрый путь нормализации считает регистр и класс символа арифметикой по
// байтам вместо таблиц Unicode. Доказать, что арифметика совпадает с
// таблицами, перечислением случаев нельзя: случаев слишком много, и опасны
// как раз те, о которых не подумали. Поэтому корректность определяется через
// эталон — дословную копию прежнего разбора, — а проверяется сравнением на
// порождённых входах.
//
// Эталон остаётся в тестах навсегда: он и есть определение правильного
// поведения. Менять его можно только вместе с осознанным изменением
// поведения лексера.
//
// T-46 (дефект D-4) — такое изменение: невидимые и комбинируемые символы
// внутри слова его не разрывают, форматирующий символ вне слова — пробел.
// Эталон описывает правило прямо, через таблицы и с аллокациями, без
// запоминания серий и перестановки на месте, которыми пользуется лексер.

// tokenizeReference — разбор через таблицы Unicode, без быстрых путей.
func tokenizeReference(text string) *Doc {
	l := &referenceLexer{text: text, d: &Doc{Text: text}, buf: make([]byte, 0, len(text))}
	for i := 0; i < len(text); {
		i = l.step(i)
	}
	l.closeToken()

	l.d.normBuf = l.buf
	l.d.Norm = string(l.buf)
	l.d.fold = string(l.d.foldBuf)
	return l.d
}

// referenceLexer — состояние эталонного разбора: текущий токен и счётчики
// букв по классам для его признаков.
type referenceLexer struct {
	text string
	d    *Doc
	buf  []byte

	cur      Token
	open     bool
	letters  int
	uppers   int
	cyrillic int
	latin    int
	hidden   int
	// lastUpper — последняя буква текущего слова заглавная.
	lastUpper bool
}

// step разбирает руну в позиции i и возвращает позицию следующей.
func (l *referenceLexer) step(i int) int {
	r, size := utf8.DecodeRuneInString(l.text[i:])
	if r == utf8.RuneError && size == 1 {
		l.closeToken()
		l.buf = append(l.buf, l.text[i])
		l.d.Tokens = append(l.d.Tokens, Token{Start: int32(i), End: int32(i + 1), Kind: KindPunct})
		return i + 1
	}

	kind, isKind := referenceClassify(r)
	if l.absorbInvisible(i, r, size, kind, isKind) {
		return i + size
	}
	l.switchToken(i, kind, isKind)
	if l.open {
		l.extend(i, r, size, kind)
	}

	l.buf = referenceFold(l.buf, l.text[i:i+size], r, size)
	return i + size
}

// absorbInvisible разбирает невидимый символ: внутри слова он входит в
// токен, но не в число букв, а форматирующий символ вне слова — пробел.
// Возвращает false, если символ не невидимый или это комбинируемый знак
// вне слова: такой разбирается как обычный знак.
func (l *referenceLexer) absorbInvisible(i int, r rune, size int, kind Kind, isKind bool) bool {
	if !isKind || kind != KindPunct || !unicode.In(r, unicode.M, unicode.Cf) {
		return false
	}
	mark := unicode.In(r, unicode.M)
	if l.open && l.cur.Kind == KindWord && l.hidden+size <= maxHidden &&
		(mark || referenceGlues(l.text[i:], l.lastUpper)) {
		// Внутри слова: символ входит в токен, но не в число букв.
		l.cur.End = int32(i + size)
		l.cur.Flags |= FlagInvisible
		l.hidden += size
		l.buf = append(l.buf, l.text[i:i+size]...)
		return true
	}
	if !mark {
		// Форматирующий символ вне слова — пробел.
		l.closeToken()
		l.buf = append(l.buf, l.text[i:i+size]...)
		return true
	}
	return false
}

// switchToken закрывает текущий токен на пробеле и на смене категории и
// открывает новый; знак препинания всегда отдельный токен.
func (l *referenceLexer) switchToken(i int, kind Kind, isKind bool) {
	switch {
	case !isKind:
		l.closeToken()
	case !l.open || l.cur.Kind != kind || kind == KindPunct:
		l.closeToken()
		l.cur = Token{Start: int32(i), Kind: kind}
		l.open = true
	}
}

// extend добавляет руну к открытому токену и считает буквы слова.
func (l *referenceLexer) extend(i int, r rune, size int, kind Kind) {
	l.cur.End = int32(i + size)
	if kind != KindWord {
		return
	}
	l.letters++
	l.lastUpper = unicode.IsUpper(r)
	if unicode.IsUpper(r) {
		l.uppers++
		if l.letters == 1 {
			l.cur.Flags |= FlagFirstUpper
		}
	}
	switch {
	case referenceCyrillic(r):
		l.cyrillic++
	case r < utf8.RuneSelf || referenceLatinExt(r):
		l.latin++
	}
}

// closeToken дописывает открытый токен с признаками алфавита и регистра.
func (l *referenceLexer) closeToken() {
	if !l.open {
		return
	}
	if l.cur.Flags&FlagInvisible != 0 {
		l.cur.Hidden = uint16(referenceHide(l.buf[l.cur.Start:l.cur.End], l.text[l.cur.Start:l.cur.End]))
	}
	if l.cur.Kind == KindWord && l.letters > 0 {
		l.cur.Flags |= l.wordFlags()
	}
	l.referenceFoldHomoglyphs()
	l.d.Tokens = append(l.d.Tokens, l.cur)
	l.open = false
	l.letters, l.uppers, l.cyrillic, l.latin, l.hidden = 0, 0, 0, 0, 0
}

// referenceHomoglyphs — латинские буквы-двойники и их кириллическая строчная
// пара (T-80, класс 6).
var referenceHomoglyphs = map[rune]rune{
	'A': 'а', 'a': 'а', 'B': 'в', 'b': 'ь', 'C': 'с', 'c': 'с', 'E': 'е', 'e': 'е',
	'H': 'н', 'h': 'н', 'K': 'к', 'k': 'к', 'M': 'м', 'm': 'м', 'O': 'о', 'o': 'о',
	'P': 'р', 'p': 'р', 'T': 'т', 't': 'т', 'X': 'х', 'x': 'х', 'Y': 'у', 'y': 'у',
}

// referenceFoldHomoglyphs сводит к кириллице слово, в котором кроме кириллицы есть
// только латинские двойники и кириллица в большинстве: руна за руной, через
// таблицу, со строчной кириллической формой из нормы.
func (l *referenceLexer) referenceFoldHomoglyphs() {
	if l.cur.Kind != KindWord || l.cyrillic == 0 || l.latin == 0 || l.cyrillic+l.latin != l.letters ||
		l.cyrillic <= l.latin || l.cur.Flags&FlagInvisible != 0 || l.latin > 7 || len(l.d.folds) >= 8192 {
		return
	}
	var b strings.Builder
	raw := l.text[l.cur.Start:l.cur.End]
	for k, r := range raw {
		if !referenceCyrillic(r) {
			c, ok := referenceHomoglyphs[r]
			if !ok {
				return
			}
			b.WriteRune(c)
			continue
		}
		size := utf8.RuneLen(r)
		b.Write(l.buf[int(l.cur.Start)+k : int(l.cur.Start)+k+size])
	}
	off := len(l.d.foldBuf)
	l.d.foldBuf = append(l.d.foldBuf, b.String()...)
	// Номер формы в старших разрядах Hidden, число латинских букв — в трёх
	// младших.
	l.cur.Flags |= FlagFolded | FlagCyrillic
	l.cur.Hidden = uint16(len(l.d.folds)*8 + b.Len() - len(raw))
	l.d.folds = append(l.d.folds, foldRef{off: int32(off), end: int32(len(l.d.foldBuf))})
}

// wordFlags — признаки слова по счётчикам его букв.
func (l *referenceLexer) wordFlags() Flags {
	var f Flags
	if l.uppers > 0 && l.letters == l.uppers && l.letters > 1 {
		f |= FlagAllUpper
	}
	if l.cyrillic == l.letters {
		f |= FlagCyrillic
	}
	if l.latin == l.letters {
		f |= FlagLatin
	}
	return f
}

// referenceGlues сообщает, что серия невидимых символов в начале s остаётся
// внутри слова: за ней идёт буква, и это не стык строчной и заглавной.
func referenceGlues(s string, lastUpper bool) bool {
	for _, r := range s {
		if !unicode.In(r, unicode.M, unicode.Cf) {
			return unicode.IsLetter(r) && (lastUpper || !unicode.IsUpper(r))
		}
	}
	return false
}

// referenceHide переписывает нормализованную копию слова: сначала невидимые
// символы в порядке появления, затем буквы; «и» с краткой U+0306 сразу за
// ней становится «й». Возвращает длину невидимой части в байтах.
func referenceHide(dst []byte, raw string) int {
	var hidden, letters []byte
	for k, r := range raw {
		size := utf8.RuneLen(r)
		if unicode.In(r, unicode.M, unicode.Cf) {
			hidden = append(hidden, raw[k:k+size]...)
			continue
		}
		next, _ := utf8.DecodeRuneInString(raw[k+size:])
		if (r == 'и' || r == 'И') && next == 0x0306 {
			letters = utf8.AppendRune(letters, 'й')
			continue
		}
		letters = append(letters, dst[k:k+size]...)
	}
	copy(dst, append(hidden, letters...))
	return len(hidden)
}

func referenceFold(dst []byte, raw string, r rune, size int) []byte {
	lower := unicode.ToLower(r)
	if r == 'ё' || r == 'Ё' {
		lower = 'е'
	}
	if lower == r || utf8.RuneLen(lower) != size {
		return append(dst, raw...)
	}
	return utf8.AppendRune(dst, lower)
}

func referenceClassify(r rune) (Kind, bool) {
	switch {
	case r >= '0' && r <= '9':
		return KindDigits, true
	case unicode.IsSpace(r):
		return 0, false
	case unicode.IsLetter(r):
		return KindWord, true
	default:
		return KindPunct, true
	}
}

func referenceCyrillic(r rune) bool {
	return (r >= 0x0400 && r <= 0x04FF) || (r >= 0x0500 && r <= 0x052F)
}

func referenceLatinExt(r rune) bool {
	return (r >= 0x0041 && r <= 0x005A) || (r >= 0x0061 && r <= 0x007A) ||
		(r >= 0x00C0 && r <= 0x024F)
}

// compareWithReference сверяет разбор с эталоном побайтово и потокенно.
func compareWithReference(t *testing.T, text string) {
	t.Helper()
	got := Tokenize(text, nil)
	want := tokenizeReference(text)

	if got.Norm != want.Norm {
		t.Fatalf("Norm разошлась\n вход   %q\n получено %q\n эталон   %q", text, got.Norm, want.Norm)
	}
	if len(got.Norm) != len(got.Text) {
		t.Fatalf("выравнивание нарушено: Norm %d байт, Text %d байт, вход %q",
			len(got.Norm), len(got.Text), text)
	}
	if len(got.Tokens) != len(want.Tokens) {
		t.Fatalf("токенов %d, эталон даёт %d, вход %q", len(got.Tokens), len(want.Tokens), text)
	}
	for i := range got.Tokens {
		if got.Tokens[i] != want.Tokens[i] {
			t.Fatalf("токен %d: получено %+v, эталон %+v, вход %q",
				i, got.Tokens[i], want.Tokens[i], text)
		}
		if got.NormOf(i) != want.NormOf(i) {
			t.Fatalf("токен %d: NormOf %q, эталон %q, вход %q", i, got.NormOf(i), want.NormOf(i), text)
		}
	}
}

// referenceSeeds — входы, на которых быстрый путь ломается охотнее всего.
var referenceSeeds = []string{
	"",
	"Клиент Иванов Иван Иванович",
	"ЁЛКА ёлка Ёлка",
	"Пётр Ильич",
	"IVAN@MAIL.RU",
	"\u0130STANBUL",            // турецкая I: нижний регистр короче на байт
	"\u212a\u2126\u1e9e",       // KELVIN, OHM, заглавная эсцет — свёртка меняет длину
	"ӀӁӂӐӑҊҋ",                  // U+04C0, U+04C1, U+04C2, U+04D0, U+04D1, U+048A, U+048B
	"\u0400\u040f\u045f\u0460", // границы кириллического быстрого пути
	"и\u0306",                  // комбинирующая краткая
	"а\u200bб",                 // нулевая ширина
	"\ufeffтекст",              // метка порядка байтов
	"ΑΒΓ σΣς",                  // греческий, финальная сигма
	"Straße ß",
	"\xED\xA0\x80", // суррогат в CESU-8
	"прив\xD0",     // обрыв на ведущем байте кириллицы
	"\xD0\xFF",     // ведущий байт с некорректным продолжением
	"\xD1\xA0",     // U+0460 — за границей быстрого пути
	"\xD0",
	"\xD1",
	"\xff\xfe",
	"текст \xff\xfe хвост",
	"Дом 5, кв. 12\tтел. +7 916 123-45-67",
	"Клиент Мaзур Олег, Смирнoв, МAЗУР, Mазур", // латинские двойники (T-80)
	"Мaзуr iPhone ivanоv SMSка Кaфé",           // двойник без пары, латиница в большинстве
}

func TestTokenizeMatchesReferenceOnSeeds(t *testing.T) {
	for _, s := range referenceSeeds {
		compareWithReference(t, s)
	}
}

func FuzzTokenizeMatchesReference(f *testing.F) {
	for _, s := range referenceSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		compareWithReference(t, s)
	})
}

// TestTokenizeMatchesReferenceRandom — детерминированный брат фаззера: ловит
// регрессию в обычном прогоне, без включённого фаззинга.
func TestTokenizeMatchesReferenceRandom(t *testing.T) {
	r := rand.New(rand.NewPCG(0x5eed, 0xa11ce))
	var b strings.Builder
	for n := 0; n < 4000; n++ {
		b.Reset()
		switch n % 4 {
		case 0, 1:
			writeWeightedRunes(&b, r, 1+r.IntN(40))
		case 2:
			// Чистый шум: заведомо некорректный UTF-8.
			for k := 1 + r.IntN(24); k > 0; k-- {
				b.WriteByte(byte(r.UintN(256)))
			}
		case 3:
			// Корректный UTF-8, обрезанный в случайной точке.
			writeWeightedRunes(&b, r, 1+r.IntN(20))
			s := b.String()
			if len(s) > 1 {
				b.Reset()
				b.WriteString(s[:1+r.IntN(len(s)-1)])
			}
		}
		compareWithReference(t, b.String())
	}
}

// writeWeightedRunes порождает смесь, в которой каждая ветвь разбора
// встречается достаточно часто, чтобы расхождение всплыло.
func writeWeightedRunes(b *strings.Builder, r *rand.Rand, count int) {
	for ; count > 0; count-- {
		switch w := r.IntN(100); {
		case w < 35: // ASCII
			b.WriteRune(rune(r.IntN(128)))
		case w < 70: // кириллица внутри быстрого пути
			b.WriteRune(rune(0x0400 + r.IntN(0x60)))
		case w < 80: // кириллица за его границей
			b.WriteRune(rune(0x0460 + r.IntN(0xD0)))
		case w < 88: // Latin-1 и расширения
			b.WriteRune(rune(0x00C0 + r.IntN(0x190)))
		case w < 94: // греческий
			b.WriteRune(rune(0x0370 + r.IntN(0x90)))
		case w < 97: // комбинирующие и нулевой ширины
			b.WriteRune([]rune{0x0300, 0x0306, 0x0483, 0x200B, 0x200D, 0xFEFF}[r.IntN(6)])
		case w < 99: // руны, у которых нижний регистр короче
			b.WriteRune([]rune{0x0130, 0x212A, 0x2126, 0x1E9E}[r.IntN(4)])
		default: // за пределами базовой плоскости
			b.WriteRune(rune(0x1F600 + r.IntN(0x40)))
		}
	}
}

// TestCyrillicRangeExhaustive проходит кириллический блок целиком: именно на
// нём быстрый путь и обязан совпасть с таблицами. Диапазон U+04C0–U+04CF
// выделен отдельно не случайно — там таблица CaseRanges меняет чётность, и
// наивная арифметика «чётный код — заглавная» даёт неверный результат.
func TestCyrillicRangeExhaustive(t *testing.T) {
	for cp := rune(0x0400); cp <= 0x052F; cp++ {
		compareWithReference(t, string(cp))
		compareWithReference(t, "а"+string(cp)+"я")
	}
}

// TestASCIIRangeExhaustive — то же для всего ASCII, включая управляющие.
func TestASCIIRangeExhaustive(t *testing.T) {
	for cp := rune(0); cp < 128; cp++ {
		compareWithReference(t, string(cp))
		compareWithReference(t, "a"+string(cp)+"z")
	}
}
