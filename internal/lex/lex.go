// Package lex — однопроходная лексическая разметка входного текста.
//
// Разметка выполняется ровно один раз на запрос; все сканеры детекции работают
// по её результату, а не по сырой строке. Исходный текст не изменяется.
//
// Ключевое свойство: нормализованная копия текста побайтово выровнена с
// оригиналом. Приведение к нижнему регистру и замена «ё» на «е» для кириллицы
// и латиницы не меняют длину в UTF-8, поэтому смещения в Norm и в Text
// совпадают. Для рун, у которых нижний регистр имеет другую длину, байты
// копируются без изменения — выравнивание сохраняется, ценой отсутствия
// нормализации для этих редких случаев.
//
// Невидимые и комбинируемые символы внутри слова его не разрывают: ударение
// U+0301 и другие знаки категории M после буквы, а также форматирующие
// символы категории Cf — мягкий перенос U+00AD, ZWSP U+200B, ZWNJ/ZWJ
// U+200C/U+200D, U+2060, U+FEFF, — если за ними снова идёт буква. Они входят
// в токен, но буквой не считаются. В Norm они собраны в начало токена, и
// NormOf их пропускает — словарь видит «иванов», а спан по Start/End
// накрывает слово целиком вместе с невидимыми символами. Разложенные «й» и
// «ё» (буква и U+0306 или U+0308) в Norm сводятся к «й» и «е». Только у
// таких слов выравнивание Norm и Text держится на границах токена, а не на
// каждом байте внутри него; см. FlagInvisible и Token.Hidden.
//
// Форматирующий символ вне слова — между словами, после последней буквы,
// между цифрами — считается пробелом: он невидим и не должен ни рвать
// цепочку «Иванов\u200b Иван Иванович», ни становиться её частью.
package lex

import (
	"unicode"
	"unicode/utf8"
)

// Kind — категория токена.
type Kind uint8

const (
	// KindWord — непрерывный ряд букв.
	KindWord Kind = iota
	// KindDigits — непрерывный ряд ASCII-цифр.
	KindDigits
	// KindPunct — одиночный знак препинания или символ.
	KindPunct
)

// Flags — признаки токена, вычисленные при разметке.
type Flags uint8

const (
	// FlagFirstUpper — первая буква в верхнем регистре.
	FlagFirstUpper Flags = 1 << iota
	// FlagAllUpper — все буквы в верхнем регистре и их больше одной.
	FlagAllUpper
	// FlagCyrillic — все буквы кириллические.
	FlagCyrillic
	// FlagLatin — все буквы латинские.
	FlagLatin
	// FlagInvisible — внутри слова есть невидимые или комбинируемые символы.
	// В Norm они стоят в начале токена, перед буквами, и занимают
	// Token.Hidden байт; NormOf возвращает слово без них. Прямой срез
	// Norm[Start:End] у такого токена содержит их префиксом — окончания
	// слова при этом не сдвигаются.
	FlagInvisible
	// FlagFolded — в кириллическом слове есть латинские буквы-двойники
	// («Мaзур»), и NormOf отдаёт форму, сведённую к кириллице (см.
	// homoglyph.go). Такое слово помечено и FlagCyrillic; Token.Hidden у
	// него — не невидимые символы, а номер сведённой формы и поправка длины
	// (Token.FoldExtra).
	FlagFolded
)

// Has сообщает, установлены ли все перечисленные признаки.
func (f Flags) Has(m Flags) bool { return f&m == m }

// Token — размеченный фрагмент исходного текста.
//
// Start и End — смещения в байтах в Doc.Text и, что то же самое, в Doc.Norm.
// Пробельные участки токенами не становятся: промежуток между соседними
// токенами восстанавливается как Text[prev.End:next.Start].
type Token struct {
	Start int32
	End   int32
	Kind  Kind
	Flags Flags
	// Hidden — сколько байт в начале Norm[Start:End] занимают невидимые
	// символы слова (FlagInvisible). Поле лежит в выравнивании структуры и
	// её не увеличивает, а NormOf благодаря ему остаётся простым срезом.
	Hidden uint16
}

// maxHidden — предел невидимых символов в одном слове, в байтах: столько
// помещается в Token.Hidden. Слово с десятками килобайт невидимых символов
// бывает только в специально собранном входе; дальше предела символы
// разбираются так же, как вне слова.
const maxHidden = 1<<16 - 1

// Len возвращает длину токена в байтах.
func (t Token) Len() int { return int(t.End - t.Start) }

// Doc — результат разметки одного входного текста.
//
// Doc переиспользуется между запросами через Tokenize: слайсы не
// переаллоцируются, если ёмкости достаточно.
type Doc struct {
	// Text — исходный текст, неизменный.
	Text string
	// Norm — нормализованная копия, побайтово выровненная с Text.
	Norm string
	// Tokens — токены в порядке появления.
	Tokens []Token

	normBuf []byte

	// foldBuf и folds — сведённые к кириллице формы слов с латинскими
	// буквами-двойниками (FlagFolded), fold — строка над foldBuf. Такие
	// слова редки, и буфер обычно пуст.
	foldBuf []byte
	folds   []foldRef
	fold    string
}

// Tokenize размечает text и записывает результат в d.
//
// Возвращаемый Doc владеет своими буферами; ссылки на Doc.Norm и Doc.Tokens
// нельзя сохранять дольше обработки запроса — после возврата Doc в пул они
// будут переиспользованы.
func Tokenize(text string, d *Doc) *Doc {
	if d == nil {
		d = &Doc{}
	}
	d.Text = text
	d.Tokens = d.Tokens[:0]
	d.foldBuf = d.foldBuf[:0]
	d.folds = d.folds[:0]

	// Норма побайтово равна тексту по длине — это и есть инвариант
	// выравнивания, поэтому ёмкость известна заранее и запас не нужен.
	// Буфер заполняется по индексу, а не дописыванием: писать не туда
	// физически некуда, и выравнивание перестаёт держаться на дисциплине.
	if cap(d.normBuf) < len(text) {
		d.normBuf = make([]byte, len(text))
	}
	buf := d.normBuf[:len(text)]

	// Ёмкость под токены задаётся сразу: без неё срез растёт удвоениями и на
	// каждом крупном тексте переезжает десяток раз.
	if cap(d.Tokens) == 0 && len(text) > 0 {
		d.Tokens = make([]Token, 0, len(text)/4+8)
	}

	t := tokenizer{text: text, buf: buf, d: d}
	for i := 0; i < len(text); {
		info, fast := foldFast(text, buf, i)
		done := false
		if !fast {
			info, done = t.slowRune(i)
		}
		if done {
			i += info.size
			continue
		}
		if !info.isKind { // пробельный символ
			t.closeToken()
			i += info.size
			continue
		}
		if !t.open || t.cur.Kind != info.kind || info.kind == KindPunct {
			t.openToken(i, info.kind)
		}
		t.cur.End = int32(i + info.size)
		t.count(info)
		i += info.size
	}
	t.closeToken()

	d.normBuf = buf
	d.Norm = unsafeString(buf)
	d.fold = unsafeString(d.foldBuf)
	return d
}

// glueAt решает, входит ли форматирующий символ в позиции i в слово: да,
// если за серией невидимых символов, которая с него начинается, идёт буква.
//
// Решение запоминается на всю серию (end, ok), поэтому каждый байт серии
// просматривается один раз: вход из буквы и ста тысяч ZWSP разбирается за
// линейное время.
func glueAt(text string, i int, end *int, ok *bool) bool {
	if i < *end {
		return *ok
	}
	j := i
	for j < len(text) {
		r, size := utf8.DecodeRuneInString(text[j:])
		if !isInvisible(r) {
			*end, *ok = j, unicode.IsLetter(r)
			return *ok
		}
		j += size
	}
	*end, *ok = j, false
	return false
}

// caseBreakAt сообщает, что форматирующий символ стоит на стыке двух слов, а
// не внутри одного: строчная буква перед ним и заглавная после —
// «Петрович\ufeffПогода», «Иванов\u200bИван». Внутри слова регистр так не
// меняется, а заглавное слово целиком («ИВА\u00adНОВ») переходом не считается.
// Без этого правила имя и следующее слово склеивались в один токен, и часть
// ФИО оставалась вне спана.
func caseBreakAt(text string, next int, lastUpper bool) bool {
	if lastUpper || next >= len(text) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(text[next:])
	return unicode.IsUpper(r)
}

// hideInvisible переставляет нормализованную копию слова text[start:end]
// так, что невидимые символы идут в начале, а буквы — подряд за ними. Тогда
// NormOf отдаёт буквы одним срезом, без копирования.
//
// Длина слова не меняется, поэтому границы токена в Norm и Text по-прежнему
// совпадают. Перестановка — два линейных прохода внутри буфера, без
// аллокаций: буквы сдвигаются к концу слова обратным проходом (запись никогда
// не обгоняет чтение), затем невидимые символы копируются в освободившееся
// начало из Text — нормализация их не меняет.
//
// Заодно собираются разложенные буквы: «и» с краткой U+0306 даёт «й», «е» с
// диерезисом U+0308 — «е», как и нормализованная «ё». Иначе «Андреи\u0306»
// не нашлось бы в справочнике имён, где записано «андрей».
func hideInvisible(buf []byte, text string, start, end int) {
	w := end
	var mark rune // знак, стоящий сразу за текущей буквой
	for r := end; r > start; {
		c, size := utf8.DecodeLastRuneInString(text[start:r])
		r -= size
		if isInvisible(c) {
			mark = c
			continue
		}
		w -= size
		copy(buf[w:w+size], buf[r:r+size])
		if mark == combBreve && (c == 'и' || c == 'И') {
			utf8.EncodeRune(buf[w:w+size], 'й')
		}
		mark = 0
	}
	p := start
	for r := start; r < end; {
		c, size := utf8.DecodeRuneInString(text[r:end])
		if isInvisible(c) {
			copy(buf[p:p+size], text[r:r+size])
			p += size
		}
		r += size
	}
}

// combBreve — комбинируемая краткая: «и» + U+0306 — разложенная «й».
// Диерезис U+0308 отдельной обработки не требует: «е» + U+0308 — это «ё», а
// её нормализованная форма и есть «е».
const combBreve = 0x0306

// isInvisible сообщает, что руна не рвёт слово: комбинируемый знак
// (категория M — ударение, диакритика в разложенной форме) или форматирующий
// символ (Cf — мягкий перенос, символы нулевой ширины, метка порядка байтов).
// Человек их не видит, а копирование из вёрстки вставляет их внутрь слов.
//
// Ниже U+0300 таких символов ровно один — мягкий перенос, и проверка
// диапазоном избавляет от поиска по таблицам на латинице и в начале
// кириллицы.
func isInvisible(r rune) bool {
	if r < 0x0300 {
		return r == 0x00AD
	}
	return unicode.In(r, unicode.M, unicode.Cf)
}

// foldSlow записывает нормализованное представление руны в dst, сохраняя её
// длину в байтах. Если нижний регистр занимает другое число байт, руна
// копируется без изменения — выравнивание смещений важнее нормализации.
//
// dst обязан быть ровно длины size: именно на этом держится равенство
// len(Norm) == len(Text), из которого следует, что смещения токенов годятся
// как индексы в обеих строках.
func foldSlow(dst []byte, raw string, r rune, size int) {
	lower := toLowerFold(r)
	if lower == r || utf8.RuneLen(lower) != size {
		copy(dst, raw)
		return
	}
	utf8.EncodeRune(dst, lower)
}

// toLowerFold приводит руну к нижнему регистру и сводит «ё» к «е»:
// идентификация не должна зависеть от регистра (ТЗ §3.2.1).
func toLowerFold(r rune) rune {
	switch r {
	case 'ё', 'Ё':
		return 'е'
	}
	return unicode.ToLower(r)
}

func classify(r rune) (Kind, bool) {
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

func isCyrillic(r rune) bool {
	return (r >= 0x0400 && r <= 0x04FF) || (r >= 0x0500 && r <= 0x052F)
}

func isLatinExt(r rune) bool {
	return (r >= 0x0041 && r <= 0x005A) || (r >= 0x0061 && r <= 0x007A) ||
		(r >= 0x00C0 && r <= 0x024F)
}

// Raw возвращает исходный текст токена.
func (d *Doc) Raw(i int) string {
	t := d.Tokens[i]
	return d.Text[t.Start:t.End]
}

// NormOf возвращает нормализованный текст токена.
//
// У слова с латинскими буквами-двойниками (FlagFolded) это форма, сведённая
// к кириллице: «Мaзур» → «мазур». Она лежит в отдельном буфере, и её длина в
// байтах больше длины токена на Token.FoldExtra.
//
// У слова с невидимыми символами (FlagInvisible) они пропускаются: в Norm
// они собраны в начале токена, и результат — срез от первой буквы. Смещение
// хранится в Token.Hidden, поэтому функция — простой срез и встраивается:
// её зовут сканеры на каждом слове.
func (d *Doc) NormOf(i int) string {
	t := d.Tokens[i]
	if t.Flags&FlagFolded != 0 {
		f := d.folds[t.Hidden>>foldExtraBits]
		return d.fold[f.off:f.end]
	}
	return d.Norm[t.Start+int32(t.Hidden) : t.End]
}

// Span возвращает исходный текст от начала токена i до конца токена j
// включительно, вместе с разделителями между ними.
func (d *Doc) Span(i, j int) string {
	return d.Text[d.Tokens[i].Start:d.Tokens[j].End]
}

// Gap возвращает текст между концом токена i и началом токена i+1.
// Для последнего токена возвращается пустая строка.
func (d *Doc) Gap(i int) string {
	if i+1 >= len(d.Tokens) {
		return ""
	}
	return d.Text[d.Tokens[i].End:d.Tokens[i+1].Start]
}

// Adjacent сообщает, что между токенами i и i+1 нет ни одного символа.
func (d *Doc) Adjacent(i int) bool {
	return i+1 < len(d.Tokens) && d.Tokens[i].End == d.Tokens[i+1].Start
}

// SentenceBounds возвращает индексы первого и последнего токена предложения,
// содержащего токен i. Границей считается точка, вопросительный или
// восклицательный знак, а также перевод строки в промежутке между токенами.
func (d *Doc) SentenceBounds(i int) (lo, hi int) {
	lo = i
	for lo > 0 {
		if d.isBreak(lo - 1) {
			break
		}
		lo--
	}
	hi = i
	for hi < len(d.Tokens)-1 {
		if d.isBreak(hi) {
			break
		}
		hi++
	}
	return lo, hi
}

func (d *Doc) isBreak(i int) bool {
	t := d.Tokens[i]
	if t.Kind == KindPunct {
		switch d.Text[t.Start] {
		case '.':
			return !d.innerDot(i) || HasLineBreak(d.Gap(i))
		case '!', '?', ';':
			return true
		}
	}
	return HasLineBreak(d.Gap(i))
}

// innerDot сообщает, что точка i стоит внутри значения, а не в конце
// предложения: между цифрами вплотную («12.03.1985», «1.5») или сразу после
// заглавного инициала («Коваль И.И., 12.03.1985», «А. С. Пушкин»).
//
// Любая точка как граница предложения рвала дату и подпись с инициалами на
// части: подъём по кластеру и контр-правила переставали видеть соседние
// реквизиты — «Подпись: Коваль И.И., 12.03.1985» оставлял дату открытой
// (бизнес-жюри 23.09, раунд 2).
func (d *Doc) innerDot(i int) bool {
	if i == 0 || !d.Adjacent(i-1) {
		return false
	}
	prev := d.Tokens[i-1]
	if prev.Kind == KindDigits {
		return i+1 < len(d.Tokens) && d.Tokens[i+1].Kind == KindDigits && d.Adjacent(i)
	}
	return prev.Kind == KindWord && prev.Flags&FlagFirstUpper != 0 && prev.End-prev.Start <= 4 &&
		utf8.RuneCountInString(d.Text[prev.Start:prev.End]) == 1
}

// HasLineBreak сообщает, что в строке есть перевод строки.
//
// Побайтовый цикл, а не strings.ContainsAny: промежуток между токенами почти
// всегда один пробел, а ContainsAny на таком входе уходит в перебор рун с
// вызовом IndexByte на каждую. Проверка вызывается на каждый промежуток при
// каждом разборе границ предложения, и на профиле это заметная доля. Байты
// перевода строки в многобайтных последовательностях UTF-8 не встречаются,
// поэтому побайтовое сравнение эквивалентно порунному.
func HasLineBreak(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return true
		}
	}
	return false
}

// IsSentenceBreak сообщает, что токен i завершает предложение: это точка,
// вопросительный, восклицательный знак, точка с запятой, либо после токена
// идёт перевод строки.
func (d *Doc) IsSentenceBreak(i int) bool { return d.isBreak(i) }
