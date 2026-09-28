package lex

import "unicode/utf8"

// Латинские буквы-двойники внутри кириллического слова (раунд 5 жюри, Б5-9).
//
// «Мaзур» с латинской «a», «Смирнoв» с латинской «o» выглядят для человека и
// для модели как обычные русские фамилии, но для словаря и морфологии это
// другое слово: ни справочник имён, ни суффиксы фамилии их не узнают, и ФИО
// уходит открытым. Такие буквы попадают в текст при наборе в чужой раскладке
// и при копировании, а в худшем случае — нарочно, чтобы обойти фильтр.
//
// Нормализованная копия Norm побайтово выровнена с Text, а латинская буква
// занимает один байт против двух у кириллической, поэтому заменить её в Norm
// нельзя. Сведённая к кириллице форма слова пишется в отдельный буфер Doc, и
// NormOf отдаёт её вместо среза Norm. Text, Norm и границы токенов не
// меняются: спан по Start/End накрывает исходное слово вместе с латинской
// буквой.
//
// Слово сводится, только если в нём одни кириллические буквы и латинские
// двойники, кириллических больше, чем латинских, и невидимых символов нет.
// «iPhone», «SMS» и «ivanоv» с кириллической «о» под правило не попадают: у
// них нет кириллицы, латиница в большинстве или латинская буква без двойника.

// homoglyphs — кириллическая строчная буква для латинской буквы-двойника
// ASCII, ноль — у буквы двойника нет.
var homoglyphs = [128]rune{
	'A': 'а', 'a': 'а',
	'B': 'в', 'b': 'ь',
	'C': 'с', 'c': 'с',
	'E': 'е', 'e': 'е',
	'H': 'н', 'h': 'н',
	'K': 'к', 'k': 'к',
	'M': 'м', 'm': 'м',
	'O': 'о', 'o': 'о',
	'P': 'р', 'p': 'р',
	'T': 'т', 't': 'т',
	'X': 'х', 'x': 'х',
	'Y': 'у', 'y': 'у',
}

// foldRef — сведённая форма слова: байты [off, end) буфера Doc.fold.
type foldRef struct {
	off, end int32
}

// Token.Hidden сведённого слова хранит номер его формы в Doc.folds и
// поправку длины: Hidden = номер<<foldExtraBits | число латинских букв. Так
// NormOf остаётся срезом без поиска и встраивается, а Token не растёт.
// Слово, в котором латинских букв больше foldExtraMask, и слова сверх
// maxFolds в одном тексте не сводятся: в живом тексте двойников единицы.
const (
	foldExtraBits = 3
	foldExtraMask = 1<<foldExtraBits - 1
	maxFolds      = 1 << (16 - foldExtraBits)
)

// foldable сообщает, что закрываемое слово надо свести к кириллице: в нём
// обе азбуки, других букв нет, кириллица в большинстве, невидимых символов
// нет. Проверка — сравнение счётчиков, и обычное слово за неё не платит.
func (t *tokenizer) foldable() bool {
	return t.cur.Kind == KindWord && t.cyrillic > 0 && t.latin > 0 &&
		t.cyrillic+t.latin == t.letters && t.cyrillic > t.latin &&
		t.cur.Flags&FlagInvisible == 0 && t.latin <= foldExtraMask && len(t.d.folds) < maxFolds
}

// fold пишет сведённую форму текущего слова в буфер Doc и помечает токен.
// Если в слове нашлась латинская буква без двойника, буфер откатывается, и
// слово остаётся как есть.
func (t *tokenizer) fold() {
	d := t.d
	start, end := int(t.cur.Start), int(t.cur.End)
	mark := len(d.foldBuf)
	for i := start; i < end; {
		r, size := homoglyphAt(t.text, i, end)
		if r < 0 {
			d.foldBuf = d.foldBuf[:mark]
			return
		}
		if r > 0 {
			d.foldBuf = utf8.AppendRune(d.foldBuf, r)
		} else {
			d.foldBuf = append(d.foldBuf, t.buf[i:i+size]...)
		}
		i += size
	}
	extra := len(d.foldBuf) - mark - t.cur.Len()
	t.cur.Flags |= FlagFolded | FlagCyrillic
	t.cur.Hidden = uint16(len(d.folds)<<foldExtraBits | extra)
	d.folds = append(d.folds, foldRef{off: int32(mark), end: int32(len(d.foldBuf))})
}

// homoglyphAt разбирает руну слова text[:end] с байта i: кириллическая пара
// латинского двойника, ноль — кириллическая буква (её нормализованные байты
// берутся из Norm), -1 — латинская буква без двойника.
func homoglyphAt(text string, i, end int) (rune, int) {
	if b := text[i]; b < utf8.RuneSelf {
		if r := homoglyphs[b]; r != 0 {
			return r, 1
		}
		return -1, 1
	}
	r, size := utf8.DecodeRuneInString(text[i:end])
	if !isCyrillic(r) {
		return -1, size
	}
	return 0, size
}

// FoldExtra возвращает, на сколько байт сведённая форма слова (NormOf)
// длиннее самого токена: по байту на каждую латинскую букву-двойник. У
// остальных токенов — ноль. Сканеру, который считает буквы кириллического
// слова по длине в байтах, эта поправка возвращает верный счёт.
func (t Token) FoldExtra() int {
	if t.Flags&FlagFolded == 0 {
		return 0
	}
	return int(t.Hidden & foldExtraMask)
}
