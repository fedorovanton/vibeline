package detect

import (
	"strings"
	"unicode/utf8"

	"ai-gateway/internal/lex"
)

// Маркеры цифрового сканера, которые не укладываются в таблицу digitsMarkers:
// опечатки в слове «паспорт», сокращение «уд.» после «вод.», «выдан» справа
// от номера. Все проверки работают по срезам нормализованного текста и не
// аллоцируют.

// digitsPassportWord — слово, опечатки в котором распознаёт
// digitsPassportTypo.
const digitsPassportWord = "паспорт"

// digitsPassportEndings — окончания словоформ «паспорта», «паспорту»,
// «паспорте», «паспортом»: опечатка ищется в основе без окончания.
var digitsPassportEndings = [...]string{"а", "у", "е", "ом"}

// digitsMarkerFinal доводит класс m, собранный markerAt по таблице, до
// ответа. Класс dmAt бывает только у слова «at» и только один: сравнение с
// ним дешевле отдельной проверки слова на каждом токене. Слово без класса
// проверяется на маркеры вне таблицы.
func digitsMarkerFinal(doc *lex.Doc, i int, w string, m digitMarker) digitMarker {
	switch m {
	case dmAt:
		return meAt(doc, i)
	case 0:
		return digitsMarkerFallback(doc, i, w)
	}
	return m
}

// digitsMarkerFallback — класс слова w в позиции i, которого нет в таблице
// digitsMarkers. Вызывается только для слов без маркера, поэтому на
// обычном тексте стоит одного сравнения длины и префикса.
func digitsMarkerFallback(doc *lex.Doc, i int, w string) digitMarker {
	switch {
	case w == "уд":
		return digitsDriverShort(doc, i)
	case strings.HasPrefix(w, "пас") && digitsPassportTypo(w):
		return dmPassportTypo
	}
	return 0
}

// digitsDriverShort — «уд.» в сокращении «вод. уд.»: маркер водительского
// удостоверения, если ближайшее значимое слово слева — «вод» или «водит».
// Одно «уд.» ничего не значит: «уд. вес», «уд. сопротивление».
func digitsDriverShort(doc *lex.Doc, i int) digitMarker {
	for k := i - 1; k >= 0; k-- {
		if hasLineBreak(doc.Gap(k)) {
			return 0
		}
		switch doc.Tokens[k].Kind {
		case lex.KindPunct:
			continue
		case lex.KindWord:
			if w := doc.NormOf(k); w == "вод" || w == "водит" {
				return dmDriver
			}
		}
		return 0
	}
	return 0
}

// digitsPassportTypo сообщает, что слово w — «паспорт» с одной опечаткой
// (вставка, пропуск или замена буквы), в том числе в словоформе:
// «пасорт», «пасспорт», «пасорта». «Пастор» отстоит от «паспорт» на две
// правки и маркером не становится.
func digitsPassportTypo(w string) bool {
	if digitsOneEdit(w, digitsPassportWord) {
		return true
	}
	for _, e := range digitsPassportEndings {
		if strings.HasSuffix(w, e) && digitsOneEdit(w[:len(w)-len(e)], digitsPassportWord) {
			return true
		}
	}
	return false
}

// digitsOneEdit сообщает, что строки a и b отличаются не больше чем одной
// правкой по Левенштейну: вставкой, удалением или заменой одной руны.
//
// После общего префикса остаётся одна точка расхождения, и три варианта
// правки проверяются сравнением хвостов — без таблицы расстояний и без
// аллокаций.
func digitsOneEdit(a, b string) bool {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	// Префикс сравнивался по байтам и мог остановиться внутри руны: две
	// кириллические буквы делят ведущий байт.
	for i > 0 && ((i < len(a) && !utf8.RuneStart(a[i])) || (i < len(b) && !utf8.RuneStart(b[i]))) {
		i--
	}
	ta, tb := a[i:], b[i:]
	_, na := utf8.DecodeRuneInString(ta)
	_, nb := utf8.DecodeRuneInString(tb)
	return ta[na:] == tb[nb:] || ta[na:] == tb || ta == tb[nb:]
}

// digitsIssuedRight сообщает, что ближайшее значимое слово справа от
// числа — «выдан», «выдана», «выдано»: «4618 330291, выдан в 2019 году»
// (бизнес-жюри 23.09, раунд 5, Б5-7). Слева то же слово маркером номера не
// служит: в «выдан чек № 1234 567890» выдан чек, а не документ.
func digitsIssuedRight(doc *lex.Doc, last int) bool {
	for k := last + 1; k < len(doc.Tokens); k++ {
		if hasLineBreak(doc.Gap(k - 1)) {
			return false
		}
		switch doc.Tokens[k].Kind {
		case lex.KindPunct:
			continue
		case lex.KindWord:
			return strings.HasPrefix(doc.NormOf(k), "выда")
		}
		return false
	}
	return false
}

// digitsDocMarkers дополняет маркеры числа признаками, которые действуют
// только при записи номера группами — «4509 123456», «45 09 123456»:
// опечатка в слове «паспорт» и «выдан» справа. Десять цифр слитно — это и
// ИНН, и телефон, и номер заявки, поэтому для них признаки не действуют.
func digitsDocMarkers(doc *lex.Doc, r *digitRun, all digitMarker) digitMarker {
	if r.parts < 2 {
		return all
	}
	if all&dmPassportTypo != 0 {
		all |= dmPassport
	}
	if all&(dmPassport|dmDriver|dmDoc) == 0 && digitsIssuedRight(doc, r.last) {
		all |= dmDoc
	}
	return all
}

// digitsSplitShape сообщает, что десять цифр записаны серией и номером из
// двух троек через пробел: «4521 603 918», «45 21 603 918».
func digitsSplitShape(r *digitRun) bool {
	if r.seps != dsSpace {
		return false
	}
	switch r.parts {
	case 3:
		return r.lens[0] == 4 && r.lens[1] == 3 && r.lens[2] == 3
	case 4:
		return r.lens[0] == 2 && r.lens[1] == 2 && r.lens[2] == 3 && r.lens[3] == 3
	}
	return false
}

// digitsSeriesTail разбирает номер документа после серии, начиная с
// цифрового токена k: шесть цифр подряд или две тройки через пробел —
// «серии 45 21 номер 603 918» (технический жюри 23.09, раунд 5, P5-2).
// Возвращает байтовый конец номера.
//
// Тройка, за которой пробег продолжается ещё группой, номером не
// считается: «603 918 11» — другое число.
func digitsSeriesTail(doc *lex.Doc, k int) (int, bool) {
	tok := doc.Tokens[k]
	switch tok.Len() {
	case 6:
		return int(tok.End), true
	case 3:
	default:
		return 0, false
	}
	next, sep, ok := nextDigitPart(doc, k, false)
	if !ok || sep != dsSpace || doc.Tokens[next].Len() != 3 {
		return 0, false
	}
	if _, _, more := nextDigitPart(doc, next, false); more {
		return 0, false
	}
	return int(doc.Tokens[next].End), true
}
