package detect

import (
	"strings"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
)

// Дата в записи анкеты через разделитель и принадлежность пометки рождения.
//
// Запись вида «Лысенко;Ольга;Петровна;02.02.1979;89031234567» — выгрузка
// таблицы или CSV. Точка с запятой для движка — граница предложения, и дата в
// такой записи не поднималась по кластеру даже рядом с опознанным телефоном
// (технический жюри 23.09, раунд 5, P5-1). Запятая без пробела —
// «Лысенко,Ольга,Петровна,02.02.1979» — та же запись, но в одном
// предложении с именами, которые без суффикса фамилии остаются слабыми.
//
// Запись опознаётся по форме строки, а не по заголовку: заголовка в тексте
// может не быть. Дата — поле записи, если разделитель стоит рядом с ней,
// в строке не меньше трёх полей, и одно из полей — личное имя из
// справочника или отчество. Без имени строка с датой — журнал операций:
// «12.03.2005;Оплата;500».

const (
	// datesGivenTable — справочник личных имён.
	datesGivenTable = "given_names"
	// ruleDatesRecord — дата рождения в записи анкеты через разделитель.
	ruleDatesRecord = "date_record"
	// datesRecordReach — сколько токенов в каждую сторону от даты
	// просматривается в поисках полей записи. Анкетная строка короткая;
	// предел делает проверку константной по времени.
	datesRecordReach = 24
	// datesRecordMinSeps — сколько разделителей нужно в строке, кроме
	// стоящего вплотную к дате: три поля и больше — запись, два — перечисление.
	datesRecordMinSeps = 2
)

// datesRecord — то, что найдено в строке вокруг даты.
type datesRecord struct {
	seps  int  // разделителей записи
	named bool // есть поле с личным именем или отчеством
}

// datesRecordField сообщает, что дата first..last — поле записи анкеты
// через разделитель.
func datesRecordField(doc *lex.Doc, given *dict.Table, first, last int) bool {
	sep, ok := datesRecordSep(doc, first, last)
	if !ok {
		return false
	}
	var rec datesRecord
	datesRecordWalk(doc, given, sep, first-1, -1, &rec)
	datesRecordWalk(doc, given, sep, last+1, 1, &rec)
	return rec.seps >= datesRecordMinSeps && rec.named
}

// datesRecordSep находит разделитель записи рядом с датой — слева или
// справа: «;», «|» или «,». Точка с запятой и черта допускают пробел
// между разделителем и полем: «Лысенко | Ольга | 02.02.1979». Запятая
// считается разделителем только без пробелов с обеих сторон: «Ольга,
// 02.02.1979, Москва» — обычная фраза.
func datesRecordSep(doc *lex.Doc, first, last int) (byte, bool) {
	if k := first - 1; k >= 0 {
		if c, ok := datesRecordSepAt(doc, k); ok {
			return c, true
		}
	}
	if k := last + 1; k < len(doc.Tokens) {
		if c, ok := datesRecordSepAt(doc, k); ok {
			return c, true
		}
	}
	return 0, false
}

// datesRecordSepAt сообщает, что токен k — разделитель записи, и какой.
func datesRecordSepAt(doc *lex.Doc, k int) (byte, bool) {
	t := doc.Tokens[k]
	if t.Kind != lex.KindPunct || t.Len() != 1 {
		return 0, false
	}
	switch c := doc.Text[t.Start]; c {
	case ';', '|':
		return c, datesRecordGap(doc, k, 1)
	case ',':
		return c, datesRecordGap(doc, k, 0)
	}
	return 0, false
}

// datesRecordGap сообщает, что по обе стороны от разделителя k не больше
// spaces пробелов и нет перевода строки.
func datesRecordGap(doc *lex.Doc, k, spaces int) bool {
	return (k == 0 || onlySpaces(doc.Gap(k-1), spaces)) && (k+1 >= len(doc.Tokens) || onlySpaces(doc.Gap(k), spaces))
}

// datesRecordWalk проходит строку от токена k в направлении dir (−1 или 1)
// до перевода строки или предела datesRecordReach и считает разделители sep
// и поля с личным именем.
func datesRecordWalk(doc *lex.Doc, given *dict.Table, sep byte, k, dir int, rec *datesRecord) {
	for n := 0; n < datesRecordReach && k >= 0 && k < len(doc.Tokens); n++ {
		// Промежуток между текущим токеном и соседним, уже пройденным.
		gap := k
		if dir > 0 {
			gap = k - 1
		}
		if hasLineBreak(doc.Gap(gap)) {
			return
		}
		t := doc.Tokens[k]
		switch t.Kind {
		case lex.KindPunct:
			if doc.Text[t.Start] == sep {
				rec.seps++
			}
		case lex.KindWord:
			rec.named = rec.named || datesRecordName(doc, given, k)
		}
		k += dir
	}
}

// datesRecordName сообщает, что слово k — личное имя из справочника или
// отчество, написанное с заглавной.
func datesRecordName(doc *lex.Doc, given *dict.Table, k int) bool {
	if !doc.Tokens[k].Flags.Has(lex.FlagFirstUpper) {
		return false
	}
	w := doc.NormOf(k)
	return given.Has(w) || strings.HasSuffix(w, "вич") || strings.HasSuffix(w, "вна") ||
		strings.HasSuffix(w, "ична")
}

// datesBirthMarkerOf решает, чья пометка рождения стоит в позиции i слева от
// даты. Пометка после года — «1981 года рождения», «1981 г.р.» — относится к
// этому году, а не к следующей дате: в «Клиент 1981 года рождения,
// 12.03.2026 подал жалобу» вторая дата — дата события (технический жюри
// 23.09, раунд 5, P5-7). Тогда маркера у даты нет; иначе это маркер
// рождения.
//
// «Д.р.» — подпись поля «дата рождения», она стоит перед значением и чужой
// не бывает.
func datesBirthMarkerOf(doc *lex.Doc, i int) dateMarker {
	if doc.NormOf(i) == "д" {
		return dateMarkerBirth
	}
	k := datesPrevSignificant(doc, i)
	if k >= 0 && doc.Tokens[k].Kind == lex.KindWord {
		switch doc.NormOf(k) {
		case wordOfYear, wordYear, "г":
			k = datesPrevSignificant(doc, k)
		}
	}
	if k >= 0 && doc.Tokens[k].Kind == lex.KindDigits && doc.Tokens[k].Len() == 4 {
		if y := dateNum(doc, k); y >= dateMinYear && y <= dateMaxYear {
			return dateMarkerNone
		}
	}
	return dateMarkerBirth
}

// datesPrevSignificant возвращает ближайший слева от i токен, не являющийся
// знаком препинания, или −1.
func datesPrevSignificant(doc *lex.Doc, i int) int {
	for k := i - 1; k >= 0; k-- {
		if doc.Tokens[k].Kind != lex.KindPunct {
			return k
		}
	}
	return -1
}
