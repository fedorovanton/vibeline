package detect

import (
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Адрес почты, записанный словами вместо знаков: «ivan.petrov(собака)mail.ru»,
// «ivan (at) mail dot ru», «ivan[at]mail[dot]ru». Так адрес прячут от
// сборщиков, но для модели он читается так же, как с «@» (технический жюри
// 23.09, раунд 5, P5-8).
//
// «@» заменяет только слово в скобках: одно «at» — английский предлог, а
// «собака» — животное. Точку в домене заменяет «dot» или «точка» — в скобках
// или через пробелы, — либо она стоит как есть. Адресом запись считается,
// только если домен кончается верхним доменом из букв после такой точки.

// ruleEmailObfuscated — адрес со словом вместо «@».
const ruleEmailObfuscated = "email_obfuscated"

// emailGapSpaces — сколько пробелов допускается между частями записи:
// «ivan (at) mail dot ru».
const emailGapSpaces = 1

// emitObfuscatedEmail разбирает запись, в которой токен open — открывающая
// скобка перед словом «at» или «собака».
func emitObfuscatedEmail(doc *lex.Doc, orgs *dict.Table, open int, out *Candidates) {
	after, ok := emailBracketWord(doc, open, emailIsAtWord)
	if !ok {
		return
	}
	start := emailObfuscatedLocalStart(doc, open)
	if start < 0 || after >= len(doc.Tokens) || !onlySpaces(doc.Gap(after-1), emailGapSpaces) {
		return
	}
	end := emailObfuscatedDomainEnd(doc, after)
	if end < 0 {
		return
	}
	out.Add(start, end, pii.Email, Strong, ruleEmailObfuscated)
	if orgs.Has(doc.Norm[start:int(doc.Tokens[open-1].End)]) {
		out.Deny(start, end, emailVetoTypes, ruleEmailOrg)
	}
}

// emailBracketWord сообщает, что с токена open идёт слово в скобках, которое
// принимает is: «(at)», «[dot]». Возвращает индекс токена за закрывающей
// скобкой. Внутри скобок допускается по пробелу с каждой стороны.
func emailBracketWord(doc *lex.Doc, open int, is func(string) bool) (int, bool) {
	w, closing := open+1, open+2
	if closing >= len(doc.Tokens) || doc.Tokens[w].Kind != lex.KindWord || !is(doc.NormOf(w)) {
		return 0, false
	}
	if !emailClosing(doc.Text[doc.Tokens[open].Start], doc, closing) {
		return 0, false
	}
	if !onlySpaces(doc.Gap(open), emailGapSpaces) || !onlySpaces(doc.Gap(w), emailGapSpaces) {
		return 0, false
	}
	return closing + 1, true
}

// emailClosing сообщает, что токен k — скобка, закрывающая открывающую c.
func emailClosing(c byte, doc *lex.Doc, k int) bool {
	t := doc.Tokens[k]
	if t.Kind != lex.KindPunct {
		return false
	}
	switch doc.Text[t.Start] {
	case ')':
		return c == '('
	case ']':
		return c == '['
	case '}':
		return c == '{'
	}
	return false
}

// emailIsAtWord — слово, заменяющее «@».
func emailIsAtWord(w string) bool {
	switch w {
	case "at", "собака", "собачка", "эт":
		return true
	}
	return false
}

// emailIsDotWord — слово, заменяющее точку в домене.
func emailIsDotWord(w string) bool { return w == "dot" || w == "точка" }

// emailObfuscatedLocalStart отдаёт байтовое начало локальной части перед
// скобкой open или −1. Между локальной частью и скобкой допускается пробел:
// «ivan (at) …».
func emailObfuscatedLocalStart(doc *lex.Doc, open int) int {
	last := open - 1
	if last < 0 || !emailIsLabel(doc.Tokens[last]) || !onlySpaces(doc.Gap(last), emailGapSpaces) {
		return -1
	}
	if start := emailLocalStart(doc, last); start >= 0 {
		return start
	}
	return int(doc.Tokens[last].Start)
}

// emailObfuscatedDomainEnd разбирает домен с токена k: метки, разделённые
// точкой вплотную или словом «dot», «точка». Возвращает байтовый конец
// последней метки, годной в верхний домен, или −1.
func emailObfuscatedDomainEnd(doc *lex.Doc, k int) int {
	i, ok := emailLabelEnd(doc, k)
	if !ok {
		return -1
	}
	end := -1
	for {
		next, ok := emailObfuscatedDot(doc, i)
		if !ok {
			return end
		}
		label, ok := emailLabelEnd(doc, next)
		if !ok {
			return end
		}
		if label == next && emailIsTLD(doc, label) {
			end = int(doc.Tokens[label].End)
		}
		i = label
	}
}

// emailObfuscatedDot разбирает разделитель меток домена за токеном i и
// возвращает индекс первого токена следующей метки: «.» вплотную, «dot»,
// «точка» или то же слово в скобках через пробел.
func emailObfuscatedDot(doc *lex.Doc, i int) (int, bool) {
	j := i + 1
	if j+1 >= len(doc.Tokens) {
		return 0, false
	}
	t := doc.Tokens[j]
	if t.Kind == lex.KindPunct && doc.Text[t.Start] == '.' {
		return j + 1, doc.Adjacent(i) && doc.Adjacent(j)
	}
	if !onlySpaces(doc.Gap(i), emailGapSpaces) {
		return 0, false
	}
	switch {
	case t.Kind == lex.KindWord && emailIsDotWord(doc.NormOf(j)):
		j++
	case t.Kind == lex.KindPunct:
		next, ok := emailBracketWord(doc, j, emailIsDotWord)
		if !ok {
			return 0, false
		}
		j = next
	default:
		return 0, false
	}
	if j >= len(doc.Tokens) || !onlySpaces(doc.Gap(j-1), emailGapSpaces) {
		return 0, false
	}
	return j, true
}
