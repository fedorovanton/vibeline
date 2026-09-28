package detect

import (
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

func init() { Register(emailScanner{}) }

// emailScanner — адреса электронной почты.
//
// Разбор идёт от символа «@» в обе стороны по токенам: грамматика
// local@domain.tld самодостаточна, поэтому найденный адрес получает уровень
// Certain без всякого контекста.
//
// Адреса организаций («info@», домен банка) — не персональные данные, но
// решение о них принимает движок: сканер регистрирует и кандидата, и вето.
// Так контр-правило видно в отчёте о качестве, а не растворяется в пропуске.
type emailScanner struct{}

// Name реализует Scanner.
func (emailScanner) Name() string { return "email" }

// emailVetoTypes — область действия контр-правила для адресов организаций.
// Собрано один раз: в Scan не должно быть ни одной аллокации.
var emailVetoTypes = pii.NewSet(pii.Email)

// ruleEmailOrg — контр-правило для адреса организации.
const ruleEmailOrg = "email_org"

// Scan реализует Scanner.
//
// Кроме «@» разбирается запись со скобками — «ivan(собака)mail.ru», «ivan
// (at) mail dot ru», см. emitObfuscatedEmail.
func (emailScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	orgs := dicts.Table("email_orgs")
	for i := range doc.Tokens {
		t := doc.Tokens[i]
		if t.Kind != lex.KindPunct {
			continue
		}
		switch doc.Text[t.Start] {
		case '@':
			emitEmail(doc, orgs, i, out)
		case '(', '[', '{':
			emitObfuscatedEmail(doc, orgs, i, out)
		}
	}
}

// emitEmail разбирает адрес вокруг «@» в токене i.
func emitEmail(doc *lex.Doc, orgs *dict.Table, i int, out *Candidates) {
	start := emailLocalStart(doc, i)
	if start < 0 {
		return
	}
	end := emailDomainEnd(doc, i)
	if end < 0 {
		return
	}
	out.Add(start, end, pii.Email, Certain, "email")

	// Смещения байтовые и в Norm, и в Text: нормализованная копия
	// выровнена с исходником, поэтому сравнение со справочником идёт
	// по срезу Norm, без сборки временной строки.
	at := int(doc.Tokens[i].Start)
	if orgs.Has(doc.Norm[start:end]) || orgs.Has(doc.Norm[start:at]) ||
		orgs.Has(doc.Norm[at+1:end]) {
		out.Deny(start, end, emailVetoTypes, ruleEmailOrg)
	}
}

// emailLocalStart отдаёт байтовое смещение начала локальной части или -1,
// если её нет.
//
// Локальная часть — буквы, цифры и «._%+-» без пробелов. Она обязана
// начинаться с буквы или цифры, поэтому ведущие разделители отбрасываются:
// в «напишите: .ivan@mail.ru» точка в спан не входит.
func emailLocalStart(doc *lex.Doc, at int) int {
	first := -1
	for i := at - 1; i >= 0 && doc.Adjacent(i); i-- {
		t := doc.Tokens[i]
		if t.Kind == lex.KindPunct {
			if !emailIsLocalPunct(doc.Text[t.Start]) {
				break
			}
			continue
		}
		if !emailIsLabel(t) {
			break
		}
		first = i
	}
	if first < 0 {
		return -1
	}
	return int(doc.Tokens[first].Start)
}

// emailDomainEnd отдаёт байтовое смещение конца домена или -1, если домен не
// разобран.
//
// Домен — метки через точку или дефис; концом считается последняя метка,
// стоящая после точки и состоящая не менее чем из двух букв. Точка в конце
// предложения таким концом не станет: «напишите на ivan@mail.ru.» даёт спан
// «ivan@mail.ru».
func emailDomainEnd(doc *lex.Doc, at int) int {
	toks := doc.Tokens
	if !doc.Adjacent(at) {
		return -1
	}
	i, ok := emailLabelEnd(doc, at+1)
	if !ok {
		return -1
	}
	end := -1
	for i+2 < len(toks) && doc.Adjacent(i) && doc.Adjacent(i+1) {
		sep := toks[i+1]
		if sep.Kind != lex.KindPunct {
			break
		}
		c := doc.Text[sep.Start]
		if c != '.' && c != '-' {
			break
		}
		label, ok := emailLabelEnd(doc, i+2)
		if !ok {
			break
		}
		// Верхним доменом может быть только цельное слово: метка «mail2»
		// состоит из двух токенов и на эту роль не годится.
		if c == '.' && label == i+2 && emailIsTLD(doc, label) {
			end = int(toks[label].End)
		}
		i = label
	}
	return end
}

// emailLabelEnd проглатывает метку целиком и отдаёт индекс её последнего
// токена. Лексер делит «mail2» на слово и цифры, но внутри метки разделителя
// нет — подряд идущие вплотную токены остаются одной меткой.
func emailLabelEnd(doc *lex.Doc, i int) (int, bool) {
	toks := doc.Tokens
	if i >= len(toks) || !emailIsLabel(toks[i]) {
		return 0, false
	}
	for i+1 < len(toks) && doc.Adjacent(i) && emailIsLabel(toks[i+1]) {
		i++
	}
	return i, true
}

// emailIsLabel сообщает, что токен годится в метку домена или в часть
// локальной части: цифры либо слово из букв одного алфавита. Смешанные
// написания вроде «ivanиван» отбрасываются как непохожие на адрес.
func emailIsLabel(t lex.Token) bool {
	switch t.Kind {
	case lex.KindDigits:
		return true
	case lex.KindWord:
		return t.Flags.Has(lex.FlagLatin) || t.Flags.Has(lex.FlagCyrillic)
	}
	return false
}

// emailIsTLD сообщает, что метка годится в верхний домен: буквы, не меньше
// двух. Считаются руны, а не байты: «рф» — два символа и четыре байта.
func emailIsTLD(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	if t.Kind != lex.KindWord || !emailIsLabel(t) {
		return false
	}
	return utf8.RuneCountInString(doc.Text[t.Start:t.End]) >= 2
}

func emailIsLocalPunct(c byte) bool {
	switch c {
	case '.', '_', '%', '+', '-':
		return true
	}
	return false
}
