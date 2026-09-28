package detect

import (
	"strings"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Сканер номера банковского счёта: двадцать цифр по плану счетов Банка
// России. Первые пять цифр — балансовый счёт второго порядка («40817» —
// счета физических лиц), дальше код валюты, контрольный ключ, код
// подразделения и номер лицевого счёта: «40817 810 0 9991 0004312».
//
// В обязательные категории ТЗ §3.2.1 счёт не входит, но для банка это
// банковская тайна, и «Счёт клиента 40817810099910004312» уходил в модель
// открытым (бизнес-жюри 23.09, раунд 4, Б4-14).
//
// Контрольный ключ (девятая цифра) считается по БИК банка, а БИК в тексте
// рядом со счётом бывает не всегда. Поэтому ключ не проверяется, а
// уверенность задают маркер и балансовый счёт:
//   - после маркера — «счёт», «р/с», «л/с», «расчётный счёт», «account» —
//     кандидат Strong;
//   - без маркера, но с балансовым счётом клиента (405–408, 423, 426) и в
//     обычной записи — Weak: его поднимает до маски соседнее ПД того же
//     предложения.
//
// Корреспондентский счёт банка — «к/с 30101810400000000225» — реквизит
// банка, а не клиента: он не маскируется, и участок закрывается запретом.

func init() { Register(accountScanner{}) }

// accountScanner — сканер номера банковского счёта.
type accountScanner struct{}

// Name реализует Scanner.
func (accountScanner) Name() string { return "account" }

// Имена правил. Идут в отчёты рядом с типом и уверенностью, значения ПД
// никогда не сопровождают.
const (
	ruleAccountMarker = "account/marker"
	ruleAccountForm   = "account/form"
	ruleAccountCorr   = "account/corr"
	// ruleAccountTransfer — счёт после маркера перевода: «реквизиты»,
	// «переведите на».
	ruleAccountTransfer = "account/transfer"
)

const (
	// accountLen — длина номера счёта по плану счетов.
	accountLen = 20
	// maxAccountParts — предел групп в записи счёта. Самая дробная обычная
	// запись — «408 17 810 0 9991 0004312», шесть групп; запас на запись
	// парами при маркере.
	maxAccountParts = 10
)

// accountMarker — класс маркера рядом с номером счёта.
type accountMarker uint8

const (
	// amAccount — маркер счёта клиента: «счёт», «р/с», «л/с», «account».
	amAccount accountMarker = 1 + iota
	// amCorr — маркер корреспондентского счёта: «к/с», «корр. счёт».
	amCorr
	// amTransfer — маркер реквизитов перевода без слова «счёт»:
	// «реквизиты», «переведите на», «для перевода», «перечислить на». Такое
	// слово стоит и перед номером карты, договора или суммой, поэтому оно
	// поднимает до Strong только двадцать цифр в обычной записи с балансовым
	// счётом клиента, и только слева от номера, см. accountMarkerNear.
	amTransfer
)

// accountDenied — запрет на участке корреспондентского счёта: сам счёт и
// чужие прочтения тех же цифр.
var accountDenied = docsCollidingTypes.Add(pii.BankAccount)

// Scan реализует Scanner.
//
// Номер ищется с каждого цифрового токена, а не только с начала пробега
// цифр: «от 12.05 40817810099910004312» — пробег длиннее двадцати цифр, но
// счёт в нём есть. После найденного счёта проход его перешагивает.
func (accountScanner) Scan(doc *lex.Doc, _ *dict.Set, out *Candidates) {
	var lens [maxAccountParts]uint8
	for i := 0; i < len(doc.Tokens); i++ {
		t := doc.Tokens[i]
		// Счёт не начинается с нуля: балансовые счета нумеруются с 102.
		if t.Kind != lex.KindDigits || t.Len() > accountLen || doc.Text[t.Start] == '0' {
			continue
		}
		last, parts, more, ok := accountRun(doc, i, &lens)
		if !ok {
			continue
		}
		if emitAccount(doc, i, last, lens[:parts], more, out) {
			i = last
		}
	}
}

// accountRun собирает от токена i группы цифр, пока их не наберётся ровно
// двадцать. Группы соединяют пробелы, дефисы и тире — как в пробеге
// цифрового сканера, но без точек, скобок и косой: так счёт не пишут.
//
// more сообщает, что за двадцатой цифрой пробег продолжается ещё одной
// группой: тогда двадцать цифр — начало более длинного числа, а не счёт.
func accountRun(doc *lex.Doc, i int, lens *[maxAccountParts]uint8) (last, parts int, more, ok bool) {
	sum := doc.Tokens[i].Len()
	lens[0] = uint8(sum)
	parts = 1
	j := i
	for sum < accountLen {
		if parts == maxAccountParts {
			return 0, 0, false, false
		}
		k, sep, found := nextDigitPart(doc, j, false)
		if !found || sep&^(dsSpace|dsHyphen|dsDash) != 0 {
			return 0, 0, false, false
		}
		n := doc.Tokens[k].Len()
		lens[parts] = uint8(n)
		parts++
		sum += n
		j = k
	}
	if sum != accountLen {
		return 0, 0, false, false
	}
	_, _, more = nextDigitPart(doc, j, false)
	return j, parts, more, true
}

// accountCanonical сообщает, что группы записаны одной из обычных форм
// номера счёта: слитно, «40817 810 0 9991 0004312», «408 17 810 0 9991
// 0004312» или пятью четвёрками.
func accountCanonical(lens []uint8) bool {
	switch len(lens) {
	case 1:
		return true
	case 5:
		if lens[0] == 5 && lens[1] == 3 && lens[2] == 1 && lens[3] == 4 && lens[4] == 7 {
			return true
		}
		for _, n := range lens {
			if n != 4 {
				return false
			}
		}
		return true
	case 6:
		return lens[0] == 3 && lens[1] == 2 && lens[2] == 3 && lens[3] == 1 && lens[4] == 4 && lens[5] == 7
	}
	return false
}

// emitAccount решает судьбу двадцати цифр от токена first до last и
// сообщает, принят ли участок: заведён кандидат или поставлен запрет.
func emitAccount(doc *lex.Doc, first, last int, lens []uint8, more bool, out *Candidates) bool {
	canonical := accountCanonical(lens)
	// Необычная группировка, за которой пробег продолжается или перед
	// которой он начался, — часть длинного числа, а не счёт: в «408 178 100
	// 999 100 043 121 55» с «178» набирается ровно двадцать цифр.
	if (more || accountJoinedLeft(doc, first)) && !canonical {
		return false
	}
	start, end := int(doc.Tokens[first].Start), int(doc.Tokens[last].End)
	var head [5]byte
	accountHead(doc, first, &head)
	marker := accountMarkerNear(doc, first, last)

	// Корреспондентский счёт банка в Банке России — всегда 30101; прочие
	// корреспондентские — 301xx при маркере «к/с». Это реквизит банка, а не
	// клиента: маска на нём — ложное срабатывание.
	if string(head[:]) == "30101" || (marker == amCorr && string(head[:3]) == "301") {
		out.Deny(start, end, accountDenied, ruleAccountCorr)
		return true
	}
	rule := ruleAccountMarker
	if marker == amTransfer {
		rule = ruleAccountTransfer
		if !accountTransferOK(doc, first, last, canonical, head) {
			marker = 0
		}
	}
	switch {
	case marker != 0:
		out.Add(start, end, pii.BankAccount, Strong, rule)
		// Цифры опознанного счёта ничьим другим реквизитом не являются.
		out.Deny(start, end, docsCollidingTypes, rule)
		return true
	case canonical && accountClientHead(head) && !accountNotPersonal(doc, first, last):
		out.Add(start, end, pii.BankAccount, Weak, ruleAccountForm)
		return true
	}
	return false
}

// accountTransferOK сообщает, что маркер перевода подтверждает счёт: номер
// записан обычной формой, балансовый счёт — счёт клиента, и рядом нет
// маркера договора. «Договор перевода № 40817…» — номер договора.
func accountTransferOK(doc *lex.Doc, first, last int, canonical bool, head [5]byte) bool {
	if !canonical || !accountClientHead(head) {
		return false
	}
	_, all := findDigitMarkers(doc, first, last)
	return all&dmContract == 0
}

// accountJoinedLeft сообщает, что цифровой токен i продолжает группу цифр
// слева — через пробел, дефис или тире, как соединяет группы accountRun.
func accountJoinedLeft(doc *lex.Doc, i int) bool {
	k := i - 1
	if k < 0 {
		return false
	}
	switch doc.Tokens[k].Kind {
	case lex.KindDigits:
		return onlySpaces(doc.Gap(k), 2)
	case lex.KindPunct:
		if k == 0 || doc.Tokens[k-1].Kind != lex.KindDigits || !zeroWidth(doc.Gap(k-1)) || !zeroWidth(doc.Gap(k)) {
			return false
		}
		switch doc.Raw(k) {
		case "-", "‐", "‑", "‒", "–", "−":
			return true
		}
	}
	return false
}

// accountHead записывает первые пять цифр счёта в dst. Группа может быть
// короче пяти цифр — «408 17 …», — поэтому цифры собираются по токенам.
func accountHead(doc *lex.Doc, first int, dst *[5]byte) {
	n := 0
	for i := first; n < len(dst) && i < len(doc.Tokens); i++ {
		t := doc.Tokens[i]
		if t.Kind != lex.KindDigits {
			continue
		}
		n += copy(dst[n:], doc.Text[t.Start:t.End])
	}
}

// accountClientHead сообщает, что балансовый счёт первого порядка — счёт
// клиента: 405–407 — организации, 408 — физические лица и
// предприниматели, 423 и 426 — вклады физических лиц. Только такая форма
// заводит кандидата без маркера.
func accountClientHead(head [5]byte) bool {
	switch string(head[:3]) {
	case "405", "406", "407", "408", "423", "426":
		return true
	}
	return false
}

// accountNotPersonal сообщает, что рядом маркер договора или реквизита
// операции: «договор № 40817…», «номер транзакции …». Без маркера счёта
// такие двадцать цифр — номер документа, и слабого кандидата они не дают.
func accountNotPersonal(doc *lex.Doc, first, last int) bool {
	_, all := findDigitMarkers(doc, first, last)
	return all&(dmContract|dmRecord) != 0
}

// accountMarkerNear ищет маркер счёта в том же окне, что цифровой сканер:
// до четырёх значимых слов слева и до двух справа. Слева маркер ищется
// первым: реквизиты подписываются перед значением, и в «р/с 40702…, к/с
// 30101…» у первого счёта ближайший маркер — «р/с», хотя «к/с» стоит
// справа вплотную. Маркер перевода засчитывается только слева: «40817…
// переведён» — не подпись реквизита.
func accountMarkerNear(doc *lex.Doc, first, last int) accountMarker {
	if m := accountMarkerLeft(doc, first); m != 0 {
		return m
	}
	if m := accountMarkerRight(doc, last); m != amTransfer {
		return m
	}
	return 0
}

// accountMarkerLeft ищет маркер счёта не дальше markerWindowLeft значимых
// токенов левее токена first, не переходя через перевод строки.
func accountMarkerLeft(doc *lex.Doc, first int) accountMarker {
	for i, seen := first-1, 0; i >= 0 && seen < markerWindowLeft; i-- {
		if hasLineBreak(doc.Gap(i)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		if m := accountMarkerAt(doc, i); m != 0 {
			return m
		}
	}
	return 0
}

// accountMarkerRight ищет маркер счёта не дальше markerWindowRight значимых
// токенов правее токена last, не переходя через перевод строки.
func accountMarkerRight(doc *lex.Doc, last int) accountMarker {
	for i, seen := last+1, 0; i < len(doc.Tokens) && seen < markerWindowRight; i++ {
		if hasLineBreak(doc.Gap(i - 1)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		if m := accountMarkerAt(doc, i); m != 0 {
			return m
		}
	}
	return 0
}

// accountMarkerAt определяет класс маркера счёта для токена i.
//
// Сокращения «р/с», «л/с», «к/с», «р/сч» приходят тремя токенами — буква,
// косая, буква, — и разбираются по последнему из них. Полные слова
// сравниваются по префиксу, чтобы покрыть словоформы: «счёта», «счету»,
// «расчётного», «корреспондентский». Короткие — «сч», «кор», «корр» —
// только целиком: префиксом «кор» стал бы «короткий».
func accountMarkerAt(doc *lex.Doc, i int) accountMarker {
	if doc.Tokens[i].Kind != lex.KindWord {
		return 0
	}
	w := doc.NormOf(i)
	if (w == "с" || w == "сч" || w == "c") && i >= 2 && doc.NormOf(i-1) == "/" {
		switch doc.NormOf(i - 2) {
		case "р", "л":
			return amAccount
		case "к":
			return amCorr
		case "a":
			// «a/c» — account латиницей.
			return amAccount
		}
		return 0
	}
	switch {
	case strings.HasPrefix(w, "корреспондент"), strings.HasPrefix(w, "корсчет"),
		w == "кор", w == "корр", strings.HasPrefix(w, "correspondent"):
		return amCorr
	case strings.HasPrefix(w, "счет"), w == "сч", strings.HasPrefix(w, "расчетн"),
		strings.HasPrefix(w, "лицев"), strings.HasPrefix(w, "вклад"), strings.HasPrefix(w, "депозит"),
		strings.HasPrefix(w, "account"), w == "acc", w == "acct":
		return amAccount
	case accountIsTransferWord(w):
		return amTransfer
	}
	return 0
}

// accountTransferStems — основы слов, которыми подписывают реквизиты
// перевода без слова «счёт»: «Реквизиты клиента: 42307…», «Переведите на
// 40817…», «номер для перевода 40817…», «перечислить на …» (бизнес-жюри
// 23.09, раунд 5, Б5-5). Сравнение по префиксу покрывает словоформы:
// «реквизиты», «реквизитам», «перевести», «переведите», «перевода»,
// «перечислите».
var accountTransferStems = [...]string{"реквизит", "перевод", "перевед", "перевест", "перечисл"}

// accountIsTransferWord сообщает, что слово w — маркер реквизитов перевода.
func accountIsTransferWord(w string) bool {
	for _, s := range accountTransferStems {
		if strings.HasPrefix(w, s) {
			return true
		}
	}
	return false
}
