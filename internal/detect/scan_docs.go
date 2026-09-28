package detect

import (
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

func init() { Register(docsScanner{}) }

// docsScanner — документы, удостоверяющие личность, и прочие реквизиты помимо
// паспорта РФ (ТЗ §6): СНИЛС, загранпаспорт, полис ОМС, государственный
// регистрационный знак и VIN транспортного средства, ОГРН.
//
// Сканер заведён отдельно от цифрового не ради порядка в файлах, а потому что
// решает другую задачу. Цифровой сканер раскладывает числа по длине, и все эти
// документы попадают в его ветки чужими: одиннадцать цифр СНИЛС неотличимы по
// форме от телефона, шестнадцать цифр полиса ОМС — от номера карты, три цифры
// в госномере — от CVV. Опознав документ, сканер не только заводит своего
// кандидата, но и запрещает чужое прочтение на том же участке: при равной силе
// спор выигрывает тип, объявленный раньше, а номер карты объявлен раньше всех
// этих документов.
//
// ОГРН относится к юридическому лицу, а не к человеку. Он включён потому, что
// стоит рядом с данными индивидуального предпринимателя, где служит косвенным
// идентификатором.
type docsScanner struct{}

// Name реализует Scanner.
func (docsScanner) Name() string { return "docs" }

// docMarkersTable — справочник слов, называющих документ.
const docMarkersTable = "doc_markers"

// Имена правил. Идут в отчёты рядом с типом и уверенностью, значения ПД
// никогда не сопровождают.
const (
	ruleDocsSNILSChecksum   = "docs/snils_checksum"
	ruleDocsSNILSMarker     = "docs/snils_marker"
	ruleDocsForeignPassport = "docs/foreign_passport"
	ruleDocsOMS             = "docs/oms_policy"
	ruleDocsOGRNChecksum    = "docs/ogrn_checksum"
	ruleDocsOGRNMarker      = "docs/ogrn_marker"
	ruleDocsOGRNOrg         = "docs/ogrn_org"
	ruleDocsVINChecksum     = "docs/vin_checksum"
	ruleDocsVINMarker       = "docs/vin_marker"
	ruleDocsVINForm         = "docs/vin_form"
	ruleDocsVehicleReg      = "docs/vehicle_reg"
)

// docsCollidingTypes — типы, чью форму повторяют документы этого сканера.
// Запрет накладывается только на участок опознанного документа, поэтому ИНН
// или карта в другом месте предложения не затрагиваются.
var docsCollidingTypes = pii.Set(0).
	Add(pii.PassportNumber).
	Add(pii.PassportDeptCode).
	Add(pii.DriverLicense).
	Add(pii.Phone).
	Add(pii.INN).
	Add(pii.CardNumber).
	Add(pii.CVV).
	Add(pii.PIN)

// docsOrgDenied — запрет на участке ОГРН организации: чужие прочтения цифр и
// сам ОГРН.
var docsOrgDenied = docsCollidingTypes.Add(pii.OGRN)

const (
	// vinLen — длина VIN: семнадцать знаков, стандарт ISO 3779.
	vinLen = 17
	// plateTokens — число токенов госномера: буква, три цифры, две буквы,
	// код региона. Лексер режет буквы и цифры на разные токены.
	plateTokens = 4
)

// Scan реализует Scanner.
func (docsScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	marks := dicts.Table(docMarkersTable)
	var run digitRun
	for i := 0; i < len(doc.Tokens); {
		if !docsIsAlnum(doc.Tokens[i].Kind) {
			i++
			continue
		}
		// Буквенно-цифровые документы разбираются первыми: их значение
		// содержит цифровые группы, и разбирать эти группы как самостоятельное
		// число нельзя.
		if last, ok := docsAlnumRun(doc, i); ok {
			if end, ok := emitAlnumDoc(doc, marks, i, last, out); ok {
				i = end + 1
				continue
			}
		}
		if doc.Tokens[i].Kind != lex.KindDigits {
			i++
			continue
		}
		next := collectDigitRun(doc, i, &run)
		emitDocRun(doc, marks, &run, out)
		i = next
	}
}

// docsIsAlnum сообщает, что токен — буква или цифра.
func docsIsAlnum(k lex.Kind) bool { return k == lex.KindWord || k == lex.KindDigits }

// docsAlnumRun находит непрерывный буквенно-цифровой отрезок, начинающийся
// токеном i. Второе значение ложно, если отрезок начался левее: разбирать его
// хвост отдельно нельзя, иначе «XTA21099052233445» дало бы кандидата на свои
// четырнадцать цифр.
func docsAlnumRun(doc *lex.Doc, i int) (last int, ok bool) {
	if i > 0 && doc.Adjacent(i-1) && docsIsAlnum(doc.Tokens[i-1].Kind) {
		return 0, false
	}
	last = i
	for last+1 < len(doc.Tokens) && doc.Adjacent(last) && docsIsAlnum(doc.Tokens[last+1].Kind) {
		last++
	}
	// Отрезок из одного токена ни VIN, ни госномером быть не может: в обоих
	// буквы и цифры чередуются.
	if last == i {
		return 0, false
	}
	return last, true
}

// emitAlnumDoc разбирает буквенно-цифровой отрезок. Возвращает последний
// токен опознанного документа и признак того, что документ опознан и проход
// должен его перешагнуть. Документ бывает длиннее отрезка: код региона
// госномера пишут и через пробел.
func emitAlnumDoc(doc *lex.Doc, marks *dict.Table, first, last int, out *Candidates) (int, bool) {
	start, end := int(doc.Tokens[first].Start), int(doc.Tokens[last].End)
	if emitVIN(doc, marks, first, last, start, end, out) {
		return last, true
	}
	return emitPlate(doc, first, last, out)
}

// emitVIN разбирает VIN: семнадцать знаков латиницы и цифр без I, O и Q.
//
// Контрольный символ обязателен только в Северной Америке, поэтому его провал
// не отменяет кандидата, а лишь не подтверждает его. Запрет чужих прочтений
// ставится в любом случае: цифры внутри семнадцатизначной буквенно-цифровой
// строки номером карты не являются независимо от того, VIN это или нет.
func emitVIN(doc *lex.Doc, marks *dict.Table, first, last, start, end int, out *Candidates) bool {
	if end-start != vinLen {
		return false
	}
	letters, digits := 0, 0
	for i := start; i < end; i++ {
		c := doc.Text[i]
		if _, ok := vinValue(c); !ok {
			return false
		}
		if c >= '0' && c <= '9' {
			digits++
		} else {
			letters++
		}
	}
	// Семнадцать цифр подряд — не VIN, а просто длинное число.
	if letters == 0 || digits == 0 {
		return false
	}

	conf, rule := Weak, ruleDocsVINForm
	switch {
	case VINCheck(doc.Text[start:end]):
		conf, rule = Certain, ruleDocsVINChecksum
	case docsMarkersAround(doc, marks, first, last).Has(pii.VIN):
		conf, rule = Strong, ruleDocsVINMarker
	}
	out.Add(start, end, pii.VIN, conf, rule)
	out.Deny(start, end, docsCollidingTypes, ruleDocsVINForm)
	return true
}

// emitPlate разбирает государственный регистрационный знак: буква, три цифры,
// две буквы, код региона из двух или трёх цифр.
//
// Маркер не требуется: набор из двенадцати букв и жёсткий порядок групп — это
// самодостаточная грамматика, а не просто форма.
//
// Код региона пишут и слитно — «А123ВС77», — и через один пробел — «А123ВС 77»
// (замечание жюри 23.09, N10). Во второй записи отрезок кончается на буквах, и
// регион берётся следующим токеном. Трёхзначный регион через пробел
// принимается только с первой цифрой 1 или 7 — других трёхзначных кодов нет,
// а «А123ВС 250» скорее номер с числом после него. Полностью раздельная запись
// «А 123 ВС 77» не разбирается: «с 100 на 150» — та же последовательность
// одиночной буквы, трёх цифр, двух букв и числа.
func emitPlate(doc *lex.Doc, first, last int, out *Candidates) (int, bool) {
	last, ok := plateEnd(doc, first, last)
	if !ok || !plateShape(doc, first) {
		return 0, false
	}
	toks := doc.Tokens
	start, end := int(toks[first].Start), int(toks[last].End)
	out.Add(start, end, pii.VehicleReg, Certain, ruleDocsVehicleReg)
	out.Deny(start, end, docsCollidingTypes, ruleDocsVehicleReg)
	return last, true
}

// plateEnd возвращает последний токен госномера, отрезок которого занимает
// токены [first, last]: слитная запись — сам last, запись с регионом через
// пробел — следующий за ним токен региона.
func plateEnd(doc *lex.Doc, first, last int) (int, bool) {
	switch last - first + 1 {
	case plateTokens:
		return last, true
	case plateTokens - 1:
		return plateRegion(doc, last)
	}
	return 0, false
}

// plateRegion возвращает токен кода региона, записанного через один пробел
// после букв last.
func plateRegion(doc *lex.Doc, last int) (int, bool) {
	toks := doc.Tokens
	region := last + 1
	if region >= len(toks) || toks[region].Kind != lex.KindDigits || !onlySpaces(doc.Gap(last), 1) {
		return 0, false
	}
	// Регион не должен продолжаться словом или числом вплотную:
	// «А123ВС 77км» — уже не госномер.
	if doc.Adjacent(region) && docsIsAlnum(toks[region+1].Kind) {
		return 0, false
	}
	if n := toks[region].Len(); n == 3 {
		if c := doc.Text[toks[region].Start]; c != '1' && c != '7' {
			return 0, false
		}
	}
	return region, true
}

// plateShape проверяет группы госномера, начатого токеном first: буква, три
// цифры, две буквы из набора docsPlateLetters, регион из двух или трёх цифр.
func plateShape(doc *lex.Doc, first int) bool {
	toks := doc.Tokens
	if toks[first].Kind != lex.KindWord || toks[first+1].Kind != lex.KindDigits ||
		toks[first+2].Kind != lex.KindWord || toks[first+3].Kind != lex.KindDigits {
		return false
	}
	if n, ok := docsPlateLetters(doc.NormOf(first)); !ok || n != 1 {
		return false
	}
	if n, ok := docsPlateLetters(doc.NormOf(first + 2)); !ok || n != 2 {
		return false
	}
	if toks[first+1].Len() != 3 {
		return false
	}
	region := toks[first+3].Len()
	return region >= 2 && region <= 3
}

// docsPlateLetters считает буквы и сообщает, все ли они допустимы в госномере.
//
// Набор из двенадцати букв выбран не произвольно: в российских госномерах
// используются только те кириллические буквы, что совпадают по начертанию с
// латинскими. Поэтому принимается и латинское написание — его дают раскладка
// клавиатуры и выгрузки из иностранных систем.
func docsPlateLetters(s string) (int, bool) {
	n := 0
	for _, r := range s {
		switch r {
		case 'а', 'в', 'е', 'к', 'м', 'н', 'о', 'р', 'с', 'т', 'у', 'х',
			'a', 'b', 'e', 'k', 'm', 'h', 'o', 'p', 'c', 't', 'y', 'x':
			n++
		default:
			return 0, false
		}
	}
	return n, true
}

// emitDocRun применяет к цифровому пробегу правила документов. Длины не
// пересекаются, поэтому число попадает не более чем в одну ветку.
func emitDocRun(doc *lex.Doc, marks *dict.Table, r *digitRun, out *Candidates) {
	start, end := r.bounds(doc)
	switch r.total {
	case 9:
		emitForeignPassport(doc, marks, r, start, end, out)
	case 11:
		emitSNILS(doc, marks, r, start, end, out)
	case 13, 15:
		emitOGRN(doc, marks, r, start, end, out)
	case 16:
		emitOMS(doc, marks, r, start, end, out)
	}
}

// emitSNILS разбирает СНИЛС: одиннадцать цифр, обычно группами 3-3-3-2.
//
// Контрольная сумма сама по себе кандидата не создаёт: одиннадцать цифр — это
// ещё и номер телефона, и примерно один случайный номер из ста контрольную
// сумму проходит. Поэтому требуется либо группировка СНИЛС, либо маркер.
func emitSNILS(doc *lex.Doc, marks *dict.Table, r *digitRun, start, end int, out *Candidates) {
	grouped := r.parts == 4 && r.lens[0] == 3 && r.lens[1] == 3 && r.lens[2] == 3 && r.lens[3] == 2
	if r.parts != 1 && !grouped {
		return
	}
	marked := docsMarkersAround(doc, marks, r.first, r.last).Has(pii.SNILS)
	if !marked && !grouped {
		return
	}
	conf, rule := Strong, ruleDocsSNILSMarker
	if docsSNILSOK(doc, r) {
		conf, rule = Certain, ruleDocsSNILSChecksum
	} else if !marked {
		return
	}
	out.Add(start, end, pii.SNILS, conf, rule)
	out.Deny(start, end, docsCollidingTypes, rule)
}

// emitForeignPassport разбирает загранпаспорт: две цифры серии и семь цифр
// номера. Контрольной суммы у него нет, поэтому маркер обязателен: девять
// цифр без него — любое число.
func emitForeignPassport(doc *lex.Doc, marks *dict.Table, r *digitRun, start, end int, out *Candidates) {
	shaped := r.parts == 1 || (r.parts == 2 && r.lens[0] == 2 && r.lens[1] == 7)
	if !shaped || !docsMarkersAround(doc, marks, r.first, r.last).Has(pii.ForeignPassport) {
		return
	}
	out.Add(start, end, pii.ForeignPassport, Strong, ruleDocsForeignPassport)
	out.Deny(start, end, docsCollidingTypes, ruleDocsForeignPassport)
}

// emitOMS разбирает полис ОМС: шестнадцать цифр, той же формы, что номер
// карты. Маркер обязателен именно поэтому — иначе сканер отбирал бы у карты
// каждое её число.
func emitOMS(doc *lex.Doc, marks *dict.Table, r *digitRun, start, end int, out *Candidates) {
	shaped := r.parts == 1 ||
		(r.parts == 4 && r.lens[0] == 4 && r.lens[1] == 4 && r.lens[2] == 4 && r.lens[3] == 4)
	if !shaped || !docsMarkersAround(doc, marks, r.first, r.last).Has(pii.OMSPolicy) {
		return
	}
	out.Add(start, end, pii.OMSPolicy, Strong, ruleDocsOMS)
	out.Deny(start, end, docsCollidingTypes, ruleDocsOMS)
}

// emitOGRN разбирает ОГРН (13 цифр) и ОГРНИП (15 цифр). Контрольной суммы
// достаточно: число такой длины одной группой встречается редко, а совпадение
// контрольного разряда случайно происходит в одном случае из десяти.
//
// Тринадцатизначный ОГРН выдаётся только юридическому лицу, и рядом со словом
// «банк», «организация», «ООО» это реквизит организации, а не человека: маска
// на нём — ложное срабатывание (замечание жюри 23.09, F2). Такой ОГРН не
// регистрируется, но участок закрывается запретом, как у опознанного
// документа: иначе те же цифры, прошедшие Луна, достались бы номеру карты.
// ОГРНИП из пятнадцати цифр — реквизит предпринимателя, то есть человека, и
// правило его не касается.
func emitOGRN(doc *lex.Doc, marks *dict.Table, r *digitRun, start, end int, out *Candidates) {
	if r.parts != 1 {
		return
	}
	if r.total == 13 {
		if _, all := findDigitMarkers(doc, r.first, r.last); all&dmOrg != 0 {
			out.Deny(start, end, docsOrgDenied, ruleDocsOGRNOrg)
			return
		}
	}
	marked := docsMarkersAround(doc, marks, r.first, r.last).Has(pii.OGRN)
	conf, rule := Strong, ruleDocsOGRNMarker
	if docsOGRNOK(doc, r) {
		conf, rule = Certain, ruleDocsOGRNChecksum
	} else if !marked {
		return
	}
	out.Add(start, end, pii.OGRN, conf, rule)
	out.Deny(start, end, docsCollidingTypes, rule)
}

// docsSNILSOK и docsOGRNOK считают контрольную сумму пробега.
//
// Для числа из одной группы проверяется подстрока исходного текста, для числа
// с разделителями — стековый буфер цифр: строка из него не покидает вызов и
// потому в кучу не уезжает. Идиома та же, что у digitRun.luhnOK.
func docsSNILSOK(doc *lex.Doc, r *digitRun) bool {
	if r.overflow {
		return false
	}
	if r.parts == 1 {
		t := doc.Tokens[r.first]
		return SNILS(doc.Text[t.Start:t.End])
	}
	return SNILS(string(r.digits[:r.digitsLen]))
}

func docsOGRNOK(doc *lex.Doc, r *digitRun) bool {
	if r.overflow {
		return false
	}
	if r.parts == 1 {
		t := doc.Tokens[r.first]
		return OGRN(doc.Text[t.Start:t.End])
	}
	return OGRN(string(r.digits[:r.digitsLen]))
}

// docsMarkersAround собирает типы документов, названные словами вокруг числа.
// Окно то же, что у цифрового сканера: знаки препинания его не расходуют,
// перевод строки обрывает.
func docsMarkersAround(doc *lex.Doc, marks *dict.Table, first, last int) pii.Set {
	var set pii.Set
	for i, seen := first-1, 0; i >= 0 && seen < markerWindowLeft; i-- {
		if hasLineBreak(doc.Gap(i)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		set = set.Union(docsMarkerAt(doc, marks, i))
	}
	for i, seen := last+1, 0; i < len(doc.Tokens) && seen < markerWindowRight; i++ {
		if hasLineBreak(doc.Gap(i - 1)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		set = set.Union(docsMarkerAt(doc, marks, i))
	}
	return set
}

// docsMarkerAt читает маркер документа из справочника. Метка справочника —
// машинный ключ типа ПД, поэтому новый документ добавляется строкой в файл.
func docsMarkerAt(doc *lex.Doc, marks *dict.Table, i int) pii.Set {
	if doc.Tokens[i].Kind != lex.KindWord {
		return 0
	}
	key, ok := marks.Get(doc.NormOf(i))
	if !ok {
		return 0
	}
	t, ok := pii.ByKey(key)
	if !ok {
		return 0
	}
	return pii.Set(0).Add(t)
}
