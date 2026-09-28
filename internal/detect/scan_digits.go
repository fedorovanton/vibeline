package detect

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Сканер цифровых типов ПД: паспорт, код подразделения, водительское
// удостоверение, банковская карта, CVV, ПИН, ИНН и телефон.
//
// Форму даёт не регулярное выражение, а разбор пробега цифровых токенов:
// число распадается на группы, разделённые пробелами, дефисами, точками и
// скобками, и правило смотрит на набор длин групп. Косая черта группы в общем
// случае не соединяет — «1/2», «12/345-67» — и разбирается отдельным пробегом,
// см. emitSlashRun. Этого достаточно, чтобы
// отличить «4509 123456» от «2200 7001 2345 6781», и при этом не платить ни
// одной аллокации на кандидата.
//
// Три цифры и четыре цифры встречаются в тексте повсюду, поэтому CVV, ПИН,
// код подразделения и водительское удостоверение регистрируются только рядом
// с маркером своего типа. Контрольная сумма, где она есть, поднимает кандидата
// до Certain без всякого маркера.

func init() { Register(digitsScanner{}) }

// phoneCodesTable — справочник кодов, по которым номер телефона не является
// персональными данными клиента.
const phoneCodesTable = "phone_codes"

const (
	// maxDigitParts ограничивает число групп в одном пробеге. Больше, чем у
	// любого реквизита, но защищает от склейки колонки цифр в одного кандидата.
	maxDigitParts = 12
	// maxDigitChars — ёмкость буфера цифр пробега. Длиннее самого длинного
	// реквизита (19 цифр карты); что не поместилось, до контрольных сумм и
	// справочника не доходит.
	maxDigitChars = 24
	// markerWindowLeft и markerWindowRight — окно поиска маркера в значимых
	// токенах. Знаки препинания окно не расходуют: «тел.:» и «пин-код» — это
	// одно значимое слово, а не три токена.
	markerWindowLeft  = 4
	markerWindowRight = 2
)

// Имена правил. Попадают в отладочные отчёты рядом с типом и уверенностью,
// но никогда не сопровождаются значением ПД.
const (
	ruleDigitsPassport       = "digits/passport"
	ruleDigitsPassportSeries = "digits/passport_series"
	ruleDigitsDriver         = "digits/driver_license"
	ruleDigitsDriverSeries   = "digits/driver_series"
	ruleDigitsDept           = "digits/dept_code"
	ruleDigitsPhone          = "digits/phone"
	ruleDigitsPhoneLocal     = "digits/phone_local"
	ruleDigitsPhoneIntl      = "digits/phone_intl"
	ruleDigitsOrgINN         = "digits/org_inn"
	ruleDigitsINNChecksum    = "digits/inn_checksum"
	ruleDigitsINNMarker      = "digits/inn_marker"
	ruleDigitsCardLuhn       = "digits/card_luhn"
	ruleDigitsCardMarker     = "digits/card_marker"
	ruleDigitsCardForm       = "digits/card_form"
	ruleDigitsCVV            = "digits/cvv"
	ruleDigitsPIN            = "digits/pin"
)

// digitSep — вид разделителя между группами цифр.
type digitSep uint8

const (
	dsSpace digitSep = 1 << iota
	dsHyphen
	dsParen
	dsDot
	// dsDash — типографское тире или дефис вместо «-»: U+2010, U+2011,
	// U+2012, U+2013, U+2212. Его ставит автозамена редактора и вёрстка, и
	// номер «+7 916 123–45–67» уходил открытым (замечание жюри 23.09, N1).
	// Вид заведён отдельно от dsHyphen: «100–200» — чаще диапазон, чем код
	// подразделения, и слабое правило формы ddd-ddd на тире не срабатывает.
	dsDash
	// dsSlash — косая черта: «4276/0198/7654/3215». Встречается только в
	// пробеге emitSlashRun: дробь, дата и номер договора пишутся так же.
	dsSlash
)

// digitMarker — класс контекстного маркера рядом с числом.
type digitMarker uint16

const (
	dmPassport digitMarker = 1 << iota
	dmDriver
	dmDept
	dmPhone
	dmINN
	dmCVV
	dmPIN
	// dmDoc — маркер реквизита документа без указания, какого именно:
	// «серия», «номер», «документ». Он разрешает разбор формы «серия и
	// номер», но тип документа не задаёт.
	dmDoc
	// dmContract — маркер номера договора. Он не заводит кандидата, а
	// снимает его: номер договора записывается той же формой, что серия и
	// номер паспорта, но персональными данными не является.
	dmContract
	// dmCard — маркер банковской карты: «карта», «card», платёжная система.
	dmCard
	// dmCVVHint — описательный маркер CVV: «код безопасности», «защитный
	// код», «на обороте». Сам по себе он слабее «cvv»: вместе со словом
	// «код» даёт Strong, без него — Weak, который поднимает карта в том же
	// предложении.
	dmCVVHint
	// dmCode — слово «код». Отдельно ничего не задаёт.
	dmCode
	// dmRecord — реквизит заявки, обращения, операции, заказа. Номер такого
	// реквизита записывается десятью цифрами, как паспорт, но персональными
	// данными не является. Снимает кандидата только в связке со словом
	// «номер» или знаком «№» прямо перед числом, см. recordBound.
	dmRecord
	// dmOrg — слово, называющее организацию: «банк», «организация», «ООО».
	// Десятизначный ИНН и тринадцатизначный ОГРН рядом с ним — реквизиты
	// юридического лица, а не человека.
	dmOrg
	// dmAt — английский предлог «at». Наружу markerAt его не отдаёт: после
	// «me» он становится маркером телефона, в остальных случаях — ничем.
	dmAt
	// dmPassportTypo — слово «паспорт» с одной опечаткой, не совпавшее с
	// префиксом «пасп»: «пасорт», «пасспорт» (бизнес-жюри 23.09, раунд 5,
	// Б5-7). Маркером паспорта оно служит только при записи номера группами
	// «4509 123456» или «45 09 123456», см. digitsDocMarkers.
	dmPassportTypo
)

// nearDocMask — классы, среди которых ищется ближайший к числу маркер.
// Форму «серия и номер» делят паспорт, водительское удостоверение и договор,
// и спор между ними решает близость маркера, а не сам факт его присутствия.
const nearDocMask = dmPassport | dmDriver | dmContract

// digitsMarker — слово-маркер и класс, который оно задаёт.
//
// Маркеры живут здесь, а не в справочнике: их немного, и каждый привязан к
// конкретному правилу этого файла. Короткие маркеры сравниваются целиком —
// иначе «инн» ловит «инновации», а «ву» — «вузе». Длинные сравниваются по
// префиксу, чтобы покрыть словоформы: «паспорта», «паспортом», «удостоверения».
type digitsMarker struct {
	word  string
	class digitMarker
	exact bool
}

var digitsMarkers = []digitsMarker{
	// «Пасп» — префиксом: покрывает и полное «паспорт» во всех словоформах, и
	// сокращение «пасп.» из анкет и заметок операциониста. С полным словом
	// префикс «пасп.» не совпадал, и «Клиент Иванов И.И., пасп. 4509 123456»
	// уходил с открытым номером (бизнес-жюри 23.09, раунд 4, Б4-2).
	{word: "пасп", class: dmPassport},
	{word: "сери", class: dmDoc},
	{word: "номер", class: dmDoc},
	// Сокращения «сер.» и «ном.» — только целиком: префикс «сер» поймал бы
	// «сервис» и «серый», «ном» — «номинал» (технический жюри 23.09, P4-7).
	{word: "сер", class: dmDoc, exact: true},
	{word: "ном", class: dmDoc, exact: true},
	{word: "документ", class: dmDoc},
	{word: "договор", class: dmContract},
	{word: "контракт", class: dmContract},
	{word: "соглашен", class: dmContract},
	{word: "водительск", class: dmDriver},
	{word: "удостоверен", class: dmDriver},
	{word: "прав", class: dmDriver},
	{word: "ву", class: dmDriver, exact: true},
	// Сокращения анкет «водит. удост.» — только целиком: префикс «вод»
	// поймал бы «вода», «удост» — «удостоен» (технический жюри 23.09,
	// раунд 5, P5-4). «Уд.» из «вод. уд.» — см. digitsMarkerFallback.
	{word: "водит", class: dmDriver, exact: true},
	{word: "удост", class: dmDriver, exact: true},
	{word: "удостов", class: dmDriver, exact: true},
	// «Подразд.» покрывает и полное «подразделение», и сокращение. «Подр.»
	// и «КП» сравниваются целиком: префикс «подр» поймал бы «подробно»,
	// а «кп» — «кпп» (замечание жюри 23.09, N4).
	{word: "подразд", class: dmDept},
	{word: "подр", class: dmDept, exact: true},
	{word: "кп", class: dmDept, exact: true},
	{word: "тел", class: dmPhone},
	{word: "моб", class: dmPhone},
	{word: "контакт", class: dmPhone},
	{word: "звон", class: dmPhone},
	{word: "позвон", class: dmPhone},
	{word: "перезвон", class: dmPhone},
	{word: "инн", class: dmINN, exact: true},
	{word: "cvv", class: dmCVV},
	{word: "cvc", class: dmCVV},
	{word: "cvp", class: dmCVV},
	{word: "проверк", class: dmCVV},
	{word: "безопасност", class: dmCVVHint},
	{word: "защитн", class: dmCVVHint},
	{word: "секретн", class: dmCVVHint},
	{word: "обороте", class: dmCVVHint, exact: true},
	{word: "оборотной", class: dmCVVHint, exact: true},
	{word: "обратной", class: dmCVVHint, exact: true},
	{word: "код", class: dmCode, exact: true},
	// Реквизиты, номер которых не относится к человеку. «Счёт» здесь —
	// лицевой или номер счёта на оплату из десяти цифр: двадцатизначный
	// банковский счёт до этой ветки не доходит.
	{word: "заявк", class: dmRecord},
	{word: "обращени", class: dmRecord},
	{word: "транзакц", class: dmRecord},
	{word: "операци", class: dmRecord},
	{word: "заказ", class: dmRecord},
	{word: "трек", class: dmRecord},
	{word: "рейс", class: dmRecord},
	{word: "тикет", class: dmRecord},
	{word: "квитанц", class: dmRecord},
	{word: "платеж", class: dmRecord},
	{word: "перевод", class: dmRecord},
	{word: "запрос", class: dmRecord},
	{word: "инцидент", class: dmRecord},
	{word: "накладн", class: dmRecord},
	{word: "отправлени", class: dmRecord},
	{word: "счет", class: dmRecord},
	{word: "order", class: dmRecord},
	{word: "ticket", class: dmRecord},
	{word: "transaction", class: dmRecord},
	{word: "tracking", class: dmRecord},
	// Организация. Короткие формы собственности — только целиком: «ао»
	// префиксом накрыло бы любое слово на «ао…».
	{word: wordBank, class: dmOrg},
	{word: "организац", class: dmOrg},
	{word: "работодател", class: dmOrg},
	{word: "компани", class: dmOrg},
	{word: "юрлиц", class: dmOrg},
	{word: "юридическ", class: dmOrg},
	{word: "предприят", class: dmOrg},
	{word: "учрежден", class: dmOrg},
	{word: "ооо", class: dmOrg, exact: true},
	{word: "оао", class: dmOrg, exact: true},
	{word: "зао", class: dmOrg, exact: true},
	{word: "пао", class: dmOrg, exact: true},
	{word: "ао", class: dmOrg, exact: true},
	// Английские маркеры: анкеты и обращения на латинице («passport 4509
	// 123456», «phone +7 …») дают ту же форму числа, что и русские.
	{word: "passport", class: dmPassport},
	{word: "driver", class: dmDriver},
	{word: "licen", class: dmDriver},
	{word: "phone", class: dmPhone},
	{word: "mobile", class: dmPhone},
	{word: "tel", class: dmPhone, exact: true},
	// «Call me at», «reach me at», «text me at»: предлог «at» маркером
	// телефона служит только после «me», см. meAt (бизнес-жюри 23.09,
	// раунд 4, Б4-15).
	{word: "at", class: dmAt, exact: true},
	{word: "карт", class: dmCard},
	{word: "card", class: dmCard},
	{word: "visa", class: dmCard},
	{word: "mastercard", class: dmCard},
	{word: "maestro", class: dmCard},
	{word: "пин", class: dmPIN},
	{word: "pin", class: dmPIN},
}

// digitsMarkerIndex — маркеры, разложенные по корзинам первой буквы.
// Собирается один раз при инициализации пакета и дальше только читается.
var digitsMarkerIndex = indexDigitsMarkers(digitsMarkers)

// digitsMarkerKey возвращает корзину слова длиной не меньше двух байт.
//
// Строчная кириллица в UTF-8 начинается байтом 0xD0 или 0xD1, и букву задаёт
// второй байт: корзины 0–127 без пересечений. Остальные слова раскладываются
// по первому байту в корзины 128–255; совпадение корзины у разных букв
// только добавляет сравнений — ответ проверяет полное сравнение слова.
func digitsMarkerKey(w string) int {
	if w[0] == 0xD0 || w[0] == 0xD1 {
		return int(w[0]&1)<<6 | int(w[1]&0x3F)
	}
	return 128 | int(w[0]&0x7F)
}

func indexDigitsMarkers(list []digitsMarker) *[256][]digitsMarker {
	var idx [256][]digitsMarker
	for _, mk := range list {
		k := digitsMarkerKey(mk.word)
		idx[k] = append(idx[k], mk)
	}
	return &idx
}

// digitsScanner — сканер цифровых типов ПД.
type digitsScanner struct{}

// Name возвращает имя сканера.
func (digitsScanner) Name() string { return "digits" }

// Scan находит цифровые персональные данные и дописывает кандидатов в out.
//
// Состояния между вызовами нет: единственная изменяемая структура — пробег
// цифр — живёт на стеке вызова и переиспользуется внутри одного прохода.
func (digitsScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	codes := dicts.Table(phoneCodesTable)
	var run digitRun
	for i := 0; i < len(doc.Tokens); {
		if doc.Tokens[i].Kind != lex.KindDigits {
			i++
			continue
		}
		if cvvSuffix(doc, i) {
			i++
			continue
		}
		// Запись через косую — «4276/0198/7654/3215», «+7/926/407/18/35» —
		// сначала пробуется целиком. Не опознана — числа разбираются
		// порознь, как и до правки: «Серия/номер: 4509/123456» остаётся
		// серией и номером, а «1/2» — двумя числами.
		if slashFollows(doc, i) {
			if next, ok := emitSlashRun(doc, i, &run, codes, out); ok {
				i = next
				continue
			}
		}
		next := collectDigitRun(doc, i, &run)
		emitDigitRun(doc, &run, codes, out)
		i = next
	}
}

// cvvSuffix сообщает, что цифровой токен i — хвост маркера «CVV2», «CVC2»:
// одна цифра вплотную за словом-маркером CVV.
//
// Лексер режет «CVV2» на слово и цифру, и без этой проверки «2» склеивалась
// со значением в пробег «2 417» из четырёх цифр: CVV уходил открытым, а рядом
// с «ПИН» маской становилось «CVV[ПИН_1]» (замечание жюри 23.09, N2). Цифра
// остаётся маркером и в окне поиска маркеров по-прежнему занимает место.
func cvvSuffix(doc *lex.Doc, i int) bool {
	if i == 0 || doc.Tokens[i].Len() != 1 || !zeroWidth(doc.Gap(i-1)) {
		return false
	}
	return markerAt(doc, i-1)&dmCVV != 0
}

// digitRun — пробег цифровых токенов, соединённых разделителями.
//
// Структура заводится один раз на проход и переиспользуется: копия цифр без
// разделителей нужна контрольным суммам и справочнику кодов, а собирать её
// в куче на каждом числе недопустимо.
type digitRun struct {
	first, last int                  // границы пробега в токенах
	parts       int                  // число групп цифр
	lens        [maxDigitParts]uint8 // длины групп в цифрах
	total       int                  // всего цифр в пробеге
	seps        digitSep             // виды встреченных разделителей
	plus        bool                 // перед первой группой стоит «+»
	paren       bool                 // первая группа в скобках: «(916) 482-17-35»
	digits      [maxDigitChars]byte  // цифры без разделителей
	digitsLen   int
	overflow    bool // цифр больше буфера: контрольные суммы не считаем
}

// collectDigitRun собирает пробег, начинающийся цифровым токеном i,
// и возвращает индекс токена, с которого продолжать проход.
func collectDigitRun(doc *lex.Doc, i int, r *digitRun) int { return collectRun(doc, i, r, false) }

// collectRun собирает пробег. При slash группы соединяет только косая черта
// вплотную, иначе — пробелы, дефисы, тире, точки и скобки.
func collectRun(doc *lex.Doc, i int, r *digitRun, slash bool) int {
	r.reset()
	r.first, r.last = i, i
	r.addPart(doc, i)
	// «+» перед первой цифрой — часть номера телефона, а не знак препинания.
	// Невидимый символ между ними разрывом не считается: на экране
	// «+\u200b7 916 …» выглядит так же, как «+7 916 …».
	if i > 0 && doc.Tokens[i-1].Kind == lex.KindPunct && doc.Raw(i-1) == "+" && zeroWidth(doc.Gap(i-1)) {
		r.plus = true
	}
	j := i
	for r.parts < maxDigitParts {
		k, sep, ok := nextDigitPart(doc, j, slash)
		if !ok {
			break
		}
		r.seps |= sep
		r.addPart(doc, k)
		r.last = k
		j = k
	}
	// Код города в скобках без кода страны: «(916) 482-17-35». Скобка
	// открывается вплотную перед первой группой и закрывается сразу за ней.
	if i > 0 && r.parts > 1 && zeroWidth(doc.Gap(i-1)) && doc.Raw(i-1) == "(" && doc.Raw(i+1) == ")" {
		r.paren = true
	}
	return j + 1
}

// nextDigitPart ищет следующую группу цифр за токеном j и вид разделителя
// перед ней. Разделитель, стоящий не вплотную там, где так не пишут,
// пробег обрывает: «в 2024. 1234567890» — два числа, а не одно.
//
// «Вплотную» — это без видимого промежутка: невидимый форматирующий символ
// рядом с дефисом или точкой промежутком не считается, как и в лексере.
//
// При slash принимается только косая черта вплотную: пробег через косую
// собирается отдельно и с обычной записью не смешивается.
func nextDigitPart(doc *lex.Doc, j int, slash bool) (int, digitSep, bool) {
	k := j + 1
	if k >= len(doc.Tokens) {
		return 0, 0, false
	}
	if doc.Tokens[k].Kind == lex.KindDigits {
		if slash || !onlySpaces(doc.Gap(j), 2) {
			return 0, 0, false
		}
		return k, dsSpace, true
	}
	if doc.Tokens[k].Kind != lex.KindPunct {
		return 0, 0, false
	}
	if k+1 >= len(doc.Tokens) || doc.Tokens[k+1].Kind != lex.KindDigits {
		return 0, 0, false
	}
	before, after := doc.Gap(j), doc.Gap(k)
	tight := zeroWidth(before) && zeroWidth(after)
	if slash {
		return digitPartAt(k, dsSlash, tight && doc.Raw(k) == "/")
	}
	var sep digitSep
	switch doc.Raw(k) {
	case "-":
		sep = dsHyphen
	case "‐", "‑", "‒", "–", "−":
		sep = dsDash
	case "(", ")":
		// Скобка кода города допускает по пробелу с каждой стороны, остальные
		// разделители стоят вплотную.
		sep, tight = dsParen, onlySpaces(before, 1) && onlySpaces(after, 1)
	case ".":
		sep = dsDot
	default:
		return 0, 0, false
	}
	return digitPartAt(k, sep, tight)
}

// digitPartAt — результат nextDigitPart для разделителя sep в позиции k:
// следующая группа цифр k+1, если разделитель допустим (ok).
func digitPartAt(k int, sep digitSep, ok bool) (int, digitSep, bool) {
	if !ok {
		return 0, 0, false
	}
	return k + 1, sep, true
}

// slashFollows сообщает, что за цифровым токеном i идёт косая черта, а за
// ней ещё токен: «4276/0198…». Проверка встраивается в Scan и отсекает
// пробег через косую у всех чисел, где его заведомо нет; зазоры и цифры за
// косой проверяет сам пробег. С «/» начинается только знаковый токен из
// одного этого символа — слово и число с него не начинаются.
func slashFollows(doc *lex.Doc, i int) bool {
	k := i + 1
	return k+1 < len(doc.Tokens) && doc.Text[doc.Tokens[k].Start] == '/'
}

// emitSlashRun разбирает число, записанное группами через косую черту, и
// сообщает, опознан ли реквизит; при успехе возвращает индекс токена, с
// которого продолжать проход.
//
// Так же пишут дробь «1/2», дату «12/05/2024», номер договора «12/345-67» и
// серию с номером «4509/123456», поэтому косая принимается только там, где
// ошибиться нельзя (технический жюри 23.09, P4-6):
//   - номер карты — только с верным Луном;
//   - ИНН — только при маркере «ИНН» и с верной контрольной суммой;
//   - телефон из одиннадцати цифр — только с «+», маркером телефона или
//     кодом мобильной сети «9xx»; с «+» и кодом другой страны — как в
//     intlPhone.
//
// Всё остальное возвращается в обычный разбор, где косая числа разделяет.
func emitSlashRun(doc *lex.Doc, i int, r *digitRun, codes *dict.Table, out *Candidates) (int, bool) {
	next := collectRun(doc, i, r, true)
	if r.parts < 2 || r.overflow {
		return 0, false
	}
	start, end := r.bounds(doc)
	switch {
	case intlPhone(r):
		out.Add(int(doc.Tokens[r.first-1].Start), end, pii.Phone, Strong, ruleDigitsPhoneIntl)
	case r.total == 11:
		_, all := findDigitMarkers(doc, r.first, r.last)
		if !slashPhone(r, all, codes) {
			return 0, false
		}
		if r.plus {
			start = int(doc.Tokens[r.first-1].Start)
		}
		out.Add(start, end, pii.Phone, Strong, ruleDigitsPhone)
	case r.total == 12:
		_, all := findDigitMarkers(doc, r.first, r.last)
		if all&dmINN == 0 || !INN(string(r.digits[:r.digitsLen])) {
			return 0, false
		}
		out.Add(start, end, pii.INN, Certain, ruleDigitsINNChecksum)
	case r.total >= 13 && r.total <= 19:
		if !r.cardShape() || !r.luhnOK(doc) {
			return 0, false
		}
		out.Add(start, end, pii.CardNumber, Certain, ruleDigitsCardLuhn)
	default:
		return 0, false
	}
	return next, true
}

// slashPhone сообщает, что одиннадцать цифр через косую — российский номер
// телефона: «7» или «8» в начале, код не из справочника сервисных и признак
// телефона — «+», маркер или мобильный код «9xx». Маркер договора без маркера
// телефона номер снимает, как и в emitPhone.
func slashPhone(r *digitRun, all digitMarker, codes *dict.Table) bool {
	if c := r.digits[0]; c != '7' && c != '8' {
		return false
	}
	if codes.Has(string(r.digits[1:4])) {
		return false
	}
	if r.plus || all&dmPhone != 0 {
		return true
	}
	return r.digits[1] == '9' && all&dmContract == 0
}

// reset очищает пробег, не трогая буферы: их содержимое за пределами
// заполненной длины не читается.
func (r *digitRun) reset() {
	r.parts = 0
	r.total = 0
	r.seps = 0
	r.plus = false
	r.paren = false
	r.digitsLen = 0
	r.overflow = false
}

// addPart добавляет к пробегу группу цифр — токен k.
func (r *digitRun) addPart(doc *lex.Doc, k int) {
	t := doc.Tokens[k]
	n := t.Len()
	r.lens[r.parts] = uint8(n)
	if n > 255 {
		r.lens[r.parts] = 255
	}
	r.parts++
	r.total += n
	if r.digitsLen+n <= len(r.digits) {
		copy(r.digits[r.digitsLen:], doc.Text[t.Start:t.End])
		r.digitsLen += n
		return
	}
	r.overflow = true
}

// bounds возвращает границы значения в байтах: от первой до последней цифры.
// Разделители внутри числа в спан входят, служебные слова вокруг — нет.
func (r *digitRun) bounds(doc *lex.Doc) (int, int) {
	return int(doc.Tokens[r.first].Start), int(doc.Tokens[r.last].End)
}

// luhnOK проверяет пробег по алгоритму Луна.
//
// Для числа из одной группы проверяется подстрока исходного текста, для
// числа с разделителями — стековый буфер цифр: строка из него не покидает
// вызов, поэтому в кучу не уезжает.
func (r *digitRun) luhnOK(doc *lex.Doc) bool {
	if r.overflow {
		return false
	}
	if r.parts == 1 {
		t := doc.Tokens[r.first]
		return Luhn(doc.Text[t.Start:t.End])
	}
	return Luhn(string(r.digits[:r.digitsLen]))
}

// docShape сообщает, что пробег имеет форму серии и номера документа:
// десять цифр подряд, 4+6 или 2+2+6.
func (r *digitRun) docShape() bool {
	switch r.parts {
	case 1:
		return true
	case 2:
		return r.lens[0] == 4 && r.lens[1] == 6
	case 3:
		return r.lens[0] == 2 && r.lens[1] == 2 && r.lens[2] == 6
	}
	return false
}

// seriesShape сообщает, что пробег записан как серия документа: четыре цифры
// подряд либо двумя парами через пробел.
//
// Вторая форма — «серия 24 13» — в паспорте встречается не реже первой: так
// серия напечатана на самом бланке. ТЗ §3.2.2 прямо требует учитывать
// вариации написания, и разбиение серии пробелом — одна из них.
func (r *digitRun) seriesShape() bool {
	switch r.parts {
	case 1:
		return r.lens[0] == 4
	case 2:
		return r.lens[0] == 2 && r.lens[1] == 2 && r.seps == dsSpace
	}
	return false
}

// cardShape сообщает, что пробег записан как номер карты: 13–19 цифр подряд
// либо группами по четыре через пробел, дефис, точку или косую черту.
//
// Точка и косая форму дают, но сами по себе номер не подтверждают: их
// принимает только номер с верным Луном, см. emitDigitRun и emitSlashRun.
func (r *digitRun) cardShape() bool {
	if r.total < 13 || r.total > 19 {
		return false
	}
	if r.parts == 1 {
		return true
	}
	if r.seps&^(dsSpace|dsHyphen|dsDash|dsDot|dsSlash) != 0 {
		return false
	}
	// American Express печатает номер группами 4-6-5 (замечание жюри 23.09,
	// N10): «3782 822463 10005».
	if r.parts == 3 && r.lens[0] == 4 && r.lens[1] == 6 && r.lens[2] == 5 {
		return true
	}
	for i := 0; i < r.parts-1; i++ {
		if r.lens[i] != 4 {
			return false
		}
	}
	last := r.lens[r.parts-1]
	return last >= 1 && last <= 4
}

// emitDigitRun применяет к пробегу правила своего размера. Размеры не
// пересекаются, поэтому одно число попадает ровно в одну ветку — а внутри
// ветки может дать нескольких кандидатов разных типов: выбор между ними
// делает движок, а не сканер.
func emitDigitRun(doc *lex.Doc, r *digitRun, codes *dict.Table, out *Candidates) {
	near, all := findDigitMarkers(doc, r.first, r.last)
	start, end := r.bounds(doc)

	if intlPhone(r) {
		// «+» — часть номера, а не служебный знак: маскируется вместе с
		// цифрами, как и у российского номера в emitPhone.
		out.Add(int(doc.Tokens[r.first-1].Start), end, pii.Phone, Strong, ruleDigitsPhoneIntl)
		return
	}

	switch {
	case r.total == 2:
		emitDriverOldForm(doc, r, all, out)
	case r.total == 3:
		emitCVV(all, start, end, out)
	case r.total == 4:
		if all&dmPIN != 0 {
			out.Add(start, end, pii.PIN, Strong, ruleDigitsPIN)
		}
		emitSeriesNumber(doc, r, near, all, out)
	case r.total == 6:
		emitDeptCode(r, all, start, end, out)
	case r.total == 7:
		emitLocalPhone(r, all, start, end, out)
	case r.total == 10:
		digitEmitTen(doc, r, near, all, codes, start, end, out)
	case r.total == 11:
		emitPhone(r, all, codes, doc, start, end, out)
	case r.total == 12:
		if all&dmINN == 0 && recordBound(doc, r.first) {
			return
		}
		emitINN(doc, r, all, start, end, out)
	case r.total >= 13 && r.total <= 19:
		digitEmitCard(doc, r, near, all, start, end, out)
	}
}

// digitEmitTen разбирает десять цифр: номер реквизита операции, телефон без
// кода страны, ИНН организации либо номер документа — в этом порядке, первое
// сработавшее правило останавливает разбор.
func digitEmitTen(doc *lex.Doc, r *digitRun, near, all digitMarker, codes *dict.Table, start, end int, out *Candidates) {
	switch {
	case recordBound(doc, r.first):
		// «Номер заявки 1234567890», «Трек-номер …»: номер реквизита
		// операции не является персональными данными, а по форме от
		// паспорта и ИНН не отличим (замечание жюри 23.09, F1).
	case emitPhoneNoCountry(doc, r, all, codes, start, end, out):
	case emitOrgINN(doc, r, all, start, end, out):
	default:
		emitDocNumber(doc, r, near, all, start, end, out)
	}
}

// digitEmitCard разбирает 13–19 цифр — номер карты.
func digitEmitCard(doc *lex.Doc, r *digitRun, near, all digitMarker, start, end int, out *Candidates) {
	if !r.cardShape() {
		return
	}
	luhn := r.luhnOK(doc)
	// «4276.0198.7654.3215» — номер карты, только если Лун верен: через
	// точку пишут и суммы, и номера версий, и маркер карты рядом такую
	// запись не подтверждает (технический жюри 23.09, P4-6).
	if r.seps&dsDot != 0 && !luhn {
		return
	}
	conf, rule := Weak, ruleDigitsCardForm
	switch {
	case luhn:
		conf, rule = Certain, ruleDigitsCardLuhn
	case all&dmCard != 0 && near&dmContract == 0:
		// Номер, не прошедший проверку Луна, рядом со словом «карта» —
		// всё равно номер карты: опечатка или выдуманный пример в
		// обращении не делают его безопасным. Пропуск здесь дороже
		// лишней маски.
		conf, rule = Strong, ruleDigitsCardMarker
	}
	out.Add(start, end, pii.CardNumber, conf, rule)
}

// emitDocNumber разбирает десять цифр: паспорт, водительское удостоверение
// и ИНН записываются одинаково, различает их маркер и контрольная сумма.
//
// Запись номера двумя тройками — «4521 603 918», «45 21 603 918» —
// принимается только при маркере документа: без него это любое число
// (технический жюри 23.09, раунд 5, P5-2).
func emitDocNumber(doc *lex.Doc, r *digitRun, near, all digitMarker, start, end int, out *Candidates) {
	if shape, split := r.docShape(), digitsSplitShape(r); shape || split {
		all = digitsDocMarkers(doc, r, all)
		if t, conf, ok := docNumberType(near, all); ok && (shape || conf == Strong) {
			out.Add(start, end, t, conf, docNumberRule(t))
		}
	}
	// ИНН пишется только сплошными цифрами: «45 09 123456» — не ИНН.
	if r.parts == 1 {
		emitINN(doc, r, all, start, end, out)
	}
}

// docNumberType выбирает тип документа по маркерам вокруг числа.
//
// Форма «серия и номер» одинакова у паспорта, водительского удостоверения и
// номера договора, поэтому решает контекст. Когда рядом маркеры сразу двух
// хозяев, спор разрешает ближайший к числу: в «ВУ 9455209598, паспорт серия
// 7771 номер 721789» подряд стоят два разных документа, и разбирать их надо
// порознь.
//
// Маркер договора рядом с числом снимает кандидата вовсе: номер договора
// персональными данными не является, а по форме от паспорта не отличим.
// Ложное срабатывание здесь стоит дороже обычного — это отдельный критерий
// проверки, — поэтому контекст договора имеет приоритет над формой.
func docNumberType(near, all digitMarker) (pii.Type, Confidence, bool) {
	if near&dmContract != 0 {
		return 0, 0, false
	}
	driver, passport := all&dmDriver != 0, all&dmPassport != 0
	if driver && passport {
		driver = near&dmDriver != 0
		passport = !driver
	}
	switch {
	case driver:
		return pii.DriverLicense, Strong, true
	case passport:
		return pii.PassportNumber, Strong, true
	case all&dmDoc != 0:
		// «Серия», «номер», «документ» говорят, что перед нами реквизит
		// документа, но не говорят какого. Без уточнения это паспорт:
		// в банковском обиходе документ по умолчанию — он.
		return pii.PassportNumber, Strong, true
	default:
		return pii.PassportNumber, Weak, true
	}
}

// docNumberRule возвращает имя правила для типа документа.
func docNumberRule(t pii.Type) string {
	if t == pii.DriverLicense {
		return ruleDigitsDriver
	}
	return ruleDigitsPassport
}

// emitINN регистрирует ИНН. Без верной контрольной суммы и без маркера
// кандидат не заводится вовсе: десять цифр подряд — слишком частая форма.
func emitINN(doc *lex.Doc, r *digitRun, all digitMarker, start, end int, out *Candidates) {
	if r.parts != 1 {
		emitGroupedINN(r, all, start, end, out)
		return
	}
	t := doc.Tokens[r.first]
	switch {
	case INN(doc.Text[t.Start:t.End]):
		out.Add(start, end, pii.INN, Certain, ruleDigitsINNChecksum)
	case all&dmINN != 0:
		out.Add(start, end, pii.INN, Strong, ruleDigitsINNMarker)
	}
}

// emitGroupedINN регистрирует двенадцатизначный ИНН, записанный группами:
// «ИНН 7728 1456 3088», «ИНН: 77 28 14 56 30 88» (замечание жюри 23.09, N10).
// Группы у ИНН не приняты, поэтому без маркера «ИНН» такая запись не
// разбирается: двенадцать цифр группами — и сумма, и номер счёта.
//
// Через точку — «ИНН 5024.1183.5606» — ИНН принимается только с верной
// контрольной суммой (технический жюри 23.09, P4-6): точкой разделяют и
// суммы, и номера версий.
func emitGroupedINN(r *digitRun, all digitMarker, start, end int, out *Candidates) {
	if r.total != 12 || r.overflow || all&dmINN == 0 || r.seps&^(dsSpace|dsHyphen|dsDash|dsDot) != 0 {
		return
	}
	if INN(string(r.digits[:r.digitsLen])) {
		out.Add(start, end, pii.INN, Certain, ruleDigitsINNChecksum)
		return
	}
	if r.seps&dsDot != 0 {
		return
	}
	out.Add(start, end, pii.INN, Strong, ruleDigitsINNMarker)
}

// emitDeptCode регистрирует код подразделения. Шесть цифр подряд без маркера
// не регистрируются: это и номер дома, и сумма, и год с месяцем.
func emitDeptCode(r *digitRun, all digitMarker, start, end int, out *Candidates) {
	if all&dmDept != 0 {
		out.Add(start, end, pii.PassportDeptCode, Strong, ruleDigitsDept)
		return
	}
	if r.parts == 2 && r.lens[0] == 3 && r.lens[1] == 3 && r.seps == dsHyphen {
		out.Add(start, end, pii.PassportDeptCode, Weak, ruleDigitsDept)
	}
}

// emitPhone регистрирует номер телефона.
//
// Номера с кодом из справочника не регистрируются вовсе: бесплатная линия
// и сервисный номер — не персональные данные клиента, и контр-правило здесь
// не нужно, достаточно не заводить кандидата.
func emitPhone(r *digitRun, all digitMarker, codes *dict.Table, doc *lex.Doc, start, end int, out *Candidates) {
	if r.overflow {
		return
	}
	if c := r.digits[0]; c != '7' && c != '8' {
		return
	}
	if codes.Has(string(r.digits[1:4])) {
		return
	}
	conf := Weak
	switch {
	case r.plus || all&dmPhone != 0:
		conf = Strong
	case r.digits[1] == '9' && all&dmContract == 0:
		// Одиннадцать цифр с «7» или «8» и кодом мобильной сети «9xx» — форма
		// мобильного номера, а не суммы или даты: «Мой номер 89161234567,
		// перезвоните». Без слова «телефон» такой номер оставался Weak и в
		// одиночном предложении уходил открытым. Номер договора той же формы
		// маркером договора снимается.
		conf = Strong
	}
	// «+» — часть номера, а не служебный знак: маскируется вместе с цифрами.
	if r.plus {
		start = int(doc.Tokens[r.first-1].Start)
	}
	out.Add(start, end, pii.Phone, conf, ruleDigitsPhone)
}

// intlPhone сообщает, что пробег — номер телефона с «+» и кодом страны,
// который не разбирает emitPhone: «+375 29 123-45-67», «+380 67 123 4567»,
// «+1 212 555 0100» (замечание жюри 23.09, N1).
//
// «+» вплотную перед числом из десяти–пятнадцати цифр — запись номера по
// E.164, а не знак суммы: сумма с плюсом такой длины в обращениях не
// встречается. Российский номер «+7 …» из одиннадцати цифр идёт в emitPhone:
// там справочник сервисных кодов, и «+7 800 …» телефоном клиента не станет.
func intlPhone(r *digitRun) bool {
	if !r.plus || r.total < 10 || r.total > 15 {
		return false
	}
	return r.total != 11 || (r.digits[0] != '7' && r.digits[0] != '8')
}

// emitCVV регистрирует три цифры CVV.
//
// Явный маркер («cvv», «cvc», «код проверки») даёт Strong. Описательный —
// «код безопасности», «защитный код», «на обороте» — даёт Strong только
// вместе со словом «код»: «защитный слой 417» кодом карты не является. Без
// «кода» кандидат Weak, и маскирует его карта в том же предложении — подъём по
// кластеру (замечание жюри 23.09, N2).
func emitCVV(all digitMarker, start, end int, out *Candidates) {
	switch {
	case all&dmCVV != 0, all&dmCVVHint != 0 && all&dmCode != 0:
		out.Add(start, end, pii.CVV, Strong, ruleDigitsCVV)
	case all&dmCVVHint != 0:
		out.Add(start, end, pii.CVV, Weak, ruleDigitsCVV)
	}
}

// emitLocalPhone регистрирует семизначный городской номер без кода —
// «тел. 123-45-67» — только при маркере телефона и в форме 3-2-2: семь цифр
// сами по себе — любое число.
func emitLocalPhone(r *digitRun, all digitMarker, start, end int, out *Candidates) {
	if all&dmPhone == 0 || r.parts != 3 || r.lens[0] != 3 || r.lens[1] != 2 || r.lens[2] != 2 {
		return
	}
	if r.seps&^(dsSpace|dsHyphen|dsDash) != 0 {
		return
	}
	out.Add(start, end, pii.Phone, Strong, ruleDigitsPhoneLocal)
}

// emitPhoneNoCountry разбирает номер из десяти цифр без «+7» и «8»:
// «телефон (916) 482-17-35», «тел. 495-123-45-67», «мобильный 916 482-17-35»
// (замечание жюри 23.09, N1). Возвращает true, если номер признан телефоном
// и остальные прочтения пробега — паспорт, ИНН — не нужны.
//
// Десять цифр — форма паспорта и ИНН юрлица, поэтому одной формы мало.
// Телефоном число считается, если выполнено одно из трёх:
//   - рядом маркер телефона, и он ближе маркеров паспорта, в/у и ИНН;
//   - код в скобках — «(916) 482-17-35»: так документы не пишут;
//   - мобильная форма 9xx xxx-xx-xx группами 3-3-2-2 — так не пишут ни
//     документ, ни сумму.
//
// Первая цифра — 3, 4, 8 или 9: так начинаются российские коды городов и
// мобильных сетей. Коды из справочника (800, 900 …) не регистрируются, как
// и в emitPhone.
func emitPhoneNoCountry(doc *lex.Doc, r *digitRun, all digitMarker, codes *dict.Table, start, end int, out *Candidates) bool {
	if r.overflow || r.plus {
		return false
	}
	switch r.digits[0] {
	case '3', '4', '8', '9':
	default:
		return false
	}
	if codes.Has(string(r.digits[0:3])) || !r.localPhoneShape() {
		return false
	}
	mobile := r.digits[0] == '9' && r.parts == 4 &&
		r.lens[0] == 3 && r.lens[1] == 3 && r.lens[2] == 2 && r.lens[3] == 2
	marked := all&dmPhone != 0
	if docs := all & (dmPassport | dmDriver | dmINN); docs != 0 && marked {
		marked = nearestMarker(doc, r.first, r.last, docs|dmPhone)&dmPhone != 0
	}
	switch {
	case marked:
	case all&dmContract != 0:
		// Номер договора той же формы маркером договора снимается, как и
		// одиннадцатизначный в emitPhone.
		return false
	case !r.paren && !mobile:
		return false
	}
	if r.paren {
		start = int(doc.Tokens[r.first-1].Start)
	}
	out.Add(start, end, pii.Phone, Strong, ruleDigitsPhone)
	return true
}

// localPhoneShape сообщает, что десять цифр сгруппированы как телефон: одной
// группой либо кодом из трёх цифр (в скобках — до пяти, «(4942) 31-00-00»)
// и группами по две–четыре цифры или одной группой номера. Форма паспорта
// «4509 123456» сюда не подходит: первая группа из четырёх цифр без скобок —
// серия, а не код.
func (r *digitRun) localPhoneShape() bool {
	if r.parts == 1 {
		return true
	}
	if r.seps&^(dsSpace|dsHyphen|dsDash|dsParen|dsDot) != 0 {
		return false
	}
	first := r.lens[0]
	if first != 3 && (!r.paren || first < 3 || first > 5) {
		return false
	}
	if r.parts == 2 {
		return r.lens[1] >= 5
	}
	for i := 1; i < r.parts; i++ {
		if r.lens[i] < 2 || r.lens[i] > 4 {
			return false
		}
	}
	return true
}

// recordBound сообщает, что число — номер заявки, обращения, операции или
// заказа: слово такого реквизита связано с числом словом «номер» или знаком
// «№». Связка обязательна: «Паспорт, указанный в заявке: 4509 123456» —
// паспорт, а «Номер заявки 1234567890» — нет.
//
// Разбираются формы «номер заявки N», «заявка номер N», «трек-номер N» и
// «заявка № N»: не больше двух значимых слов слева от числа.
func recordBound(doc *lex.Doc, first int) bool {
	var words [2]int
	n := 0
	sign := false // «№» между числом и ближайшим словом
	for i := first - 1; i >= 0 && n < len(words); i-- {
		if hasLineBreak(doc.Gap(i)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			if n == 0 && doc.Raw(i) == "№" {
				sign = true
			}
			continue
		}
		words[n] = i
		n++
	}
	if n == 0 {
		return false
	}
	switch {
	case isRecordWord(doc, words[0]):
		// «Заявка № N», «номер заявки N».
		return sign || (n == 2 && isNumberWord(doc, words[1]))
	case isNumberWord(doc, words[0]):
		// «Заявка номер N», «трек-номер N».
		return n == 2 && isRecordWord(doc, words[1])
	}
	return false
}

func isRecordWord(doc *lex.Doc, i int) bool { return markerAt(doc, i)&dmRecord != 0 }

// isNumberWord сообщает, что токен i — слово «номер» в любой словоформе или
// его сокращение «ном.»: «сер. 4618 ном. 507329».
func isNumberWord(doc *lex.Doc, i int) bool {
	if doc.Tokens[i].Kind != lex.KindWord {
		return false
	}
	w := doc.NormOf(i)
	return w == "ном" || strings.HasPrefix(w, "номер")
}

// emitOrgINN снимает ИНН организации: десять цифр рядом со словом «банк»,
// «организация», «ООО» (замечание жюри 23.09, F2). Десятизначный ИНН выдаётся
// только юридическому лицу — у человека ИНН из двенадцати цифр, — и маска на
// реквизите банка оценивается как ложное срабатывание. Возвращает true, если
// число признано ИНН организации.
//
// Число должно быть именно ИНН: при маркере «ИНН» — любое, без него — только
// с верной контрольной суммой и без маркера документа. Маркер паспорта,
// в/у или телефона рядом отменяет правило: «работает в банке, паспорт
// 4509123456» — паспорт клиента.
//
// Кроме отказа от кандидата ставится запрет на участок: слабое прочтение
// паспорта той же формы иначе поднял бы соседний ОГРН по кластеру.
func emitOrgINN(doc *lex.Doc, r *digitRun, all digitMarker, start, end int, out *Candidates) bool {
	if r.parts != 1 || all&dmOrg == 0 || all&(dmPassport|dmDriver|dmPhone) != 0 {
		return false
	}
	if all&dmINN == 0 {
		t := doc.Tokens[r.first]
		if all&dmDoc != 0 || !INN(doc.Text[t.Start:t.End]) {
			return false
		}
	}
	out.Deny(start, end, orgINNDenied, ruleDigitsOrgINN)
	return true
}

// orgINNDenied — типы, прочтение которых снимает ИНН организации.
var orgINNDenied = pii.Set(0).
	Add(pii.INN).
	Add(pii.PassportNumber).
	Add(pii.DriverLicense).
	Add(pii.Phone)

// nearestMarker возвращает класс ближайшего к числу маркера из mask — в том
// же окне и в том же порядке обхода, что findDigitMarkers: сначала слева,
// затем справа. Нужен только при споре двух маркеров, поэтому считается
// отдельно, а не на каждом числе.
func nearestMarker(doc *lex.Doc, first, last int, mask digitMarker) digitMarker {
	if m := digitNearestLeft(doc, first, mask); m != 0 {
		return m
	}
	return digitNearestRight(doc, last, mask)
}

// digitNearestLeft — ближайший маркер из mask слева от числа, в окне
// findDigitMarkers.
func digitNearestLeft(doc *lex.Doc, first int, mask digitMarker) digitMarker {
	for i, seen := first-1, 0; i >= 0 && seen < markerWindowLeft; i-- {
		if hasLineBreak(doc.Gap(i)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		if m := markerAt(doc, i) & mask; m != 0 {
			return m
		}
	}
	return 0
}

// digitNearestRight — ближайший маркер из mask справа от числа, в окне
// findDigitMarkers.
func digitNearestRight(doc *lex.Doc, last int, mask digitMarker) digitMarker {
	for i, seen := last+1, 0; i < len(doc.Tokens) && seen < markerWindowRight; i++ {
		if hasLineBreak(doc.Gap(i - 1)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		if m := markerAt(doc, i) & mask; m != 0 {
			return m
		}
	}
	return 0
}

// emitSeriesNumber разбирает конструкцию «серия 4509 номер 123456» и её
// варианты: серию двумя парами («серия 24 13 № 269252») и водительское
// удостоверение в той же раздельной записи («серия 4098 номер 849020»).
//
// ТЗ §3.2.2 требует учитывать разделяющие слова, а форма у паспорта и
// водительского удостоверения одна, поэтому одно правило обслуживает оба
// типа, а выбор делает ближайший маркер.
//
// Между серией и номером стоит служебное слово, поэтому регистрируются два
// спана, а не один: «номер» и «№» в маску попасть не должны.
func emitSeriesNumber(doc *lex.Doc, r *digitRun, near, all digitMarker, out *Candidates) {
	if !r.seriesShape() || all&(dmPassport|dmDriver|dmDoc) == 0 {
		return
	}
	t, _, ok := docNumberType(near, all)
	if !ok {
		return
	}
	rule := ruleDigitsPassportSeries
	if t == pii.DriverLicense {
		rule = ruleDigitsDriverSeries
	}
	seen := 0
	for k := r.last + 1; k < len(doc.Tokens) && seen <= markerWindowRight; k++ {
		tok := doc.Tokens[k]
		// Знаки препинания окно не расходуют: «№» между серией и номером —
		// такое же служебное обозначение, как слово «номер».
		if tok.Kind == lex.KindPunct {
			continue
		}
		if tok.Kind == lex.KindDigits {
			numEnd, ok := digitsSeriesTail(doc, k)
			if !ok {
				return
			}
			start, end := r.bounds(doc)
			out.Add(start, end, t, Strong, rule)
			out.Add(int(tok.Start), numEnd, t, Strong, rule)
			return
		}
		// Между серией и номером допустимо только служебное слово самой
		// конструкции: «серия 4509 выдан 123456» разбирать нечего.
		if !isNumberWord(doc, k) {
			return
		}
		seen++
	}
}

// emitDriverOldForm разбирает водительское удостоверение старого образца:
// две цифры, две буквы, шесть цифр.
func emitDriverOldForm(doc *lex.Doc, r *digitRun, all digitMarker, out *Candidates) {
	if r.parts != 1 || all&dmDriver == 0 {
		return
	}
	k := r.last + 1
	if k+1 >= len(doc.Tokens) {
		return
	}
	w := doc.Tokens[k]
	if w.Kind != lex.KindWord || utf8.RuneCountInString(doc.NormOf(k)) != 2 {
		return
	}
	n := doc.Tokens[k+1]
	if n.Kind != lex.KindDigits || n.Len() != 6 {
		return
	}
	if !onlySpaces(doc.Gap(r.last), 1) || !onlySpaces(doc.Gap(k), 1) {
		return
	}
	out.Add(int(doc.Tokens[r.first].Start), int(n.End), pii.DriverLicense, Strong, ruleDigitsDriver)
}

// findDigitMarkers ищет маркеры вокруг числа: до четырёх значимых токенов
// слева и до двух справа.
//
// Возвращается объединение всех найденных классов и ближайший к числу класс
// из nearDocMask. Объединение нужно там, где достаточно самого факта маркера;
// ближайший — там, где за одну и ту же форму спорят паспорт, водительское
// удостоверение и номер договора. Слова «серия» и «номер» в этом споре не
// участвуют: они стоят при любом из них.
func findDigitMarkers(doc *lex.Doc, first, last int) (near, all digitMarker) {
	for i, seen := first-1, 0; i >= 0 && seen < markerWindowLeft; i-- {
		// Перевод строки разрывает связь слова с числом: заголовок строкой
		// выше маркером соседней строки не является.
		if hasLineBreak(doc.Gap(i)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		near, all = digitMarkerMerge(near, all, markerAt(doc, i))
	}
	for i, seen := last+1, 0; i < len(doc.Tokens) && seen < markerWindowRight; i++ {
		if hasLineBreak(doc.Gap(i - 1)) {
			break
		}
		if doc.Tokens[i].Kind == lex.KindPunct {
			continue
		}
		seen++
		near, all = digitMarkerMerge(near, all, markerAt(doc, i))
	}
	return near, all
}

// digitMarkerMerge добавляет к накопленным маркерам findDigitMarkers класс m
// очередного токена в порядке обхода; ноль — токен не маркер. Ближайшим
// становится первый встреченный класс из nearDocMask.
func digitMarkerMerge(near, all, m digitMarker) (digitMarker, digitMarker) {
	if m == 0 {
		return near, all
	}
	if near == 0 {
		near = m & nearDocMask
	}
	return near, all | m
}

// markerAt определяет класс маркера для токена i.
func markerAt(doc *lex.Doc, i int) digitMarker {
	// Маркер — всегда слово: число соседнего кандидата маркером быть не может,
	// и перебирать по нему таблицу незачем.
	if doc.Tokens[i].Kind != lex.KindWord {
		return 0
	}
	// Все маркеры длиннее одного байта, так что пустое и однобайтовое слово —
	// латинская буква — маркером быть не может. Проверка стоит до сокращений
	// «в/у» и «к/п»: их буквы «у» и «п» — кириллица в два байта.
	w := doc.NormOf(i)
	if len(w) < 2 {
		return 0
	}
	// Сокращения «в/у» и «к/п» приходят тремя токенами: буква, косая, буква.
	if i >= 2 && doc.NormOf(i-1) == "/" {
		if m := digitSlashMarker(doc, i, w); m != 0 {
			return m
		}
	}
	var m digitMarker
	// Перебирается только корзина первой буквы: таблица смотрится на каждом
	// значимом токене вокруг каждого числа, и полный перебор был самым
	// дорогим местом сканера.
	for _, mk := range digitsMarkerIndex[digitsMarkerKey(w)] {
		if mk.exact {
			if w == mk.word {
				m |= mk.class
			}
			continue
		}
		if strings.HasPrefix(w, mk.word) {
			m |= mk.class
		}
	}
	return digitsMarkerFinal(doc, i, w, m)
}

// digitSlashMarker распознаёт вторую букву сокращений «в/у» и «к/п»: слово w
// в позиции i стоит за косой чертой. Для прочих слов возвращает ноль.
func digitSlashMarker(doc *lex.Doc, i int, w string) digitMarker {
	switch {
	case w == "у" && doc.NormOf(i-2) == "в":
		return dmDriver
	case w == "п" && doc.NormOf(i-2) == "к":
		return dmDept
	}
	return 0
}

// meAt решает, служит ли предлог «at» в позиции i маркером телефона: да,
// если перед ним стоит «me» — «call me at», «reach me at». Одно «at» —
// предлог при любом времени и месте: «meeting at 10 30».
func meAt(doc *lex.Doc, i int) digitMarker {
	k := i - 1
	if k >= 0 && doc.Tokens[k].Kind == lex.KindWord && doc.NormOf(k) == "me" && onlySpaces(doc.Gap(k), 2) {
		return dmPhone
	}
	return 0
}

// onlySpaces сообщает, что промежуток состоит не более чем из max пробелов
// или табуляций. Пустой промежуток подходит.
//
// Неразрывный пробел U+00A0, узкий неразрывный U+202F, типографские пробелы
// U+2000–U+200A (среди них цифровой U+2007 и тонкий U+2009) и U+205F тоже
// считаются пробелом, каждый за один: текстовые редакторы и вёрстка
// разделяют ими группы цифр («4111 1111 1111 1111» с U+00A0), и номер,
// записанный так, уходил открытым (замечание технического жюри 23.09, S3).
//
// Невидимые форматирующие символы категории Cf — ZWSP U+200B, ZWNJ и ZWJ
// U+200C и U+200D, U+2060, U+FEFF, мягкий перенос U+00AD — не считаются
// вовсе: лексер разбирает их между цифрами как пробел (описание пакета
// internal/lex), а на экране их нет. Без этого «4276\u200b0198\u200b…»
// распадалось на четыре числа, и номер карты уходил открытым (технический
// жюри 23.09, P4-6).
//
// Обычный промежуток — один ASCII-пробел, и он разбирается без
// декодирования рун.
func onlySpaces(s string, limit int) bool {
	n := 0
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			if c != ' ' && c != '\t' {
				return false
			}
			i++
			n++
		} else {
			r, size := utf8.DecodeRuneInString(s[i:])
			i += size
			switch {
			case gapSpace(r):
				n++
			case !unicode.Is(unicode.Cf, r):
				return false
			}
		}
		if n > limit {
			return false
		}
	}
	return true
}

// gapSpace сообщает, что руна — видимый пробел шириной с обычный или уже.
func gapSpace(r rune) bool {
	return r == 0x00A0 || r == 0x202F || r == 0x205F || (r >= 0x2000 && r <= 0x200A)
}

// zeroWidth сообщает, что промежуток пуст или состоит только из невидимых
// форматирующих символов: для дефиса, точки и косой черты это «вплотную».
//
// Пустой промежуток — почти единственный, что здесь встречается, поэтому
// проверка на него вынесена в функцию, которая встраивается в место вызова,
// а разбор рун — в отдельную.
func zeroWidth(s string) bool { return s == "" || invisibleOnly(s) }

// invisibleOnly сообщает, что непустая строка состоит только из символов
// категории Cf.
func invisibleOnly(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r < utf8.RuneSelf || !unicode.Is(unicode.Cf, r) {
			return false
		}
		i += size
	}
	return true
}

// hasLineBreak сообщает, что в промежутке есть перевод строки.
func hasLineBreak(s string) bool { return lex.HasLineBreak(s) }
