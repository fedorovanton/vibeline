package detect

import (
	"strings"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Сканер адреса и его компонентов: страна, индекс, регион, город, улица, дом,
// корпус, строение, квартира. ТЗ считает адрес одним типом, поэтому цепочка
// компонентов выдаётся одним спаном pii.Address, а не россыпью типов.
//
// Улицы списком не ведутся: их сотни тысяч, и список устаревает быстрее, чем
// его успевают обновлять. Поэтому адрес собирается вокруг маркеров компонентов
// («ул.», «д.», «кв.»), а населённый пункт и регион подтверждаются
// справочником. Цепочка растёт слева направо, пока соседние токены остаются
// компонентами адреса, и закрывается на первом постороннем слове — поэтому
// «проживает по адресу» в спан не попадает: эти слова компонентами не являются
// и цепочку не открывают.
//
// Границы спана — принятое решение, а не побочный эффект разбора.
// Сокращения-маркеры включаются в спан, когда стоят ВНУТРИ цепочки:
// «Москва, ул. Ленина, д. 5, кв. 12» — один спан целиком. Обрывать цепочку на
// каждом «д.» значило бы породить россыпь огрызков: их нельзя прочитать как
// адрес, нельзя осмысленно пронумеровать плейсхолдерами, а восстановленный
// текст распадается на «[АДРЕС_1], д. [АДРЕС_2], кв. [АДРЕС_3]». Внутри
// цепочки маркер служебным словом быть перестаёт — он часть значения.
// Но маркер, открывающий или закрывающий цепочку, в спан НЕ входит:
// «г. Москва, ул. Ленина» → спан начинается с «Москва», «кв. 45» → спан «45».
// Это прямое требование CONTRACTS.md («ул. Ленина, д. 5» → правильный спан
// «Ленина, д. 5») и AGENTS.md: служебное слово на границе значения — это
// избыточное маскирование, оно штрафуется отдельной проверкой.
//
// Контр-правила ловушек (адрес отделения банка, офис организации) здесь не
// применяются: сканер только регистрирует кандидата, вето ставит отдельное
// правило, а решение принимает движок.

func init() { Register(addressScanner{}) }

// Справочники сканера. Маркеры лежат в справочнике, а не в константах кода:
// ТЗ §3.2.1 требует расширять набор распознаваемого без правки ядра.
const (
	addressMarkersTable = "address_markers"
	geoCitiesTable      = "geo_cities"
	geoRegionsTable     = "geo_regions"
	// addrGivenNamesTable — справочник личных имён. Его ведёт сканер ФИО,
	// здесь он только читается: город рядом с именем — фамилия, а не адрес.
	addrGivenNamesTable = "given_names"
)

// Имена правил. Идут в отладочные отчёты рядом с типом и уверенностью,
// значением ПД они не сопровождаются.
const (
	ruleAddressFull       = "address/index_city_street"
	ruleAddressComponents = "address/components"
	ruleAddressSingle     = "address/single_component"
	ruleAddressStreet     = "address/street_house"
	// ruleAddressCitySurname — не адрес, а ФИО: город из справочника вплотную
	// к личному имени («Жуков Игорь», «Юрий Гагарин»).
	ruleAddressCitySurname = "address/city_surname"
)

const (
	// maxAddrToponymTokens — предел длины составного топонима в токенах.
	// «Ростов-на-Дону» — пять токенов, «Ханты-Мансийский автономный округ» —
	// пять; семи хватает с запасом, а перебор дальше только греет процессор.
	maxAddrToponymTokens = 7
	// maxAddrSeps — сколько знаков препинания подряд допустимо между
	// компонентами. Двух хватает на «д. 5, кв. 12» и на «ул.,», больше —
	// уже не адрес, а перечисление.
	maxAddrSeps = 2
	// maxAddrSepSpaces — предел пробелов между соседними токенами цепочки.
	// Перевод строки сюда не проходит: соседняя строка — другой контекст.
	maxAddrSepSpaces = 3
	// maxAddrNameRun — сколько капитализированных слов подряд принимается за
	// одно название: «ул. Красных Партизан».
	maxAddrNameRun = 2
	// maxAddrNumberLen — предел длины номера дома, корпуса и квартиры в цифрах.
	maxAddrNumberLen = 6
	// addrIndexLen — длина почтового индекса России.
	addrIndexLen = 6
)

// addrKind — класс компонента адреса. Совпадает с метками справочника маркеров.
type addrKind uint16

const (
	akCity addrKind = 1 << iota
	akStreet
	akHouse
	akFlat
	akBuilding
	akRegion
	akIndex
	// akOblique — маркер улицы в косвенном падеже: «на улице», «на
	// проспекте». Метка справочника street_oblique. Такой маркер — обычное
	// слово речи («на улице холодно»), поэтому засчитывается только внутри
	// цепочки после населённого пункта или после «живу на», и только если
	// за ним стоит название с номером дома. Из класса маркера снимается
	// сразу после проверки: дальше он ведёт себя как «ул.».
	akOblique
	// akAnchor — название улицы открыто контекстом проживания: «живу на
	// Баумана 12». Метка компонента, а не справочника.
	akAnchor
)

// addrKindOf переводит метку справочника в класс компонента.
func addrKindOf(label string) addrKind {
	switch label {
	case "city":
		return akCity
	case "street":
		return akStreet
	case "street_oblique":
		return akStreet | akOblique
	case "house":
		return akHouse
	case "flat":
		return akFlat
	case "building":
		return akBuilding
	case "region":
		return akRegion
	case "index":
		return akIndex
	}
	return 0
}

// addrRole — роль токена в цепочке адреса.
type addrRole uint8

const (
	addrRoleNone addrRole = iota
	// addrRoleMarker — маркер компонента: «ул.», «д.», «обл.».
	addrRoleMarker
	// addrRoleIndex — почтовый индекс: шесть цифр, первая не ноль.
	addrRoleIndex
	// addrRoleCity — населённый пункт из справочника.
	addrRoleCity
	// addrRoleRegion — регион или страна из справочника.
	addrRoleRegion
	// addrRoleName — название улицы или пункта, не подтверждённое справочником.
	addrRoleName
	// addrRoleNumber — номер дома, корпуса, квартиры.
	addrRoleNumber
)

// addrFlags — признаки, набранные цепочкой; по ним выбирается уверенность.
type addrFlags uint8

const (
	// afIndex — в цепочке есть почтовый индекс.
	afIndex addrFlags = 1 << iota
	// afCity — населённый пункт подтверждён справочником.
	afCity
	// afStreet — есть улица: маркер проезда либо название перед номером дома.
	afStreet
	// afHouse — есть номер дома при улице.
	afHouse
	// afNamedStreet — улица названа и опознана как улица не по одной форме
	// слова: название стоит при маркере проезда («ул. Молодёжная»,
	// «Кутузовский проспект») или открыто контекстом проживания.
	afNamedStreet
)

// afCertain — набор признаков полного адреса: индекс, город из справочника и
// улица с номером дома. Такую цепочку нельзя принять за что-то другое.
const afCertain = afIndex | afCity | afStreet | afHouse

// addressScanner — сканер адреса.
type addressScanner struct{}

// Name возвращает имя сканера.
func (addressScanner) Name() string { return "address" }

// Scan находит адреса и их компоненты и дописывает кандидатов в out.
//
// Состояния между вызовами нет: единственная изменяемая структура — текущая
// цепочка — живёт на стеке вызова и переиспользуется внутри одного прохода.
func (addressScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	tabs := addrTables{
		markers: dicts.Table(addressMarkersTable),
		cities:  dicts.Table(geoCitiesTable),
		regions: dicts.Table(geoRegionsTable),
		given:   dicts.Table(addrGivenNamesTable),
	}
	var ch addressChain
	for i := 0; i < len(doc.Tokens); {
		// Разрыв текста рвёт цепочку: перевод строки и длинный пробел между
		// токенами означают, что дальше идёт другой фрагмент, а не адрес.
		if ch.open && i > 0 && !onlySpaces(doc.Gap(i-1), maxAddrSepSpaces) {
			ch.flush(doc, out)
		}
		role, kind, last := addrRoleAt(doc, tabs, &ch, i, out)
		if role != addrRoleNone {
			ch.add(role, kind, i, last)
			i = last + 1
			continue
		}
		if ch.open && ch.seps < maxAddrSeps && addrIsSeparator(doc, i) {
			ch.addSep(doc, i)
			i++
			continue
		}
		if ch.open && ch.seps < maxAddrSeps && addrIsConnector(doc, tabs, &ch, i) {
			// «Казани на улице Баумана»: предлог между пунктом и улицей
			// остаётся внутри цепочки, как запятая в «Казань, ул. Баумана».
			ch.seps++
			ch.numJoin = false
			i++
			continue
		}
		ch.flush(doc, out)
		i++
	}
	ch.flush(doc, out)
}

// addrTables — справочники сканера, собранные один раз на проход.
type addrTables struct {
	markers *dict.Table
	cities  *dict.Table
	regions *dict.Table
	given   *dict.Table
}

// addressChain — цепочка компонентов, собираемая сейчас.
//
// firstVal и lastVal — границы значения: маркеры, открывающие и закрывающие
// цепочку, в них не попадают. Внутренние маркеры попадают неизбежно, так как
// лежат между значениями.
type addressChain struct {
	open     bool
	hasVal   bool
	firstVal int
	lastVal  int
	comps    int
	flags    addrFlags
	lastRole addrRole
	lastKind addrKind
	nameRun  int
	seps     int
	// numJoin — последний разделитель склеивает числа: «д. 5/2», «5-7».
	numJoin bool
	// streetNum — последний компонент — число сразу за маркером улицы:
	// «ул. 8» в «ул. 8 Марта». Если за ним идёт название, число было частью
	// названия улицы, а не номером дома.
	streetNum bool
	// marked — в цепочке есть маркер компонента: «г.», «ул.», «обл.».
	marked bool
	// house — последний компонент — номер дома: число за названием улицы
	// или за маркером дома. За ним без маркера может стоять квартира:
	// «Шереметевский 85 207».
	house bool
}

// add присоединяет к цепочке компонент, занимающий токены from..to.
func (ch *addressChain) add(role addrRole, kind addrKind, from, to int) {
	if !ch.open {
		*ch = addressChain{open: true}
	}
	if role != addrRoleMarker {
		if !ch.hasVal {
			ch.firstVal = from
			ch.hasVal = true
		}
		ch.lastVal = to
	}
	ch.countComponent(role, kind)
	ch.setFlags(role, kind)
	if role == addrRoleMarker {
		ch.marked = true
	}
	streetNum := role == addrRoleNumber && ch.lastRole == addrRoleMarker && ch.lastKind&akStreet != 0
	ch.house = role == addrRoleNumber && ch.houseNumberNext()
	if role == addrRoleName {
		ch.nameRun++
	} else {
		ch.nameRun = 0
	}
	ch.lastRole, ch.lastKind = role, kind
	ch.seps = 0
	ch.numJoin = false
	ch.streetNum = streetNum
}

// countComponent считает компоненты адреса, а не сработавшие признаки:
// значение при своём маркере — это один компонент, а не два. От счётчика
// зависит уверенность, поэтому «г. Москва» обязано остаться одним компонентом.
func (ch *addressChain) countComponent(role addrRole, kind addrKind) {
	switch role {
	case addrRoleMarker:
		// Маркер сразу после названия своего же класса завершает тот же
		// компонент: «Невский проспект» — одна улица, «Одинцовский р-н» —
		// один район, а не название плюс отдельный компонент-маркер.
		if ch.lastRole == addrRoleName && ch.lastKind&kind != 0 {
			return
		}
		ch.comps++
	case addrRoleCity, addrRoleRegion, addrRoleIndex:
		if ch.lastRole == addrRoleMarker && ch.lastKind&kind != 0 {
			return
		}
		ch.comps++
	case addrRoleName:
		if ch.lastRole == addrRoleMarker || ch.lastRole == addrRoleName {
			return
		}
		ch.comps++
	case addrRoleNumber:
		// Номер — значение предыдущего компонента, своим он не бывает.
	}
}

// setFlags отмечает признаки, по которым выбирается уверенность.
func (ch *addressChain) setFlags(role addrRole, kind addrKind) {
	switch role {
	case addrRoleIndex:
		ch.flags |= afIndex
	case addrRoleCity:
		ch.flags |= afCity
	case addrRoleMarker, addrRoleName:
		if kind&akStreet != 0 {
			ch.flags |= afStreet
		}
		ch.setNamedStreet(role, kind)
	case addrRoleNumber:
		if ch.lastKind&(akStreet|akHouse) != 0 {
			ch.flags |= afHouse
		}
	}
}

// setNamedStreet отмечает названную улицу для маркера или названия.
func (ch *addressChain) setNamedStreet(role addrRole, kind addrKind) {
	switch {
	case kind&akAnchor != 0:
		ch.flags |= afNamedStreet
	case role == addrRoleName && kind&akStreet != 0 && ch.lastRole == addrRoleMarker && ch.lastKind&akStreet != 0:
		// «ул. Молодёжная»: название при маркере слева.
		ch.flags |= afNamedStreet
	case role == addrRoleMarker && kind&akStreet != 0 && ch.lastRole == addrRoleName && ch.lastKind&akStreet != 0:
		// «Кутузовский проспект»: маркер справа от названия.
		ch.flags |= afNamedStreet
	case role == addrRoleName && ch.streetNum:
		// «ул. 8 Марта»: число было началом названия, а не домом.
		ch.flags = ch.flags&^afHouse | afNamedStreet
	}
}

// addSep запоминает разделитель между компонентами.
func (ch *addressChain) addSep(doc *lex.Doc, i int) {
	ch.seps++
	// Дробь и дефис вплотную склеивают числа: «д. 5/2» — один номер дома.
	c := doc.Text[doc.Tokens[i].Start]
	ch.numJoin = (c == '/' || c == '-') && doc.Adjacent(i) && i > 0 && doc.Adjacent(i-1)
}

// houseNumberNext сообщает, что число, которое присоединится к цепочке
// следующим, — номер дома: слева название улицы или маркер дома.
func (ch *addressChain) houseNumberNext() bool {
	switch ch.lastRole {
	case addrRoleName:
		return ch.lastKind&akStreet != 0
	case addrRoleMarker:
		return ch.lastKind&akHouse != 0
	}
	return false
}

// expectsNumber сообщает, что следующее число будет номером компонента,
// а не посторонней цифрой.
func (ch *addressChain) expectsNumber() bool {
	if !ch.open {
		return false
	}
	switch ch.lastRole {
	case addrRoleMarker:
		return ch.lastKind&(akStreet|akHouse|akFlat|akBuilding|akIndex) != 0
	case addrRoleName:
		return ch.lastKind&akStreet != 0
	case addrRoleNumber:
		return ch.numJoin
	}
	return false
}

// flush закрывает цепочку и регистрирует кандидата.
func (ch *addressChain) flush(doc *lex.Doc, out *Candidates) {
	if !ch.open {
		return
	}
	if ch.hasVal && ch.comps > 0 && !ch.bareToponym(doc) {
		conf, rule := ch.verdict()
		out.Add(int(doc.Tokens[ch.firstVal].Start), int(doc.Tokens[ch.lastVal].End), pii.Address, conf, rule)
	}
	*ch = addressChain{}
}

// bareToponym сообщает, что цепочка — одно название города или региона без
// маркера, индекса и дома, и слева нет слов об адресе: «любит
// Санкт-Петербург», «Паспорт РФ». Такое название — география речи, а не
// адрес субъекта. Раньше оно заводило слабого кандидата, и подъём по кластеру
// рядом с любыми ПД делал его [АДРЕС] (замечание технического жюри 23.09,
// раунд 4, P4-11). С маркером («г. Казань»), с другими компонентами или после
// «адрес», «проживает», «регион» кандидат по-прежнему заводится.
func (ch *addressChain) bareToponym(doc *lex.Doc) bool {
	if ch.marked || ch.comps != 1 || ch.flags&^afCity != 0 {
		return false
	}
	if ch.lastRole != addrRoleCity && ch.lastRole != addrRoleRegion {
		return false
	}
	return !addrContextBefore(doc, ch.firstVal)
}

// addrContextWindow — сколько значимых слов слева от названия ищется слово
// об адресе.
const addrContextWindow = 3

// addrContextBefore сообщает, что слева от токена at в пределах строки стоит
// слово об адресе или месте жительства: «адрес: Москва», «проживает в
// Казани», «регион — Татарстан».
func addrContextBefore(doc *lex.Doc, at int) bool {
	for i, seen := at-1, 0; i >= 0 && seen < addrContextWindow; i-- {
		if hasLineBreak(doc.Gap(i)) {
			return false
		}
		t := doc.Tokens[i]
		if t.Kind == lex.KindPunct {
			continue
		}
		seen++
		if t.Kind != lex.KindWord {
			continue
		}
		w := doc.NormOf(i)
		if addrIsResidenceWord(w) {
			return true
		}
		for _, p := range addrContextStems {
			if strings.HasPrefix(w, p) {
				return true
			}
		}
	}
	return false
}

// addrContextStems — основы слов об адресе и месте жительства.
var addrContextStems = [...]string{
	"адрес", "прописк", "регистрац", "жительств", "проживани", "регион",
	"доставк", "почтов", "населенн",
}

// verdict выбирает уверенность по набранным компонентам.
//
// Уровни здесь — перечисление сработавших условий, а не вероятность:
// Certain — полный адрес, который не спутать ни с чем другим; Strong — два и
// более самостоятельных компонента; Weak — один компонент, форма и только.
func (ch *addressChain) verdict() (Confidence, string) {
	switch {
	case ch.flags&afCertain == afCertain:
		return Certain, ruleAddressFull
	case ch.comps >= 2:
		return Strong, ruleAddressComponents
	case ch.flags&(afNamedStreet|afHouse) == afNamedStreet|afHouse:
		// Названная улица с номером дома — «ул. Молодёжная, 4», «живу на
		// Баумана 12» — адрес и без города: улицу без дома («ул. Пушкина»)
		// правило не поднимает.
		return Strong, ruleAddressStreet
	default:
		return Weak, ruleAddressSingle
	}
}

// addrRoleAt определяет роль токена i в цепочке и последний занятый им токен:
// топоним и дефисное сокращение занимают несколько токенов.
//
// Аргумент out нужен одному случаю: город, оказавшийся фамилией рядом с
// личным именем, регистрируется кандидатом ФИО — см. addrCityAsName.
func addrRoleAt(doc *lex.Doc, tabs addrTables, ch *addressChain, i int, out *Candidates) (addrRole, addrKind, int) {
	switch doc.Tokens[i].Kind {
	case lex.KindDigits:
		return addrDigitsRole(doc, ch, i)
	case lex.KindWord:
		return addrWordRole(doc, tabs, ch, i, out)
	}
	return addrRoleNone, 0, i
}

// addrDigitsRole разбирает число: индекс либо номер компонента.
//
// Одиночное число без цепочки адресом не считается ни при каких условиях —
// иначе адресом станет любая цифра в тексте.
func addrDigitsRole(doc *lex.Doc, ch *addressChain, i int) (addrRole, addrKind, int) {
	t := doc.Tokens[i]
	n := t.Len()
	// Индекс России: ровно шесть цифр, первая не ноль.
	isIndex := n == addrIndexLen && doc.Text[t.Start] != '0'
	// Число сразу после маркера дома или квартиры — номер, даже если по форме
	// похоже на индекс. Исключение — сам маркер индекса: там ждут индекс.
	numberHere := ch.expectsNumber()
	if isIndex && (!numberHere || ch.lastKind == akIndex) {
		// Маркер индекса слева сильнее контекста: «индекс 150000 руб.» —
		// опечатка, а не сумма.
		if ch.open && ch.lastRole == addrRoleMarker && ch.lastKind == akIndex || !addrNotIndex(doc, i) {
			return addrRoleIndex, akIndex, i
		}
		return addrRoleNone, 0, i
	}
	// Число, с которого начинается дата, номером дома не бывает: в «Жуков
	// Игорь 12.03.1985» цепочка забирала день даты, и дата разрывалась
	// (бизнес-жюри 23.09, раунд 4, Б4-6).
	if numberHere && n <= maxAddrNumberLen && !addrDateStart(doc, i) {
		return addrRoleNumber, 0, addrNumberTail(doc, i)
	}
	if addrFlatAfterHouse(doc, ch, i) {
		return addrRoleNumber, 0, i
	}
	return addrRoleNone, 0, i
}

// addrFlatMaxLen — предел длины номера квартиры без маркера в цифрах.
const addrFlatMaxLen = 4

// addrFlatAfterHouse сообщает, что число i — номер квартиры без маркера
// сразу за номером дома: «153002 Иваново Шереметевский 85 207» (техническое
// жюри 23.09, раунд 5, P5-5). Раньше цепочка закрывалась на доме, и квартира
// уходила в модель открытой.
//
// Число без маркера — самая слабая форма компонента, поэтому условия узкие:
// в цепочке есть улица, число стоит через один пробел за номером дома, не
// длиннее четырёх цифр, не начинает дату, и адрес на нём заканчивается —
// дальше конец текста, строки или знак препинания, не склеенный с цифрами.
// «Тверская 5 2 раза» и «ул. Ленина 5 12 лет» квартиры не дают: за числом
// идёт слово; «ул. Тверская, 12 12.03.1985» — тоже: за числом дата.
func addrFlatAfterHouse(doc *lex.Doc, ch *addressChain, i int) bool {
	if !ch.open || !ch.house || ch.flags&afStreet == 0 || ch.lastVal != i-1 || doc.Gap(i-1) != " " {
		return false
	}
	if doc.Tokens[i].Len() > addrFlatMaxLen || addrDateStart(doc, i) {
		return false
	}
	k := i + 1
	if k >= len(doc.Tokens) || hasLineBreak(doc.Gap(i)) {
		return true
	}
	return doc.Tokens[k].Kind == lex.KindPunct && addrClosingPunct(doc, k) && !addrDigitGlue(doc, k)
}

// addrDigitGlue сообщает, что знак k склеивает цифры вплотную: «12.03.1985»,
// «1,5». Такое число — начало даты или дроби, а не номер квартиры.
func addrDigitGlue(doc *lex.Doc, k int) bool {
	return k+1 < len(doc.Tokens) && doc.Tokens[k+1].Kind == lex.KindDigits &&
		doc.Adjacent(k-1) && doc.Adjacent(k)
}

// addrClosingPunct сообщает, что знак k закрывает адрес: запятая, точка,
// точка с запятой, скобка, восклицательный или вопросительный знак.
func addrClosingPunct(doc *lex.Doc, k int) bool {
	switch doc.Text[doc.Tokens[k].Start] {
	case ',', '.', ';', ')', '!', '?':
		return true
	}
	return false
}

// addrDateStart сообщает, что с токена i начинается числовая дата
// «дд.мм.гггг». Разбор тот же, что у сканера дат.
func addrDateStart(doc *lex.Doc, i int) bool {
	_, _, ok := matchNumericDate(doc, i)
	return ok
}

// addrNotIndex сообщает, что шестизначное число по контексту не почтовый
// индекс, а номер или сумма:
//
//   - часть числовой группы через пробел: «договор № 4618 507329» — серия и
//     номер, а не индекс (замечание технического жюри 23.09, раунд 4, P4-5);
//   - после знака номера или слова-номера: «пасп. 45 12 № 889901»,
//     «заявка 123456», «№ договора 123456» (Б4-16);
//   - сумма денег: перед валютой («500000 рублей», «150000 руб.», «₽») или
//     после денежного слова, в том числе через предлог: «сумма 150000»,
//     «кредит на 500000» (Б4-12, находка раунда 3).
func addrNotIndex(doc *lex.Doc, i int) bool {
	toks := doc.Tokens
	if addrInDigitGroup(doc, i) || addrCurrencyAfter(doc, i) {
		return true
	}
	p := addrPrevSignificant(doc, i)
	if p < 0 {
		return false
	}
	if toks[p].Kind == lex.KindPunct {
		return addrIsNumberSign(doc, p)
	}
	if toks[p].Kind != lex.KindWord {
		return false
	}
	w := doc.NormOf(p)
	if addrIsNumberWord(w) || addrIsMoneyWord(w) {
		return true
	}
	// «кредит на 500000», «№ договора 123456»: предлог или слово между
	// числом и признаком — одно, дальше не ищется.
	return addrIsLinkWord(w) && addrSignOrMoneyBefore(doc, p)
}

// addrInDigitGroup сообщает, что число i — часть числовой группы через
// пробел: слева или справа вплотную через пробел стоит ещё число.
func addrInDigitGroup(doc *lex.Doc, i int) bool {
	toks := doc.Tokens
	if i > 0 && toks[i-1].Kind == lex.KindDigits && dateSpaceGap(doc.Gap(i-1)) {
		return true
	}
	return i+1 < len(toks) && toks[i+1].Kind == lex.KindDigits && dateSpaceGap(doc.Gap(i))
}

// addrIsLinkWord — предлоги и слова, которые стоят между числом и знаком
// номера или денежным словом: «кредит на 500000», «№ договора 123456».
func addrIsLinkWord(w string) bool {
	switch w {
	case "на", "в", "до", "от", "за", "договора", "заявки", "обращения", "заказа":
		return true
	}
	return false
}

// addrSignOrMoneyBefore сообщает, что ближайший значимый токен слева от p —
// знак номера или денежное слово.
func addrSignOrMoneyBefore(doc *lex.Doc, p int) bool {
	q := addrPrevSignificant(doc, p)
	if q < 0 {
		return false
	}
	if doc.Tokens[q].Kind == lex.KindPunct {
		return addrIsNumberSign(doc, q)
	}
	return doc.Tokens[q].Kind == lex.KindWord && addrIsMoneyWord(doc.NormOf(q))
}

// addrIsNumberSign сообщает, что знак i — знак номера: «№» или «#».
func addrIsNumberSign(doc *lex.Doc, i int) bool {
	r := doc.Raw(i)
	return r == "№" || r == "#"
}

// addrPrevSignificant возвращает ближайший слева токен, пропуская точку и
// двоеточие («пасп.», «договор:»), в пределах строки и трёх токенов. Для его
// отсутствия возвращается -1.
func addrPrevSignificant(doc *lex.Doc, i int) int {
	for j := i - 1; j >= 0 && i-j <= 3; j-- {
		if hasLineBreak(doc.Gap(j)) {
			return -1
		}
		if doc.Tokens[j].Kind == lex.KindPunct {
			if r := doc.Raw(j); r == ":" || r == "." {
				continue
			}
		}
		return j
	}
	return -1
}

// addrCurrencyAfter сообщает, что сразу за числом через пробел или вплотную
// стоит обозначение валюты.
func addrCurrencyAfter(doc *lex.Doc, i int) bool {
	toks := doc.Tokens
	j := i + 1
	if j >= len(toks) || !doc.Adjacent(i) && !onlySpaces(doc.Gap(i), 1) {
		return false
	}
	switch toks[j].Kind {
	case lex.KindPunct:
		return addrIsCurrencySign(doc.Raw(j))
	case lex.KindWord:
		return addrCurrencyWord(doc, j)
	}
	return false
}

// addrIsCurrencySign — знаки валют.
func addrIsCurrencySign(raw string) bool {
	switch raw {
	case "₽", "$", "€":
		return true
	}
	return false
}

// addrCurrencyWord сообщает, что слово j — название или сокращение валюты
// либо разряда суммы.
func addrCurrencyWord(doc *lex.Doc, j int) bool {
	switch doc.NormOf(j) {
	case "р":
		// «р-н» после индекса — район, а не рубли.
		return j+1 >= len(doc.Tokens) || !doc.Adjacent(j) || doc.Raw(j+1) != "-"
	case "руб", "рублей", "рубля", "рубль", "rub", "rur", "usd", "eur",
		"долларов", "доллара", "евро", "тыс", "млн", "тенге", "сом", "грн":
		return true
	}
	return false
}

// addrIsNumberWord — слова, после которых число — номер документа или
// обращения: «договор», «заявка», «номер», «код».
func addrIsNumberWord(w string) bool {
	switch w {
	case "ном", "no", "n", "код", "кп", "id":
		return true
	}
	for _, p := range addrNumberStems {
		if strings.HasPrefix(w, p) {
			return true
		}
	}
	return false
}

// addrNumberStems — основы слов-номеров.
var addrNumberStems = [...]string{"договор", "заявк", "обращени", "заказ", "номер", "полис", "тикет"}

// addrIsMoneyWord — слова, после которых число — сумма денег.
func addrIsMoneyWord(w string) bool {
	for _, p := range addrMoneyStems {
		if strings.HasPrefix(w, p) {
			return true
		}
	}
	return false
}

// addrMoneyStems — основы денежных слов.
var addrMoneyStems = [...]string{
	"сумм", "стоимост", "лимит", "остат", "баланс", "задолженност", "долг",
	"платеж", "взнос", "кредит", "займ", "заем", "ипотек", "вклад", "депозит",
	"доход", "зарплат", "перевод", "комисси", "штраф", "цен",
}

// addrCityAsName решает, что город из справочника в позиции i..last — часть
// ФИО, а не адрес, и регистрирует кандидата ФИО на пару «фамилия — имя».
//
// Фамилии, совпадающие с городами, — Жуков, Королёв, Чехов, Киров, Ершов,
// Сокол, Орёл, Гагарин — обычны. Рядом с личным именем из справочника такой
// «город» становился адресом, а цепочка забирала имя и день даты рождения:
// «Клиент Жуков Игорь 12.03.1985» → «Клиент [АДРЕС_1].03.1985»
// (бизнес-жюри 23.09, раунд 4, Б4-6, 7 из 10). Правило позиционное: имя
// стоит вплотную через один пробел — до или после, — и слева нет маркера
// населённого пункта («г. Киров Олег…» — по-прежнему адрес).
//
// Случай, когда сам город — личное имя («Владимир Высоцкий»), кандидата не
// заводит: такую пару находит сканер ФИО, здесь только снимается адрес.
// Контр-правила ловушек применяются к кандидату ФИО как обычно: публичная
// персона («Маршал Георгий Жуков») остаётся открытой.
func addrCityAsName(doc *lex.Doc, tabs addrTables, ch *addressChain, i, last int, out *Candidates) bool {
	if last != i || tabs.given == nil {
		return false
	}
	if ch.open && ch.lastRole == addrRoleMarker && ch.lastKind&akCity != 0 {
		return false
	}
	toks := doc.Tokens
	switch {
	case i+1 < len(toks) && doc.Gap(i) == " " && addrIsGivenName(doc, tabs, i+1):
		out.Add(int(toks[i].Start), int(toks[i+1].End), pii.FullName, Strong, ruleAddressCitySurname)
		return true
	case i > 0 && doc.Gap(i-1) == " " && addrIsGivenName(doc, tabs, i-1):
		out.Add(int(toks[i-1].Start), int(toks[i].End), pii.FullName, Strong, ruleAddressCitySurname)
		return true
	case addrIsGivenName(doc, tabs, i) && i+1 < len(toks) && doc.Gap(i) == " " &&
		toks[i+1].Kind == lex.KindWord && toks[i+1].Flags.Has(lex.FlagFirstUpper):
		// «Владимир Высоцкий»: город-имя перед словом с заглавной, которое
		// не маркер и не топоним.
		if _, _, isMarker := addrMarker(doc, tabs.markers, i+1); isMarker {
			return false
		}
		if _, isCity := addrToponym(doc, tabs.cities, i+1); isCity {
			return false
		}
		_, isRegion := addrToponym(doc, tabs.regions, i+1)
		return !isRegion
	}
	return false
}

// addrIsGivenName сообщает, что токен j — слово с заглавной из справочника
// личных имён.
func addrIsGivenName(doc *lex.Doc, tabs addrTables, j int) bool {
	t := doc.Tokens[j]
	return t.Kind == lex.KindWord && t.Flags.Has(lex.FlagFirstUpper) && tabs.given.Has(doc.NormOf(j))
}

// addrNumberTail прихватывает буквенный индекс дома: «д. 5а» — один номер.
func addrNumberTail(doc *lex.Doc, i int) int {
	j := i + 1
	if j >= len(doc.Tokens) || !doc.Adjacent(i) {
		return i
	}
	t := doc.Tokens[j]
	if t.Kind == lex.KindWord && t.Len() <= 2 {
		return j
	}
	return i
}

// addrWordRole разбирает слово: топоним из справочника, маркер компонента
// либо название внутри уже открытой цепочки.
func addrWordRole(doc *lex.Doc, tabs addrTables, ch *addressChain, i int, out *Candidates) (addrRole, addrKind, int) {
	upper := doc.Tokens[i].Flags.Has(lex.FlagFirstUpper)
	// Топоним обязан быть с заглавной буквы: «город орел» — не адрес.
	// Проверка регистра идёт по флагам лексера, а сравнение со справочником —
	// по нормализованному тексту, поэтому «МОСКВА» находится так же.
	if upper {
		if role, kind, last, ok := addrToponymRole(doc, tabs, ch, i, out); ok {
			return role, kind, last
		}
	}
	if kind, last, ok := addrMarker(doc, tabs.markers, i); ok {
		if kind, ok = addrMarkerFits(doc, tabs, ch, kind, i, last); ok {
			return addrRoleMarker, kind, last
		}
		return addrRoleNone, 0, i
	}
	if kind, ok := addrBareLetterMarker(doc, tabs, ch, i); ok {
		return addrRoleMarker, kind, i
	}
	if ch.open && addrStreetConnector(doc, ch, i) {
		return addrRoleName, akStreet, i
	}
	if !upper {
		return addrRoleNone, 0, i
	}
	if !ch.open {
		return addrOpeningRole(doc, tabs, i)
	}
	if kind, ok := addrNameFits(doc, tabs, ch, i); ok {
		return addrRoleName, kind, i
	}
	return addrRoleNone, 0, i
}

// addrBareLetterMarker разбирает однобуквенное сокращение без точки:
// «г Иваново ул Лежневская д 120 кв 5» (техническое жюри 23.09, раунд 5,
// P5-5). Без точки одна буква — это и предлог, и инициал, поэтому маркером
// она признаётся только по контексту с обеих сторон:
//
//   - маркер дома («д») — внутри цепочки сразу за названием улицы и перед
//     номером: «Лежневская д 120»;
//   - маркер корпуса, строения, квартиры («к») — сразу за номером дома и
//     перед номером: «д 5 к 2»;
//   - маркер населённого пункта («г») — перед городом или регионом из
//     справочника: «г Иваново».
//
// «к 10 утра», «с Москвой», инициал «И Петров» маркерами не становятся:
// справа нет ни номера за улицей, ни города из справочника.
func addrBareLetterMarker(doc *lex.Doc, tabs addrTables, ch *addressChain, i int) (addrKind, bool) {
	t := doc.Tokens[i]
	if t.Len() > 2 || tabs.markers == nil {
		return 0, false
	}
	label, ok := tabs.markers.Get(doc.NormOf(i))
	if !ok {
		return 0, false
	}
	switch kind := addrKindOf(label); {
	case kind == akHouse:
		return kind, ch.open && ch.lastRole == addrRoleName && ch.lastKind&akStreet != 0 && addrNextIsNumber(doc, i)
	case kind&(akBuilding|akFlat) != 0:
		return kind, ch.open && ch.house && addrNextIsNumber(doc, i)
	case kind == akCity:
		return kind, addrCityAhead(doc, tabs, i)
	}
	return 0, false
}

// addrCityAhead сообщает, что за токеном i через один пробел стоит город или
// регион из справочника.
func addrCityAhead(doc *lex.Doc, tabs addrTables, i int) bool {
	j := i + 1
	if j >= len(doc.Tokens) || doc.Gap(i) != " " || doc.Tokens[j].Kind != lex.KindWord ||
		!doc.Tokens[j].Flags.Has(lex.FlagFirstUpper) {
		return false
	}
	if _, ok := addrToponym(doc, tabs.cities, j); ok {
		return true
	}
	_, ok := addrToponym(doc, tabs.regions, j)
	return ok
}

// addrToponymRole разбирает слово с заглавной как город или регион из
// справочника. Последнее значение сообщает, что слово — топоним; город,
// оказавшийся фамилией рядом с личным именем, получает роль addrRoleNone.
func addrToponymRole(doc *lex.Doc, tabs addrTables, ch *addressChain, i int, out *Candidates) (addrRole, addrKind, int, bool) {
	if last, ok := addrToponym(doc, tabs.cities, i); ok {
		if addrCityAsName(doc, tabs, ch, i, last, out) {
			return addrRoleNone, 0, i, true
		}
		return addrRoleCity, akCity, last, true
	}
	if last, ok := addrToponym(doc, tabs.regions, i); ok {
		return addrRoleRegion, akRegion, last, true
	}
	return addrRoleNone, 0, i, false
}

// addrMarkerFits проверяет маркер по контексту и уточняет его класс.
//
//   - Маркер улицы в косвенном падеже («улице», «проспекте») засчитывается
//     только после населённого пункта в цепочке или после «живу на» и только
//     перед названием с номером дома: «на улице Пушкина» без дома и
//     «отделение на проспекте Ленина» адресом не становятся.
//   - «д.» перед названием — деревня, а не дом: «д. Ивановка, ул.
//     Центральная, 5».
func addrMarkerFits(doc *lex.Doc, tabs addrTables, ch *addressChain, kind addrKind, i, last int) (addrKind, bool) {
	if kind&akOblique != 0 {
		return addrObliqueFits(doc, tabs, ch, kind, i, last)
	}
	if kind == akHouse && last == i && doc.NormOf(i) == "д" && addrVillageAhead(doc, tabs, i) {
		return akCity, true
	}
	return kind, true
}

// addrObliqueFits проверяет маркер улицы в косвенном падеже: он засчитывается
// после населённого пункта в цепочке или после «живу на» и только перед
// названием с номером дома.
func addrObliqueFits(doc *lex.Doc, tabs addrTables, ch *addressChain, kind addrKind, i, last int) (addrKind, bool) {
	settled := ch.open && (ch.lastRole == addrRoleCity || ch.lastRole == addrRoleRegion ||
		ch.lastRole == addrRoleName && ch.lastKind&akCity != 0)
	if !settled && !addrResidenceBefore(doc, i) {
		return 0, false
	}
	if !addrStreetAhead(doc, tabs, addrNextSignificant(doc, last)) {
		return 0, false
	}
	return kind &^ akOblique, true
}

// addrVillageAhead сообщает, что за «д.» в позиции i стоит слово с заглавной,
// не являющееся маркером: «д. Ивановка» — деревня, а не дом.
func addrVillageAhead(doc *lex.Doc, tabs addrTables, i int) bool {
	j := addrNextSignificant(doc, i)
	if j < 0 || doc.Tokens[j].Kind != lex.KindWord || !doc.Tokens[j].Flags.Has(lex.FlagFirstUpper) {
		return false
	}
	_, _, isMarker := addrMarker(doc, tabs.markers, j)
	return !isMarker
}

// addrOpeningRole решает, открывает ли капитализированное слово цепочку
// само, без маркера слева. Таких случаев три, и каждый держится на контексте
// справа, а не на форме слова:
//
//   - название перед маркером улицы, за которым стоит дом: «Кутузовский
//     проспект, д. 30», «Сивцев Вражек пер., д. 5»;
//   - название после «живу на» / «проживает на» с номером дома: «живу на
//     Баумана 12, квартира 3»;
//   - населённый пункт в предложном падеже после «в» перед улицей: «в
//     Химках, ул. Молодёжная, 4», «в Казани на улице Баумана».
func addrOpeningRole(doc *lex.Doc, tabs addrTables, i int) (addrRole, addrKind, int) {
	if addrNameOpens(doc, tabs, i) {
		return addrRoleName, akStreet, i
	}
	// «Московская обл., г. Химки, …»: название региона перед сокращённым
	// маркером региона открывает цепочку. Полная форма «Московская область»
	// находится справочником, а сокращение — нет, и адрес начинался только с
	// «Химки», а «Московская» доставалась сканеру ФИО (замечание технического
	// жюри 23.09, раунд 4, P4-11).
	if j := i + 1; j < len(doc.Tokens) && doc.Gap(i) == " " {
		if kind, _, ok := addrMarker(doc, tabs.markers, j); ok && kind == akRegion {
			return addrRoleName, akRegion, i
		}
	}
	if addrResidenceBefore(doc, i) && addrResidenceHouse(doc, tabs, i) {
		return addrRoleName, akStreet | akAnchor, i
	}
	if last, ok := addrObliqueCity(doc, tabs, i); ok {
		return addrRoleCity, akCity, last
	}
	return addrRoleNone, 0, i
}

// addrNameFits решает, является ли капитализированное слово названием внутри
// цепочки, и возвращает класс компонента, к которому название относится.
//
// Название улицы справочником не подтверждается — их сотни тысяч, — поэтому
// его держит контекст: либо слева стоит маркер, либо справа номер дома или
// маркер проезда. Сама по себе «Тверская» цепочку не открывает: это слово
// становится улицей только рядом с другими компонентами адреса.
func addrNameFits(doc *lex.Doc, tabs addrTables, ch *addressChain, i int) (addrKind, bool) {
	if ch.lastRole == addrRoleMarker && ch.lastKind&(akStreet|akCity|akRegion) != 0 {
		return ch.lastKind, true
	}
	if ch.lastRole == addrRoleName && ch.nameRun < maxAddrNameRun {
		return ch.lastKind &^ akAnchor, true
	}
	// «ул. 8 Марта»: число сразу за маркером улицы и слово вплотную через
	// пробел — одно название.
	if ch.lastRole == addrRoleNumber && ch.streetNum && doc.Gap(i-1) == " " {
		return akStreet, true
	}
	// «Казань, Баумана 12»: после населённого пункта слово с номером дома —
	// улица без маркера.
	if ch.lastRole == addrRoleCity && addrNextIsNumber(doc, i) {
		return akStreet, true
	}
	// Название перед маркером своего класса: «Невский проспект»,
	// «Одинцовский р-н», «Ленинградское шоссе».
	if kind, ok := addrNextMarker(doc, tabs.markers, i); ok && kind&(akStreet|akRegion|akCity) != 0 {
		return kind, true
	}
	if addrStreetish(doc.NormOf(i)) && addrNextIsNumber(doc, i) {
		return akStreet, true
	}
	return 0, false
}

// addrStreetSuffixes — окончания, по которым слово опознаётся как название
// улицы без маркера: «Тверская 5», «Невский проспект». Список намеренно узкий:
// по нему цепочка только продолжается, но никогда не начинается.
var addrStreetSuffixes = [...]string{"ская", "ский", "ское", "ской", "ские", "цкая", "цкий"}

// addrStreetish сообщает, что нормализованное слово похоже на название улицы.
func addrStreetish(w string) bool {
	for _, s := range addrStreetSuffixes {
		if strings.HasSuffix(w, s) {
			return true
		}
	}
	return false
}

// addrToponym сопоставляет со справочником последовательность токенов,
// начиная с i, и возвращает последний токен самого длинного совпадения.
//
// Составные названия («Нижний Новгород», «Ростов-на-Дону») ищутся срезом
// doc.Norm, а не склейкой строк: срез строки не аллоцирует, и поиск по карте
// от него тоже.
func addrToponym(doc *lex.Doc, tab *dict.Table, i int) (int, bool) {
	if tab == nil {
		return i, false
	}
	start := doc.Tokens[i].Start
	last, found := i, tab.Has(doc.Norm[start:doc.Tokens[i].End])
	for j := i; j-i < maxAddrToponymTokens-1; j++ {
		if !addrToponymJoin(doc, j) {
			break
		}
		if tab.Has(doc.Norm[start:doc.Tokens[j+1].End]) {
			last, found = j+1, true
		}
	}
	return last, found
}

// addrToponymJoin сообщает, что токен j+1 может продолжать составное название:
// слово через один пробел либо дефис вплотную.
func addrToponymJoin(doc *lex.Doc, j int) bool {
	if j+1 >= len(doc.Tokens) {
		return false
	}
	next := doc.Tokens[j+1]
	gap := doc.Gap(j)
	switch next.Kind {
	case lex.KindWord:
		return gap == "" || gap == " "
	case lex.KindPunct:
		return gap == "" && next.Len() == 1 && doc.Text[next.Start] == '-' &&
			j+2 < len(doc.Tokens) && doc.Tokens[j+2].Kind == lex.KindWord && doc.Adjacent(j+1)
	}
	return false
}

// addrMarker сопоставляет токен i со справочником маркеров и возвращает класс
// компонента и последний занятый токен.
func addrMarker(doc *lex.Doc, tab *dict.Table, i int) (addrKind, int, bool) {
	if tab == nil || doc.Tokens[i].Kind != lex.KindWord {
		return 0, i, false
	}
	start := doc.Tokens[i].Start
	// Дефисные сокращения приходят тремя токенами: «пр-т», «р-н», «б-р».
	if i+2 < len(doc.Tokens) && doc.Tokens[i+1].Kind == lex.KindPunct &&
		doc.Text[doc.Tokens[i+1].Start] == '-' && doc.Tokens[i+2].Kind == lex.KindWord &&
		doc.Adjacent(i) && doc.Adjacent(i+1) {
		if label, ok := tab.Get(doc.Norm[start:doc.Tokens[i+2].End]); ok {
			return addrKindOf(label), i + 2, true
		}
	}
	end := doc.Tokens[i].End
	// Точка после сокращения — часть его записи, поэтому справочник принимает
	// обе формы, «ул» и «ул.»: расширять его должно быть можно не задумываясь
	// о том, как лексер делит текст. В спане точка остаётся разделителем.
	dotted := i+1 < len(doc.Tokens) && doc.Adjacent(i) &&
		doc.Tokens[i+1].Kind == lex.KindPunct && doc.Text[doc.Tokens[i+1].Start] == '.'
	if dotted {
		if label, ok := tab.Get(doc.Norm[start:doc.Tokens[i+1].End]); ok {
			return addrKindOf(label), i, true
		}
	}
	label, ok := tab.Get(doc.Norm[start:end])
	if !ok {
		return 0, i, false
	}
	// Однобуквенные сокращения («г.», «д.», «к.») засчитываются только с
	// точкой: без неё маркером адреса стал бы предлог или инициал.
	// Кириллическая буква занимает два байта — отсюда порог.
	if int(end-start) <= 2 && !dotted {
		return 0, i, false
	}
	return addrKindOf(label), i, true
}

// addrIsSeparator сообщает, что знак препинания допустим между компонентами.
func addrIsSeparator(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	if t.Kind != lex.KindPunct || t.Len() != 1 {
		return false
	}
	switch doc.Text[t.Start] {
	case ',', '.', '-', '/':
		return true
	}
	return false
}

// addrNextSignificant возвращает индекс ближайшего справа значимого токена,
// пропуская допустимые разделители. Для их отсутствия возвращается -1.
func addrNextSignificant(doc *lex.Doc, i int) int {
	seps := 0
	for j := i + 1; j < len(doc.Tokens); j++ {
		if !onlySpaces(doc.Gap(j-1), maxAddrSepSpaces) {
			return -1
		}
		if doc.Tokens[j].Kind != lex.KindPunct {
			return j
		}
		if seps++; seps > maxAddrSeps || !addrIsSeparator(doc, j) {
			return -1
		}
	}
	return -1
}

// addrNextIsNumber сообщает, что за токеном i идёт число, пригодное в номера.
func addrNextIsNumber(doc *lex.Doc, i int) bool {
	j := addrNextSignificant(doc, i)
	return j >= 0 && doc.Tokens[j].Kind == lex.KindDigits && doc.Tokens[j].Len() <= maxAddrNumberLen &&
		!addrDateStart(doc, j)
}

// addrNextMarker возвращает класс маркера, стоящего сразу за токеном i.
func addrNextMarker(doc *lex.Doc, tab *dict.Table, i int) (addrKind, bool) {
	j := addrNextSignificant(doc, i)
	if j < 0 {
		return 0, false
	}
	kind, _, ok := addrMarker(doc, tab, j)
	return kind, ok
}

// addrIsConnector сообщает, что слово i — предлог между населённым пунктом и
// улицей внутри цепочки: «Тула на ул. Советской», «Казани на улице Баумана».
// Предлог в цепочку берётся только тогда, когда справа сразу стоит маркер
// улицы, принятый addrMarkerFits.
func addrIsConnector(doc *lex.Doc, tabs addrTables, ch *addressChain, i int) bool {
	if ch.lastRole != addrRoleCity && (ch.lastRole != addrRoleName || ch.lastKind&akCity == 0) {
		return false
	}
	if doc.Tokens[i].Kind != lex.KindWord || doc.Gap(i) != " " || i+1 >= len(doc.Tokens) {
		return false
	}
	if w := doc.NormOf(i); w != "на" && w != "по" {
		return false
	}
	kind, last, ok := addrMarker(doc, tabs.markers, i+1)
	if !ok || kind&akStreet == 0 {
		return false
	}
	_, ok = addrMarkerFits(doc, tabs, ch, kind, i+1, last)
	return ok
}

// addrStreetConnectors — строчные слова внутри названия улицы сразу за
// маркером: «наб. реки Фонтанки», «наб. канала Грибоедова», «ул. имени
// Ленина».
var addrStreetConnectors = [...]string{"реки", "канала", "им", wordNamed}

// addrIsStreetConnectorWord сообщает, что нормализованное слово — связующее
// внутри названия улицы.
func addrIsStreetConnectorWord(w string) bool {
	for _, c := range addrStreetConnectors {
		if w == c {
			return true
		}
	}
	return false
}

// addrStreetConnector сообщает, что строчное слово i продолжает название улицы
// за маркером: справа от него обязано стоять капитализированное слово.
func addrStreetConnector(doc *lex.Doc, ch *addressChain, i int) bool {
	if ch.lastRole != addrRoleMarker || ch.lastKind&akStreet == 0 || !addrIsStreetConnectorWord(doc.NormOf(i)) {
		return false
	}
	j := addrNextSignificant(doc, i)
	return j >= 0 && doc.Tokens[j].Kind == lex.KindWord && doc.Tokens[j].Flags.Has(lex.FlagFirstUpper)
}

// addrNameOpens сообщает, что капитализированное слово i (и, возможно,
// следующее за ним) — название улицы перед маркером проезда, за которым
// стоит дом: «Кутузовский проспект, д. 30», «Сивцев Вражек пер., д. 5».
//
// Без дома справа цепочку название не открывает: «Невский проспект» сам по
// себе — достопримечательность, а не адрес клиента.
func addrNameOpens(doc *lex.Doc, tabs addrTables, i int) bool {
	toks := doc.Tokens
	last := i
	for n := 1; n < maxAddrNameRun; n++ {
		j := last + 1
		if j >= len(toks) || toks[j].Kind != lex.KindWord || !toks[j].Flags.Has(lex.FlagFirstUpper) ||
			doc.Gap(last) != " " {
			break
		}
		if _, _, ok := addrMarker(doc, tabs.markers, j); ok {
			break
		}
		last = j
	}
	j := addrNextSignificant(doc, last)
	if j < 0 {
		return false
	}
	kind, mlast, ok := addrMarker(doc, tabs.markers, j)
	if !ok || kind&akStreet == 0 || kind&akOblique != 0 {
		return false
	}
	return addrHouseAhead(doc, tabs, mlast)
}

// addrHouseAhead сообщает, что за токеном i идёт номер дома либо маркер
// дома, корпуса или помещения.
func addrHouseAhead(doc *lex.Doc, tabs addrTables, i int) bool {
	j := addrNextSignificant(doc, i)
	if j < 0 {
		return false
	}
	switch doc.Tokens[j].Kind {
	case lex.KindDigits:
		return doc.Tokens[j].Len() <= maxAddrNumberLen
	case lex.KindWord:
		kind, _, ok := addrMarker(doc, tabs.markers, j)
		return ok && kind&(akHouse|akBuilding|akFlat) != 0
	}
	return false
}

// addrStreetAhead сообщает, что с токена j начинается название улицы с
// номером дома: одно-два капитализированных слова (перед ними допустим
// строчный связующий «реки», «имени»), затем дом.
func addrStreetAhead(doc *lex.Doc, tabs addrTables, j int) bool {
	toks := doc.Tokens
	if j < 0 || toks[j].Kind != lex.KindWord {
		return false
	}
	if !toks[j].Flags.Has(lex.FlagFirstUpper) {
		if !addrIsStreetConnectorWord(doc.NormOf(j)) {
			return false
		}
		if j = addrNextSignificant(doc, j); j < 0 {
			return false
		}
	}
	for n := 0; n < maxAddrNameRun; n, j = n+1, j+1 {
		if j >= len(toks) || toks[j].Kind != lex.KindWord || !toks[j].Flags.Has(lex.FlagFirstUpper) {
			return false
		}
		if addrHouseAhead(doc, tabs, j) {
			return true
		}
		if doc.Gap(j) != " " {
			return false
		}
	}
	return false
}

// addrResidenceBefore сообщает, что слову i предшествует «живу на» /
// «проживает по» и т. п.: предлог места и глагол проживания через пробел.
func addrResidenceBefore(doc *lex.Doc, i int) bool {
	if i < 2 || doc.Tokens[i-1].Kind != lex.KindWord || doc.Tokens[i-2].Kind != lex.KindWord ||
		doc.Gap(i-1) != " " || doc.Gap(i-2) != " " {
		return false
	}
	if p := doc.NormOf(i - 1); p != "на" && p != "по" {
		return false
	}
	return addrIsResidenceWord(doc.NormOf(i - 2))
}

// addrIsResidenceWord — глаголы и причастия проживания и регистрации.
// Список закрытый: префикс «жив» поймал бы «живописный». Прошедшего времени
// «жил», «жила» здесь нет намеренно: «Пушкин жил на Мойке, 12» — биография
// персоны, а не адрес клиента.
func addrIsResidenceWord(w string) bool {
	switch w {
	case "живу", "живет", "живем", "живете", "живешь", "живут":
		return true
	}
	return strings.HasPrefix(w, "прожива") || strings.HasPrefix(w, "прописан") ||
		strings.HasPrefix(w, "зарегистрирован")
}

// addrResidenceHouse сообщает, что за названием i после «живу на» стоит
// номер дома, которым фраза и заканчивается или за которым идёт помещение:
// «живу на Баумана 12, квартира 3». «Живу на Земле 12 лет» адресом не
// становится: после числа стоит слово, а не конец адреса.
func addrResidenceHouse(doc *lex.Doc, tabs addrTables, i int) bool {
	toks := doc.Tokens
	j := i + 1
	if j >= len(toks) || toks[j].Kind != lex.KindDigits || toks[j].Len() > maxAddrNumberLen || doc.Gap(i) != " " {
		return false
	}
	j = addrNumberTail(doc, j)
	k := j + 1
	if k >= len(toks) {
		return true
	}
	if toks[k].Kind == lex.KindPunct {
		if addrClosingPunct(doc, k) {
			return true
		}
		switch doc.Text[toks[k].Start] {
		case '/', '-':
			return doc.Adjacent(j) && k+1 < len(toks) && toks[k+1].Kind == lex.KindDigits
		}
		return false
	}
	if toks[k].Kind != lex.KindWord {
		return false
	}
	kind, _, ok := addrMarker(doc, tabs.markers, k)
	return ok && kind&(akBuilding|akFlat) != 0
}

// addrObliqueCity разбирает населённый пункт из справочника в предложном
// падеже после «в» и перед улицей: «в Химках, ул. Молодёжная», «в Казани на
// улице Баумана», «в Санкт-Петербурге, Невский пр.». Возвращает последний
// токен названия. Без улицы справа падежная форма не разбирается вовсе:
// «живу в Москве 12 лет» адресом не становится.
func addrObliqueCity(doc *lex.Doc, tabs addrTables, i int) (int, bool) {
	if i < 1 || doc.Tokens[i-1].Kind != lex.KindWord || doc.Gap(i-1) != " " {
		return i, false
	}
	if p := doc.NormOf(i - 1); p != "в" && p != "во" {
		return i, false
	}
	// Составное название через дефис склоняется последней частью:
	// «Санкт-Петербурге», «Ростове-на-Дону» — поэтому пробуются все
	// продолжения, как в addrToponym.
	start := doc.Tokens[i].Start
	for j := i; j-i < maxAddrToponymTokens; j++ {
		if addrStreetAfterCity(doc, tabs, j) && addrCityDeclined(tabs, doc.Norm[start:doc.Tokens[j].End]) {
			return j, true
		}
		if !addrToponymJoin(doc, j) || doc.Gap(j) != "" {
			break
		}
	}
	return i, false
}

// addrStreetAfterCity сообщает, что за токеном j стоит улица: маркер улицы
// через разделитель или через предлог «на» / «по» либо название перед
// маркером с домом («в Санкт-Петербурге, Невский пр., д. 100»).
func addrStreetAfterCity(doc *lex.Doc, tabs addrTables, j int) bool {
	k := addrNextSignificant(doc, j)
	if k < 0 || doc.Tokens[k].Kind != lex.KindWord {
		return false
	}
	if w := doc.NormOf(k); (w == "на" || w == "по") && doc.Gap(k) == " " && k+1 < len(doc.Tokens) {
		k++
	}
	if kind, _, ok := addrMarker(doc, tabs.markers, k); ok {
		return kind&akStreet != 0
	}
	return doc.Tokens[k].Flags.Has(lex.FlagFirstUpper) && addrNameOpens(doc, tabs, k)
}

// addrCityEndings — замены окончания предложного падежа на окончание
// именительного: «Химках» → «химки», «Москве» → «москва», «Саратове» →
// «саратов», «Казани» → «казань», «Ярославле» → «ярославль», «Кемерове» →
// «кемерово». Беглые гласные («Орле» → «Орёл») не разбираются.
var addrCityEndings = [...][2]string{
	{"ах", "и"}, {"ах", "ы"},
	{"е", "а"}, {"е", ""}, {"е", "ь"}, {"е", "о"},
	{"и", "ь"},
}

// addrDeclBuf — предел длины слова для разбора падежа, в байтах. Строка до
// 32 байт, не покидающая функцию, собирается компилятором на стеке, поэтому
// поиск по справочнику не аллоцирует. Длиннее — «Петропавловске-Камчатском»
// — падеж не разбирается.
const addrDeclBuf = 32

// addrDeclMinStem — минимальная длина основы в байтах: две кириллические
// буквы. Более короткая основа справочником не подтверждается, а поиск по
// ней только тратит время.
const addrDeclMinStem = 4

// addrCityDeclined сообщает, что нормализованное слово w — падежная форма
// населённого пункта из справочника. Смотрится и справочник регионов: города
// федерального значения («Санкт-Петербург», «Севастополь») лежат там.
func addrCityDeclined(tabs addrTables, w string) bool {
	if len(w) > addrDeclBuf {
		return false
	}
	var buf [addrDeclBuf]byte
	for _, e := range addrCityEndings {
		if !strings.HasSuffix(w, e[0]) {
			continue
		}
		stem := len(w) - len(e[0])
		if stem < addrDeclMinStem || stem+len(e[1]) > addrDeclBuf {
			continue
		}
		n := copy(buf[:], w[:stem])
		n += copy(buf[n:], e[1])
		if key := string(buf[:n]); tabs.cities.Has(key) || tabs.regions.Has(key) {
			return true
		}
	}
	return false
}
