package corpus

import "strings"

// Собственные справочники значений корпуса.
//
// Списки составлены для этого инструмента и намеренно не берутся из
// internal/detect/dict: корпус, производный от словарей детектора, измерял бы
// совпадение кода с самим собой. Все значения синтетические; исключение —
// исторические публичные персоны и топонимы, они встречаются только в
// ловушках, где по условию задачи и должны быть.

// Машинные ключи типов ПД. Должны совпадать с internal/pii/types.go, иначе
// отчёт качества не сойдётся по типам.
const (
	KFullName          = "full_name"
	KBirthDate         = "birth_date"
	KBirthPlace        = "birth_place"
	KCitizenship       = "citizenship"
	KPassportNumber    = "passport_number"
	KPassportAuthority = "passport_authority"
	KPassportDeptCode  = "passport_dept_code"
	KPassportIssueDate = "passport_issue_date"
	KDriverLicense     = "driver_license"
	KAddress           = "address"
	KEmail             = "email"
	KPhone             = "phone"
	KINN               = "inn"
	KCardNumber        = "card_number"
	KCVV               = "cvv"
	KPIN               = "pin"
	KCardHolder        = "card_holder"
)

// RequiredTypes — 17 обязательных типов ТЗ §3.2.1 в порядке спецификации.
var RequiredTypes = []string{
	KFullName, KBirthDate, KBirthPlace, KCitizenship,
	KPassportNumber, KPassportAuthority, KPassportDeptCode, KPassportIssueDate,
	KDriverLicense, KAddress, KEmail, KPhone,
	KINN, KCardNumber, KCVV, KPIN, KCardHolder,
}

// Причины ловушек: по ним отчёт считает ложные срабатывания.
const (
	ReasonPublicFigure   = "public_figure"   // поэт Пушкин
	ReasonToponym        = "toponym"         // улица Пушкина
	ReasonOrgAddress     = "org_address"     // адрес отделения банка
	ReasonHotline        = "hotline"         // телефон горячей линии
	ReasonContractNumber = "contract_number" // номер договора
	ReasonEventDate      = "event_date"      // дата события, а не рождения
)

// TrapReasons — все причины ловушек; первые пять обязательны по задаче.
var TrapReasons = []string{
	ReasonPublicFigure, ReasonToponym, ReasonOrgAddress,
	ReasonHotline, ReasonContractNumber, ReasonEventDate,
}

// grammCase — падеж, в котором нужно значение. Корпус — естественный текст,
// поэтому имена склоняются, а не вставляются всегда в именительном.
type grammCase int

const (
	cNom grammCase = iota // именительный: «клиент Веретенников Аркадий Петрович»
	cGen                  // родительный: «справка для Веретенникова Аркадия Петровича»
	cAcc                  // винительный: «найди Веретенникова Аркадия Петровича»
)

// word — три формы одного слова.
type word struct{ nom, gen, acc string }

func (w word) form(c grammCase) string {
	switch c {
	case cGen:
		return w.gen
	case cAcc:
		return w.acc
	default:
		return w.nom
	}
}

// mascNoun склоняет мужское существительное на согласный, «й» или «ь».
// У одушевлённых родительный и винительный совпадают.
//
// Две ветви нужны только фамилиям без русского суффикса: «Кравец» теряет
// беглую гласную («Кравца»), а «Сорока» склоняется как существительное на
// «-а» — у мужчины так же, как у женщины. Среди имён и отчеств корпуса нет
// ни одного слова на «-ец» или «-а», поэтому их формы от этих ветвей не
// меняются.
func mascNoun(nom string) word {
	switch {
	case strings.HasSuffix(nom, "а"):
		return femNoun(nom)
	case strings.HasSuffix(nom, "ец"):
		g := strings.TrimSuffix(nom, "ец") + "ца"
		return word{nom, g, g}
	case strings.HasSuffix(nom, "й"), strings.HasSuffix(nom, "ь"):
		g := nom[:len(nom)-len("й")] + "я"
		return word{nom, g, g}
	default:
		g := nom + "а"
		return word{nom, g, g}
	}
}

// femNoun склоняет женское существительное на «а»/«я».
func femNoun(nom string) word {
	switch {
	case strings.HasSuffix(nom, "ия"), strings.HasSuffix(nom, "ья"):
		base := strings.TrimSuffix(nom, "я")
		return word{nom, base + "и", base + "ю"}
	case strings.HasSuffix(nom, "а"):
		base := strings.TrimSuffix(nom, "а")
		gen := base + "ы"
		// После шипящих и заднеязычных пишется «и», а не «ы»: Вероника → Вероники.
		if strings.ContainsRune("гкхжшчщ", lastRune(base)) {
			gen = base + "и"
		}
		return word{nom, gen, base + "у"}
	}
	return word{nom, nom, nom}
}

// mascAdj склоняет фамилию-прилагательное: Заозёрский → Заозёрского.
func mascAdj(nom string) word {
	g := adjStem(nom) + "ого"
	return word{nom, g, g}
}

// femAdj строит женскую фамилию-прилагательное от мужской формы:
// Заозёрский → Заозёрская / Заозёрской / Заозёрскую.
func femAdj(masc string) word {
	s := adjStem(masc)
	return word{s + "ая", s + "ой", s + "ую"}
}

// femSur строит женскую фамилию от мужской формы: «Веретенников» →
// «Веретенникова» / «Веретенниковой» / «Веретенникову».
//
// Фамилия без русского суффикса женской формы не имеет и не склоняется:
// «Анна Мельник», «для Анны Мельник». Исключение — фамилии на «-а»: «Сорока»
// склоняется как существительное и у женщины.
func femSur(masc string) word {
	switch {
	case hasRussianSurnameSuffix(masc):
		return word{masc + "а", masc + "ой", masc + "у"}
	case strings.HasSuffix(masc, "а"):
		return femNoun(masc)
	default:
		return word{masc, masc, masc}
	}
}

// hasRussianSurnameSuffix сообщает, что мужская фамилия кончается на
// «-ов», «-ев», «-ёв», «-ин» или «-ын» — то есть имеет женскую форму на «-а».
func hasRussianSurnameSuffix(masc string) bool {
	for _, suf := range []string{"ов", "ев", "ёв", "ин", "ын"} {
		if strings.HasSuffix(masc, suf) {
			return true
		}
	}
	return false
}

// concatLists склеивает списки в новый срез, не трогая исходные.
func concatLists(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

func adjStem(nom string) string {
	for _, suf := range []string{"ий", "ый", "ой"} {
		if strings.HasSuffix(nom, suf) {
			return strings.TrimSuffix(nom, suf)
		}
	}
	return nom
}

func lastRune(s string) rune {
	r := []rune(s)
	if len(r) == 0 {
		return 0
	}
	return r[len(r)-1]
}

// femPatronymic строит женское отчество от мужского: Юрьевич → Юрьевна.
func femPatronymic(masc string) string { return strings.TrimSuffix(masc, "ич") + "на" }

// Собственные списки основ. Фамилии с суффиксом выбраны нечастотные, чтобы
// синтетика не совпала с узнаваемым реальным человеком.
var (
	surnamesSuffixed = []string{
		"Веретенников", "Кривошапкин", "Пятибратов", "Шелестов", "Гвоздарёв",
		"Мещеряков", "Худолеев", "Бортников", "Ясенев", "Трубников",
		"Кожемякин", "Свиридонов", "Пересветов", "Черноусов", "Ольхин",
		"Бакланов", "Сухоруков", "Подгорнов", "Ремезов", "Зуйков",
	}
	// surnamesBare — фамилии без русского суффикса: ни «-ов», ни «-ин», ни
	// окончания прилагательного. До T-50 корпус их не содержал вовсе, и
	// утечку «Клиент Олег Петрович Мельник → Клиент [ФИО_1] Мельник» нашло
	// бизнес-жюри, а не прогон качества. Список взят из того отчёта. Сами по
	// себе фамилии частотные, но человек синтетический: имя и отчество
	// выбираются независимо, и совпасть с живым человеком сочетанию неоткуда.
	surnamesBare = []string{
		"Мельник", "Коваль", "Бондарь", "Кравец", "Гончар", "Цой", "Шульц",
		"Мороз", "Сорока", "Жук", "Лебедь",
	}
	// surnamesNoun — все фамилии-существительные. Генератор выбирает из
	// одного списка, поэтому фамилия без суффикса встречается во всех стилях
	// и падежах наравне с суффиксной.
	surnamesNoun = concatLists(surnamesSuffixed, surnamesBare)
	surnamesAdj  = []string{
		"Заозёрский", "Ольховский", "Бережной", "Приволжский", "Задворный",
		"Луговской", "Краснопольский",
	}
	firstMale = []string{
		"Аркадий", "Пётр", "Тимофей", "Егор", "Матвей", "Савелий", "Кирилл",
		"Роман", "Глеб", "Артём", "Виктор", "Леонид", "Станислав", "Юрий",
		"Платон", "Герман", "Родион", "Захар",
	}
	firstFemale = []string{
		"Валентина", "Алевтина", "Ксения", "Марина", "Полина", "Эльвира",
		"Раиса", "Таисия", "Людмила", "Вероника", "Ангелина", "Дарья",
		"Аграфена", "Зинаида", "Устинья",
	}
	patronymicMale = []string{
		"Викторович", "Аркадьевич", "Тимофеевич", "Егорович", "Матвеевич",
		"Савельевич", "Кириллович", "Романович", "Глебович", "Артёмович",
		"Леонидович", "Станиславович", "Юрьевич", "Платонович", "Германович",
		"Родионович", "Захарович",
	}
	// Публичные персоны — только для ловушек: это не персональные данные.
	publicFigures = []struct{ role, nom, gen string }{
		{"поэт", "Александр Пушкин", "Александра Пушкина"},
		{"композитор", "Пётр Чайковский", "Петра Чайковского"},
		{"писатель", "Лев Толстой", "Льва Толстого"},
		{"космонавт", "Юрий Гагарин", "Юрия Гагарина"},
		{"химик", "Дмитрий Менделеев", "Дмитрия Менделеева"},
		{"художник", "Иван Шишкин", "Ивана Шишкина"},
	}
	// Топонимы, образованные от фамилий: тоже не персональные данные.
	toponymStreets = []struct{ kind, name string }{
		{"улице", "Пушкина"},
		{"проспекте", "Ленина"},
		{"площади", "Гагарина"},
		{"улице", "Чайковского"},
		{"бульваре", "Менделеева"},
		{"переулке", "Лермонтова"},
	}
	// Фамилии публичных персон для записей-однофамильцев: там это уже ПД.
	namesakeSurnames = []string{"Пушкин", "Гагарин", "Лермонтов", "Менделеев", "Шишкин"}

	cities = []string{
		"Тверь", "Великие Луки", "Новочеркасск", "Вышний Волочёк", "Сыктывкар",
		"Ирбит", "Сызрань", "Кинешма", "Бугуруслан", "Балашов", "Ливны",
		"Рыбинск", "Котлас", "Зеленодольск", "Миасс", "Шадринск",
		"Каменск-Уральский", "Гусь-Хрустальный", "Верхняя Салда", "Кимры",
	}
	settlements = []string{
		"с. Верхние Ключи", "пос. Заречный", "д. Малые Броды", "ст. Лесная",
		"пгт Красногорье", "с. Ольховатка",
	}
	regions = []string{
		"Тверская область", "Ростовская область", "Псковская область",
		"Курганская область", "Ивановская область", "Свердловская область",
		"Кировская область", "Республика Марий Эл",
	}
	streets = []struct{ kind, name string }{
		{"ул.", "Овражная"}, {"ул.", "Садовая"}, {"ул.", "Лесозаводская"},
		{"ул.", "Приречная"}, {"ул.", "Луговая"}, {"ул.", "Малиновая"},
		{"ул.", "Стекольная"}, {"ул.", "Кирпичная"}, {"ул.", "Слободская"},
		{"ул.", "Кленовая"}, {"пер.", "Ремесленный"}, {"пер.", "Тихий"},
		{"пр-т", "Заводской"}, {"б-р", "Тенистый"}, {"наб.", "Старичная"},
	}
	// Органы выдачи собраны из реальных по форме, но синтетических по составу
	// сочетаний «подразделение — регион — район».
	authorities = []string{
		"ОУФМС России по Тверской области в Заволжском районе",
		"ГУ МВД России по Ростовской области",
		"УМВД России по Псковской области",
		"ТП УФМС России по Курганской области в г. Шадринске",
		"МО УФМС России по Ивановской области в г. Кинешме",
		"ОВД Заречного района г. Ирбита",
		"ГУ МВД России по Свердловской области",
		"ОУФМС России по Кировской области в Слободском районе",
	}
	citizenships = []word{
		{"РФ", "РФ", "РФ"},
		{"Российская Федерация", "Российской Федерации", "Российскую Федерацию"},
		{"Россия", "России", "Россию"},
		{"Республика Беларусь", "Республики Беларусь", "Республику Беларусь"},
		{"Республика Казахстан", "Республики Казахстан", "Республику Казахстан"},
		{"Армения", "Армении", "Армению"},
		{"Узбекистан", "Узбекистана", "Узбекистан"},
		{"Киргизия", "Киргизии", "Киргизию"},
	}
	// Почтовые домены — из зарезервированных RFC 2606, чтобы синтетика не
	// попала в чей-то реальный почтовый ящик.
	emailDomains = []string{
		"example.com", "example.org", "example.net",
		"mail.example.com", "corp.example.org", "post.example.net",
	}
	// Тестовые BIN платёжных систем: номер собирается из них, контрольная
	// цифра считается по Луну, поэтому карта проходит проверку, но не
	// принадлежит никому.
	testBINs = []string{"411111", "400000", "555555", "510510", "222100", "220000", "676454"}
)

// person — синтетический человек: три склоняемых слова и пол.
type person struct {
	female bool
	last   word
	first  word
	mid    word
}

// nameStyle — вариация написания ФИО по ТЗ §3.2.2: порядок компонентов и регистр.
type nameStyle int

const (
	styleFIO   nameStyle = iota // Фамилия Имя Отчество
	styleIOF                    // Имя Отчество Фамилия
	styleFI                     // Фамилия Имя
	styleUpper                  // ФАМИЛИЯ ИМЯ ОТЧЕСТВО
	styleLower                  // фамилия имя отчество
	styleShort                  // Фамилия И. О. — только в именительном
	nameStyleCount
)

// render собирает ФИО в заданном стиле и падеже.
func (p person) render(st nameStyle, c grammCase) string {
	last, first, mid := p.last.form(c), p.first.form(c), p.mid.form(c)
	switch st {
	case styleIOF:
		return first + " " + mid + " " + last
	case styleFI:
		return last + " " + first
	case styleUpper:
		return strings.ToUpper(last + " " + first + " " + mid)
	case styleLower:
		return strings.ToLower(last + " " + first + " " + mid)
	case styleShort:
		// Фамилия склоняется и в краткой форме: «справка для Ольхина А. П.».
		return last + " " + initial(p.first.nom) + ". " + initial(p.mid.nom) + "."
	default:
		return last + " " + first + " " + mid
	}
}

func initial(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}

// verb выбирает форму слова по полу: «родился» или «родилась». Без согласования
// текст перестаёт быть естественным, а корпус должен мерить детекцию на
// естественном тексте.
func (p person) verb(masc, fem string) string {
	if p.female {
		return fem
	}
	return masc
}

// latin — имя держателя карты латиницей.
func (p person) latin() string { return toLatin(p.first.nom) + " " + toLatin(p.last.nom) }

// translit — собственная таблица транслитерации; результат сразу в верхнем
// регистре, как эмбоссируют на карте.
var translit = map[rune]string{
	'а': "A", 'б': "B", 'в': "V", 'г': "G", 'д': "D", 'е': "E", 'ё': "E",
	'ж': "ZH", 'з': "Z", 'и': "I", 'й': "I", 'к': "K", 'л': "L", 'м': "M",
	'н': "N", 'о': "O", 'п': "P", 'р': "R", 'с': "S", 'т': "T", 'у': "U",
	'ф': "F", 'х': "KH", 'ц': "TS", 'ч': "CH", 'ш': "SH", 'щ': "SHCH",
	'ъ': "", 'ы': "Y", 'ь': "", 'э': "E", 'ю': "IU", 'я': "IA", '-': "-",
}

func toLatin(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if v, ok := translit[r]; ok {
			b.WriteString(v)
		}
	}
	return b.String()
}

// deyo заменяет «ё» на «е»: распространённая вариация написания, которую
// детектор обязан переживать.
func deyo(s string) string {
	return strings.NewReplacer("ё", "е", "Ё", "Е").Replace(s)
}
