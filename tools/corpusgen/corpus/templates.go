package corpus

// Собственные шаблоны предложений. Элемент корпуса — естественный запрос к
// ассистенту, а не изолированная строка со значением: детектор должен
// находить ПД в живом тексте, поэтому и измерять его надо на живом тексте.

// Куски текста, общие для нескольких шаблонов.
const (
	litClient     = "Клиент "
	litPassport   = ", паспорт "
	litFindClient = "Найди клиента "
)

// tmpl — шаблон записи: какие типы ПД он порождает и как собирает текст.
type tmpl struct {
	types []string
	make  func(g *gen) []piece
}

// join склеивает отдельные куски и группы кусков в один список.
func join(items ...any) []piece {
	out := make([]piece, 0, len(items)+4)
	for _, it := range items {
		switch v := it.(type) {
		case piece:
			out = append(out, v)
		case []piece:
			out = append(out, v...)
		default:
			panic("corpus: join принимает только piece и []piece")
		}
	}
	return out
}

// valueTmpl — шаблон с одним значением типа typ между двумя кусками текста.
func valueTmpl(typ, before string, value func(g *gen) string, after string) tmpl {
	return tmpl{types: []string{typ}, make: func(g *gen) []piece {
		return join(lit(before), val(typ, value(g)), lit(after))
	}}
}

// piecesTmpl — то же для значения, которое собирается из нескольких кусков
// (паспорт с необязательным словом «серия», дата со словом «года»).
func piecesTmpl(typ, before string, value func(g *gen) []piece, after string) tmpl {
	return tmpl{types: []string{typ}, make: func(g *gen) []piece {
		return join(lit(before), value(g), lit(after))
	}}
}

// datePieces выдаёт дату вместе с необязательным словом «года»/«г.».
// Слово служебное и в спан не входит: маскировать его — избыточность,
// которая штрафуется (07-clarifications.md §7.1).
func (g *gen) datePieces(typ string, d date, c grammCase) []piece {
	form := g.next(&g.dateSeq, dateFormCount)
	ps := []piece{val(typ, renderDate(d, form, c))}
	if form == 6 || form == 7 {
		switch g.r.IntN(3) {
		case 0:
			ps = append(ps, lit(" года"))
		case 1:
			ps = append(ps, lit(" г."))
		}
	}
	return ps
}

func (g *gen) cityOnly() string { return pick(g.r, cities) }

// singles — шаблоны с одним типом ПД, по ключу типа.
var singles = map[string][]tmpl{}

// multis — шаблоны с несколькими типами ПД в одном запросе.
var multis []tmpl

// cleanTexts — запросы вовсе без ПД: по ним считается доля ложных
// срабатываний на тексте, где маскировать нечего.
var cleanTexts []string

func init() {
	singles[KFullName] = []tmpl{
		valueTmpl(KFullName, litFindClient, func(g *gen) string { return g.fullName(g.person(), cAcc) }, " и покажи последние операции по счёту."),
		valueTmpl(KFullName, "Подготовь справку об остатке для ", func(g *gen) string { return g.fullName(g.person(), cGen) }, ", формат PDF."),
		valueTmpl(KFullName, "В заявке указан заявитель: ", func(g *gen) string { return g.fullName(g.person(), cNom) }, ". Что делать дальше по процессу?"),
		valueTmpl(KFullName, "Клиент представился как ", func(g *gen) string { return g.fullName(g.person(), cNom) }, " — проверь, есть ли такой клиент в базе."),
		valueTmpl(KFullName, "Оформи доверенность на ", func(g *gen) string { return g.fullName(g.person(), cAcc) }, ", срок — один год."),
	}

	singles[KBirthDate] = []tmpl{
		piecesTmpl(KBirthDate, "Проверь, совпадает ли дата рождения ", func(g *gen) []piece { return g.datePieces(KBirthDate, g.birthDate(), cNom) }, " с данными анкеты."),
		piecesTmpl(KBirthDate, "В анкете указана дата рождения ", func(g *gen) []piece { return g.datePieces(KBirthDate, g.birthDate(), cNom) }, " — клиент подходит под условия вклада?"),
		piecesTmpl(KBirthDate, "Клиент родился ", func(g *gen) []piece { return g.datePieces(KBirthDate, g.birthDate(), cGen) }, ", посчитай возраст на дату выдачи кредита."),
		piecesTmpl(KBirthDate, "Сверь дату рождения ", func(g *gen) []piece { return g.datePieces(KBirthDate, g.birthDate(), cNom) }, " с паспортными данными и ответь, есть ли расхождение."),
	}

	singles[KBirthPlace] = []tmpl{
		valueTmpl(KBirthPlace, "Место рождения в заявлении — ", (*gen).birthPlace, ". Это влияет на проверку документов?"),
		valueTmpl(KBirthPlace, "Клиент родился в городе ", (*gen).cityOnly, ", уточни список нужных документов."),
		valueTmpl(KBirthPlace, "В анкете графа «место рождения» заполнена как ", (*gen).birthPlace, " — сверь с паспортом."),
		valueTmpl(KBirthPlace, "Укажи в справке место рождения: ", (*gen).birthPlace, "."),
	}

	singles[KCitizenship] = []tmpl{
		valueTmpl(KCitizenship, "Гражданство клиента — ", func(g *gen) string { return pick(g.r, citizenships).nom }, ", какие документы нужны для открытия счёта?"),
		valueTmpl(KCitizenship, "В анкете указано гражданство ", func(g *gen) string { return pick(g.r, citizenships).nom }, ". Проверь ограничения по тарифу."),
		valueTmpl(KCitizenship, "Клиент — гражданин ", func(g *gen) string { return pick(g.r, citizenships).gen }, ", подскажи требования к удалённой идентификации."),
		valueTmpl(KCitizenship, "Подтверди, что гражданство ", func(g *gen) string { return pick(g.r, citizenships).nom }, " не мешает оформить вклад онлайн."),
	}

	singles[KPassportNumber] = []tmpl{
		piecesTmpl(KPassportNumber, "Проверь паспорт ", (*gen).passport, " по базе недействительных документов."),
		piecesTmpl(KPassportNumber, "В анкете указан паспорт ", (*gen).passport, ", сверь его с оригиналом."),
		piecesTmpl(KPassportNumber, "Клиент прислал скан документа: паспорт ", (*gen).passport, ". Что делать дальше?"),
		piecesTmpl(KPassportNumber, "Реквизиты паспорта ", (*gen).passport, " подойдут для удалённой идентификации?"),
	}

	singles[KPassportAuthority] = []tmpl{
		valueTmpl(KPassportAuthority, "Паспорт выдан ", func(g *gen) string { return pick(g.r, authorities) }, " — проверь, верно ли указан код подразделения."),
		valueTmpl(KPassportAuthority, "В графе «кем выдан» стоит ", func(g *gen) string { return pick(g.r, authorities) }, ", сверь с реестром подразделений."),
		valueTmpl(KPassportAuthority, "Уточни, действует ли ещё подразделение ", func(g *gen) string { return pick(g.r, authorities) }, "."),
	}

	singles[KPassportDeptCode] = []tmpl{
		valueTmpl(KPassportDeptCode, "Код подразделения ", (*gen).deptCode, " — сверь его с органом выдачи."),
		valueTmpl(KPassportDeptCode, "В анкете код подразделения ", (*gen).deptCode, ", проверь соответствие региону."),
		valueTmpl(KPassportDeptCode, "Клиент диктует код подразделения ", (*gen).deptCode, " — запиши в заявку."),
	}

	singles[KPassportIssueDate] = []tmpl{
		piecesTmpl(KPassportIssueDate, "Паспорт выдан ", func(g *gen) []piece { return g.datePieces(KPassportIssueDate, g.recentDate(2005, 20), cGen) }, " — пора ли его менять?"),
		piecesTmpl(KPassportIssueDate, "Дата выдачи паспорта — ", func(g *gen) []piece { return g.datePieces(KPassportIssueDate, g.recentDate(2005, 20), cNom) }, ". Проверь срок действия документа."),
		piecesTmpl(KPassportIssueDate, "В скане дата выдачи читается как ", func(g *gen) []piece { return g.datePieces(KPassportIssueDate, g.recentDate(2005, 20), cNom) }, ", подтверди по базе."),
	}

	singles[KDriverLicense] = []tmpl{
		piecesTmpl(KDriverLicense, "Проверь водительское удостоверение ", (*gen).driverLicense, " по базе ГИБДД."),
		piecesTmpl(KDriverLicense, "В заявке на автокредит указано ВУ ", (*gen).driverLicense, ", сверь с паспортом."),
		piecesTmpl(KDriverLicense, "Клиент прикрепил права ", (*gen).driverLicense, " — этого достаточно для идентификации?"),
	}

	singles[KAddress] = []tmpl{
		valueTmpl(KAddress, "Клиент зарегистрирован по адресу ", (*gen).address, " — измени адрес доставки карты."),
		valueTmpl(KAddress, "Адрес проживания: ", (*gen).address, ". Подбери ближайшее отделение."),
		valueTmpl(KAddress, "Отправь выписку почтой на адрес ", (*gen).address, "."),
		valueTmpl(KAddress, "В заявке указан адрес ", (*gen).address, " — проверь, входит ли он в зону доставки."),
	}

	singles[KEmail] = []tmpl{
		valueTmpl(KEmail, "Отправь подтверждение операции на ", func(g *gen) string { return g.email(g.person()) }, "."),
		valueTmpl(KEmail, "В профиле указана почта ", func(g *gen) string { return g.email(g.person()) }, ", она не совпадает с адресом в заявке."),
		valueTmpl(KEmail, "Клиент пишет с адреса ", func(g *gen) string { return g.email(g.person()) }, " — это тот же человек?"),
		valueTmpl(KEmail, "Добавь ", func(g *gen) string { return g.email(g.person()) }, " в рассылку по вкладам."),
	}

	singles[KPhone] = []tmpl{
		valueTmpl(KPhone, "Позвони клиенту на ", (*gen).phone, " и уточни адрес доставки."),
		valueTmpl(KPhone, "В анкете телефон ", (*gen).phone, " — отправь туда код подтверждения."),
		valueTmpl(KPhone, "Номер ", (*gen).phone, " не отвечает, есть другой контакт?"),
		valueTmpl(KPhone, "Замени контактный телефон на ", (*gen).phone, " и подтверди изменение."),
	}

	singles[KINN] = []tmpl{
		valueTmpl(KINN, "Проверь ИНН ", (*gen).inn, " в реестре налогоплательщиков."),
		valueTmpl(KINN, "В справке о доходах указан ИНН ", (*gen).inn, ", сверь с анкетой."),
		valueTmpl(KINN, "Клиент диктует ИНН ", (*gen).inn, " — добавь его в профиль."),
	}

	singles[KCardNumber] = []tmpl{
		valueTmpl(KCardNumber, "Заблокируй карту ", (*gen).cardNumber, ", клиент потерял её вчера."),
		valueTmpl(KCardNumber, "Проверь, прошёл ли платёж по карте ", (*gen).cardNumber, "."),
		valueTmpl(KCardNumber, "Перевыпусти карту ", (*gen).cardNumber, " на новый срок."),
		valueTmpl(KCardNumber, "По карте ", (*gen).cardNumber, " не приходят уведомления о списании."),
	}

	singles[KCVV] = []tmpl{
		valueTmpl(KCVV, "Клиент продиктовал CVV ", (*gen).cvv, " — объясни, что так делать нельзя."),
		valueTmpl(KCVV, "В форме оплаты поле CVV заполнено как ", (*gen).cvv, ", проверь тикет."),
		valueTmpl(KCVV, "Из переписки нужно вычистить CVV ", (*gen).cvv, " до передачи в модель."),
	}

	singles[KPIN] = []tmpl{
		valueTmpl(KPIN, "Клиент сообщил пин-код ", (*gen).pin, " — напомни ему правила безопасности."),
		valueTmpl(KPIN, "В обращении остался ПИН ", (*gen).pin, ", удали его из тикета."),
		valueTmpl(KPIN, "Проверь, не совпадает ли новый пин ", (*gen).pin, " с предыдущим."),
	}

	singles[KCardHolder] = []tmpl{
		valueTmpl(KCardHolder, "На карте эмбоссировано имя держателя ", func(g *gen) string { return g.person().latin() }, " — сверь с паспортом."),
		valueTmpl(KCardHolder, "Держатель карты — ", func(g *gen) string { return g.person().latin() }, ". Совпадает ли с ФИО в заявке?"),
		valueTmpl(KCardHolder, "В платёжном поручении указан держатель ", func(g *gen) string { return g.person().latin() }, ", проверь получателя."),
	}

	multis = []tmpl{
		{types: []string{KFullName, KPassportNumber, KAddress}, make: func(g *gen) []piece {
			p := g.person()
			return join(
				lit(litFindClient), val(KFullName, g.fullName(p, cAcc)),
				lit(litPassport), g.passport(),
				lit(", и покажи его адрес: "), val(KAddress, g.address()), lit("."),
			)
		}},
		{types: []string{KFullName, KBirthDate, KINN, KPhone}, make: func(g *gen) []piece {
			p := g.person()
			return join(
				lit("Оформи заявку: "), val(KFullName, g.fullName(p, cNom)),
				lit(", дата рождения "), g.datePieces(KBirthDate, g.birthDate(), cNom),
				lit(", ИНН "), val(KINN, g.inn()),
				lit(", телефон "), val(KPhone, g.phone()), lit("."),
			)
		}},
		{types: []string{KFullName, KBirthPlace, KCitizenship, KPassportNumber, KPassportAuthority, KPassportIssueDate, KPassportDeptCode}, make: func(g *gen) []piece {
			p := g.person()
			c := pick(g.r, citizenships)
			return join(
				lit("Проверь анкету: "), val(KFullName, g.fullName(p, cNom)),
				lit(", место рождения "), val(KBirthPlace, g.birthPlace()),
				lit(", гражданство "), val(KCitizenship, c.nom),
				lit(litPassport), g.passport(),
				lit(", выдан "), val(KPassportAuthority, pick(g.r, authorities)),
				lit(" "), g.datePieces(KPassportIssueDate, g.recentDate(2005, 20), cGen),
				lit(", код подразделения "), val(KPassportDeptCode, g.deptCode()), lit("."),
			)
		}},
		{types: []string{KFullName, KCardNumber, KCardHolder, KAddress, KPhone, KEmail}, make: func(g *gen) []piece {
			p := g.person()
			return join(
				lit(litClient), val(KFullName, g.fullName(p, cNom)),
				lit(" просит перевыпустить карту "), val(KCardNumber, g.cardNumber()),
				lit(" (держатель "), val(KCardHolder, p.latin()),
				lit("), новый адрес доставки "), val(KAddress, g.address()),
				lit(", контакты "), val(KPhone, g.phone()),
				lit(" и "), val(KEmail, g.email(p)), lit("."),
			)
		}},
		{types: []string{KDriverLicense, KPassportNumber, KINN, KAddress}, make: func(g *gen) []piece {
			return join(
				lit("Для автокредита собери документы: ВУ "), g.driverLicense(),
				lit(litPassport), g.passport(),
				lit(", ИНН "), val(KINN, g.inn()),
				lit(", адрес регистрации "), val(KAddress, g.address()), lit("."),
			)
		}},
		{types: []string{KPhone, KCardNumber, KCVV, KPIN}, make: func(g *gen) []piece {
			return join(
				lit("Клиент по телефону "), val(KPhone, g.phone()),
				lit(" диктует данные карты "), val(KCardNumber, g.cardNumber()),
				lit(", CVV "), val(KCVV, g.cvv()),
				lit(" и пин "), val(KPIN, g.pin()),
				lit(" — останови его и объясни правила безопасности."),
			)
		}},
		{types: []string{KFullName, KBirthDate, KBirthPlace, KEmail}, make: func(g *gen) []piece {
			p := g.person()
			return join(
				lit("Заполни карточку клиента: "), val(KFullName, g.fullName(p, cNom)),
				lit(", "+p.verb("родился", "родилась")+" "), g.datePieces(KBirthDate, g.birthDate(), cGen),
				lit(" в городе "), val(KBirthPlace, g.cityOnly()),
				lit(", почта для уведомлений "), val(KEmail, g.email(p)), lit("."),
			)
		}},
		{types: []string{KFullName, KCitizenship, KDriverLicense, KPhone}, make: func(g *gen) []piece {
			p := g.person()
			c := pick(g.r, citizenships)
			return join(
				lit("Подготовь ответ: заявитель "), val(KFullName, g.fullName(p, cNom)),
				lit(", гражданство "), val(KCitizenship, c.nom),
				lit(", водительское удостоверение "), g.driverLicense(),
				lit(", для связи "), val(KPhone, g.phone()), lit("."),
			)
		}},
		{types: []string{KCardHolder, KCardNumber, KCVV, KAddress}, make: func(g *gen) []piece {
			p := g.person()
			return join(
				lit("В платёжной форме держатель "), val(KCardHolder, p.latin()),
				lit(", карта "), val(KCardNumber, g.cardNumber()),
				lit(", CVV "), val(KCVV, g.cvv()),
				lit(", адрес выставления счёта "), val(KAddress, g.address()),
				lit(" — проверь, почему платёж отклонён."),
			)
		}},
	}

	cleanTexts = []string{
		"Какие документы нужны для открытия накопительного счёта?",
		"Подскажи текущие тарифы на переводы между своими счетами.",
		"Сколько стоит годовое обслуживание премиальной карты?",
		"Объясни, чем дебетовая карта отличается от кредитной.",
		"Как долго идёт межбанковский перевод в выходные дни?",
		"Составь шаблон ответа клиенту про сроки рассмотрения заявки.",
		"Нужно ли уведомлять банк о смене работодателя?",
		"Что такое льготный период по кредитной карте и когда он сгорает?",
		"Собери статистику по обращениям за прошлую неделю в разрезе тем.",
		"Напомни, какие операции доступны без подтверждения по СМС.",
		"Сформулируй вежливый отказ по заявке, не раскрывая причину скоринга.",
		"Чем отличается накопительный счёт от вклада с пополнением?",
		"Переведи описание тарифа на простой язык для пожилых клиентов.",
		"Какие лимиты действуют на снятие наличных в банкомате партнёра?",
	}
}
