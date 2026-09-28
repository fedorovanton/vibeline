package detect

import (
	"strings"
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

func init() { Register(counterScanner{}) }

// counterScanner — контр-правила: отличает персональные данные конкретного
// человека от похожих на них общедоступных сведений. Упоминание поэта
// Александра Пушкина персональными данными не является, как и адрес
// отделения банка (ТЗ §3.2.1, критерий 3).
//
// Сканер не удаляет чужих кандидатов: он их не видит. Результат работы —
// только запреты через Deny, а сопоставляет их с находками движок. Поэтому
// правило, отменяющее ФИО, пишется один раз и работает для любого сканера,
// который эти ФИО нашёл.
//
// Четыре правила:
//
//  1. Ролевое слово слева: «поэт Александр Пушкин» — вето на ФИО. Молчит,
//     если сразу перед ролью стоит маркер клиента: «Клиент — поэт Иван
//     Петров» — это клиент, а не публичная персона.
//  2. Топоним-производное: «улица Пушкина», «музей Пушкина», «имени
//     Королёва» — вето на ФИО. На адрес вето НЕ ставится: улица остаётся
//     адресом, просто не именем человека. Вето накрывает только название
//     объекта, а не ФИО, идущее за ним: «ул. Пушкина Иванов Иван Иванович».
//  3. Маркер организации слева: «отделение банка по адресу …», «горячая
//     линия …» — вето на адрес, телефон и email в окне справа.
//  4. Фамилия известного публичного лица — вето на ФИО, но только если в
//     предложении нет ни маркера клиента, ни цифровых реквизитов, ни
//     банковского слова («Юрий Гагарин хочет открыть вклад» — это клиент).
//
// Раунд 4 жюри (T-67) добавил к ним:
//
//   - должности: «министр финансов Антон Силуанов», «председатель ЦБ …» —
//     правило 1 с дополнением между должностью и именем
//     (counterDenyAfterOffice);
//   - контексты «памяти X», «в честь X», «к юбилею X», «по роману X»,
//     «роман «Анна Каренина»» — вариации правила 2, которые снимают ФИО
//     только того, кто стоит за словом, и ничьё больше;
//   - финансовых чиновников в новостях («Эльвира Набиуллина сообщила о
//     ключевой ставке») — правило 4, в котором банковские слова не
//     отменяют вето (publicMention с relaxed);
//   - контакты организации слева от оборота «X — адрес нашего офиса» и
//     блок реквизитов за маркером организации: «Отделение банка: 620014,
//     Екатеринбург, ул. Малышева, 31, тел. …» (правило 3).
//
// Раунд 5 жюри (T-82) — новостной и маркетинговый текст банка:
//
//   - профессии публичных лиц («вратарь», «экономист», «основатель»,
//     составная «пресс-секретарь») — метка fame, правило должности без
//     дополнения и с отменой вето банковским словом;
//   - «цитата от X», «собрание сочинений X», «в творчестве X», «выставка
//     X», «к дню рождения X» — метка mention, вариация tribute;
//   - «банк» — учреждение, а не операция (метка venue справочника
//     банковских слов): «продал долю в банке» вето правила 4 не отменяет;
//   - слово произведения с заглавной буквы в начале предложения: «Картина
//     Ильи Репина …».
//
// Асимметрия цены ошибки определяет всю настройку: лишняя маска стоит штрафа,
// пропуск означает утечку. Поэтому каждое правило снабжено условием, при
// котором оно молчит, и самое осторожное из них — четвёртое: однофамилец
// клиента по фамилии Пушкин обязан защищаться.
//
// Сложность прохода линейна по числу токенов: каждое окно ограничено
// константой, а признаки предложения считаются один раз на предложение
// (counterSentence). Вход сервиса — до сотен килобайт в одном предложении,
// и квадратичный цикл здесь — это ответ дольше таймаута проверяющей системы.
type counterScanner struct{}

// Name возвращает имя сканера.
func (counterScanner) Name() string { return "counter" }

// Справочники сканера. name_markers — чужой справочник маркеров человека,
// он читается только на чтение: дублировать список «клиент/заявитель/
// плательщик» во втором файле значило бы завести второй источник правды.
const (
	counterDictRoles   = "counter_roles"
	counterDictOrg     = "counter_org"
	counterDictPublic  = "counter_public"
	counterDictBanking = "counter_banking"
	counterDictPersons = "name_markers"
	counterDictGiven   = nameDictGiven
	// counterDictAddress — чужой справочник адресных маркеров («г», «ул»,
	// «д», «корп»), только на чтение: в блоке реквизитов организации он
	// отличает продолжение адреса от постороннего текста.
	counterDictAddress = "address_markers"
)

// Метки записей counter_org: назначение маркера. Подробное описание — в
// самом справочнике.
const (
	counterLabelToponym  = "toponym"
	counterLabelOrg      = "org"
	counterLabelOwner    = "owner"    // «X — адрес партнёра»
	counterLabelMemorial = "memorial" // «памяти X», «в честь X»
	counterLabelTribute  = "tribute"  // «к юбилею X» — только публичное лицо
	counterLabelMention  = "mention"  // «цитата от X», «выставка X» (T-82)
	counterLabelWork     = "work"     // «роман «…»», «по роману X»
)

// Метки записей counter_roles. Пустая метка — роль исторической или
// публичной фигуры (правило 1 без дополнения).
const (
	counterLabelOffice = "office" // государственная должность
	counterLabelChair  = "chair"  // должность, публичная только при органе
	counterLabelBody   = "body"   // орган в дополнении должности, не роль
	counterLabelFame   = "fame"   // профессия, публичная только в новостях (T-82)
)

// counterLabelOfficial — метка counter_public: финансовый чиновник, рядом с
// которым банковские слова — тема новости, а не признак клиента.
const counterLabelOfficial = "official"

// Метки записей counter_banking. Пустая метка — основа слова: совпадает любое
// слово, которое с неё начинается. Подробное описание — в самом справочнике.
const (
	counterLabelExact  = "exact"  // только слово целиком
	counterLabelExcept = "except" // исключение из более короткой основы
	counterLabelIdiom  = "idiom"  // не засчитывается в обороте «X в <что-то>»
	counterLabelVenue  = "venue"  // учреждение, а не операция: «банк» (T-82)
)

// Имена правил. Константы, а не собираемые строки: Scan не аллоцирует.
const (
	counterRuleRole    = "counter/public_role"
	counterRuleToponym = "counter/toponym"
	counterRuleOrg     = "counter/org_contacts"
	counterRulePublic  = "counter/public_person"
	counterRuleOffice  = "counter/public_office"
	counterRuleMention = "counter/public_context"
)

const (
	// counterRoleSkip — сколько связок допускается между ролевым словом и
	// именем: «поэт, писатель и драматург Александр Пушкин». Связкой считается
	// только другое ролевое слово или союз «и», поэтому произвольный текст
	// между ролью и именем правило не проскакивает.
	counterRoleSkip = 3

	// counterNameRunMax — предел длины конструкции имени, накрываемой вето,
	// в словах. Больше четырёх слов подряд с заглавной буквы — это уже не имя,
	// а название, и накрывать его целиком незачем.
	counterNameRunMax = 4

	// counterOrgWindow — окно справа от маркера организации в значимых
	// токенах. Ровно столько, сколько занимает служебная обвязка адреса
	// («по адресу», «расположено»), и не больше: за окном начинаются данные,
	// к организации отношения не имеющие.
	counterOrgWindow = 5

	// counterOrgLeftGuard — окно слева от маркера организации, в котором
	// маркер человека отменяет правило: «клиент банка Иванов» — это человек,
	// а не контакты банка.
	counterOrgLeftGuard = 2

	// counterSentenceDigits — сколько цифр в предложении достаточно, чтобы
	// правило 4 промолчало. Сканер не видит находок других сканеров, поэтому
	// «есть ли рядом другие ПД» проверяется по тексту: пять цифр — это год
	// и номер дома, шесть и больше — уже реквизит.
	counterSentenceDigits = 6

	// counterAbbrevRunes — предел длины слова, после которого точка считается
	// точкой сокращения, а не концом предложения: «ул.», «д.», «им.», «И.».
	counterAbbrevRunes = 3

	// counterMaxGap — предел промежутка между словами одной конструкции
	// в байтах: выравнивание колонок в форме даёт длинный пробел, но не
	// произвольный.
	counterMaxGap = 16

	// counterBioPlaceBack — на сколько токенов назад counterBioPlaceWord ищет
	// предлог места. Составной топоним — два-три слова («в Нижнем
	// Новгороде»); без предела шаг назад по серии заглавных слов делал проход
	// квадратичным: «родился в » + «Москва »×100 000 — 12 с на один запрос.
	counterBioPlaceBack = 3

	// counterRoleClientLeft — сколько слов слева от ролевой цепочки
	// проверяется на маркер клиента: «Клиент — поэт Иван Петров», «наш
	// клиент, известный поэт …». Дальше маркер относится уже к другому имени:
	// «Клиент Иванов просит открытку, где изображён композитор Чайковский».
	counterRoleClientLeft = 2

	// counterBankIdiomWindow — в пределах скольких слов за словом с меткой
	// idiom ищется предлог устойчивого оборота: «вклад Александра Пушкина в
	// литературу» — предлог третьим словом.
	counterBankIdiomWindow = 3

	// counterOfficeSkip — сколько слов дополнения допускается между
	// должностью и именем: «министр экономического развития Максим …»,
	// «председатель комитета Госдумы по …».
	counterOfficeSkip = 3

	// counterOfficeSteps — предел просмотра справа от должности в токенах.
	// Пунктуация и другие должности окно не расходуют, поэтому без общего
	// предела серия «министр , , , министр , , , …» делала бы проход
	// квадратичным.
	counterOfficeSteps = 24

	// counterOfficeRuns — сколько конструкций с заглавной буквы за
	// должностью накрывает вето: «губернатор Московской области Андрей
	// Воробьёв» — две.
	counterOfficeRuns = 3

	// counterQuoteMax — предел длины названия в кавычках после слова
	// произведения в токенах: «Война и мир», «Мастер и Маргарита». Незакрытая
	// за пределом кавычка — уже не название.
	counterQuoteMax = 10

	// counterOrgBack — на сколько токенов назад от оборота «— адрес нашего
	// офиса» простирается адрес организации: «Улица Льва Толстого, 16».
	counterOrgBack = 16

	// counterOwnerWindow — в пределах скольких слов за «адрес»/«телефон»
	// ищется владелец контакта: «адрес нашего офиса» — второе слово.
	counterOwnerWindow = 2

	// counterProseRunes — строчное слово от этой длины в блоке реквизитов
	// организации — уже посторонний текст: «…, д. 5 обслуживает Иванова,
	// тел. …». Короче — предлог или союз: «для», «при», «по».
	counterProseRunes = 4
)

// counterBirthField — основа явного поля анкеты «дата рождения», «место
// рождения». Такое поле в предложении означает реквизиты человека, и
// биография публичной персоны в нём не снимается.
const counterBirthField = "рождени"

// counterConj — союз, который в конструкции «поэт и писатель Пушкин» окно
// ролевых слов не разрывает.
const counterConj = "и"

var (
	// counterFullNameOnly — вето правил 2 и 4. Только ФИО: «улица
	// Пушкина» остаётся адресом.
	counterFullNameOnly = pii.NewSet(pii.FullName)

	// counterRoleTypes — вето правила 1. Кроме ФИО снимается и адрес:
	// фамилия публичной персоны бывает и названием города («композитор Пётр
	// Чайковский» — и город Чайковский в Пермском крае), а сразу за ролевым
	// словом стоит человек, а не место. Без адреса в наборе вето снимало
	// кандидата на ФИО, после чего фамилию подхватывал справочник городов, и
	// ловушка срабатывала под чужим типом: «композитор Пётр [АДРЕС_1]».
	//
	// Правилам 2 и 4 такое расширение противопоказано: в «улице Пушкина»
	// адрес — это и есть ответ, а упоминание персоны без ролевого слова
	// слишком слабо, чтобы гасить адрес клиента.
	counterRoleTypes = pii.NewSet(pii.FullName, pii.Address)

	// counterRoleBioTypes — вето правила 1 на остаток предложения после имени
	// публичной персоны: «Поэт Александр Пушкин родился в Москве» — место и
	// дата рождения здесь биография персоны, а не реквизиты клиента.
	counterRoleBioTypes = pii.NewSet(pii.BirthPlace, pii.BirthDate)

	// counterOrgTypes — вето правила 3: контакты организации.
	counterOrgTypes = pii.NewSet(pii.Address, pii.Phone, pii.Email)
)

// counterWord — слово-маркер. Короткие маркеры сравниваются целиком, иначе
// «инн» ловит «инновации»; длинные — по префиксу, чтобы покрыть словоформы.
//
// weak — слабое название реквизита: «карта», «счёт». В новости о
// финансовом чиновнике («ставки по картам», «за счёт бюджета») оно — тема
// текста, а не реквизит клиента, и в publicMention с relaxed не
// засчитывается.
type counterWord struct {
	word  string
	exact bool
	weak  bool
}

// counterPersonWords — слова, обозначающие конкретного человека. Дополняют
// справочник name_markers теми словами, которых там нет, и перечислены в
// коде, потому что привязаны к правилам этого файла.
//
// Слова «представитель» здесь нет намеренно: его префикс накрыл бы
// «представительство» — маркер организации с обратным смыслом.
var counterPersonWords = [...]counterWord{
	{word: "клиент"},
	{word: "заявител"},
	{word: "граждан"},
	{word: "плательщ"},
	{word: "получател"},
	{word: "держател"},
	{word: "сотрудник"},
	{word: "сотрудниц"},
	{word: "абонент"},
	{word: "господин"},
	{word: "госпожа"},
	{word: "пациент"},
	{word: "покупател"},
	{word: "заемщик"},
	{word: "заемщиц"},
	{word: "страховател"},
	{word: "застрахован"},
	{word: "вкладчик"},
	{word: "арендатор"},
	{word: "наниматель"},
	{word: "подписант"},
	{word: "доверител"},
	{word: "владелец", exact: true},
	// Английское обращение к человеку: «call me at», «call Mr. …» — это
	// телефон человека, а не call-центра из counter_org.
	{word: "me", exact: true},
	{word: "mr", exact: true},
	{word: "mrs", exact: true},
	{word: "ms", exact: true},
	{word: "владельц"},
	{word: "владелиц"},
	{word: "фио", exact: true},
}

// counterWordPhone — слово «телефон» в трёх списках ниже: реквизит человека,
// название контакта в блоке реквизитов и контакт в обороте «— телефон
// нашего офиса».
const counterWordPhone = "телефон"

// counterDataWords — слова, обозначающие реквизит конкретного человека.
// Их присутствие в предложении отменяет правило 4: рядом с паспортом и
// картой фамилия принадлежит клиенту, а не поэту.
//
// Правило 3 этот список НЕ использует: «отделение банка, телефон +7 495 …» —
// это телефон организации, и слово «телефон» отменять вето не должно.
var counterDataWords = [...]counterWord{
	{word: "паспорт"},
	{word: counterWordPhone},
	{word: "тел", exact: true},
	// Почта — такой же реквизит, как телефон: «Юрий Гагарин, почта …» —
	// клиент (бизнес-жюри 23.09, раунд 4, Б4-3). Формы перечислены: основа
	// «почт» ловит «почти».
	{word: "почта", exact: true},
	{word: "почты", exact: true},
	{word: "почте", exact: true},
	{word: "почту", exact: true},
	{word: "почтой", exact: true},
	{word: "email", exact: true},
	{word: "mail", exact: true},
	{word: "емейл"},
	{word: "имейл"},
	{word: "карта", exact: true, weak: true},
	{word: "карты", exact: true, weak: true},
	{word: "карте", exact: true, weak: true},
	{word: "карту", exact: true, weak: true},
	{word: "картой", exact: true, weak: true},
	{word: "карт", exact: true, weak: true},
	{word: "снилс", exact: true},
	{word: "инн", exact: true},
	{word: "полис"},
	{word: "счет", weak: true},
}

// counterRoleNeutral — маркеры из name_markers, которые перед ролевым словом
// клиента не означают: «фамилия поэта Пушкина», «подпись поэта», «наследник
// композитора» — имя за ролью принадлежит персоне, а не носителю поля.
// Правило 1 на них не молчит; правило 4 по-прежнему считает их маркерами
// клиента (поле анкеты — реквизит человека).
var counterRoleNeutral = [...]counterWord{
	{word: "фамили"},
	{word: "отчеств"},
	{word: "подпис"},
	{word: "наследни"},
}

// counterBlockWords — название контакта и часть адреса, которой нет в
// address_markers. В блоке реквизитов организации такое слово продлевает
// окно, как «адрес»: «…, ул. Малышева, 31, тел. +7 343 …», «…, 3 этаж».
var counterBlockWords = [...]counterWord{
	{word: "тел", exact: true},
	{word: counterWordPhone},
	{word: "факс"},
	{word: "почта", exact: true},
	{word: "почты", exact: true},
	{word: "email", exact: true},
	{word: "mail", exact: true},
	{word: "сайт"},
	{word: "доб", exact: true},
	{word: "этаж"},
	{word: "эт", exact: true},
	{word: "пом", exact: true},
	{word: "помещени"},
	{word: "каб", exact: true},
	{word: "кабинет"},
	{word: "подъезд"},
	{word: "вход", exact: true},
}

// counterOwnedWords — контакт в обороте «X — адрес нашего офиса»: слово, за
// которым назван владелец, а перед которым через тире — сам контакт.
var counterOwnedWords = [...]counterWord{
	{word: "адрес", exact: true},
	{word: "адреса", exact: true},
	{word: counterWordPhone, exact: true},
	{word: "телефоны", exact: true},
	{word: "тел", exact: true},
}

// counterPronouns — местоимения лица. В окне правила 3 они, как маркер
// человека, окно закрывают: «Филиал на Тверской обслуживает Иванова, его
// телефон …», «Клиент спросил адрес нашего офиса, сам он живёт по адресу …»
// — дальше данные человека. «Мы» здесь нет: «мы находимся по адресу …» —
// голос организации.
var counterPronouns = [...]string{
	// «им» нет намеренно: это и сокращение «им. Ленина» в адресе.
	"я", "он", "она", "они", wordHis, "ее", "их", "ему", "ей", "него", "нее", "нему", "ней",
	"мой", "моя", "мое", "мои", "мне", "меня", "свой", "своя", "свое", "свои",
}

// counterAdjEndings — окончания прилагательного. Одиночное слово с
// заглавной буквы с таким окончанием за должностью — дополнение, а не
// фамилия: «губернатор Московской области …», «председатель Центрального
// банка …».
var counterAdjEndings = [...]string{"ой", "ий", "ый", "ая", "ого", wordHis, "ому", "ему", "ых", "их"}

// counterAddressLead — служебное слово, после которого адрес ещё не начался.
// Внутри окна правила 3 оно окно продлевает: «отделение банка по адресу
// Москва, ул. Ленина, 5» — сам адрес стоит через три служебных слова.
const counterAddressLead = "адрес"

// Scan регистрирует запреты. Кандидатов сканер не добавляет: его результат —
// только вето, которые движок сопоставляет с находками остальных сканеров.
func (counterScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	p := counterPass{
		roles:   dicts.Table(counterDictRoles),
		orgs:    dicts.Table(counterDictOrg),
		public:  dicts.Table(counterDictPublic),
		persons: dicts.Table(counterDictPersons),
		given:   dicts.Table(counterDictGiven),
		address: dicts.Table(counterDictAddress),
	}
	p.sent = counterSentence{
		roles:   p.roles,
		persons: p.persons,
		banking: dicts.Table(counterDictBanking),
		orgs:    p.orgs,
		hi:      -1,
	}

	for i := range doc.Tokens {
		if doc.Tokens[i].Kind != lex.KindWord {
			continue
		}
		p.word(doc, i, out)
	}
}

// counterPass — справочники и признаки предложения одного прохода Scan.
// Значение живёт на стеке Scan.
type counterPass struct {
	roles, orgs, public, persons, given, address *dict.Table
	sent                                         counterSentence
}

// word применяет контр-правила к слову i.
func (p *counterPass) word(doc *lex.Doc, i int, out *Candidates) {
	if label, last, ok := counterRoleAt(doc, p.roles, i); ok {
		p.afterRole(doc, last, label, out)
		return
	}
	w := doc.NormOf(i)
	if label, ok := p.orgs.Get(w); ok {
		p.afterOrg(doc, i, label, out)
		return
	}
	if counterMatch(counterOwnedWords[:], w) {
		counterDenyOrgBefore(doc, p.orgs, p.persons, i, out)
		return
	}
	// Правило 4. Заглавная буква обязательна: кандидатом на ФИО слово со
	// строчной всё равно не станет, а лишнее вето стоит проверки.
	if !counterNameToken(doc, i) {
		return
	}
	if label, ok := p.public.Get(w); ok && p.sent.load(doc, i).publicMention(label == counterLabelOfficial) {
		t := doc.Tokens[i]
		out.Deny(int(t.Start), int(t.End), counterFullNameOnly, counterRulePublic)
	}
}

// afterRole применяет правило ролевого слова или должности с меткой label.
func (p *counterPass) afterRole(doc *lex.Doc, i int, label string, out *Candidates) {
	switch label {
	case counterLabelOffice, counterLabelChair, counterLabelFame:
		counterDenyAfterOffice(doc, &p.sent, i, label, out)
	default:
		counterDenyAfterRole(doc, &p.sent, i, out)
	}
}

// counterRoleAt ищет ролевое слово, начатое токеном i: составное через
// дефис («пресс-секретарь», «экс-министр») или одиночное. Возвращает метку
// и последний токен роли. Орган из дополнения должности (метка body) ролью
// не считается.
//
// Лексер делит «Пресс-секретарь» на три токена, и по одиночным словам роль
// не находилась: «пресс» ролью не бывает, а «секретарь» без приставки —
// сотрудник, чьё имя защищается (бизнес-жюри 23.09, раунд 5).
func counterRoleAt(doc *lex.Doc, roles *dict.Table, i int) (string, int, bool) {
	if end := i + 2; end < len(doc.Tokens) && doc.Tokens[end].Kind == lex.KindWord &&
		counterHyphenJoin(doc, i, end) && doc.Adjacent(i) && doc.Adjacent(i+1) {
		key := doc.Norm[doc.Tokens[i].Start:doc.Tokens[end].End]
		if label, ok := roles.Get(key); ok && label != counterLabelBody {
			return label, end, true
		}
	}
	label, ok := roles.Get(doc.NormOf(i))
	return label, i, ok && label != counterLabelBody
}

// afterOrg применяет правило маркера объекта или организации с меткой label.
func (p *counterPass) afterOrg(doc *lex.Doc, i int, label string, out *Candidates) {
	switch label {
	case counterLabelToponym:
		counterDenyAfterToponym(doc, p.given, i, out)
	case counterLabelMemorial:
		counterDenyAfterMention(doc, nil, i, out)
	case counterLabelTribute, counterLabelMention:
		counterDenyAfterMention(doc, p.public, i, out)
	case counterLabelWork:
		counterDenyAfterWork(doc, p.given, p.public, i, out)
	case counterLabelOrg:
		counterDenyOrgContacts(doc, p.orgs, p.persons, p.address, i, out)
	}
}

// counterIsRole сообщает, что слово — ролевое слово или должность, а не
// орган из дополнения должности (метка body).
func counterIsRole(roles *dict.Table, w string) bool {
	label, ok := roles.Get(w)
	return ok && label != counterLabelBody
}

// counterDenyRoleBio снимает место и дату рождения в остатке предложения
// после имени публичной персоны. role — индекс ролевого слова, last —
// последний токен имени.
//
// Биография не снимается вовсе, если в предложении есть признак клиента
// (counterSentence.bioAllowed): «Клиент Иванов Иван Иванович, как и поэт
// Александр Пушкин, родился 06.06.1985 в Москве» — дата и место здесь
// клиента, хотя стоят после имени поэта.
//
// Вето кончается на границе предложения, на следующем слове, похожем на
// начало другого имени, и на следующем ролевом слове: «поэт Пушкин и клиент
// Иванов Иван, родился в Твери» — место рождения здесь уже может относиться к
// клиенту, и снимать его нельзя. Пропуск дороже лишней маски, поэтому граница
// консервативная. Обрыв на ролевом слове делает прогоны биографии
// непересекающимися: у следующей персоны прогон свой, и общий проход остаётся
// линейным.
func counterDenyRoleBio(doc *lex.Doc, sent *counterSentence, role, last int, out *Candidates) {
	if counterSentenceEnd(doc, last) || !sent.load(doc, role).bioAllowed(role) {
		return
	}
	end := last
	for j := last + 1; j < len(doc.Tokens); j++ {
		if counterNameToken(doc, j) && !counterBioPlaceWord(doc, j) {
			break
		}
		if doc.Tokens[j].Kind == lex.KindWord && counterIsRole(sent.roles, doc.NormOf(j)) {
			break
		}
		end = j
		if counterSentenceEnd(doc, j) {
			break
		}
	}
	if end > last {
		out.Deny(int(doc.Tokens[last].End), int(doc.Tokens[end].End), counterRoleBioTypes, counterRuleRole)
	}
}

// counterBioPlaceWord сообщает, что заглавное слово стоит после предлога
// места («в Москве», «под Тулой», «из Твери») — это топоним биографии, а не
// начало чужого имени. Назад просматривается не больше counterBioPlaceBack
// токенов.
func counterBioPlaceWord(doc *lex.Doc, j int) bool {
	for k := j - 1; k >= 0 && k >= j-counterBioPlaceBack; k-- {
		t := doc.Tokens[k]
		if t.Kind == lex.KindPunct {
			return false
		}
		if t.Kind != lex.KindWord {
			return false
		}
		switch doc.NormOf(k) {
		case "в", "во", wordUnder, "из", "на", "у", "близ", wordNear, "г", "город", "городе", "села", "селе", "деревне":
			return true
		}
		// Второе слово составного топонима: «в Нижнем Новгороде».
		if !doc.Tokens[k].Flags.Has(lex.FlagFirstUpper) {
			return false
		}
	}
	return false
}

// counterDenyAfterRole — правило 1: ролевое слово публичной персоны слева.
//
// Между ролью и именем допускаются только другие ролевые слова и союз «и»:
// «поэт написал письмо Иванову» вето не даёт, потому что «написал» связкой
// не является и разбор на нём прекращается.
//
// Маркер клиента сразу перед ролевой цепочкой правило отменяет: «Клиент —
// поэт Иван Петров, дата рождения 14.02.1979» — это клиент с профессией,
// и снять его ФИО значит отдать его наружу.
func counterDenyAfterRole(doc *lex.Doc, sent *counterSentence, i int, out *Candidates) {
	roles := sent.roles
	if counterClientBeforeRole(doc, roles, sent.persons, i) {
		return
	}
	skipped := 0
	for j := i + 1; j < len(doc.Tokens); j++ {
		if counterSentenceEnd(doc, j-1) {
			return
		}
		t := doc.Tokens[j]
		switch {
		case t.Kind == lex.KindPunct:
			// Запятая в «поэт, писатель Александр Пушкин» окно не расходует.
			continue
		case counterNameToken(doc, j):
			last := counterNameRunEnd(doc, j)
			out.Deny(int(t.Start), int(doc.Tokens[last].End), counterRoleTypes, counterRuleRole)
			counterDenyRoleBio(doc, sent, i, last, out)
			return
		case t.Kind == lex.KindWord:
			w := doc.NormOf(j)
			if !counterIsRole(roles, w) && w != counterConj {
				return
			}
			skipped++
			if skipped > counterRoleSkip {
				return
			}
		default:
			return
		}
	}
}

// counterDenyAfterToponym — правило 2: фамилия внутри названия объекта.
//
// Вето ставится только на ФИО. Адрес при этом остаётся адресом: «улица
// Пушкина, дом 5» — не имя человека, но вполне место жительства.
//
// Вето накрывает название объекта, а не всю цепочку слов с заглавной буквы
// за маркером: в табличной выгрузке «ул. Пушкина⇥Иванов Иван Иванович» за
// названием улицы сразу идёт ФИО клиента, и вето на всю цепочку отпускало
// его открытым. Границу названия определяет counterToponymEnd.
func counterDenyAfterToponym(doc *lex.Doc, given *dict.Table, i int, out *Candidates) {
	j, ok := counterObjectStart(doc, i)
	if !ok {
		return
	}
	last := counterToponymEnd(doc, given, j)
	out.Deny(int(doc.Tokens[j].Start), int(doc.Tokens[last].End), counterFullNameOnly, counterRuleToponym)
}

// counterObjectStart возвращает первый токен имени сразу за маркером i:
// «улица Пушкина», «им. Королёва», «памяти Виктора Цоя». Точка сокращения
// после маркера пропускается, конец предложения и разрыв строки — нет.
func counterObjectStart(doc *lex.Doc, i int) (int, bool) {
	j := i + 1
	if j >= len(doc.Tokens) {
		return 0, false
	}
	if counterAbbrevDot(doc, i, j) {
		// «им. Королёва»: точка сокращения предложение не заканчивает.
		j++
	} else if counterSentenceEnd(doc, i) {
		return 0, false
	}
	if j >= len(doc.Tokens) || !counterNameToken(doc, j) || !counterJoinable(doc, j-1) {
		return 0, false
	}
	return j, true
}

// counterDenyAfterMention — «памяти Виктора Цоя», «в честь Юрия Гагарина»
// (метка memorial) и «к юбилею Юрия Гагарина», «по местам Михаила
// Лермонтова», «с портретом …» (метка tribute), T-67. Вето получает только
// тот, кто назван за словом: клиентка «Анна Цой, тел. …, хочет билеты на
// концерт памяти Виктора Цоя» остаётся под маской — её имя стоит не за
// словом «памяти». Зато признаки клиента в предложении вето не отменяют:
// «Экскурсия по местам Михаила Лермонтова для держателей премиальных карт» —
// держатели здесь другие люди.
//
// Юбилей и портрет бывают и у клиента, поэтому для tribute и mention
// (public не nil) вето ставится, только если в имени есть фамилия из
// counter_public. Метка mention (T-82) — «цитата», «творчество»,
// «выставка», «день рождения», «интервью»: действует как tribute, но в
// counterTributeAlone не участвует.
//
// Граница имени — вся конструкция с заглавной буквы, а не название объекта
// counterToponymEnd: за «памяти» и «юбилеем» идёт имя человека, а не
// табличная выгрузка адреса, и «Льва Толстого» разбирается целиком, даже
// когда формы «Льва» нет в справочнике имён.
//
// Для tribute и mention между словом и именем допускается предлог «от»,
// «о», «про», а перед ним — одно строчное слово: «Цитата от Льва Толстого
// для открытки клиентам», «Цитата дня от Льва Толстого» (T-82). Маркер
// клиента в таком предложении — адресат открытки, а не автор цитаты,
// поэтому правило 4 здесь молчит, и снимать автора приходится по слову
// «цитата».
func counterDenyAfterMention(doc *lex.Doc, public *dict.Table, i int, out *Candidates) {
	j, ok := counterObjectStart(doc, i)
	if !ok && public != nil {
		j, ok = counterTributeLead(doc, i)
	}
	if !ok {
		return
	}
	last := counterNameRunEnd(doc, j)
	if public != nil && !counterHasPublic(doc, public, j, last) {
		return
	}
	out.Deny(int(doc.Tokens[j].Start), int(doc.Tokens[last].End), counterFullNameOnly, counterRuleMention)
}

// counterTributeLead возвращает первый токен имени за словом tribute i,
// отделённым от имени предлогом: «цитата от Льва Толстого», «цитата дня от
// Льва Толстого». Перед предлогом допускается одно строчное слово.
func counterTributeLead(doc *lex.Doc, i int) (int, bool) {
	k := i + 1
	if counterLowerWord(doc, i, k) && !counterTributePrep(doc, k) {
		k++
	}
	if !counterLowerWord(doc, k-1, k) || !counterTributePrep(doc, k) {
		return 0, false
	}
	return counterObjectStart(doc, k)
}

// counterLowerWord сообщает, что токен k — строчное слово, стоящее за
// токеном prev без разрыва строки.
func counterLowerWord(doc *lex.Doc, prev, k int) bool {
	if k >= len(doc.Tokens) || !counterJoinable(doc, prev) {
		return false
	}
	t := doc.Tokens[k]
	return t.Kind == lex.KindWord && !t.Flags.Has(lex.FlagFirstUpper)
}

// counterTributePrep сообщает, что слово k — предлог между словом tribute и
// именем: «цитата от», «лекция о», «фильм про».
func counterTributePrep(doc *lex.Doc, k int) bool {
	w := doc.NormOf(k)
	return w == "от" || counterAboutPrep(w)
}

// counterAboutPrep сообщает, что слово — предлог темы: «о», «об», «обо»,
// «про».
func counterAboutPrep(w string) bool {
	switch w {
	case "о", "об", "обо", wordAbout:
		return true
	}
	return false
}

// counterHasPublic сообщает, что среди слов [j, last] есть фамилия из
// counter_public.
func counterHasPublic(doc *lex.Doc, public *dict.Table, j, last int) bool {
	for k := j; k <= last; k++ {
		if doc.Tokens[k].Kind == lex.KindWord && public.Has(doc.NormOf(k)) {
			return true
		}
	}
	return false
}

// counterDenyAfterWork — произведение (метка work, T-67): «роман «Анна
// Каренина»», «по роману Льва Толстого», «фильм о Владимире Высоцком».
//
// Название в кавычках снимается целиком — и как ФИО, и как адрес: «Анна
// Каренина» — заглавие, а не человек. Имя автора за кавычкой («Роман «Анна
// Каренина» Толстого») и имя сразу за словом — автор или герой — снимается
// как ФИО. Слово-имя с заглавной буквы работает только перед кавычкой:
// «Роман Иванов хочет кредит» — это имя, а не произведение. Остальные слова
// работают и с заглавной, в начале предложения: «Картина Ильи Репина
// «Бурлаки на Волге» хранится в Русском музее» (бизнес-жюри 23.09, раунд 5)
// — «Картина» именем не бывает.
//
// Имя автора или героя снимается, только если в нём есть фамилия из
// counter_public, как у tribute. Без этого условия правило снимало любое
// имя за словом произведения, и «Картина Ивана Петрова продана, деньги на
// счёт 40817810…» отдавала наружу ФИО продавца рядом с его счётом (проверка
// оркестратора 23.09, T-82). Автор известного произведения — публичное лицо
// по определению, и справочник публичных лиц его знает; имя, которого в
// справочнике нет, отличить от клиента по одному слову «картина» нельзя, а
// пропуск ПД дороже лишней маски. Название в кавычках снимается по-прежнему
// всегда: заглавие человеком не является.
func counterDenyAfterWork(doc *lex.Doc, given, public *dict.Table, i int, out *Candidates) {
	j := i + 1
	if j >= len(doc.Tokens) || counterSentenceEnd(doc, i) {
		return
	}
	if counterQuote(doc, j) {
		counterDenyQuotedWork(doc, public, j, out)
		return
	}
	if doc.Tokens[i].Flags.Has(lex.FlagFirstUpper) && counterGivenName(given, doc.NormOf(i)) {
		return
	}
	if t := doc.Tokens[j]; t.Kind == lex.KindWord && counterAboutPrep(doc.NormOf(j)) {
		// «фильм о Владимире Высоцком».
		j++
	}
	if j >= len(doc.Tokens) || !counterNameToken(doc, j) || !counterJoinable(doc, j-1) {
		return
	}
	counterDenyPublicRun(doc, public, j, out)
}

// counterDenyPublicRun снимает ФИО с конструкции имени, начатой токеном j,
// если в ней есть фамилия из counter_public. Граница имени — вся
// конструкция, как в counterDenyAfterMention.
func counterDenyPublicRun(doc *lex.Doc, public *dict.Table, j int, out *Candidates) {
	last := counterNameRunEnd(doc, j)
	if counterHasPublic(doc, public, j, last) {
		out.Deny(int(doc.Tokens[j].Start), int(doc.Tokens[last].End), counterFullNameOnly, counterRuleMention)
	}
}

// counterGivenName сообщает, что слово — личное имя из справочника в любом
// падеже: «Роман», «Романа».
func counterGivenName(given *dict.Table, w string) bool {
	_, ok := nameLookupGiven(given, w)
	return ok
}

// counterDenyQuotedWork снимает название произведения в кавычках, открытых
// кавычкой open, и имя публичного автора сразу за закрывающей кавычкой.
func counterDenyQuotedWork(doc *lex.Doc, public *dict.Table, open int, out *Candidates) {
	end, ok := counterQuoteEnd(doc, open)
	if !ok {
		return
	}
	if end > open+1 {
		out.Deny(int(doc.Tokens[open+1].Start), int(doc.Tokens[end-1].End), counterRoleTypes, counterRuleMention)
	}
	if a := end + 1; a < len(doc.Tokens) && counterNameToken(doc, a) && counterJoinable(doc, end) {
		counterDenyPublicRun(doc, public, a, out)
	}
}

// counterQuote сообщает, что токен — кавычка.
func counterQuote(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	if t.Kind != lex.KindPunct {
		return false
	}
	switch doc.Raw(i) {
	case "«", "»", "\"", "„", "“", "”":
		return true
	}
	return false
}

// counterQuoteEnd возвращает закрывающую кавычку названия, открытого
// кавычкой open. Название длиннее counterQuoteMax токенов и название,
// оборванное концом предложения, названием не считаются.
func counterQuoteEnd(doc *lex.Doc, open int) (int, bool) {
	for k := open + 1; k < len(doc.Tokens) && k <= open+counterQuoteMax; k++ {
		if counterQuote(doc, k) {
			return k, true
		}
		if counterSentenceEnd(doc, k) {
			return 0, false
		}
	}
	return 0, false
}

// counterDenyAfterOffice — должность (метки office и chair, T-67):
// «Министр финансов Антон Силуанов», «Председатель Банка России Эльвира
// Набиуллина», «губернатор Московской области Андрей Воробьёв».
//
// В отличие от правила 1, между должностью и именем допускается дополнение:
// до counterOfficeSkip строчных слов и одиночные слова с заглавной буквы,
// похожие на часть названия органа («Московской», «ЦБ»). Вето накрывает все
// конструкции с заглавной буквы в окне — ФИО и адрес, как в правиле 1:
// орган в дополнении («Москвы», «Московской области») адресом клиента не
// является.
//
// Должность — не роль исторической фигуры: и депутат, и министр бывают
// клиентами банка. Поэтому правило молчит при признаках клиента в
// предложении (publicMention с relaxed: маркер, реквизит, его название,
// банковская операция с лицом) и при маркере клиента прямо перед
// должностью. Банковские слова его не отменяют: «Министр финансов … заявил
// о снижении ключевой ставки» — новость, а не заявка.
//
// Метка chair требует органа в дополнении (метка body): «председатель ЦБ» —
// публичное лицо, «председатель ТСЖ Иванова» — соседка, её имя защищается.
//
// Метка fame (T-82) — профессия, публичная только в новостном тексте:
// «вратарь Игорь Акинфеев», «основатель Telegram Павел Дуров», «экономист
// Сергей Гуриев». Такая профессия бывает и у клиента, поэтому правило
// строже, чем у должности: банковские слова вето отменяют (publicMention
// без relaxed), а строчного дополнения между словом и именем нет —
// «основатель компании Иванов Иван» остаётся под маской.
func counterDenyAfterOffice(doc *lex.Doc, sent *counterSentence, i int, label string, out *Candidates) {
	roles := sent.roles
	fame := label == counterLabelFame
	if counterClientBeforeRole(doc, roles, sent.persons, i) || !sent.load(doc, i).publicMention(!fame) {
		return
	}
	w := counterOfficeWindow{
		roles:   roles,
		persons: sent.persons,
		body:    label != counterLabelChair,
		skip:    counterOfficeSkip,
		stop:    min(len(doc.Tokens), i+1+counterOfficeSteps),
	}
	if fame {
		w.skip = 0
	}
	for j := i + 1; j < w.stop; j++ {
		if counterSentenceEnd(doc, j-1) {
			break
		}
		next, more := w.step(doc, j)
		if !more {
			break
		}
		j = next
	}
	if !w.body {
		return
	}
	for _, r := range w.runs[:w.n] {
		out.Deny(int(doc.Tokens[r[0]].Start), int(doc.Tokens[r[1]].End), counterRoleTypes, counterRuleOffice)
	}
}

// counterOfficeWindow — состояние окна за должностью в counterDenyAfterOffice.
type counterOfficeWindow struct {
	roles, persons *dict.Table
	// runs — конструкции с заглавной буквы в окне, n — их число.
	runs [counterOfficeRuns][2]int
	n    int
	// words — число строчных слов дополнения, skip — их предел, stop —
	// граница окна.
	words, skip, stop int
	// body — в дополнении назван орган, single — предыдущая конструкция —
	// одно слово-дополнение.
	body, single bool
}

// step разбирает токен j окна. Возвращает токен, с которого окно идёт
// дальше, и сообщает, что окно не закончилось.
func (w *counterOfficeWindow) step(doc *lex.Doc, j int) (int, bool) {
	t := doc.Tokens[j]
	switch {
	case t.Kind == lex.KindPunct:
		return j, true
	case counterNameToken(doc, j):
		return w.nameRun(doc, j)
	case t.Kind == lex.KindWord:
		return j, w.word(doc, j)
	}
	return j, false
}

// nameRun запоминает конструкцию с заглавной буквы, начатую токеном j.
func (w *counterOfficeWindow) nameRun(doc *lex.Doc, j int) (int, bool) {
	last := counterNameRunEnd(doc, j)
	if counterRunHasBody(doc, w.roles, j, last) {
		w.body = true
	}
	w.runs[w.n] = [2]int{j, last}
	w.n++
	if last > j || w.n == len(w.runs) || !counterOfficeComplement(doc, w.roles, j) {
		// Имя из двух слов и больше или одиночная фамилия: окно
		// закончилось на ней.
		return j, false
	}
	w.single = true
	return last, true
}

// word разбирает строчное слово j дополнения и сообщает, что окно не
// закончилось.
func (w *counterOfficeWindow) word(doc *lex.Doc, j int) bool {
	s := doc.NormOf(j)
	if counterPersonMarker(w.persons, s) {
		return false
	}
	label, ok := w.roles.Get(s)
	if ok && label == counterLabelBody {
		w.body = true
	}
	if w.single && !ok {
		// За одиночным словом-дополнением — не больше одного слова:
		// «Московской области Андрей …», «Центрального банка России …».
		// «министр Толстой заявил, что Иванов Иван …» дальше не идёт.
		w.single = false
		if j+1 < w.stop && !counterNameToken(doc, j+1) {
			return false
		}
	}
	w.words++
	return w.words <= w.skip
}

// counterRunHasBody сообщает, что среди слов [j, last] есть орган из
// дополнения должности (метка body).
func counterRunHasBody(doc *lex.Doc, roles *dict.Table, j, last int) bool {
	for k := j; k <= last; k++ {
		if l, ok := roles.Get(doc.NormOf(k)); ok && l == counterLabelBody {
			return true
		}
	}
	return false
}

// counterOfficeComplement сообщает, что одиночное слово с заглавной буквы за
// должностью — часть названия органа, а не фамилия: орган из справочника
// («ЦБ», «Минфина») или прилагательное перед строчным словом
// («Московской области», «Центрального банка»).
func counterOfficeComplement(doc *lex.Doc, roles *dict.Table, j int) bool {
	w := doc.NormOf(j)
	if l, ok := roles.Get(w); ok && l == counterLabelBody {
		return true
	}
	next := j + 1
	if next >= len(doc.Tokens) || doc.Tokens[next].Kind != lex.KindWord ||
		doc.Tokens[next].Flags.Has(lex.FlagFirstUpper) || !counterJoinable(doc, j) {
		return false
	}
	for _, end := range counterAdjEndings {
		if strings.HasSuffix(w, end) {
			return true
		}
	}
	return false
}

// counterToponymTitles — звания и титулы в названиях объектов: «улица
// Маршала Жукова», «проспект Академика Сахарова». Формы — родительный
// падеж, в нормализованном виде (ё → е).
var counterToponymTitles = [...]string{
	"академика", "маршала", "генерала", "адмирала", "героя", "героев",
	"космонавта", "летчика", "профессора", "доктора", "писателя", "поэта",
	"композитора", "художника", "архитектора", "капитана", "полковника",
	"майора", "лейтенанта", "сержанта", "партизана", "командарма",
	"комиссара", "братьев", "сестер", "святого", "святой", "преподобного",
}

// counterToponymTails — окончания слова, продолжающего составное название
// объекта. Название от имени человека стоит в родительном падеже: «Льва
// Толстого», «Зои Космодемьянской», «Маршала Жукова», «Тараса Шевченко».
var counterToponymTails = [...]string{"а", "я", "о", "ого", wordHis, "ой", "ей", "ы", "и"}

// counterPatronymicGenitive — окончания отчества в родительном падеже:
// «музей Александра Сергеевича Пушкина».
var counterPatronymicGenitive = [...]string{"вича", "ича", "вны", "ичны"}

// counterToponymEnd возвращает последний токен названия объекта, которое
// начинается с токена j сразу за маркером топонима.
//
// Название — одно слово («Пушкина») вместе с частями через дефис
// («Салтыкова-Щедрина»). Составное название из нескольких слов («Льва
// Толстого», «Маршала Жукова», «М. Горького») принимается, только если
// выполнены все три условия:
//
//   - каждое слово, кроме последнего, — инициал, звание из
//     counterToponymTitles, имя из справочника или отчество в родительном
//     падеже: такое слово само названием не бывает и требует продолжения;
//   - каждое следующее слово стоит в родительном падеже;
//   - за последним словом цепочка слов с заглавной буквы заканчивается.
//
// Иначе вето накрывает только первое слово. Третье условие и есть граница с
// ФИО: «ул. Льва Толстого Иванов Иван» — за составным названием идут ещё
// слова, и разделить название и имя по одной морфологии нельзя. Тогда вето
// сужается до «Льва», а остаток отдаётся сканеру ФИО: лишняя маска на
// «Толстого» стоит штрафа, вето на ФИО клиента — утечки.
func counterToponymEnd(doc *lex.Doc, given *dict.Table, j int) int {
	r := counterToponymRun{head: j, last: j, composite: true}
	for words := 1; words < counterNameRunMax; words++ {
		next, ok := counterRunNext(doc, r.last)
		if !ok {
			break
		}
		r.link(doc, given, next)
		if !r.composite && r.headDone {
			return r.head
		}
		r.last = next
	}
	if !r.composite {
		return r.head
	}
	if _, more := counterRunNext(doc, r.last); more {
		// Цепочка длиннее предела или продолжается за составным названием.
		return r.head
	}
	return r.last
}

// counterToponymRun — состояние разбора названия объекта в counterToponymEnd.
type counterToponymRun struct {
	// head — последний токен первого слова вместе с частями через дефис,
	// last — последний разобранный токен.
	head, last int
	// composite — слова пока складываются в составное название, headDone —
	// первое слово закончилось.
	composite, headDone bool
}

// link присоединяет к названию слово next, следующее за last.
func (r *counterToponymRun) link(doc *lex.Doc, given *dict.Table, next int) {
	if counterHyphenJoin(doc, r.last, next) {
		if !r.headDone {
			r.head = next
		}
		return
	}
	r.headDone = true
	if !counterToponymLead(doc, given, r.last) || !counterToponymTail(doc, next) {
		r.composite = false
	}
}

// counterHyphenJoin сообщает, что слова last и next соединены дефисом:
// «Салтыкова-Щедрина» — одно название.
func counterHyphenJoin(doc *lex.Doc, last, next int) bool {
	if next != last+2 {
		return false
	}
	t := doc.Tokens[last+1]
	return t.Kind == lex.KindPunct && doc.Text[t.Start] == '-'
}

// counterToponymLead сообщает, что слово открывает составное название и
// требует продолжения: инициал, звание, имя или отчество в родительном
// падеже.
func counterToponymLead(doc *lex.Doc, given *dict.Table, i int) bool {
	if counterInitial(doc, i) {
		return true
	}
	w := doc.NormOf(i)
	for _, title := range counterToponymTitles {
		if w == title {
			return true
		}
	}
	for _, end := range counterPatronymicGenitive {
		if strings.HasSuffix(w, end) {
			return true
		}
	}
	return counterGivenName(given, w)
}

// counterToponymTail сообщает, что слово может продолжать составное
// название: инициал или слово в родительном падеже.
func counterToponymTail(doc *lex.Doc, i int) bool {
	if counterInitial(doc, i) {
		return true
	}
	w := doc.NormOf(i)
	for _, end := range counterToponymTails {
		if strings.HasSuffix(w, end) {
			return true
		}
	}
	return false
}

// counterDenyOrgContacts — правило 3: адрес, телефон и email организации.
//
// Вето накрывает окно справа от маркера, а не весь остаток предложения:
// «Филиал на Тверской обслуживает Иванова, его телефон +7 …» — телефон здесь
// принадлежит человеку и должен быть замаскирован. Ограниченное окно и есть
// та граница, за которой правило перестаёт действовать.
//
// Блок реквизитов организации (T-67, P4-11 технического жюри): «Отделение
// банка: 620014, Екатеринбург, ул. Малышева, 31, тел. +7 343 000-00-00» — в
// пять значимых токенов телефон не помещался. Поэтому окно продлевают, как
// «по адресу», адресные маркеры из address_markers («г», «ул», «д») и
// названия контакта («тел», «факс», «почта»), а число из нескольких групп
// цифр считается одним значимым токеном. Продление действует, только пока
// за маркером не встретился посторонний текст — строчное слово от четырёх
// букв: в «Отделение банка обслуживает Иванова Ивана, тел. …» слово «тел»
// окна уже не продлевает. Внутри блока посторонний текст окно закрывает:
// «…, ул. Ленина, д. 5 обслуживает Иванова, тел. …». Местоимение лица
// закрывает окно всегда, как маркер человека: «…, его телефон …».
func counterDenyOrgContacts(doc *lex.Doc, orgs, persons, address *dict.Table, i int, out *Candidates) {
	// «клиент банка», «сотрудник компании»: слева человек, и дальше идут его
	// данные, а не контакты организации.
	if counterPersonLeft(doc, persons, i) {
		return
	}
	start := int(doc.Tokens[i].End)
	w := counterOrgScan{orgs: orgs, persons: persons, address: address, end: -1}
	for j := i + 1; j < len(doc.Tokens); j++ {
		if counterSentenceEnd(doc, j-1) {
			break
		}
		if !w.step(doc, j) {
			break
		}
	}
	if w.end > start {
		out.Deny(start, w.end, counterOrgTypes, counterRuleOrg)
	}
}

// counterOrgScan — состояние окна правила 3 за маркером организации.
type counterOrgScan struct {
	orgs, persons, address *dict.Table
	// end — конец последнего токена окна, seen — значимые токены с начала
	// окна или с последнего продления.
	end, seen int
	prose     bool // до блока встретился посторонний текст
	block     bool // начался блок реквизитов
	digits    bool // предыдущий значимый токен — группа цифр
}

// step разбирает токен j окна и сообщает, что окно не закончилось.
func (w *counterOrgScan) step(doc *lex.Doc, j int) bool {
	t := doc.Tokens[j]
	if t.Kind == lex.KindPunct {
		return true
	}
	s := doc.NormOf(j)
	if t.Kind == lex.KindWord && (counterPersonMarker(w.persons, s) || counterPronoun(s)) {
		// Дальше пошли данные человека: «наш клиент Иванов, телефон …».
		return false
	}
	if !w.count(doc, j, t.Kind, s) {
		return false
	}
	if w.seen > counterOrgWindow {
		return false
	}
	w.end = int(t.End)
	if label, ok := w.orgs.Get(s); ok && label == counterLabelOrg {
		// Следующий маркер организации продлевает окно, но дальше его
		// ведёт уже он сам: внешний цикл Scan дойдёт и до него. Без этого
		// обрыва каждый маркер в серии «офис, офис, офис, …» проходил бы
		// до конца серии, и проход становился квадратичным.
		return false
	}
	return true
}

// count учитывает значимый токен j вида kind со словом s: продлевает окно
// или расходует его. Сообщает, что окно не закрыто посторонним текстом
// внутри блока реквизитов.
func (w *counterOrgScan) count(doc *lex.Doc, j int, kind lex.Kind, s string) bool {
	switch {
	case kind == lex.KindDigits:
		if !w.digits {
			w.seen++
		}
		w.digits = true
	case strings.HasPrefix(s, counterAddressLead):
		// Служебная обвязка адреса окно продлевает: «по адресу …».
		w.digits, w.seen, w.block = false, 0, true
	case !w.prose && (counterMatch(counterBlockWords[:], s) || w.address.Has(s)):
		w.digits, w.seen, w.block = false, 0, true
	default:
		w.digits = false
		if counterProse(doc, j) {
			if w.block {
				// Посторонний текст внутри блока реквизитов закрывает окно.
				return false
			}
			w.prose = true
		}
		w.seen++
	}
	return true
}

// counterProse сообщает, что слово — посторонний для блока реквизитов текст:
// строчное кириллическое слово от counterProseRunes букв. Латиница («info»,
// «bank» в адресе почты) и предлоги посторонним текстом не считаются.
func counterProse(doc *lex.Doc, j int) bool {
	t := doc.Tokens[j]
	if t.Kind != lex.KindWord || t.Flags.Has(lex.FlagFirstUpper) || !t.Flags.Has(lex.FlagCyrillic) {
		return false
	}
	return utf8.RuneCountInString(doc.NormOf(j)) >= counterProseRunes
}

// counterPronoun сообщает, что слово — местоимение лица (counterPronouns).
func counterPronoun(w string) bool {
	for _, p := range counterPronouns {
		if w == p {
			return true
		}
	}
	return false
}

// counterDenyOrgBefore — правило 3 слева: «Улица Гагарина, дом 5 — адрес
// нашего офиса», «Улица Льва Толстого, 16 — адрес партнёра», «+7 343 … —
// телефон отделения» (T-67, раунды 2 и 4 бизнес-жюри). Слово i — «адрес»
// или «телефон».
//
// Оборот признаётся, только если за словом в пределах counterOwnerWindow
// слов назван владелец — организация (метка org) или партнёр (метка owner),
// а перед словом стоит тире или двоеточие, при необходимости через «это».
// Тогда контакт организации — всё, что стоит перед тире, в пределах
// counterOrgBack токенов, до начала предложения или маркера человека.
// «Клиент спросил адрес нашего офиса» оборотом не является: перед словом
// нет тире.
func counterDenyOrgBefore(doc *lex.Doc, orgs, persons *dict.Table, i int, out *Candidates) {
	if !counterOwnerAfter(doc, orgs, i) {
		return
	}
	dash := i - 1
	if dash >= 0 && doc.Tokens[dash].Kind == lex.KindWord && doc.NormOf(dash) == wordThis {
		dash--
	}
	if dash <= 0 || !counterDash(doc, dash) || counterSentenceEnd(doc, dash-1) {
		return
	}
	first := dash
	for k := dash - 1; k >= 0 && k >= dash-counterOrgBack; k-- {
		if counterSentenceEnd(doc, k) {
			break
		}
		if doc.Tokens[k].Kind == lex.KindWord && counterPersonMarker(persons, doc.NormOf(k)) {
			break
		}
		first = k
	}
	if first < dash {
		out.Deny(int(doc.Tokens[first].Start), int(doc.Tokens[dash-1].End), counterOrgTypes, counterRuleOrg)
	}
}

// counterOwnerAfter сообщает, что за словом i назван владелец контакта:
// «адрес нашего офиса», «телефон отделения», «адрес партнёра».
func counterOwnerAfter(doc *lex.Doc, orgs *dict.Table, i int) bool {
	for j := i + 1; j < len(doc.Tokens) && j <= i+counterOwnerWindow; j++ {
		if doc.Tokens[j].Kind != lex.KindWord {
			return false
		}
		if label, ok := orgs.Get(doc.NormOf(j)); ok && (label == counterLabelOrg || label == counterLabelOwner) {
			return true
		}
	}
	return false
}

// counterDash сообщает, что токен — тире, дефис или двоеточие.
func counterDash(doc *lex.Doc, i int) bool {
	if doc.Tokens[i].Kind != lex.KindPunct {
		return false
	}
	switch doc.Raw(i) {
	case "—", "–", "-", ":":
		return true
	}
	return false
}

// counterSentence — признаки одного предложения, нужные правилу 4 и
// биографии правила 1. Считаются один раз на предложение и переиспользуются
// для всех фамилий и ролевых слов внутри него: в «Пушкин и Пушкин и …» на
// 200 КБ пересчёт предложения на каждую фамилию давал квадратичный проход и
// ответ дольше десяти секунд.
//
// Значение живёт на стеке Scan и ссылок на документ за пределами прохода не
// хранит.
type counterSentence struct {
	roles, persons, banking, orgs *dict.Table

	// lo, hi — границы посчитанного предложения в токенах; hi < lo — ещё
	// ничего не посчитано.
	lo, hi int

	client    bool // маркер клиента или название реквизита
	weak      bool // слабое название реквизита: «карта», «счёт» (T-67)
	requisite bool // шесть и больше цифр либо адрес почты
	bank      bool // банковское слово из counter_banking (T-51)
	operation bool // банковская операция с лицом: «перевод от», «платёж для» (T-67)
	field     bool // явное поле анкеты «дата/место рождения»
	tribute   bool // «к юбилею», «памяти» без имени за словом (T-67)
	otherName int  // первое имя человека, не публичной персоны; -1 — нет
}

// load возвращает признаки предложения, в котором стоит токен i. Scan идёт
// слева направо, поэтому предложение считается заново, только когда проход
// из него вышел: каждое предложение просматривается один раз.
func (s *counterSentence) load(doc *lex.Doc, i int) *counterSentence {
	if s.lo <= i && i <= s.hi {
		return s
	}
	lo, hi := counterSentenceBounds(doc, i)
	s.lo, s.hi = lo, hi
	s.client, s.weak, s.requisite, s.bank, s.operation, s.field, s.tribute = false, false, false, false, false, false, false
	s.otherName = -1

	// Маркер клиента решает оба вопроса сразу — и правило 4, и биографию,
	// поэтому на нём просмотр предложения заканчивается.
	digits := 0
	for k := lo; k <= hi && !s.client; k++ {
		t := doc.Tokens[k]
		switch t.Kind {
		case lex.KindDigits:
			digits += t.Len()
		case lex.KindWord:
			s.scanWord(doc, k, lo, hi)
		case lex.KindPunct:
			// Собака в предложении означает почтовый адрес, а он личный,
			// пока не доказано обратное.
			if doc.Text[t.Start] == '@' {
				s.requisite = true
			}
		}
	}
	if digits >= counterSentenceDigits {
		s.requisite = true
	}
	if !s.client && !s.weak && !s.field {
		s.otherName = counterOtherName(doc, s.roles, lo, hi)
	}
	return s
}

// counterSentenceBounds возвращает первый и последний токены предложения, в
// котором стоит токен i.
func counterSentenceBounds(doc *lex.Doc, i int) (lo, hi int) {
	lo = i
	for lo > 0 && !counterSentenceEnd(doc, lo-1) {
		lo--
	}
	hi = i
	for hi < len(doc.Tokens)-1 && !counterSentenceEnd(doc, hi) {
		hi++
	}
	return lo, hi
}

// scanWord учитывает слово k предложения [lo, hi]. Маркер клиента и сильное
// название реквизита ставят client, и на этом просмотр предложения
// заканчивается.
func (s *counterSentence) scanWord(doc *lex.Doc, k, lo, hi int) {
	w := doc.NormOf(k)
	if counterPersonMarker(s.persons, w) {
		s.client = true
		return
	}
	if found, weak := counterDataKind(w); found {
		if !weak {
			s.client = true
			return
		}
		s.weak = true
	}
	switch {
	case strings.HasPrefix(w, counterBirthField):
		s.field = true
	case (w == "от" || w == wordFor) && k > lo && doc.Tokens[k-1].Kind == lex.KindWord &&
		counterBankingWord(doc, s.banking, k-1, hi):
		// «Перевод от Льва Толстого на 5000 рублей» — операция с лицом.
		s.operation = true
	case !s.bank && counterBankingWord(doc, s.banking, k, hi):
		s.bank = true
	case !s.tribute && counterTributeAlone(doc, s.orgs, k, hi):
		s.tribute = true
	}
}

// counterTributeAlone сообщает, что слово k — «юбилей», «памяти», «портрет»
// (метки tribute и memorial), за которым не названо имя: «…Юрий Гагарин
// совершил первый полёт в космос — к юбилею выпущена карта с его
// портретом». Юбилей здесь того, кто уже назван в предложении.
func counterTributeAlone(doc *lex.Doc, orgs *dict.Table, k, hi int) bool {
	label, ok := orgs.Get(doc.NormOf(k))
	if !ok || (label != counterLabelTribute && label != counterLabelMemorial) {
		return false
	}
	return k == hi || !counterNameToken(doc, k+1)
}

// publicMention решает, можно ли снять ФИО по справочнику публичных лиц
// (правило 4). Это самое опасное место сканера: ошибка здесь снимает защиту
// с однофамильца-клиента, то есть приводит к утечке.
//
// Поэтому условие сформулировано от обратного — вето ставится, только если
// в предложении не нашлось ни одного признака того, что речь о конкретном
// человеке: ни маркера клиента, ни названия реквизита, ни самих цифр
// реквизита, ни адреса электронной почты, ни банковского слова. Предложение
// просматривается целиком, а не только слева: «Пушкин Александр Сергеевич,
// паспорт 4509 123456» — маркер стоит справа, но данные от этого личными
// быть не перестают.
//
// Банковское слово — признак клиента не хуже слова «клиент» (T-51): в тексте
// банка «Юрий Гагарин хочет открыть вклад на год» пишет клиент-однофамилец, а
// не рассказ о космонавте.
//
// relaxed (T-67) — упоминание финансового чиновника (метка official) или
// должности: банковские слова и слабые названия реквизита («карта»,
// «счёт») здесь тема новости и вето не отменяют. Так же считается
// предложение с «юбилеем» или «памятью» без имени за словом: «В 1961 году
// Юрий Гагарин совершил первый полёт в космос — к юбилею выпущена карта».
// Маркер клиента, цифры реквизита, почта, названия паспорта и телефона,
// поле анкеты и банковская операция с лицом («перевод от …») отменяют вето
// и здесь.
func (s *counterSentence) publicMention(relaxed bool) bool {
	// Явное поле «дата/место рождения» — анкета клиента, а не рассказ о
	// знаменитости (бизнес-жюри 23.09, раунд 2).
	if s.client || s.requisite || s.field || s.operation {
		return false
	}
	return relaxed || s.tribute || (!s.weak && !s.bank)
}

// bioAllowed решает, можно ли снять место и дату рождения после персоны с
// ролевым словом в позиции role. Нельзя, если в предложении есть маркер
// клиента или реквизита, явное поле «дата/место рождения» или имя другого
// человека раньше ролевого слова: «Иванов Иван Иванович, как и поэт Пушкин,
// родился 06.06.1985» — дата здесь клиента.
func (s *counterSentence) bioAllowed(role int) bool {
	if s.client || s.weak || s.field {
		return false
	}
	return s.otherName < 0 || s.otherName > role
}

// counterOtherName возвращает индекс первого в предложении [lo, hi] имени
// человека, который не является публичной персоной с ролевым словом, или -1.
//
// Имя — конструкция из двух и больше слов с заглавной буквы. Не считаются
// именем другого человека: сама ролевая цепочка («Поэт Александр Пушкин» в
// начале предложения), имя сразу за ролевым словом, топоним после предлога
// места («в Нижнем Новгороде») и конструкция, начатая однобуквенным словом
// («В Москве» — предлог, а не инициал). Проход прыгает через конструкцию
// целиком, поэтому он линеен.
func counterOtherName(doc *lex.Doc, roles *dict.Table, lo, hi int) int {
	for k := lo; k <= hi; k++ {
		if !counterNameToken(doc, k) {
			continue
		}
		end := counterNameRunEnd(doc, k)
		if end > k && !counterInitial(doc, k) && !counterIsRole(roles, doc.NormOf(k)) &&
			!counterAfterRole(doc, roles, lo, k) && !counterBioPlaceWord(doc, k) {
			return k
		}
		k = end
	}
	return -1
}

// counterAfterRole сообщает, что слово k стоит сразу за ролевым словом:
// «поэт Александр Пушкин», «поэт, Александр Пушкин».
func counterAfterRole(doc *lex.Doc, roles *dict.Table, lo, k int) bool {
	for j := k - 1; j >= lo && j >= k-2; j-- {
		t := doc.Tokens[j]
		if t.Kind == lex.KindPunct {
			continue
		}
		return t.Kind == lex.KindWord && counterIsRole(roles, doc.NormOf(j))
	}
	return false
}

// counterClientBeforeRole сообщает, что ролевой цепочке, в которую входит
// слово i, предшествует маркер клиента: «Клиент — поэт Иван Петров», «наш
// клиент, поэт и писатель …». Другие ролевые слова и союз «и» цепочки не
// прерывают; из остальных слов просматриваются counterRoleClientLeft
// ближайших. Число просмотренных слов ограничено, поэтому серия ролевых слов
// не делает проход квадратичным.
func counterClientBeforeRole(doc *lex.Doc, roles, persons *dict.Table, i int) bool {
	other, words := 0, 0
	for k := i - 1; k >= 0; k-- {
		if counterSentenceEnd(doc, k) {
			return false
		}
		t := doc.Tokens[k]
		if t.Kind != lex.KindWord {
			continue
		}
		w := doc.NormOf(k)
		if counterPersonMarker(persons, w) && !counterMatch(counterRoleNeutral[:], w) {
			return true
		}
		words++
		if words > counterRoleSkip+counterRoleClientLeft {
			return false
		}
		if counterIsRole(roles, w) || w == counterConj {
			continue
		}
		other++
		if other >= counterRoleClientLeft {
			return false
		}
	}
	return false
}

// counterBankingWord сообщает, что слово k — банковское по справочнику
// counter_banking. hi — последний токен предложения: оборот «вклад в науку»
// ищется только внутри него.
func counterBankingWord(doc *lex.Doc, banking *dict.Table, k, hi int) bool {
	label, ok := counterStem(banking, doc.NormOf(k))
	if !ok {
		return false
	}
	switch label {
	case counterLabelExcept, counterLabelVenue:
		return false
	case counterLabelIdiom:
		return !counterBankIdiom(doc, banking, k, hi)
	}
	return true
}

// counterStemMin — минимальная длина основы в рунах. Короче бывают только
// записи exact, а они сравниваются со словом целиком; более короткие
// префиксы не проверяются вовсе, и поиск стоит на несколько обращений к
// таблице меньше на каждое слово. Правило закреплено тестом справочника.
const counterStemMin = 4

// counterStem ищет самую длинную запись справочника, которой начинается
// слово w, и возвращает её метку. Запись с меткой exact совпадает только со
// словом целиком. Префиксы берутся срезом по границам рун — без аллокаций.
func counterStem(t *dict.Table, w string) (string, bool) {
	if label, ok := t.Get(w); ok {
		return label, true
	}
	label, found := "", false
	runes := 0
	for n := range w {
		if runes++; runes <= counterStemMin {
			continue
		}
		// w[:n] — первые runes-1 рун слова.
		if l, ok := t.Get(w[:n]); ok && l != counterLabelExact {
			label, found = l, true
		}
	}
	return label, found
}

// counterBankIdiom сообщает, что слово k стоит в устойчивом небанковском
// обороте «X в <что-то>»: «внёс вклад в науку», «вклад Пушкина в
// литературу». Оборот признаётся, только если за предлогом идёт слово со
// строчной буквы, само не банковское: «вклад в банке», «вклад в рублях»,
// «вклад в Сбербанке» остаются банковскими.
func counterBankIdiom(doc *lex.Doc, banking *dict.Table, k, hi int) bool {
	words := 0
	for j := k + 1; j <= hi && words < counterBankIdiomWindow; j++ {
		if doc.Tokens[j].Kind != lex.KindWord {
			return false
		}
		words++
		if w := doc.NormOf(j); w != "в" && w != "во" {
			continue
		}
		n := j + 1
		if n > hi {
			return false
		}
		obj := doc.Tokens[n]
		if obj.Kind != lex.KindWord || obj.Flags.Has(lex.FlagFirstUpper) {
			return false
		}
		label, ok := counterStem(banking, doc.NormOf(n))
		return !ok || label == counterLabelExcept
	}
	return false
}

// counterPersonLeft ищет маркер человека слева от маркера организации.
func counterPersonLeft(doc *lex.Doc, persons *dict.Table, i int) bool {
	seen := 0
	for k := i - 1; k >= 0 && seen < counterOrgLeftGuard; k-- {
		if counterSentenceEnd(doc, k) {
			return false
		}
		t := doc.Tokens[k]
		if t.Kind != lex.KindWord {
			continue
		}
		seen++
		if counterPersonMarker(persons, doc.NormOf(k)) {
			return true
		}
	}
	return false
}

// counterPersonMarker сообщает, что слово указывает на конкретного человека.
func counterPersonMarker(persons *dict.Table, w string) bool {
	return persons.Has(w) || counterMatch(counterPersonWords[:], w)
}

// counterDataKind сообщает, что слово называет реквизит человека, и слабое
// ли это название (counterWord.weak).
func counterDataKind(w string) (found, weak bool) {
	for _, m := range counterDataWords {
		if m.exact && w == m.word || !m.exact && strings.HasPrefix(w, m.word) {
			return true, m.weak
		}
	}
	return false, false
}

// counterMatch сравнивает слово со списком маркеров.
func counterMatch(list []counterWord, w string) bool {
	for _, m := range list {
		if m.exact {
			if w == m.word {
				return true
			}
			continue
		}
		if strings.HasPrefix(w, m.word) {
			return true
		}
	}
	return false
}

// counterNameRunEnd возвращает индекс последнего токена конструкции имени,
// начинающейся с токена i. Конструкция — подряд идущие слова с заглавной
// буквы, включая инициалы и фамилии через дефис.
func counterNameRunEnd(doc *lex.Doc, i int) int {
	last := i
	for words := 1; words < counterNameRunMax; words++ {
		next, ok := counterRunNext(doc, last)
		if !ok {
			return last
		}
		last = next
	}
	return last
}

// counterRunNext возвращает следующее слово конструкции имени.
func counterRunNext(doc *lex.Doc, i int) (int, bool) {
	j := i + 1
	if j >= len(doc.Tokens) {
		return 0, false
	}
	if t := doc.Tokens[j]; t.Kind == lex.KindPunct {
		c := doc.Text[t.Start]
		switch {
		// Точка инициала («А. С. Пушкин») и дефис («Салтыков-Щедрин»)
		// конструкцию не разрывают, любой другой знак разрывает.
		case c == '.' && doc.Adjacent(i) && counterInitial(doc, i):
		case c == '-' && doc.Adjacent(i) && doc.Adjacent(j):
		default:
			return 0, false
		}
		j++
		if j >= len(doc.Tokens) {
			return 0, false
		}
	}
	if !counterNameToken(doc, j) || !counterJoinable(doc, j-1) {
		return 0, false
	}
	return j, true
}

// counterNameToken сообщает, что токен может быть частью имени: слово с
// заглавной буквы. Латиница допускается наравне с кириллицей — «president
// John Smith» устроен так же.
func counterNameToken(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	if t.Kind != lex.KindWord || !t.Flags.Has(lex.FlagFirstUpper) {
		return false
	}
	return t.Flags.Has(lex.FlagCyrillic) || t.Flags.Has(lex.FlagLatin)
}

// counterInitial сообщает, что токен — одна буква, то есть инициал.
func counterInitial(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	return t.Kind == lex.KindWord && utf8.RuneCountInString(doc.NormOf(i)) == 1
}

// counterJoinable проверяет промежуток между токенами i и i+1: перевод
// строки и слишком длинный отступ конструкцию разрывают.
func counterJoinable(doc *lex.Doc, i int) bool {
	gap := doc.Gap(i)
	return len(gap) <= counterMaxGap && !counterLineBreak(gap)
}

// counterLineBreak сообщает, что промежуток содержит перевод строки.
func counterLineBreak(gap string) bool { return lex.HasLineBreak(gap) }

// counterAbbrevDot сообщает, что токен j — точка сокращения при слове i.
func counterAbbrevDot(doc *lex.Doc, i, j int) bool {
	t := doc.Tokens[j]
	return t.Kind == lex.KindPunct && doc.Text[t.Start] == '.' &&
		doc.Adjacent(i) && counterAbbrev(doc, i)
}

// counterAbbrev сообщает, что слово достаточно коротко, чтобы быть
// сокращением: «ул», «д», «им», «стр», инициал.
func counterAbbrev(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	return t.Kind == lex.KindWord &&
		utf8.RuneCountInString(doc.NormOf(i)) <= counterAbbrevRunes
}

// counterSentenceEnd — конец предложения с поправкой на сокращения.
//
// Лексер считает границей любую точку, но в адресе «Москва, ул. Ленина, 5»
// точка после «ул» предложение не заканчивает. Без этой поправки окно
// правила 3 обрывалось бы на сокращении, и адрес отделения остался бы
// незакрытым — ровно тот случай, ради которого правило написано.
func counterSentenceEnd(doc *lex.Doc, i int) bool {
	if !doc.IsSentenceBreak(i) {
		return false
	}
	t := doc.Tokens[i]
	// Точка вплотную между цифрами — разделитель даты или суммы
	// («12.03.1985», «1.5»), а не конец предложения. Без этого дата рвала
	// предложение, и правило публичной персоны не видело паспорт за ней:
	// «Пушкин Александр Сергеевич, 12.03.1985 г.р., паспорт …» уходил
	// открытым (бизнес-жюри 23.09, раунд 2).
	if t.Kind == lex.KindPunct && doc.Text[t.Start] == '.' && i > 0 && i+1 < len(doc.Tokens) &&
		doc.Tokens[i-1].Kind == lex.KindDigits && doc.Tokens[i+1].Kind == lex.KindDigits &&
		doc.Adjacent(i-1) && doc.Adjacent(i) {
		return false
	}
	// Точка вплотную между словами и цифрами — часть адреса почты или сайта
	// («yuri.g1985@example.ru»), а не конец предложения. Без этого «Юрий
	// Гагарин, почта yuri.» становилось отдельным предложением без собаки, и
	// исключение «известный человек» снимало маску с клиента (раунд 4, Б4-3).
	if t.Kind == lex.KindPunct && doc.Text[t.Start] == '.' && i > 0 && i+1 < len(doc.Tokens) &&
		doc.Tokens[i-1].Kind != lex.KindPunct && doc.Tokens[i+1].Kind != lex.KindPunct &&
		doc.Adjacent(i-1) && doc.Adjacent(i) {
		return false
	}
	if t.Kind == lex.KindPunct && doc.Text[t.Start] == '.' && i > 0 &&
		doc.Adjacent(i-1) && counterAbbrev(doc, i-1) {
		// Перевод строки после сокращения предложение всё же заканчивает.
		return counterLineBreak(doc.Gap(i))
	}
	return true
}
