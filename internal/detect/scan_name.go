package detect

import (
	"strings"
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

func init() { Register(nameScanner{}) }

// nameScanner находит фамилии, имена и отчества в русском тексте.
//
// Списка фамилий здесь нет и быть не может: их сотни тысяч, а полный перечень
// невозможен и не нужен. Кандидат опознаётся сочетанием трёх независимых
// признаков: справочник личных имён, морфология суффиксов фамилии и отчества,
// позиция слова в конструкции ФИО. Отчества списком тоже не хранятся — они
// выводятся правилом из основы.
//
// Контр-правила ловушек («поэт Пушкин», «улица Пушкина», адрес отделения)
// сюда не входят намеренно: сканер только сообщает находки, вето ставит
// отдельное контр-правило, а решение принимает движок.
type nameScanner struct{}

// Name возвращает имя сканера.
func (nameScanner) Name() string { return "name" }

const (
	nameDictGiven   = "given_names"
	nameDictMarkers = "name_markers"
	nameDictMonths  = "months"
	nameDictCities  = "geo_cities"

	// nameDictStop — слова, которые стоят с заглавной вплотную к имени, но
	// фамилией не бывают: обращения, титулы, организации, вопросительные
	// слова (T-66). Справочник, а не switch: список открыт для пополнения
	// без правки кода, как и остальные справочники детекции.
	nameDictStop = "name_stopwords"

	// nameDictCountries — названия государств из справочника гражданства.
	// Принадлежит сканеру гражданства и здесь только читается: «гражданин
	// Армении», «Слава России» — страна, а не фамилия.
	nameDictCountries = "citizenship"
)

// Слова вежливости, которые входят сразу в несколько списков сканера: в
// стоп-слова начала предложения, в слова-вводы лица, в обращения и в
// прощания. Списки разные, общие у них только эти слова.
const (
	nameWordThanks = "спасибо"
	nameWordHello  = "здравствуйте"
	nameWordHi     = "привет"
)

// nameRole — роль, которую слово может играть в конструкции ФИО. Роли не
// исключают друг друга: «Марина» — и имя из справочника, и правильная форма
// фамилии, выбор делает окружение.
type nameRole uint8

const (
	nameRoleGiven nameRole = 1 << iota
	nameRolePatronymic
	nameRoleSurname
	nameRoleInitial
)

// Имена правил. Константы, а не собираемые строки: Scan не аллоцирует.
const (
	nameRuleFIO              = "name.surname_given_patronymic"
	nameRuleIFO              = "name.given_patronymic_surname"
	nameRuleGivenPatronymic  = "name.given_patronymic"
	nameRuleGivenSurname     = "name.given_surname"
	nameRuleSurnameGiven     = "name.surname_given"
	nameRulePatronymicSur    = "name.patronymic_surname"
	nameRuleSurnameInitials  = "name.surname_initials"
	nameRuleInitialsSurname  = "name.initials_surname"
	nameRuleSurname          = "name.surname"
	nameRuleGiven            = "name.given"
	nameRulePatronymic       = "name.patronymic"
	nameRuleSurnameMarker    = "name.surname+marker"
	nameRuleGivenMarker      = "name.given+marker"
	nameRulePatronymicMarker = "name.patronymic+marker"
)

// Имена правил для конструкций, записанных целиком строчными буквами.
// Отдельные константы, а не склейка строк: Scan не аллоцирует, а по имени
// правила в отладочном отчёте должно быть видно, почему уверенность ниже.
const (
	nameRuleFIOLower             = "name.surname_given_patronymic/lower"
	nameRuleIFOLower             = "name.given_patronymic_surname/lower"
	nameRuleGivenPatronymicLower = "name.given_patronymic/lower"
	nameRuleGivenSurnameLower    = "name.given_surname/lower"
	nameRuleSurnameGivenLower    = "name.surname_given/lower"
	nameRulePatronymicSurLower   = "name.patronymic_surname/lower"
	nameRuleSurnameInitialsLower = "name.surname_initials/lower"
	nameRuleInitialsSurnameLower = "name.initials_surname/lower"
)

// Имена правил для конструкций, в которых одно слово принято по позиции —
// потому что стоит вплотную к опознанным частям имени, а не потому, что
// опознано само. «pos» в имени правила означает ровно это: в отладочном
// отчёте должно быть видно, что слово держится на соседях.
const (
	nameRuleFIOPos      = "name.surname_pos+given_patronymic"
	nameRuleIFOPosSur   = "name.given_patronymic+surname_pos"
	nameRuleIFOPosGiven = "name.given_pos+patronymic_surname"
	nameRuleSurPosGiven = "name.surname_pos+given"
	nameRuleSurPosInit  = "name.surname_pos+initials"

	nameRuleFIOPosLower      = "name.surname_pos+given_patronymic/lower"
	nameRuleIFOPosSurLower   = "name.given_patronymic+surname_pos/lower"
	nameRuleIFOPosGivenLower = "name.given_pos+patronymic_surname/lower"
	nameRuleSurPosGivenLower = "name.surname_pos+given/lower"
	nameRuleSurPosInitLower  = "name.surname_pos+initials/lower"

	nameRuleSurPosGivenMarker = "name.surname_pos+given+marker"

	// Фамилия-прилагательное справа от одиночного имени: «Лев Толстой».
	nameRuleGivenSurPos       = "name.given+surname_pos"
	nameRuleGivenSurPosMarker = "name.given+surname_pos+marker"
)

// Имена правил для фамилии без русского суффикса (T-50): «Мельник»,
// «Коваль», «Цой». «bare» в имени правила означает, что у слова нет ни
// суффикса фамилии, ни окончания прилагательного — оно держится только на
// позиции рядом с опознанными частями имени и на отсевах nameBareSurname.
const (
	nameRuleFIOBare   = "name.surname_bare+given_patronymic"
	nameRuleIFOBare   = "name.given_patronymic+surname_bare"
	nameRuleBareGiven = "name.surname_bare+given"
	nameRuleGivenBare = "name.given+surname_bare"

	nameRuleFIOBareLower = "name.surname_bare+given_patronymic/lower"
	nameRuleIFOBareLower = "name.given_patronymic+surname_bare/lower"

	nameRuleBareGivenMarker = "name.surname_bare+given+marker"
	nameRuleGivenBareMarker = "name.given+surname_bare+marker"

	// Фамилия без суффикса с двумя инициалами: «Коваль К. Г.», «К. Г. Коваль».
	nameRuleSurBareInit       = "name.surname_bare+initials"
	nameRuleSurBareInitMarker = "name.surname_bare+initials+marker"
	nameRuleInitialsBare      = "name.initials+surname_bare"
)

// Имена правил для строчной пары из двух опознанных слов, поднятой маркером
// лица слева: «клиент иванов иван». Заглавная пара той же формы заводится
// как Strong и без маркера; строчная без маркера опускается до Weak, а маркер
// возвращает ей уровень заглавной.
const (
	nameRuleGivenPatronymicLowerMarker = "name.given_patronymic/lower+marker"
	nameRuleGivenSurnameLowerMarker    = "name.given_surname/lower+marker"
	nameRuleSurnameGivenLowerMarker    = "name.surname_given/lower+marker"
	nameRuleFIOBareLowerMarker         = "name.surname_bare+given_patronymic/lower+marker"
	nameRuleIFOBareLowerMarker         = "name.given_patronymic+surname_bare/lower+marker"
	nameRuleGivenGivenLowerMarker      = "name.given_as_surname+given/lower+marker"
)

// Имена правил раунда 3 технического жюри (T-60).
const (
	// Два имени из справочника подряд: «Ким Олег», «Ли Анна». Первое — фамилия,
	// совпадающая с именем («Ким» в справочнике записан как имя), или второе
	// имя двойного имени. В обоих случаях это один человек.
	nameRuleGivenGiven           = "name.given_as_surname+given"
	nameRuleGivenGivenLower      = "name.given_as_surname+given/lower"
	nameRuleGivenGivenPatronymic = "name.given_as_surname+given_patronymic"

	// Фамилия капсом, имя и отчество строчными: «ПЕТРОВА анна сергеевна».
	nameRuleFIOCapsSurname   = "name.surname_caps+given_patronymic"
	nameRuleSurGivenCapsSurn = "name.surname_caps+given"

	// Слабая пара поднята словом, вводящим лицо: «Передайте Мельнику Олегу»,
	// «Звонила петрова анна», «анна смирнова просит выписку».
	nameRuleIntro      = "name.pair+intro"
	nameRuleLowerIntro = "name.pair/lower+intro"

	// Фамилия без суффикса и имя в одном косвенном падеже: «Мельнику Олегу».
	nameRuleBareCase = "name.surname_bare+given/case"

	// Строчная или капсом фамилия без суффикса, которую держит маркер или
	// слово-ввод вплотную: «клиентка гусь анна», «звонил цой артём».
	nameRuleBareAnchored = "name.surname_bare+given/anchored"

	// Фамилия, уже опознанная в ФИО этого текста, повторена отдельно:
	// «Клиент Шевчук Андрей Петрович… Шевчук просит перезвонить».
	nameRuleSurnameRepeat = "name.surname_repeat"

	// Одиночная фамилия без суффикса между маркером лица и сказуемым:
	// «Клиент Мельник просит перезвонить».
	nameRuleBareFramed = "name.surname_bare+marker+predicate"
)

// Имена правил раунда 4 жюри (T-66).
const (
	// Слово с заглавной вплотную перед именем в именительном падеже: «Коваль
	// Инна обратилась», «пришёл Гусь Анатолий». «title» — заглавная буква в
	// середине предложения, «start» — в начале, где её подкрепляют отсевы.
	nameRuleBareLead      = "name.surname_bare+given/title"
	nameRuleBareLeadStart = "name.surname_bare+given/start"

	// То же справа от имени: «Инна Коваль оспаривает списание».
	nameRuleGivenBareTitle = "name.given+surname_bare/title"

	// Значение поля анкеты: «Фамилия: Волк», «Отчество: Никитична»,
	// «Подпись: /Шаповалова/», «сменил фамилию с Корнеевой на Шаповалову».
	nameRuleField = "name.field"

	// Одиночная фамилия в позиции лица: после маркера, слова-ввода или «от»
	// и перед границей фразы — «Ваш клиент, Кох.», «Звонил Бык, просил…»,
	// «Заявление принято от Иванова.», — и в подписи письма.
	nameRuleSlot      = "name.surname+slot"
	nameRuleSignature = "name.surname+signature"

	// Фамилия без суффикса с одним инициалом: «Клиент Мельник О. просит…».
	nameRuleSurBareInit1 = "name.surname_bare+initial"
	nameRuleInit1Bare    = "name.initial+surname_bare"

	// Строчная фамилия с инициалами, поднятая маркером или словом-вводом:
	// «клиент шаповалова д.н.», «передайте д. н. шаповаловой».
	nameRuleSurnameInitialsLowerMarker = "name.surname_initials/lower+marker"
	nameRuleInitialsSurnameLowerMarker = "name.initials_surname/lower+marker"
	nameRuleSurBareInitLowerMarker     = "name.surname_bare+initials/lower+marker"

	// Фамилия-прилагательное перед «Имя Отчество» и перед именем при
	// маркере или обращении: «Клиент Белый Андрей Сергеевич», «Спасибо,
	// Тихий Роман».
	nameRuleFIOAdj         = "name.surname_adj+given_patronymic"
	nameRuleAdjGiven       = "name.surname_adj+given"
	nameRuleAdjGivenMarker = "name.surname_adj+given+marker"
	nameRuleGivenAdj       = "name.given+surname_adj"
	nameRuleGivenAdjMarker = "name.given+surname_adj+marker"
	nameRulePairAddress    = "name.pair+address"

	nameRuleSurBareInit1Marker = "name.surname_bare+initial+marker"

	// Фамилия с окончанием отчества перед «Имя Отчество»: «Бабич Олег
	// Петрович», вторая часть «Бонч-Бруевич Андрей Сергеевич».
	nameRuleFIOPatrSurname = "name.surname_patronymic+given_patronymic"

	// Три слова восточноазиатского имени: «Нгуен Ван Тхань», «Пак Мин Су».
	nameRuleBareGivenGiven = "name.surname_bare+given_given"
)

const (
	// nameKeyMax — предел длины ключа, который сканер собирает для обращения
	// к справочнику. Строка, построенная из []byte и не покидающая функцию,
	// размещается компилятором во временном буфере на стеке размером 32 байта;
	// ключ длиннее ушёл бы в кучу и сломал требование нулевых аллокаций.
	// Шестнадцать кириллических букв покрывают любое имя справочника.
	nameKeyMax = 32

	// nameMarkerWindow — сколько значимых токенов слева просматривается в
	// поисках маркера («клиент», «ФИО»).
	nameMarkerWindow = 3

	// nameMaxGap — предел длины промежутка между частями ФИО в байтах.
	// Выравнивание колонок в форме даёт длинный пробел, но не произвольный.
	nameMaxGap = 16

	// nameSurnameMinLen — минимальная длина фамилии в буквах.
	nameSurnameMinLen = 4

	// namePatronymicMinStem — минимальная длина основы отчества в буквах.
	namePatronymicMinStem = 3

	// nameGivenMinStem — минимальная длина основы имени при восстановлении
	// именительного падежа.
	nameGivenMinStem = 2

	// nameFleetingMinStem — минимальная длина основы при возврате беглой
	// гласной: вставлять «е» в двухбуквенный огрызок бессмысленно.
	nameFleetingMinStem = 3

	// nameGivenPosMinLen и nameGivenPosMaxLen — пределы длины слова, которое
	// принимается на место имени по позиции. Двухбуквенный огрызок и слово
	// длиннее любого русского имени в конструкцию не попадают.
	nameGivenPosMinLen = 3
	nameGivenPosMaxLen = 14

	// nameBareMinLen и nameBareMaxLen — пределы длины фамилии без суффикса.
	// Двухбуквенная «Ли» возможна, но только при свидетельстве регистра; без
	// него нижний предел — nameBareBlindMinLen, иначе в конструкцию попадали
	// бы «НА», «ИЗ» и прочие короткие служебные слова в тексте капсом.
	nameBareMinLen      = 2
	nameBareBlindMinLen = 3
	nameBareMaxLen      = 20

	// nameBareAdjMinLen — с этой длины окончание прилагательного снимает слово
	// с места фамилии без суффикса. Такие слова разбирает только
	// nameSurnamePos со своим пределом длины; bare-правило не должно обходить
	// его отсев. Трёхбуквенная «Цой» под предел не попадает, а «мой» стоит в
	// стоп-списке.
	nameBareAdjMinLen = 4

	// nameSeenMax — сколько фамилий из опознанных ФИО текста помнит сканер,
	// чтобы узнать их повтор отдельным словом. Буфер фиксированный и живёт на
	// стеке: при переполнении вытесняется самая старая запись. Шестнадцати
	// хватает на любое письмо или обращение; в длинной выгрузке с сотнями
	// клиентов повтор фамилии стоит рядом с полным ФИО, то есть среди
	// последних запомненных.
	nameSeenMax = 16

	// nameStemMinLen — минимальная длина основы фамилии в буквах после снятия
	// падежного окончания: «Цой» → «цо», «Цоя» → «цо».
	nameStemMinLen = 2
)

// nameTables — справочники, которые читает сканер. Собираются один раз на
// вызов Scan и передаются указателем: структура не покидает стек.
//
// Месяцы и города принадлежат сканерам дат и адреса; здесь они только
// читаются — как отсев для фамилии без суффикса, которую больше ничем не
// отличить от соседнего слова с заглавной буквы.
type nameTables struct {
	given, markers, months, cities, banking *dict.Table

	// roles — ролевые слова контр-правил («поэт», «художник»), stop — стоп-
	// слова рядом с именем, countries — государства. Все три только читаются.
	roles, stop, countries *dict.Table

	// groups — слова группы людей с общей фамилией («супруги», «семья»),
	// places — адресные слова сканера адреса; оба только читаются (T-80).
	groups, places *dict.Table

	// requisites — названия реквизитов за ФИО («паспорт», «телефон») (T-80).
	requisites *dict.Table
}

// nameBankMemo запоминает, есть ли банковское слово в последнем разобранном
// предложении.
//
// Банковский текст — признак клиента не хуже маркера «клиент»: «Лев Толстой
// оформил кредит» — однофамилец, а не писатель (T-51 снимает здесь правило
// публичной персоны). Но пара «имя + фамилия-прилагательное» без маркера
// остаётся Weak, и без подъёма она уходила открытой. Кандидаты идут слева
// направо, поэтому предложение просматривается один раз — линейно.
// nameRuleBankContext — пара без маркера поднята банковским предложением.
// Имя правила постоянное: склейка с исходным правилом стоила бы аллокации.
const nameRuleBankContext = "name.bank_context"

type nameBankMemo struct {
	hi    int
	ok    bool
	valid bool
}

func (m *nameBankMemo) inSentence(doc *lex.Doc, banking *dict.Table, at int) bool {
	if banking == nil {
		return false
	}
	if m.valid && at <= m.hi {
		return m.ok
	}
	lo, hi := doc.SentenceBounds(at)
	m.hi, m.ok, m.valid = hi, false, true
	for k := lo; k <= hi; k++ {
		if doc.Tokens[k].Kind == lex.KindWord && counterBankingWord(doc, banking, k, hi) {
			m.ok = true
			break
		}
	}
	return m.ok
}

// nameAddSingle выдаёт одиночное слово i кандидатом уровня Strong.
func nameAddSingle(doc *lex.Doc, out *Candidates, prev *nameLast, i int, rule string) {
	t := doc.Tokens[i]
	out.Add(int(t.Start), int(t.End), pii.FullName, Strong, rule)
	*prev = nameLast{idx: len(out.Spans) - 1, first: i, last: i}
}

// nameSingleRule решает судьбу слова i, которое nameMatch не опознал ни как
// часть имени, ни как начало конструкции, и возвращает имя правила, по
// которому оно всё же фамилия, или пустую строку.
//
// Порядок — от самого сильного довода к самому слабому: повтор фамилии из
// уже опознанного ФИО этого текста (T-60), значение поля анкеты (T-66),
// рамка «маркер — слово — сказуемое» (T-60), позиция лица и подпись (T-66).
func nameSingleRule(doc *lex.Doc, tb *nameTables, seen *nameSeen, i int) string {
	upper := doc.Tokens[i].Flags.Has(lex.FlagFirstUpper)
	// «Клиент Мельник Марина Олеговна… Мельник подтвердила перевод».
	if upper && seen.n > 0 && seen.repeatAt(doc, tb, i) {
		return nameRuleSurnameRepeat
	}
	if nameFieldLift(doc, tb, i) {
		return nameRuleField
	}
	if !upper {
		return ""
	}
	// «Супруги Мазур: Олег и Алла» (T-80).
	if nameFamilySurname(doc, tb, i) {
		return nameRuleFamily
	}
	// «Клиент Мельник просит перезвонить».
	if nameBareFramed(doc, tb, i) {
		return nameRuleBareFramed
	}
	if nameSlot(doc, tb, i, false) {
		return nameRuleSlot
	}
	if nameSignature(doc, tb, i, false) {
		return nameRuleSignature
	}
	return ""
}

// nameSingleLift поднимает опознанное одиночное слово — фамилию с суффиксом
// или отчество — по позиции: значение поля анкеты, позиция лица, подпись
// (T-66). Имя из справочника так не поднимается, кроме значения поля «Имя:».
func nameSingleLift(doc *lex.Doc, tb *nameTables, i int) string {
	if nameFieldLift(doc, tb, i) {
		return nameRuleField
	}
	if nameFamilySurname(doc, tb, i) {
		return nameRuleFamily
	}
	w := doc.NormOf(i)
	surname := nameSurname(w, nameRunes(doc.Tokens[i]))
	if !surname {
		return ""
	}
	if nameSlot(doc, tb, i, true) {
		return nameRuleSlot
	}
	if nameSignature(doc, tb, i, true) {
		return nameRuleSignature
	}
	// «Сидорчук просит перевыпустить карту» (T-83, P5-6).
	if nameSubjectSlot(doc, tb, i) {
		return nameRuleSubject
	}
	return ""
}

// nameFieldLift сообщает, что слово i — значение поля анкеты.
func nameFieldLift(doc *lex.Doc, tb *nameTables, i int) bool {
	kind, sep, ok := nameFieldSlot(doc, tb, i)
	return ok && nameFieldValue(doc, tb, i, kind, sep)
}

// nameAddressPair — правила пар, которые поднимает обращение слева: пара
// держится на одном опознанном слове, и второе стоит по позиции.
func nameAddressPair(rule string) bool {
	switch rule {
	case nameRuleSurPosGiven, nameRuleAdjGiven, nameRuleGivenSurPos, nameRuleGivenAdj,
		nameRuleBareGiven, nameRuleGivenBare:
		return true
	}
	return false
}

// nameStartsAfter сообщает, что вплотную за словом i в том же предложении
// начинается конструкция ФИО: тогда слово i может оказаться её фамилией, и
// решать его судьбу надо вместе с ней.
func nameStartsAfter(doc *lex.Doc, tb *nameTables, i int) bool {
	j := i + 1
	if j >= len(doc.Tokens) || doc.IsSentenceBreak(i) || !nameJoinable(doc, i) || !nameEligible(doc, j) {
		return false
	}
	last, _, _ := nameMatch(doc, tb, j)
	return last >= 0
}

// nameLowerCase пересчитывает уверенность конструкции, записанной целиком
// строчными буквами, и возвращает false, если такого кандидата заводить не надо.
//
// ТЗ §3.2.1 требует, чтобы идентификация не зависела от регистра, поэтому
// отбрасывать строчную запись целиком нельзя. Но признак заглавной буквы —
// одно из трёх независимых свидетельств, на которых держится сканер, и без
// него свидетельств остаётся два: справочник имён и морфология суффиксов.
// Поэтому строчная конструкция опускается на ступень и при профиле balanced
// срабатывает не сама по себе, а по кластеру — когда рядом есть другие
// персональные данные.
//
// Одиночное строчное слово кандидатом не становится вовсе: «иванов» без
// заглавной буквы — это и фамилия, и родительный падеж множественного числа
// от «иван», ровно так же, как «счетов» от «счёт». Одной морфологии суффикса
// здесь мало; маркер слева («клиент иванов») возвращает кандидата, но только
// на уровне Weak.
func nameLowerCase(conf Confidence, rule string, marker bool) (Confidence, string, bool) {
	switch conf {
	case Certain:
		// Фамилия, имя и отчество подряд — самодостаточная грамматика:
		// суффикс отчества в обычной речи почти не встречается, а совпасть
		// трём частям сразу случайно неоткуда.
		return Strong, nameLowerRule(rule), true
	case Strong:
		// Маркер сюда приходит только для пар из двух опознанных слов, у
		// которых есть вариант правила с маркером (см. Scan).
		if marker {
			if r := nameLowerMarkerRule(rule); r != "" {
				return Strong, r, true
			}
		}
		return Weak, nameLowerRule(rule), true
	default:
		if !marker {
			return conf, rule, false
		}
		return Weak, nameMarkerRule(rule), true
	}
}

// nameLowerRule подменяет имя правила на вариант для строчной записи.
func nameLowerRule(rule string) string {
	switch rule {
	case nameRuleFIO:
		return nameRuleFIOLower
	case nameRuleIFO:
		return nameRuleIFOLower
	case nameRuleGivenPatronymic:
		return nameRuleGivenPatronymicLower
	case nameRuleGivenSurname:
		return nameRuleGivenSurnameLower
	case nameRuleSurnameGiven:
		return nameRuleSurnameGivenLower
	case nameRulePatronymicSur:
		return nameRulePatronymicSurLower
	case nameRuleSurnameInitials:
		return nameRuleSurnameInitialsLower
	case nameRuleInitialsSurname:
		return nameRuleInitialsSurnameLower
	case nameRuleFIOPos:
		return nameRuleFIOPosLower
	case nameRuleIFOPosSur:
		return nameRuleIFOPosSurLower
	case nameRuleIFOPosGiven:
		return nameRuleIFOPosGivenLower
	case nameRuleSurPosGiven:
		return nameRuleSurPosGivenLower
	case nameRuleSurPosInit:
		return nameRuleSurPosInitLower
	case nameRuleFIOBare:
		return nameRuleFIOBareLower
	case nameRuleIFOBare:
		return nameRuleIFOBareLower
	case nameRuleGivenGiven:
		return nameRuleGivenGivenLower
	default:
		return rule
	}
}

// nameLowerMarkerRule возвращает имя правила для строчной пары, поднятой
// маркером лица слева, или пустую строку, если маркер такую конструкцию не
// поднимает.
//
// Подъём положен только парам из двух опознанных слов, одно из которых —
// имя из справочника: «иванов иван», «иван иванов», «иван иванович». Фамилия
// без суффикса рядом с такой парой уровень не меняет — она едет вместе с
// парой. Одиночное слово и пары, собранные по позиции из одного опознанного
// слова, здесь не поднимаются: «клиент банка иван» не должен стать ФИО
// целиком.
func nameLowerMarkerRule(rule string) string {
	switch rule {
	case nameRuleGivenPatronymic:
		return nameRuleGivenPatronymicLowerMarker
	case nameRuleGivenSurname:
		return nameRuleGivenSurnameLowerMarker
	case nameRuleSurnameGiven:
		return nameRuleSurnameGivenLowerMarker
	case nameRuleFIOBare:
		return nameRuleFIOBareLowerMarker
	case nameRuleIFOBare:
		return nameRuleIFOBareLowerMarker
	case nameRuleGivenGiven:
		return nameRuleGivenGivenLowerMarker
	// Строчная фамилия с инициалами: «клиент шаповалова д.н.», «звонил
	// мкртчян а.а.», «передайте д. н. шаповаловой» (T-66, P4-4). Инициалы
	// с точками и фамилия с суффиксом — две опознанные части, как у пары.
	case nameRuleSurnameInitials:
		return nameRuleSurnameInitialsLowerMarker
	case nameRuleInitialsSurname:
		return nameRuleInitialsSurnameLowerMarker
	}
	return ""
}

// nameHasUpper сообщает, что хотя бы одно слово конструкции начинается с
// заглавной буквы.
func nameHasUpper(doc *lex.Doc, first, last int) bool {
	for k := first; k <= last; k++ {
		t := doc.Tokens[k]
		if t.Kind == lex.KindWord && t.Flags.Has(lex.FlagFirstUpper) {
			return true
		}
	}
	return false
}

// nameSameCase сообщает, что слово j написано в том же регистре, что и первое
// слово конструкции.
//
// Требование единообразия отсекает случай, когда к настоящему ФИО слева
// прилипает обычное слово с подходящим суффиксом: в «документов Иванов
// Петрович» конструкция начинается с «Иванов», а не с «документов».
func nameSameCase(doc *lex.Doc, head, j int) bool {
	return doc.Tokens[head].Flags.Has(lex.FlagFirstUpper) ==
		doc.Tokens[j].Flags.Has(lex.FlagFirstUpper)
}

// nameMarkerRule подменяет имя правила на вариант с маркером: уровень
// уверенности без причины в отчёте не объясним.
func nameMarkerRule(rule string) string {
	switch rule {
	case nameRuleSurname:
		return nameRuleSurnameMarker
	case nameRuleGiven:
		return nameRuleGivenMarker
	case nameRuleSurPosGiven:
		return nameRuleSurPosGivenMarker
	case nameRuleGivenSurPos:
		return nameRuleGivenSurPosMarker
	case nameRuleBareGiven:
		return nameRuleBareGivenMarker
	case nameRuleGivenBare:
		return nameRuleGivenBareMarker
	case nameRuleSurBareInit:
		return nameRuleSurBareInitMarker
	case nameRuleAdjGiven:
		return nameRuleAdjGivenMarker
	case nameRuleGivenAdj:
		return nameRuleGivenAdjMarker
	case nameRuleSurBareInit1:
		return nameRuleSurBareInit1Marker
	case nameRuleGivenPosSurname:
		return nameRuleGivenPosSurnameMarker
	case nameRuleSurnameGivenPos:
		return nameRuleSurnameGivenPosMarker
	default:
		return nameRulePatronymicMarker
	}
}

// nameExtendLeft достраивает конструкцию одним словом слева и возвращает
// новый первый токен, уверенность и имя правила.
//
// Разбор идёт слева направо и начинает конструкцию с первого слова, которое
// удалось опознать. Слово перед ним оставалось снаружи даже тогда, когда это
// и была самая опознаваемая часть имени: «Аграфена Матвеевна Гвоздарёва»
// разбиралась как «Отчество Фамилия», а «Задворная Людмила Платоновна» — как
// «Имя Отчество». В обоих случаях ответ выглядел защищённым, а уцелевшее
// слово уходило в модель открытым. Это опаснее обычного пропуска: пропуск
// виден, частичная утечка маскируется под успех.
//
// Слово принимается не потому, что похоже на имя или фамилию само по себе, а
// потому, что стоит вплотную к опознанной паре и занимает в конструкции
// единственное свободное место. Тот же довод уже работает в правиле «Фамилия
// Имя Отчество», где среднее слово принимается без справочника.
//
// floor — граница слева: дальше начинается уже выданный спан.
func nameExtendLeft(doc *lex.Doc, tb *nameTables,
	first int, rule string, floor int,
) (int, Confidence, string, bool) {
	// «Лысенко;Ольга;Петровна»: разделитель записи без пробелов — как пробел
	// (T-83, P5-1).
	k := nameCSVPrev(doc, first)
	if k < floor || !nameEligible(doc, k) || !nameJoinable(doc, k) ||
		!nameSameCase(doc, first, k) {
		return 0, 0, "", false
	}
	switch rule {
	// «Имя Отчество» — слева не хватает фамилии: «Задворная Людмила
	// Платоновна», «бережной кирилл родионович».
	case nameRuleGivenPatronymic:
		return nameExtendLeftGivenPatr(doc, tb, k, first)
	// «Отчество Фамилия» — слева не хватает имени: «Аграфена Матвеевна
	// Гвоздарёва».
	case nameRulePatronymicSur:
		if nameGivenPos(doc, tb.markers, doc.NormOf(first), k) {
			return k, Certain, nameRuleIFOPosGiven, true
		}
	// Одиночное слово из справочника имён — слева не хватает фамилии:
	// «Задворная Марина».
	case nameRuleGiven, nameRuleSurname:
		if _, ok := nameLookupGiven(tb.given, doc.NormOf(first)); ok {
			return nameExtendLeftGiven(doc, tb, k, first)
		}
		// «Шахзод Турсунов»: имя вне справочника перед фамилией (T-80).
		return nameExtendLeftEthnic(doc, tb, k, first)
	// «Ван Тхань», «Мин Су» — два имени подряд; слева не хватает фамилии:
	// «Нгуен Ван Тхань», «Пак Мин Су» (T-66).
	case nameRuleGivenGiven:
		return nameExtendLeftGivenGiven(doc, tb, k)
	}
	return 0, 0, "", false
}

// nameExtendLeftGivenPatr достраивает фамилию k слева от пары «Имя Отчество»,
// которая начинается словом first.
func nameExtendLeftGivenPatr(doc *lex.Doc, tb *nameTables, k, first int) (int, Confidence, string, bool) {
	// Отчество стоит сразу за именем или за разделителем записи
	// («Мазур;Олег;Петрович»).
	patr := nameCSVNext(doc, first+1)
	if nameSurnamePos(doc, tb.markers, k) {
		return k, Certain, nameRuleFIOPos, true
	}
	// «Клиент Белый Андрей Сергеевич», «от Лысого Виктора Петровича»:
	// фамилия-прилагательное короче предела nameSurnamePos (T-66).
	if nameAdjBeforePair(doc, tb, k, patr) {
		return k, nameConfBy(k > 0 && !doc.IsSentenceBreak(k-1) && nameTitle(doc.Tokens[k])), nameRuleFIOAdj, true
	}
	// Фамилия без русского суффикса: «Мельник Олег Петрович». Отчество стоит
	// сразу за именем — так пару собрало правило «Имя Отчество».
	if nameClassify(doc, tb.given, tb.markers, k) != 0 {
		return 0, 0, "", false
	}
	if ok, evidence := nameBareSurname(doc, tb, k, patr, true); ok {
		return k, nameConfBy(evidence), nameRuleFIOBare, true
	}
	// «Орёл Сергей Петрович оформил вклад»: фамилия с окончанием глагола в
	// начале предложения. Сказуемое сразу за парой показывает, что глагол
	// предложения уже есть и слово слева — не он (T-83, P5-6).
	if namePredicateAfter(doc, patr) {
		if ok, _ := nameBareSurnameOpt(doc, tb, k, patr, true, true); ok {
			return k, Strong, nameRuleFIOBare, true
		}
	}
	return 0, 0, "", false
}

// nameExtendLeftGiven достраивает фамилию k слева от одиночного слова first.
//
// Роль здесь переспрашивается у справочника, а не берётся из имени правила:
// «Марина» — одновременно имя из справочника и правильная форма фамилии
// («-ина»), и правило для неё выбирается как одиночная фамилия. Достраивать
// фамилию слева от фамилии незачем, а слева от имени — нужно. Справочник
// спрашивает вызывающий (nameExtendLeft): first — имя из справочника.
//
// Уверенность не поднимается: вся конструкция держится на одном опознанном
// слове, и судьбу пары решает движок по кластеру или маркер слева. Поднять
// её здесь значило бы маскировать «Красивая Марина».
func nameExtendLeftGiven(doc *lex.Doc, tb *nameTables, k, first int) (int, Confidence, string, bool) {
	if nameSurnamePos(doc, tb.markers, k) {
		return k, Weak, nameRuleSurPosGiven, true
	}
	if nameClassify(doc, tb.given, tb.markers, k) != 0 {
		return 0, 0, "", false
	}
	if c, r, ok := nameExtendLeftBare(doc, tb, k, first); ok {
		return k, c, r, true
	}
	// «Клиентка Белая Ольга», «Спасибо, Тихий Роман»: короткая
	// фамилия-прилагательное, которую nameSurnamePos не берёт по длине.
	// Уровень Weak — поднимает маркер или обращение (T-66).
	if nameAdjWithGiven(doc, tb, k, first) {
		return k, Weak, nameRuleAdjGiven, true
	}
	// «Бабий Роман сообщил о краже»: в начале предложения при сказуемом
	// (T-80, класс 7).
	if nameAdjLeadsPredicate(doc, tb, k, first) {
		return k, Strong, nameRuleAdjGivenPredicate, true
	}
	return 0, 0, "", false
}

// nameExtendLeftBare принимает фамилию без суффикса k слева от одиночного
// имени first: «Клиент Мельник Олег». Опознанное слово одно, поэтому второе
// принимается только со свидетельством регистра — заглавная буква не в
// начале предложения. Уровень тот же, что у фамилии-прилагательного: Weak, и
// поднимает его маркер слева или кластер.
//
// Без свидетельства регистра (строчные, капс) слово принимается, когда его с
// другой стороны держит маркер или слово-ввод вплотную: «клиентка гусь
// анна», «ЗВОНИЛ ЦОЙ АРТЁМ». Слово зажато между двумя опорами, и свободное
// место конструкции у него одно (T-60).
func nameExtendLeftBare(doc *lex.Doc, tb *nameTables, k, first int) (Confidence, string, bool) {
	ok, evidence := nameBareSurname(doc, tb, k, -1, true)
	if !ok {
		return 0, "", false
	}
	// Раунд 4 жюри (T-66): пара «Фамилия Имя» с заглавной — ФИО целиком, как
	// «Петрова Анна» с суффиксом. См. nameBareLeads.
	if nameBareLeads(doc, tb, k, first) {
		if evidence {
			return Strong, nameRuleBareLead, true
		}
		return Strong, nameRuleBareLeadStart, true
	}
	if evidence || nameBareAnchored(doc, tb, k) {
		return Weak, nameRuleBareGiven, true
	}
	return 0, "", false
}

// nameExtendLeftGivenGiven достраивает фамилию без суффикса k слева от двух
// имён подряд: «Нгуен Ван Тхань», «Пак Мин Су» (T-66).
func nameExtendLeftGivenGiven(doc *lex.Doc, tb *nameTables, k int) (int, Confidence, string, bool) {
	if nameClassify(doc, tb.given, tb.markers, k) != 0 {
		return 0, 0, "", false
	}
	if ok, _ := nameBareSurname(doc, tb, k, -1, true); ok &&
		nameTitle(doc.Tokens[k]) && !nameLeadStop(tb, doc.NormOf(k)) {
		return k, Strong, nameRuleBareGivenGiven, true
	}
	return 0, 0, "", false
}

// nameTitle сообщает, что слово написано с заглавной буквы и не капсом.
func nameTitle(t lex.Token) bool {
	return t.Flags.Has(lex.FlagFirstUpper) && !t.Flags.Has(lex.FlagAllUpper)
}

// nameLeadStop сообщает, что слово с заглавной перед именем — не фамилия:
// служебное слово, обращение, титул, организация, ролевое слово
// контр-правил или государство (T-66).
//
// Стоп-список nameBareStopWord читается здесь и при свидетельстве регистра:
// после двоеточия и в кавычках с заглавной пишут и обычные слова
// («Оператор: Спасибо Анна»), а настоящих фамилий в нём нет.
func nameLeadStop(tb *nameTables, w string) bool {
	return nameBareStopWord(w) || tb.stop.Has(w) || tb.roles.Has(w) || nameCountry(tb, w)
}

// nameQuoted сообщает, что слово i открывает текст в кавычках: «Войну и
// мир», «Тарас Бульба». С заглавной в кавычках пишут названия книг,
// компаний и продуктов, и позиция такого слова о человеке не говорит.
func nameQuoted(doc *lex.Doc, i int) bool {
	if i == 0 || !doc.Adjacent(i-1) {
		return false
	}
	p := doc.Tokens[i-1]
	if p.Kind != lex.KindPunct {
		return false
	}
	r, _ := utf8.DecodeRuneInString(doc.Text[p.Start:p.End])
	switch r {
	case '«', '"', '„', '“', '\'':
		return true
	}
	return false
}

// nameCountry сообщает, что слово — название государства в любом падеже:
// «Армении», «Казахстана», «России». Справочник гражданства хранит
// именительный падеж, остальное восстанавливает nameLookupGiven — тот же
// разбор окончаний, что и для имён.
func nameCountry(tb *nameTables, w string) bool {
	if tb.countries == nil {
		return false
	}
	_, ok := nameLookupGiven(tb.countries, w)
	return ok
}

// nameBareLeads решает, делает ли слово k с заглавной буквы фамилией пару
// «Фамилия Имя» с одиночным именем first без маркера (раунд 4 жюри, Б4-1:
// «Коваль Инна обратилась в отделение» уходила в модель открытой).
//
// До T-66 такая пара держалась на одном опознанном слове и оставалась Weak,
// пока её не поднимут маркер или кластер. Но «Петрова Анна» с суффиксом
// маскируется без всякого маркера, и фамилия без суффикса отличается от неё
// только тем, что её не узнаёт морфология. Заглавная буква — тот же довод,
// что суффикс: имя собственное вплотную перед именем.
//
// Положительных признаков два: оба слова с заглавной (не капс) и имя стоит
// в именительном падеже. Именительный обязателен: в косвенном падеже слева
// от имени стоит обычное существительное — «Заявка Олега», «Карта Анны»,
// «Счёт Ивана», — и их согласование разбирает nameBareCaseAgrees. Отсевы —
// стоп-списки (служебные слова, обращения, титулы, организации), ролевые
// слова контр-правил, государства; месяцы, города и глаголы уже отсеял
// nameBareSurname. Публичную персону снимает контр-правило, как и у пары с
// суффиксом.
//
// Свидетельство регистра (заглавная буква слова k в середине предложения)
// правило не меняет: без него (слово начинает предложение) правило то же: отсевы nameBareSurname без
// свидетельства регистра строже и включают отсев глаголов.
func nameBareLeads(doc *lex.Doc, tb *nameTables, k, first int) bool {
	if !nameTitle(doc.Tokens[k]) || !nameTitle(doc.Tokens[first]) {
		return false
	}
	// «Тарас Бульба», «Роза Хутор» в кавычках — название, а не человек.
	if nameQuoted(doc, min(k, first)) {
		return false
	}
	if !tb.given.Has(doc.NormOf(first)) {
		return false
	}
	return !nameLeadStop(tb, doc.NormOf(k))
}

// nameExtendRight достраивает одиночное имя из справочника фамилией справа:
// «Клиент Лев Толстой», «Клиент Виктор Цой».
//
// Слева от имени фамилию достраивает nameExtendLeft; справа до T-50 её не
// достраивал никто, и «Клиент Лев Толстой» уходил в модель как «Клиент
// [ФИО_1] Толстой». Доводы и уровни те же, что слева: слово стоит вплотную к
// опознанному имени, конструкция держится на одном опознанном слове и
// остаётся Weak, пока её не поднимет маркер или кластер.
func nameExtendRight(doc *lex.Doc, tb *nameTables,
	first, last int, rule string,
) (int, Confidence, string, bool) {
	if first != last || (rule != nameRuleGiven && rule != nameRuleSurname) {
		return 0, 0, "", false
	}
	given, markers := tb.given, tb.markers
	if _, ok := nameLookupGiven(given, doc.NormOf(first)); !ok {
		// «Гелашвили Тамази»: имя вне справочника за фамилией (T-80).
		return nameExtendRightEthnic(doc, tb, first)
	}
	j, ok := nameNextPart(doc, first, first)
	if !ok || doc.IsSentenceBreak(first) || nameClassify(doc, given, markers, j) != 0 ||
		nameStartsNext(doc, tb, first, j) {
		return 0, 0, "", false
	}
	if nameSurnamePos(doc, markers, j) {
		return j, Weak, nameRuleGivenSurPos, true
	}
	// «Клиент Андрей Белый»: короткая фамилия-прилагательное справа от
	// имени — зеркало nameAdjWithGiven, уровень тот же (T-66).
	if nameAdjWithGiven(doc, tb, j, first) {
		return j, Weak, nameRuleGivenAdj, true
	}
	if c, r, ok := nameExtendRightBare(doc, tb, j, first); ok {
		return j, c, r, true
	}
	return 0, 0, "", false
}

// nameExtendRightBare принимает фамилию без суффикса j справа от одиночного
// имени first.
//
// Без свидетельства регистра слово справа от имени принимается только в
// рамке «опора — имя — слово — сказуемое»: «клиент олег мельник просит
// кредит». Одной опоры слева мало: в «клиент иван доволен» справа от имени
// стоит обычное слово, а сказуемое после него показывает, что подлежащее —
// «имя фамилия» целиком (T-60).
func nameExtendRightBare(doc *lex.Doc, tb *nameTables, j, first int) (Confidence, string, bool) {
	ok, evidence := nameBareSurname(doc, tb, j, -1, false)
	if !ok {
		return 0, "", false
	}
	// «Инна Коваль оспаривает списание»: зеркало nameBareLeads (T-66). Слово
	// справа от имени начинает предложение, только если имя стоит в конце
	// предыдущего, а этот случай отсёк IsSentenceBreak в nameExtendRight,
	// поэтому заглавная буква здесь — всегда свидетельство.
	if evidence && nameBareLeads(doc, tb, j, first) && !nameHyphenBadTail(doc, tb, j) {
		return Strong, nameRuleGivenBareTitle, true
	}
	if evidence || (nameBareAnchored(doc, tb, first) && namePredicateAfter(doc, j)) {
		return Weak, nameRuleGivenBare, true
	}
	// «звонил олег мазур, просил…», «полина гринь не получила код» (T-80).
	if nameLowerSubject(doc, tb, first, j) {
		return Weak, nameRuleGivenBare, true
	}
	return 0, "", false
}

// nameStartsNext сообщает, что слово j начинает следующую конструкцию, а не
// продолжает текущую: за ним вплотную идёт отчество. В «Олег Петрович
// Зорислава Матвеевна» слово «Зорислава» — имя второго человека, и принятое
// за фамилию первого оно оставило бы «Матвеевну» одинокой и слабой.
func nameStartsNext(doc *lex.Doc, tb *nameTables, head, j int) bool {
	k, ok := nameNextPart(doc, head, j)
	return ok && nameClassify(doc, tb.given, tb.markers, k)&nameRolePatronymic != 0
}

// nameBareSurname сообщает, годится ли слово k на место фамилии без
// русского суффикса рядом с уже опознанной частью имени, и есть ли у этого
// решения свидетельство регистра.
//
// У такой фамилии нет ни суффикса, ни окончания прилагательного: «Мельник»,
// «Коваль», «Цой», «Шульц». Это не список фамилий и не морфология — слово
// принимается только потому, что стоит на единственном свободном месте уже
// опознанной конструкции. Поэтому здесь нет положительных признаков, одни
// отсевы: всё, что на этом месте встречается и фамилией не является.
//
// Свидетельство регистра — заглавная буква у слова, которое стоит не в
// начале предложения и написано не капсом: в середине предложения с
// заглавной пишут имена собственные, и «Клиент Мельник Олег Петрович»
// читается однозначно. Без свидетельства (начало предложения, капс,
// строчная запись) добавляются стоп-список служебных слов, отсевы глаголов
// и наречий на «-но» и согласование в падеже с отчеством, а уверенность
// конструкции не поднимается выше уровня самой пары.
//
// patr — индекс отчества пары или -1, если опознано одиночное имя. left —
// слово стоит слева от опознанной части.
func nameBareSurname(doc *lex.Doc, tb *nameTables, k, patr int, left bool) (ok, evidence bool) {
	return nameBareSurnameOpt(doc, tb, k, patr, left, false)
}

// nameBareSurnameOpt — nameBareSurname, в котором отсевы глаголов и городов
// сняты (framed): их заменяет рамка «слово — Имя Отчество — сказуемое»,
// которую проверил вызывающий. «Орёл Сергей Петрович оформил вклад» — и
// глагол по окончанию, и город по справочнику, но перед парой со сказуемым
// это подлежащее.
func nameBareSurnameOpt(doc *lex.Doc, tb *nameTables, k, patr int, left, framed bool) (ok, evidence bool) {
	if !nameEligible(doc, k) {
		return false, false
	}
	t := doc.Tokens[k]
	runes := nameRunes(t)
	if runes < nameBareMinLen || runes > nameBareMaxLen {
		return false, false
	}
	if nameBareCut(doc, k, left) {
		return false, false
	}
	w := doc.NormOf(k)
	if nameBareRejected(tb, w, runes, framed) {
		return false, false
	}
	// «в Твери Олег Петрович»: после предлога места с заглавной стоит
	// топоним, а не фамилия.
	if left && k > 0 && nameToponymPrep(doc, k-1) {
		return false, false
	}
	if nameBareEvidence(doc, t, k, left) {
		return true, true
	}
	return nameBareBlind(doc, tb, k, patr, left, framed), false
}

// nameBareBlind — отсевы фамилии без суффикса без свидетельства регистра.
//
// Служебные слова стоп-списка с заглавной в середине предложения не
// пишутся, и там же с заглавной пишется «Ли» — фамилия, совпадающая с
// частицей. Поэтому стоп-список читается только без свидетельства регистра,
// вместе с отсевом глаголов (его снимает framed).
func nameBareBlind(doc *lex.Doc, tb *nameTables, k, patr int, left, framed bool) bool {
	w := doc.NormOf(k)
	if nameRunes(doc.Tokens[k]) < nameBareBlindMinLen || nameBareStopWord(w) || (!framed && nameBareVerbLike(w)) {
		return false
	}
	// Согласование снимает повелительное наклонение в начале предложения.
	// Слово, которое держит маркер лица вплотную слева, глаголом не бывает:
	// «Найди клиента цой алевтину кирилловну» (T-66, корпус seed 20260924).
	return patr < 0 || nameBareAgrees(w, doc.NormOf(patr)) || (left && nameMarkerBefore(doc, tb, k))
}

// nameBareCut сообщает, что между словом k и опознанной частью стоит перевод
// строки: за ним начинается другое поле формы («ФИО: Олег
// Петрович⏎Телефон: …»). left — слово стоит слева от опознанной части.
func nameBareCut(doc *lex.Doc, k int, left bool) bool {
	if left {
		return doc.IsSentenceBreak(k)
	}
	return doc.IsSentenceBreak(k - 1)
}

// nameBareRejected — отсевы фамилии без суффикса, которые действуют и при
// свидетельстве регистра: маркер или обращение, месяц, город (кроме рамки
// framed), окончание прилагательного, название банка.
func nameBareRejected(tb *nameTables, w string, runes int, framed bool) bool {
	return nameNotNamePart(tb.markers, w) || tb.months.Has(w) || (!framed && tb.cities.Has(w)) ||
		(runes >= nameBareAdjMinLen && nameBareAdjEnding(w)) ||
		// «Сбербанку Олегу», «Альфа-Банка Анны»: название банка с заглавной
		// буквы рядом с именем — организация, а не фамилия.
		strings.Contains(w, wordBank)
}

// nameBareEvidence сообщает, что у слова k (t) есть свидетельство регистра:
// заглавная буква не капсом. Слева от опознанной части в начале предложения
// заглавная буква ничего не говорит: «Сегодня Олег Петрович пришёл».
func nameBareEvidence(doc *lex.Doc, t lex.Token, k int, left bool) bool {
	if !nameTitle(t) {
		return false
	}
	return !left || (k > 0 && !doc.IsSentenceBreak(k-1))
}

// nameMarkerBefore сообщает, что вплотную слева от слова k стоит маркер лица
// из name_markers («клиента», «заявителя»).
func nameMarkerBefore(doc *lex.Doc, tb *nameTables, k int) bool {
	p, ok := namePrevWord(doc, k)
	return ok && tb.markers.Has(doc.NormOf(p))
}

// nameBareThenInitials разбирает «Коваль К. Г.»: слово без суффикса перед
// двумя инициалами. last — точка второго инициала, её вернул
// nameSurnameThenInitials.
//
// Одного инициала мало: «Корпус Б.», «Приложение А.» устроены так же. Два
// инициала подряд за словом с заглавной буквы в деловом тексте означают
// человека, если только за ними не стоит фамилия: в «Автор А. С. Пушкин»
// слово «Автор» — не фамилия, а инициалы относятся к «Пушкину».
//
// Строчная запись не принимается: «документы т. е. копии» устроены так же, а
// строчные инициалы свидетельством не служат. Без свидетельства регистра —
// начало предложения, капс — конструкция заводится как Weak, и её поднимает
// маркер слева или кластер.
func nameBareThenInitials(doc *lex.Doc, tb *nameTables, i, last int) (Confidence, bool) {
	if last != i+4 || !doc.Tokens[i].Flags.Has(lex.FlagFirstUpper) {
		return 0, false
	}
	if k, ok := nameNextToken(doc, last); ok && !lex.HasLineBreak(doc.Gap(last)) {
		if t := doc.Tokens[k]; t.Kind == lex.KindWord && t.Flags.Has(lex.FlagFirstUpper) {
			return 0, false
		}
	}
	ok, evidence := nameBareSurname(doc, tb, i, -1, true)
	if !ok {
		return 0, false
	}
	if evidence || nameSignatureEnd(doc, last) {
		return Strong, true
	}
	return Weak, true
}

// nameSignatureEnd сообщает, что конструкция последняя в тексте или в строке:
// «Прошу закрыть счёт. Мельник О. П.» — подпись. Фамилия с двумя инициалами
// в конце письма — человек, даже когда свидетельства регистра нет (начало
// предложения): «Корпус Б. В.» в конце строки не стоит (бизнес-жюри 23.09,
// раунд 2).
func nameSignatureEnd(doc *lex.Doc, last int) bool {
	k := last + 1
	if k >= len(doc.Tokens) {
		return true
	}
	return lex.HasLineBreak(doc.Gap(last))
}

// nameInitialsThenBare разбирает «К. Г. Коваль»: два заглавных инициала и
// слово без суффикса с заглавной буквы. Инициалы здесь — то же свидетельство,
// что заглавная буква в середине предложения, поэтому отсевы те же, что у
// nameBareSurname со свидетельством регистра.
func nameInitialsThenBare(doc *lex.Doc, tb *nameTables, i int) (int, bool) {
	dot, ok := nameInitialAt(doc, i)
	if !ok || !doc.Tokens[i].Flags.Has(lex.FlagFirstUpper) {
		return 0, false
	}
	j, ok := nameNextToken(doc, dot)
	if !ok || !nameSameCase(doc, i, j) {
		return 0, false
	}
	second, ok := nameInitialAt(doc, j)
	if !ok {
		return 0, false
	}
	k, ok := nameNextToken(doc, second)
	if !ok || lex.HasLineBreak(doc.Gap(second)) || !nameEligible(doc, k) {
		return 0, false
	}
	t := doc.Tokens[k]
	if !t.Flags.Has(lex.FlagFirstUpper) || t.Flags.Has(lex.FlagAllUpper) ||
		nameClassify(doc, tb.given, tb.markers, k) != 0 {
		return 0, false
	}
	runes := nameRunes(t)
	if runes < nameBareMinLen || runes > nameBareMaxLen {
		return 0, false
	}
	w := doc.NormOf(k)
	if nameNotNamePart(tb.markers, w) || tb.months.Has(w) || tb.cities.Has(w) ||
		(runes >= nameBareAdjMinLen && nameBareAdjEnding(w)) {
		return 0, false
	}
	return k, true
}

// nameBareAgrees проверяет согласование в падеже фамилии без суффикса с
// отчеством пары. Нужно только без свидетельства регистра, и прежде всего
// против повелительного наклонения в начале предложения: «Найди Олега
// Петровича», «Проверь Анну Петровну» — глагол стоит на месте фамилии и
// кончается на «-и», «-ь», «-й».
//
// В именительном падеже согласование не проверяется. Мужская фамилия в
// косвенном падеже кончается окончанием падежа («Мельника», «Коваля»,
// «Цою»), женская без суффикса не склоняется («Анны Петровны Мельник»),
// кроме фамилий на «-а» («Сороки»).
func nameBareAgrees(w, patronymic string) bool {
	if strings.HasSuffix(patronymic, "ич") || strings.HasSuffix(patronymic, "на") {
		return true
	}
	if namePatronymicFemale(patronymic) {
		switch nameLastRune(w) {
		case 'и', 'ь', 'й':
			return false
		}
		return true
	}
	for _, e := range nameBareMascOblique {
		if strings.HasSuffix(w, e) {
			return true
		}
	}
	return false
}

// nameBareMascOblique — окончания косвенных падежей мужской фамилии без
// суффикса: «Мельника», «Коваля», «Мельнику», «Мельником», «Коваля»,
// «Мельнике».
var nameBareMascOblique = [...]string{"а", "я", "у", "ю", "ом", "ем", "е"}

// nameBareAdjEnding сообщает, что слово кончается окончанием
// прилагательного. Такие слова на место фамилии принимает только
// nameSurnamePos со своим пределом длины, и bare-правило не должно впускать
// то, что тот отсеял: «Новая Анна Петровна».
func nameBareAdjEnding(w string) bool {
	for _, e := range nameAdjSurnameEndings {
		if strings.HasSuffix(w, e.end) {
			return true
		}
	}
	for _, e := range nameBareAdjExtra {
		if strings.HasSuffix(w, e) {
			return true
		}
	}
	return false
}

// nameBareAdjExtra — окончания прилагательных среднего рода и
// множественного числа, которых нет у фамилий-прилагательных в единственном
// числе и потому нет в nameAdjSurnameEndings.
var nameBareAdjExtra = [...]string{"ое", "ее", "ые", "ие", "ых", "их", "ыми", "ими"}

// nameBareVerbEndings — окончания глаголов и наречий, которые отсеиваются
// без свидетельства регистра: «ИВАН ИВАНОВИЧ ПРИБЫЛ», «олег петрович
// сказал», «анна петровна перезвонит», «иван иванович лично». В тексте с
// заглавными буквами глагол после имени пишется строчной и отсеивается
// раньше — сравнением регистра, поэтому фамилии «Сокол» и «Орёл» в обычном
// тексте этим отсевом не задеты.
var nameBareVerbEndings = [...]string{
	// прошедшее время
	"ал", "ял", "ил", "ыл", "ел", "ул", "ла", "ло", "ли", "лся", "лась", "лось", "лись",
	// настоящее и будущее время
	"ет", "ит", "ут", "ют", "ат", "ят", "ешь", "ишь", "ся", "сь",
	// инфинитив
	"ть", "ти", "чь",
	// повелительное наклонение множественного числа
	"те",
	// наречия
	"но",
}

// nameBareVerbLike сообщает, что слово похоже на глагол или наречие.
//
// Четырёхбуквенное слово на «-сь» глаголом не считается: возвратная форма
// глагола длиннее («учусь», «боюсь», «вернись»), а четыре буквы на «-сь» —
// это «гусь», «лось», «рысь», то есть в том числе фамилии («Клиентка гусь
// анна», раунд 3 жюри). «Весь» и «здесь» снимает стоп-список раньше.
func nameBareVerbLike(w string) bool {
	if (strings.HasSuffix(w, "сь") || strings.HasSuffix(w, "ся")) && utf8.RuneCountInString(w) <= 4 {
		// «Гусь», «Лось», «Гуся», «Лося» (T-66): четырёхбуквенный глагол на
		// «-ся» так же редок, как на «-сь».
		return false
	}
	if nameNounInSj(w) || nameShortNoun(w) {
		return false
	}
	for _, e := range nameBareVerbEndings {
		if strings.HasSuffix(w, e) {
			return true
		}
	}
	return false
}

// nameNounInSj сообщает, что слово на «-ась», «-ось», «-ысь» — существительное,
// а не возвратный глагол: «Карась», «Лосось» (T-66). Возвратные формы
// прошедшего времени кончаются на «-лась», «-лось», и их отсев не меняется;
// «-усь», «-юсь», «-ись» — первое лицо и повелительное наклонение
// («учусь», «боюсь», «вернись») — остаются глаголами.
func nameNounInSj(w string) bool {
	if !strings.HasSuffix(w, "сь") || len(w) < 6 {
		return false
	}
	stem := w[:len(w)-len("сь")]
	v, size := utf8.DecodeLastRuneInString(stem)
	switch v {
	case 'а', 'о', 'ы':
	default:
		return false
	}
	c, _ := utf8.DecodeLastRuneInString(stem[:len(stem)-size])
	return c != 'л'
}

// nameToponymPrep сообщает, что токен i — предлог места, после которого с
// заглавной буквы пишется название места: «в Твери», «из Москвы», «под
// Тулой». Предлоги, которые вводят и человека («у», «на», «для», «от»),
// сюда не входят: «доверенность на Мельника Олега Петровича».
func nameToponymPrep(doc *lex.Doc, i int) bool {
	if doc.Tokens[i].Kind != lex.KindWord {
		return false
	}
	switch doc.NormOf(i) {
	case "в", "во", "из", "изо", wordUnder, "подо", "над", wordNear, "возле",
		"близ", "вблизи", "вдоль":
		return true
	}
	return false
}

// nameBareStopWord — служебные и обиходные слова, которые стоят вплотную к
// имени и занимают место фамилии: местоимения, союзы, частицы, предлоги,
// наречия времени, приветствия, должности и родство в начале предложения.
//
// Читается только без свидетельства регистра (см. nameBareSurname): с
// заглавной в середине предложения эти слова не пишутся.
//
// Список закрытый, как закрыты сами эти классы слов; должности и обиходные
// существительные — только те, что встречаются вплотную к имени в деловом
// тексте. Сравнение через switch компилируется в поиск без аллокаций.
func nameBareStopWord(w string) bool {
	switch w {
	// местоимения
	case "я", "ты", "он", "она", "оно", "мы", "вы", "они", wordHis, "ее", "их",
		"им", "ей", "ему", "нам", "вам", "нас", "вас", "меня", "мне", "тебя",
		"тебе", "себя", "себе", wordThis, "этот", "эта", "эти", "этого", "этой",
		"тот", "та", "те", "того", "той", "весь", "вся", "все", "всех", "всем",
		"кто", "что", "чей", "сам", "сама", "сами", "свой", "своя", "свои",
		"наш", "наша", "наши", "ваш", "ваша", "ваши", "мой", "моя", "мои",
		"твой", "твоя", "никто", "ничто", "каждый", "любой", "другой", "иной",
		"такой", "какой", "который", "которая", "которые",
		"нашей", "вашей", "моей", "твоей", "своей", "всей", "нашим", "вашим",
		"моим", "своим", "нашего", "вашего", "моего", "своего",
		// союзы и частицы
		"и", "а", "но", "или", "либо", "да", "чтобы", "когда", "если", "как",
		"хотя", "пока", "потому", "поэтому", "также", "тоже", "однако", "зато",
		"ибо", "то", "не", "ни", "ли", "же", "бы", "вот", "вон", "даже",
		"только", "лишь", "уже", "еще", "именно", "разве", "пусть", "ведь",
		"нет", "ну",
		// предлоги
		"в", "во", "на", "с", "со", "к", "ко", "у", "о", "об", "обо", "от",
		"до", "по", "за", "из", "без", wordFor, "при", wordAbout, "через", "над",
		wordUnder, "перед", "между", wordNear, "возле", "после", "кроме", "среди",
		"против", "вместо", "мимо",
		// наречия
		wordToday, "вчера", "завтра", "сейчас", wordNow, "тогда", "потом",
		"затем", "сначала", "здесь", "там", "тут", "туда", "сюда", "всегда",
		"никогда", "иногда", "часто", "редко", "снова", "опять", "вновь",
		"скоро", "давно", "недавно", "пожалуйста", nameWordThanks, "просто",
		"очень", "ранее", "позже", "далее", "итак", "кстати", "например",
		"конечно", "наверное", "возможно", "вероятно", "срочно", "лично",
		"прошу", "просим", "утром", "вечером", "днем", "ночью", "сразу",
		"обязательно", "немедленно", "повторно", "заранее", "лучше",
		// приветствия и обращения
		nameWordHello, "здравствуй", nameWordHi, "добрый", "доброе", "доброго",
		"товарищ", "коллега", "коллеги", "мистер", "миссис", "мисс", "пан",
		"пани", "сударь", "сударыня",
		// должности и звания в начале предложения
		"директор", "директора", "менеджер", "менеджера", "начальник",
		"начальника", "руководитель", "руководителя", "заместитель",
		"бухгалтер", "специалист", "консультант", "оператор", "кассир",
		"инспектор", "юрист", "нотариус", "врач", "доктор", "профессор",
		"доцент", "инженер", "агент", "курьер", "водитель", "секретарь",
		"помощник", "ассистент", "администратор", "аналитик", "эксперт",
		"координатор", "куратор", "стажер", "управляющий", "председатель",
		// родство
		"брат", "сестра", "отец", "мать", "сын", "дочь", "муж", "жена",
		"дядя", "тетя", "дедушка", "бабушка", "внук", "внучка", "супруг",
		"супруга", "брата", "брату", "сестры", "сестре", "сестру", "отца",
		"отцу", "матери", "сына", "сыну", "дочери", "мужа", "мужу", "жены",
		"жене", "мама", "маме", "маму", "мамы", "папа", "папе", "папы",
		"друг", "друга", "другу", "подруга", "подруги", "подруге", "сосед",
		"соседа", "соседу", "соседка", "соседки", "супруге", "супругу",
		// обиходные существительные при маркере: «клиент банка Олег Петрович»
		"банка", wordBank, "карты", "карта", "счета", "счет", "отдела", "офиса",
		"отделения", "компании", "организации", "филиала", "договора",
		// дни недели
		"понедельник", "вторник", "среда", "среду", "четверг", "пятница",
		"пятницу", "суббота", "субботу", "воскресенье":
		return true
	}
	return false
}

// nameSurnamePos сообщает, что слово годится на место фамилии внутри уже
// опознанной конструкции.
//
// Проверяется окончание прилагательного — и только здесь, только по позиции.
// Самостоятельным признаком фамилии оно быть не может: после снятия
// требования заглавной буквы «-ный», «-ная», «-ной» носят тысячи обычных
// прилагательных, и T-20 отложила правку именно поэтому (QUALITY.md §7.3
// п. 7). Внутри конструкции цена ошибки другая — слово уже прижато к
// опознанным частям имени и стоит на месте, которое больше занять некому.
func nameSurnamePos(doc *lex.Doc, markers *dict.Table, i int) bool {
	if !nameEligible(doc, i) {
		return false
	}
	t := doc.Tokens[i]
	w := doc.NormOf(i)
	if nameNotNamePart(markers, w) {
		return false
	}
	runes := nameRunes(t)
	for _, e := range nameAdjSurnameEndings {
		if runes >= e.min && strings.HasSuffix(w, e.end) {
			return true
		}
	}
	return false
}

// nameGivenPos сообщает, что слово годится на место имени слева от опознанной
// пары «Отчество Фамилия».
//
// Здесь обязателен обратный контроль: расширение влево легко съедает соседнее
// служебное слово, и «Заявитель Матвеевна Гвоздарёва» не должен превратиться
// в спан целиком. Отсев держится на трёх независимых признаках, и каждого из
// них поодиночке хватило бы на «Заявителя»: слово-маркер из справочника,
// суффикс существительного-деятеля и согласование в роде с отчеством.
func nameGivenPos(doc *lex.Doc, markers *dict.Table, patronymic string, i int) bool {
	if !nameEligible(doc, i) {
		return false
	}
	t := doc.Tokens[i]
	if runes := nameRunes(t); runes < nameGivenPosMinLen || runes > nameGivenPosMaxLen {
		return false
	}
	w := doc.NormOf(i)
	if nameNotNamePart(markers, w) || nameRoleNoun(w) {
		return false
	}
	// Согласование в роде. Отчество называет род однозначно: «Матвеевна» —
	// женское, и слева от неё стоит женское имя, которое кончается гласной
	// или «-ой»/«-ей». Ролевые слова «Заявитель», «Сотрудник», «Гражданин»,
	// «Господин», «Абонент» — мужского рода и отсеиваются здесь морфологией,
	// не опираясь ни на какой справочник.
	if namePatronymicFemale(patronymic) {
		return nameFeminineForm(w)
	}
	return true
}

// nameNotNamePart сообщает, что слово частью ФИО не бывает.
func nameNotNamePart(markers *dict.Table, w string) bool {
	if markers.Has(w) {
		return true
	}
	for _, p := range nameFormOfAddress {
		if strings.HasPrefix(w, p) {
			return true
		}
	}
	return false
}

// nameFormOfAddress — обращения и роли, которые стоят слева от имени вплотную
// и потому первыми попадают в расширяемую конструкцию.
//
// Справочник name_markers их не покрывает: он собран, чтобы поднимать
// уверенность, и обращений «уважаемый», «дорогой» в нём нет — а «Уважаемый
// Иван Иванович» иначе замаскировался бы вместе с обращением. Сравнение по
// префиксу покрывает род, число и падеж одним правилом.
var nameFormOfAddress = [...]string{
	"уважаем", "глубокоуважаем", "многоуважаем", "дорог", "любезн",
	"абонент", "пациент", "представител", "покупател",
}

// nameRoleSuffixes — суффиксы существительных-деятелей. Личных имён с такими
// окончаниями в русском нет, а роли — «заявитель», «сотрудник», «абонент»,
// «директор» — стоят слева от имени постоянно.
var nameRoleSuffixes = [...]string{
	"тель", "ник", "щик", "чик", "ист", "тор", "ент", "ант", "арь", "лог",
}

// nameRoleCaseEndings — падежные окончания, которые снимаются перед проверкой
// суффикса деятеля: «заявителя», «сотрудником».
var nameRoleCaseEndings = [...]string{
	"а", "у", "е", "ы", "и", "я", "ю", "ом", "ем", "ей", "ой",
}

// nameRoleNoun сообщает, что слово называет роль, а не человека.
//
// Срез строки не аллоцирует, поэтому падежное окончание снимается прямо на
// месте, без сборки временного ключа.
func nameRoleNoun(w string) bool {
	if nameHasRoleSuffix(w) {
		return true
	}
	for _, e := range nameRoleCaseEndings {
		if strings.HasSuffix(w, e) && nameHasRoleSuffix(w[:len(w)-len(e)]) {
			return true
		}
	}
	return false
}

// nameHasRoleSuffix проверяет основу на суффикс деятеля.
func nameHasRoleSuffix(w string) bool {
	for _, s := range nameRoleSuffixes {
		if strings.HasSuffix(w, s) {
			return true
		}
	}
	return false
}

// namePatronymicFemale сообщает, что отчество женского рода.
//
// Мужские формы кончаются на «-ич» и его падежи и ни одной из перечисленных
// концовок не имеют, поэтому одного суффикса достаточно: перебирать таблицу
// отчеств заново не нужно.
func namePatronymicFemale(w string) bool {
	return strings.HasSuffix(w, "на") || strings.HasSuffix(w, "ны") ||
		strings.HasSuffix(w, "не") || strings.HasSuffix(w, "ну") ||
		strings.HasSuffix(w, "ной")
}

// nameFeminineForm сообщает, что слово имеет форму женского имени: кончается
// гласной («Аграфена», «Марии», «Ксению») или творительным «-ой»/«-ей»
// («Анной», «Марией»).
func nameFeminineForm(w string) bool {
	if strings.HasSuffix(w, "ой") || strings.HasSuffix(w, "ей") {
		return true
	}
	switch nameLastRune(w) {
	case 'а', 'я', 'ы', 'и', 'е', 'у', 'ю', 'о', 'э':
		return true
	}
	return false
}

// nameAdjSurnameEndings — окончания фамилий-прилагательных: «Бережной»,
// «Задворная», «Задворного», «Толстую».
//
// Таблица намеренно не входит в nameSurnameEndings и никогда не проверяется
// сама по себе: её единственный читатель — nameSurnamePos, то есть разбор уже
// опознанной конструкции. Минимальная длина здесь выше, чем у обычных
// суффиксов, и это тоже отсев: «новая», «такой», «самым» короче шести букв, а
// фамилии такой формы — длиннее.
var nameAdjSurnameEndings = [...]nameSuffix{
	{"ого", 7}, {wordHis, 7}, {"ому", 7}, {"ему", 7},
	{"ая", 6}, {"ую", 6}, {"ый", 6}, {"ий", 6}, {"ой", 6}, {"ым", 6}, {"им", 6},
}

// nameClassify определяет роли слова. Для непригодного токена возвращается
// пустой набор ролей.
func nameClassify(doc *lex.Doc, given, markers *dict.Table, i int) nameRole {
	if !nameEligible(doc, i) {
		return 0
	}
	t := doc.Tokens[i]
	w := doc.NormOf(i)
	runes := nameRunes(t)
	if runes == 1 {
		return nameRoleInitial
	}
	var role nameRole
	if _, ok := nameLookupGiven(given, w); ok {
		role |= nameRoleGiven
	}
	if namePatronymic(given, w, runes) {
		role |= nameRolePatronymic
	}
	if nameSurname(w, runes) {
		role |= nameRoleSurname
	}
	// Слово-маркер вводит имя, а не входит в него, поэтому частью ФИО быть
	// не может. Без этой проверки «Клиент гражданин Республики Казахстан»
	// давал кандидата на «гражданин»: слово оканчивается на «-ин», как
	// фамилия, а маркер «Клиент» слева поднимал его с Weak — и «гражданин»
	// уезжал под маску ФИО. Без маркера слева тот же текст разбирался верно,
	// то есть срабатывание было контекстным и одним словарём не ловилось.
	//
	// Обращение к справочнику стоит после разбора морфологии, а не до него:
	// так оно происходит только на словах, уже похожих на часть имени, — а
	// это доли процента токенов документа.
	if role != 0 && markers.Has(w) {
		return 0
	}
	return role
}

// nameEligible отсеивает токены, которые не могут быть частью ФИО.
//
// Регистр здесь не проверяется: ТЗ §3.2.1 требует, чтобы идентификация от
// него не зависела. Заглавная буква остаётся свидетельством, но учитывается
// не отбором токенов, а уровнем уверенности — см. nameLowerCase.
func nameEligible(doc *lex.Doc, i int) bool {
	t := doc.Tokens[i]
	return t.Kind == lex.KindWord && t.Flags.Has(lex.FlagCyrillic)
}

// nameNextPart возвращает следующее слово конструкции: соседний токен,
// пригодный как часть ФИО, написанный в том же регистре, что и начало
// конструкции head, и отделённый допустимым промежутком.
func nameNextPart(doc *lex.Doc, head, i int) (int, bool) {
	j := i + 1
	// «Лысенко;Ольга;Петровна» (T-83, P5-1).
	if j < len(doc.Tokens) && doc.Tokens[j].Kind == lex.KindPunct {
		j = nameCSVNext(doc, j)
	}
	if j >= len(doc.Tokens) || !nameJoinable(doc, i) || !nameEligible(doc, j) {
		return 0, false
	}
	if !nameSameCase(doc, head, j) {
		return 0, false
	}
	if nameRunes(doc.Tokens[j]) < 2 {
		return 0, false
	}
	return j, true
}

// nameRunes возвращает длину токена в буквах.
//
// Считается делением длины в байтах, а не разбором строки. Это не оценка, а
// тождество: токен сюда попадает только после nameEligible, который требует
// lex.FlagCyrillic, а флаг ставится, когда все буквы слова лежат в
// U+0400–U+052F — весь этот диапазон кодируется в UTF-8 ровно двумя байтами.
//
// Разбор здесь стоил дорого: длину одного и того же слова считали
// nameClassify, nameNextPart и цикл падежных окончаний, и на профиле
// utf8.RuneCountInString занимал заметную долю всей детекции.
//
// Предусловие обязательно: на токене без FlagCyrillic деление даст неверный
// ответ. У слова с латинскими буквами-двойниками («Мaзур», FlagFolded) NormOf
// отдаёт кириллическую форму, и каждая латинская буква в ней на байт длиннее,
// чем в тексте: поправку даёт Token.FoldExtra.
func nameRunes(t lex.Token) int { return (t.Len() + t.FoldExtra()) / 2 }

// nameJoinable проверяет промежуток между токенами i и i+1.
//
// Пустая строка (два перевода подряд) разрывает конструкцию: в форме за
// абзацем идёт уже другое поле, а не продолжение ФИО.
func nameJoinable(doc *lex.Doc, i int) bool {
	gap := doc.Gap(i)
	if len(gap) > nameMaxGap {
		return false
	}
	newlines := 0
	for k := 0; k < len(gap); k++ {
		if gap[k] == '\n' {
			newlines++
		}
	}
	return newlines < 2
}

// nameInitialAt проверяет, что токен i — инициал: одна заглавная кириллическая
// буква, к которой вплотную примыкает точка. Возвращается индекс точки.
func nameInitialAt(doc *lex.Doc, i int) (int, bool) {
	if !nameEligible(doc, i) {
		return 0, false
	}
	if utf8.RuneCountInString(doc.NormOf(i)) != 1 {
		return 0, false
	}
	d := i + 1
	if d >= len(doc.Tokens) || !doc.Adjacent(i) {
		return 0, false
	}
	dt := doc.Tokens[d]
	if dt.Kind != lex.KindPunct || doc.Text[dt.Start] != '.' {
		return 0, false
	}
	return d, true
}

// nameSurnameThenInitials разбирает «Иванов И. И.» и «Иванов И.».
// Точки инициалов входят в спан: без них конструкция не читается.
func nameSurnameThenInitials(doc *lex.Doc, i int) (int, bool) {
	j, ok := nameNextToken(doc, i)
	if !ok || !nameSameCase(doc, i, j) {
		return 0, false
	}
	dot, ok := nameInitialAt(doc, j)
	if !ok {
		return 0, false
	}
	if k, ok := nameNextToken(doc, dot); ok && nameSameCase(doc, i, k) {
		if second, ok := nameInitialAt(doc, k); ok {
			return second, true
		}
	}
	return dot, true
}

// nameInitialsThenSurname разбирает «И. И. Иванов» и «И. Иванов».
func nameInitialsThenSurname(doc *lex.Doc, given, markers *dict.Table, i int) (int, bool) {
	dot, ok := nameInitialAt(doc, i)
	if !ok {
		return 0, false
	}
	j, ok := nameNextToken(doc, dot)
	if !ok || !nameSameCase(doc, i, j) {
		return 0, false
	}
	if second, ok := nameInitialAt(doc, j); ok {
		k, ok := nameNextToken(doc, second)
		if ok && nameSameCase(doc, i, k) &&
			nameClassify(doc, given, markers, k)&nameRoleSurname != 0 {
			return k, true
		}
		return 0, false
	}
	if nameSameCase(doc, i, j) &&
		nameClassify(doc, given, markers, j)&nameRoleSurname != 0 {
		return j, true
	}
	return 0, false
}

// nameNextToken возвращает соседний токен, если промежуток до него допустим.
func nameNextToken(doc *lex.Doc, i int) (int, bool) {
	j := i + 1
	if j >= len(doc.Tokens) || !nameJoinable(doc, i) {
		return 0, false
	}
	return j, true
}

// nameMarkerLeft ищет слово-маркер слева от конструкции в окне до трёх
// значимых токенов. Знаки препинания окно не расходуют («ФИО: Иванов»),
// но граница предложения поиск прекращает.
func nameMarkerLeft(doc *lex.Doc, markers *dict.Table, i int) bool {
	seen := 0
	for k := i - 1; k >= 0 && seen < nameMarkerWindow; k-- {
		if doc.IsSentenceBreak(k) {
			return false
		}
		t := doc.Tokens[k]
		if t.Kind == lex.KindPunct {
			continue
		}
		seen++
		if markers.Has(doc.NormOf(k)) {
			return true
		}
	}
	return false
}

// nameCase — пара «окончание косвенного падежа → окончание именительного».
type nameCase struct {
	oblique    string
	nominative string
}

// nameCaseEndings восстанавливает именительный падеж имени.
//
// Падежные формы не хранятся в справочнике: полторы тысячи имён превратились
// бы в семь тысяч строк, которые невозможно вычитать глазами. Дешевле снять
// окончание и проверить восстановленную форму.
var nameCaseEndings = [...]nameCase{
	{"а", ""},   // Ивана → Иван
	{"у", ""},   // Ивану → Иван
	{"ом", ""},  // Иваном → Иван
	{"е", ""},   // Иване → Иван
	{"ы", "а"},  // Анны → Анна
	{"е", "а"},  // Анне → Анна
	{"у", "а"},  // Анну → Анна
	{"ой", "а"}, // Анной → Анна
	{"ей", "а"}, // Наташей → Наташа
	{"и", "я"},  // Марии → Мария
	// Ольги → Ольга, Маши → Маша: после г, к, х, ж, ш, ч, щ пишется «и», а
	// не «ы» (T-66). Только после этих букв: иначе каждое слово на «-и»
	// стоило бы лишнего обращения к справочнику.
	{"и", "а"},
	{"е", "я"},  // Софье → Софья
	{"ю", "я"},  // Марию → Мария
	{"ей", "я"}, // Марией → Мария
	{"я", "й"},  // Сергея → Сергей
	{"ю", "й"},  // Сергею → Сергей
	{"ем", "й"}, // Сергеем → Сергей
	{"е", "й"},  // Сергее → Сергей
	{"и", "й"},  // Юрии → Юрий
	{"я", "ь"},  // Игоря → Игорь
	{"ю", "ь"},  // Игорю → Игорь
	{"ем", "ь"}, // Игорем → Игорь
	{"и", "ь"},  // Любови → Любовь
	{"ью", "ь"}, // Любовью → Любовь
}

// fits сообщает, что окончание допустимо после последней буквы основы:
// «-и» вместо «-ы» пишется только после г, к, х, ж, ш, ч, щ.
func (c nameCase) fits(stem string) bool {
	if c.oblique != "и" || c.nominative != "а" {
		return true
	}
	switch nameLastRune(stem) {
	case 'г', 'к', 'х', 'ж', 'ш', 'ч', 'щ':
		return true
	}
	return false
}

// nameFleetingCases — окончания, после снятия которых основа могла потерять
// беглую гласную: «Павел» → «Павла».
var nameFleetingCases = [...]string{"а", "у", "ом", "е"}

const nameFleetingVowel = "е"

// nameSoftSign — мягкий знак, на месте которого выпадает беглая гласная.
const nameSoftSign = "ь"

// nameLookupGiven ищет имя в справочнике, принимая косвенные падежи.
//
// Восстановленный ключ собирается в буфере на стеке и не покидает функцию,
// поэтому обращение к справочнику не аллоцирует.
func nameLookupGiven(t *dict.Table, w string) (string, bool) {
	if label, ok := t.Get(w); ok {
		return label, true
	}
	if label, ok := nameLookupCase(t, w); ok {
		return label, true
	}
	return nameLookupFleeting(t, w)
}

// nameLookupCase ищет имя, восстанавливая именительный падеж по таблице
// nameCaseEndings: «Ивана» → «Иван», «Анны» → «Анна».
func nameLookupCase(t *dict.Table, w string) (string, bool) {
	var buf [nameKeyMax]byte
	for _, c := range nameCaseEndings {
		if !strings.HasSuffix(w, c.oblique) {
			continue
		}
		stem := w[:len(w)-len(c.oblique)]
		n := len(stem) + len(c.nominative)
		if n > len(buf) || utf8.RuneCountInString(stem) < nameGivenMinStem || !c.fits(stem) {
			continue
		}
		copy(buf[:], stem)
		copy(buf[len(stem):], c.nominative)
		if label, ok := t.Get(string(buf[:n])); ok {
			return label, true
		}
	}
	return "", false
}

// nameLookupFleeting ищет имя, возвращая беглую гласную, выпавшую при
// склонении: «Павла» → «Павел», «Льва» → «Лев».
func nameLookupFleeting(t *dict.Table, w string) (string, bool) {
	var buf [nameKeyMax]byte
	for _, end := range nameFleetingCases {
		if !strings.HasSuffix(w, end) {
			continue
		}
		stem := w[:len(w)-len(end)]
		_, tail := utf8.DecodeLastRuneInString(stem)
		n := len(stem) + len(nameFleetingVowel)
		if n > len(buf) || tail == 0 ||
			utf8.RuneCountInString(stem) < nameFleetingMinStem {
			continue
		}
		cut := len(stem) - tail
		copy(buf[:], stem[:cut])
		copy(buf[cut:], nameFleetingVowel)
		copy(buf[cut+len(nameFleetingVowel):], stem[cut:])
		if label, ok := t.Get(string(buf[:n])); ok {
			return label, true
		}
		// Беглая гласная на месте мягкого знака: «Льва», «Львом» → «Лев».
		// Мягкий знак и «е» занимают в UTF-8 по два байта, поэтому ключ той
		// же длины, что основа, собирается заменой на месте.
		if soft := cut - len(nameSoftSign); soft >= 0 && stem[soft:cut] == nameSoftSign {
			copy(buf[:], stem)
			copy(buf[soft:], nameFleetingVowel)
			if label, ok := t.Get(string(buf[:len(stem)])); ok {
				return label, true
			}
		}
	}
	return "", false
}

// nameSuffix — окончание и минимальная длина слова в буквах, при которой
// окончание считается значимым. Короткая основа делает суффикс случайным.
type nameSuffix struct {
	end string
	min int
}

// namePatronymicEndings — окончания отчеств вместе с падежными формами.
// Порядок важен: длинные окончания проверяются раньше коротких, иначе
// «Ивановича» разбирается как основа «иванов» плюс «ича».
var namePatronymicEndings = [...]nameSuffix{
	{"овичем", 9}, {"евичем", 9},
	{"овича", 8}, {"овичу", 8}, {"овиче", 8},
	{"евича", 8}, {"евичу", 8}, {"евиче", 8},
	{"ович", 7}, {"евич", 7},
	{"овной", 8}, {"евной", 8}, {"ичной", 8},
	{"овна", 7}, {"овны", 7}, {"овне", 7}, {"овну", 7},
	{"евна", 7}, {"евны", 7}, {"евне", 7}, {"евну", 7},
	{"ична", 7}, {"ичны", 7}, {"ичне", 7}, {"ичну", 7},
}

// nameShortPatronymicEndings — окончания на «-ич» без опознавательного
// «-ов-»/«-ев-». Одного такого окончания мало: его носят и обычные слова,
// поэтому основа дополнительно сверяется со справочником имён.
var nameShortPatronymicEndings = [...]nameSuffix{
	{"ичем", 7}, {"ича", 6}, {"ичу", 6}, {"иче", 6}, {"ич", 5},
}

// namePatronymicStemTails — окончания, которыми основа отчества достраивается
// до имени: «Ильич» → «Илья», «Никитич» → «Никита», «Игоревич» → «Игорь».
var namePatronymicStemTails = [...]string{"", "а", "я", "й", "ь"}

// nameLastRune — последняя буква слова. Отсев по ней снимает большинство слов
// до перебора таблицы суффиксов.
//
// С тех пор как сканер перестал требовать заглавную букву, таблицы
// перебираются на каждом кириллическом слове документа, а не на каждом слове
// с заглавной буквы. Слов в русском тексте на порядок больше, и цена перебора
// из незаметной стала главной статьёй расхода сканера.
func nameLastRune(w string) rune {
	r, _ := utf8.DecodeLastRuneInString(w)
	return r
}

// nameSurnameTails и namePatronymicTails — последние буквы всех суффиксов
// соответствующих таблиц. Полнота наборов сторожится тестом: пропущенная
// буква молча обрезала бы полноту детекции.
func nameSurnameTail(r rune) bool {
	switch r {
	case 'а', 'в', 'е', 'и', 'й', 'к', 'м', 'н', 'о', 'у', 'х', 'ы', 'ю', 'я':
		return true
	}
	return false
}

func namePatronymicTail(r rune) bool {
	switch r {
	case 'а', 'е', 'й', 'м', 'у', 'ч', 'ы':
		return true
	}
	return false
}

// namePatronymic проверяет морфологию отчества.
func namePatronymic(given *dict.Table, w string, runes int) bool {
	if !namePatronymicTail(nameLastRune(w)) {
		return false
	}
	for _, s := range namePatronymicEndings {
		if runes >= s.min && strings.HasSuffix(w, s.end) {
			return true
		}
	}
	for _, s := range nameShortPatronymicEndings {
		if runes < s.min || !strings.HasSuffix(w, s.end) {
			continue
		}
		return nameStemIsGiven(given, w[:len(w)-len(s.end)])
	}
	return false
}

// nameStemIsGiven проверяет, что основа сводится к имени из справочника.
func nameStemIsGiven(t *dict.Table, stem string) bool {
	if utf8.RuneCountInString(stem) < namePatronymicMinStem {
		return false
	}
	var buf [nameKeyMax]byte
	for _, tail := range namePatronymicStemTails {
		n := len(stem) + len(tail)
		if n > len(buf) {
			continue
		}
		copy(buf[:], stem)
		copy(buf[len(stem):], tail)
		if _, ok := t.Get(string(buf[:n])); ok {
			return true
		}
	}
	return false
}

// nameSurnameEndings — суффиксы фамилий вместе с падежными формами.
//
// Это не список фамилий, а список окончаний: «Иванов», «Иванова», «Иванову»,
// «Ивановым», «Иванове» — одна фамилия в пяти формах и ни одной записи в
// справочнике.
var nameSurnameEndings = [...]nameSuffix{
	// -ский / -цкий / -ской / -цкой
	{"ского", 7}, {"скому", 7}, {"цкого", 7}, {"цкому", 7},
	{"ский", 6}, {"ская", 6}, {"ской", 6}, {"скую", 6}, {"ским", 6}, {"ском", 6},
	{"цкий", 6}, {"цкая", 6}, {"цкой", 6}, {"цкую", 6}, {"цким", 6}, {"цком", 6},
	// -швили / -дзе; -зода / -заде (T-80): «Рахимзода», «Кулизаде»
	{"швили", 7}, {"дзе", 6}, {"зода", 7}, {"заде", 7},
	// -енко / -ко
	{"енко", 7}, {"ко", 5},
	// -ук / -юк
	{"уком", 7}, {"юком", 7},
	{"ука", 6}, {"уку", 6}, {"уке", 6}, {"юка", 6}, {"юку", 6}, {"юке", 6},
	{"ук", 5}, {"юк", 5},
	// -ян
	{"яном", 7}, {"яна", 6}, {"яну", 6}, {"яне", 6}, {"ян", 5},
	// -их / -ых
	{"их", 5}, {"ых", 5},
	// -ов / -ев / -ёв / -ин / -ын. «ё» сведена к «е» нормализацией лексера.
	{"овым", 6}, {"евым", 6}, {"иным", 6}, {"ыным", 6},
	{"овой", 6}, {"евой", 6}, {"иной", 6}, {"ыной", 6},
	{"ова", 5}, {"ову", 5}, {"ове", 5}, {"овы", 5},
	{"ева", 5}, {"еву", 5}, {"еве", 5}, {"евы", 5},
	{"ина", 5}, {"ину", 5}, {"ине", 5}, {"ины", 5},
	{"ына", 5}, {"ыну", 5}, {"ыне", 5}, {"ыны", 5},
	{"ов", 4}, {"ев", 4}, {"ин", 4}, {"ын", 4},
}

// nameSurname проверяет морфологию фамилии.
func nameSurname(w string, runes int) bool {
	if runes < nameSurnameMinLen || !nameSurnameTail(nameLastRune(w)) {
		return false
	}
	for _, s := range nameSurnameEndings {
		if runes >= s.min && strings.HasSuffix(w, s.end) {
			return true
		}
	}
	return false
}

// --- Раунд 3 технического жюри (T-60) ---------------------------------------
//
// Три класса утечек, которые жюри пишет с высокой вероятностью:
//
//  1. строчная пара «фамилия имя» после слова, вводящего лицо: «Звонила
//     петрова анна», «Передайте смирновой ольге», «анна смирнова просит
//     выписку»;
//  2. фамилия из опознанного ФИО, повторённая отдельно: «…Шевчук просит
//     перезвонить»;
//  3. фамилия без суффикса рядом с именем: «Звонил Ким Олег», «Передайте
//     Мельнику Олегу», «звонил цой артём».
//
// Все правила ниже — позиционные и морфологические, без списков фамилий:
// слово-ввод или сказуемое вплотную к паре, согласование в падеже, повтор
// фамилии, уже опознанной в этом же тексте.

// nameGivenGiven сообщает, что слова i и i+1 — два имени из справочника
// подряд, ни одно из которых не отчество: «Ким Олег», «Ли Анна», «Анна
// Мария». Перевод строки между ними пару рвёт: в форме это два поля.
func nameGivenGiven(doc *lex.Doc, i int, role, second nameRole) bool {
	return role&nameRoleGiven != 0 && second&nameRoleGiven != 0 &&
		role&nameRolePatronymic == 0 && second&nameRolePatronymic == 0 &&
		!lex.HasLineBreak(doc.Gap(i))
}

// nameCapsSurnameLower разбирает «ПЕТРОВА анна сергеевна» и «ПЕТРОВА анна»:
// фамилия капсом, за ней имя из справочника и, возможно, отчество строчными.
// Обычный разбор требует одного регистра у всех слов конструкции и резал
// такое ФИО на два спана.
func nameCapsSurnameLower(doc *lex.Doc, tb *nameTables, i int) (int, Confidence, string, bool) {
	t := doc.Tokens[i]
	if !t.Flags.Has(lex.FlagAllUpper) || nameRunes(t) < nameSurnameMinLen {
		return 0, 0, "", false
	}
	j, ok := nameLowerNext(doc, i)
	if !ok || nameClassify(doc, tb.given, tb.markers, j)&nameRoleGiven == 0 {
		return 0, 0, "", false
	}
	if k, ok := nameLowerNext(doc, j); ok &&
		nameClassify(doc, tb.given, tb.markers, k)&nameRolePatronymic != 0 {
		return k, Certain, nameRuleFIOCapsSurname, true
	}
	return j, Strong, nameRuleSurGivenCapsSurn, true
}

// nameInitialAhead — дешёвая проверка перед разбором инициалов: за словом i
// стоит короткое слово с заглавной буквы и вплотную к нему — знак. Точную
// проверку делает nameInitialAt; здесь отсеиваются обычные слова, чтобы не
// считать буквы у каждого имени в тексте. Кириллическая буква — два байта,
// запас — на невидимые символы внутри токена.
func nameInitialAhead(doc *lex.Doc, i int) bool {
	j := i + 1
	if j+1 >= len(doc.Tokens) {
		return false
	}
	t := doc.Tokens[j]
	return t.Kind == lex.KindWord && t.Len() <= 4 && t.Flags.Has(lex.FlagFirstUpper) &&
		doc.Tokens[j+1].Kind == lex.KindPunct && doc.Adjacent(j)
}

// nameLowerNext возвращает соседнее справа слово, написанное строчными, если
// промежуток до него не содержит перевода строки.
func nameLowerNext(doc *lex.Doc, i int) (int, bool) {
	j := i + 1
	if j >= len(doc.Tokens) || !nameJoinable(doc, i) || lex.HasLineBreak(doc.Gap(i)) ||
		!nameEligible(doc, j) || doc.Tokens[j].Flags.Has(lex.FlagFirstUpper) ||
		nameRunes(doc.Tokens[j]) < 2 {
		return 0, false
	}
	return j, true
}

// namePrevWord возвращает ближайшее слово слева от токена i в том же
// предложении. Знаки препинания внутри предложения пропускаются: «ФИО: цой
// артём», «Здравствуйте, анна петрова».
func namePrevWord(doc *lex.Doc, i int) (int, bool) {
	for k := i - 1; k >= 0; k-- {
		if doc.IsSentenceBreak(k) {
			return 0, false
		}
		switch doc.Tokens[k].Kind {
		case lex.KindPunct:
			continue
		case lex.KindWord:
			return k, true
		}
		return 0, false
	}
	return 0, false
}

// nameIntroduced сообщает, что конструкцию [first, last] вводит слово лица:
// слева — глагол или предлог, за которым в деловом тексте стоит человек
// («звонила», «передайте», «для», «от»), справа — сказуемое, подлежащим
// которого бывает только человек («просит», «подтвердил»).
func nameIntroduced(doc *lex.Doc, first, last int) bool {
	return nameIntroLeft(doc, first) || namePredicateAfter(doc, last)
}

// nameIntroLeft ищет слово-ввод слева от конструкции. Окно — одно слово,
// плюс одно служебное между ними: «Позвоните, пожалуйста, анне смирновой»,
// «Звонила сегодня петрова анна». Шире окно не делается: чем дальше слово,
// тем меньше оно говорит о соседе.
func nameIntroLeft(doc *lex.Doc, first int) bool {
	k, ok := namePrevWord(doc, first)
	if !ok {
		return false
	}
	w := doc.NormOf(k)
	if nameIntroWord(w) {
		return true
	}
	if !nameFillerWord(w) {
		return false
	}
	k, ok = namePrevWord(doc, k)
	return ok && nameIntroWord(doc.NormOf(k))
}

// namePredicateAfter сообщает, что сразу за токеном last в том же
// предложении стоит сказуемое лица.
func namePredicateAfter(doc *lex.Doc, last int) bool {
	j := last + 1
	if j >= len(doc.Tokens) || doc.IsSentenceBreak(last) || !nameJoinable(doc, last) {
		return false
	}
	// «полина гринь не получила код»: частица «не» сказуемого не меняет
	// (T-80).
	if j+1 < len(doc.Tokens) && doc.Tokens[j].Kind == lex.KindWord && doc.NormOf(j) == "не" && nameJoinable(doc, j) {
		j++
	}
	return doc.Tokens[j].Kind == lex.KindWord && namePredicateWord(doc.NormOf(j))
}

// nameBareAnchored сообщает, что слово k держит опора вплотную слева: маркер
// лица («клиентка гусь анна») или слово-ввод («звонил цой артём»).
func nameBareAnchored(doc *lex.Doc, tb *nameTables, k int) bool {
	p, ok := namePrevWord(doc, k)
	if !ok {
		return false
	}
	w := doc.NormOf(p)
	return tb.markers.Has(w) || nameIntroWord(w) || nameLabelAnchored(doc, tb, k)
}

// nameBareFramed сообщает, что одиночное слово i без суффикса фамилии стоит в
// рамке «маркер лица — слово с заглавной — сказуемое лица»: «Клиент Мельник
// просит перезвонить», «Заявитель Коваль подал заявку». Каждая из трёх опор
// сама по себе слаба; вместе они не оставляют слову другой роли, кроме
// подлежащего-человека. Нужна заглавная буква не в начале предложения и не
// капсом — свидетельство регистра nameBareSurname.
func nameBareFramed(doc *lex.Doc, tb *nameTables, i int) bool {
	p, ok := namePrevWord(doc, i)
	if !ok || !tb.markers.Has(doc.NormOf(p)) || !namePredicateAfter(doc, i) {
		return false
	}
	ok, evidence := nameBareSurname(doc, tb, i, -1, true)
	// «Сотрудник Росгвардии пришёл»: организация на месте фамилии (T-66).
	return ok && evidence && !nameOrgStem(doc.NormOf(i))
}

// nameIntroWord — слова, за которыми в деловом тексте стоит человек:
// глаголы звонка, передачи, уведомления и получения, самопредставление,
// предлоги лица. Справочник name_markers для них не годится: его читает и
// контр-правило публичной персоны (counter.go), и «для»/«от» в роли маркера
// клиента отключили бы вето в «Для справки: поэт Александр Пушкин».
//
// Одного слова-ввода мало, чтобы сделать человеком одиночное слово: оно
// поднимает только пару из двух опознанных частей имени. Сравнение через
// switch компилируется в поиск без аллокаций.
func nameIntroWord(w string) bool {
	switch w {
	// звонок
	case "звонил", "звонила", "звонили", "звонит", "позвонил", "позвонила",
		"позвонили", "перезвонил", "перезвонила", "позвоните", "перезвоните",
		"позвонить", "перезвонить", "звоните", "наберите",
		// передача и перевод
		"передайте", "передать", "передай", "передал", "передала", "переведите",
		"перевести", "перевел", "перевела", "отправьте", "отправить", "отправил",
		"отправила", "выдайте", "выдать", "выдал", "выдала", "вручить", "вручите",
		// уведомление
		"уведомить", "уведомите", "уведомили", "сообщите", "сообщить",
		"напомните", "напомнить", "известите", "известить", "ответьте",
		"ответить", "напишите", "написать",
		// получение
		"получит", "получил", "получила", "получили", "получат", "получает",
		// обращение и самопредставление
		"пишет", "писал", "писала", "написал", "написала", "обратился",
		"обратилась", "обращается", "пришел", "пришла", "приходил", "приходила",
		"просил", "просила", "просит", "спрашивал", "спрашивала",
		"интересовался", "интересовалась", "жаловался", "жаловалась",
		"представился", "представилась", nameWordHello, "приветствую", nameWordHi,
		// предлоги лица
		"от", wordFor, "у", "к", "ко", "с", "со", "о", "об", wordAbout, "на":
		return true
	}
	return false
}

// nameIntroCommon сообщает, что в строчной паре есть обиходное слово с
// суффиксом фамилии: «для славы других», «от веры своих», «для анны только».
// Окончание «-их/-ых» носят и фамилии («Черных», «Седых»), но в строчной
// записи после предлога его куда чаще носит местоимение или прилагательное
// во множественном числе, поэтому подъём словом-вводом здесь не действует —
// маркер лица («клиент черных анна») по-прежнему поднимает.
func nameIntroCommon(doc *lex.Doc, first, last int) bool {
	for k := first; k <= last; k++ {
		if doc.Tokens[k].Kind != lex.KindWord {
			continue
		}
		w := doc.NormOf(k)
		if strings.HasSuffix(w, "их") || strings.HasSuffix(w, "ых") || w == "только" {
			return true
		}
	}
	return false
}

// nameFillerWord — служебные слова, которые встают между словом-вводом и
// именем, не разрывая связи: «Позвоните, пожалуйста, анне смирновой».
func nameFillerWord(w string) bool {
	switch w {
	case "пожалуйста", wordToday, "вчера", "завтра", "срочно", "снова", "опять",
		"еще", "также", "тоже", "лично", "повторно", "уже":
		return true
	}
	return false
}

// namePredicateWord — сказуемые, подлежащим которых в банковском тексте
// бывает только человек: «анна смирнова просит выписку», «иванов иван
// подтвердил перевод».
func namePredicateWord(w string) bool {
	switch w {
	case "просит", "просил", "просила", "просят", "просили",
		"звонил", "звонила", "звонит", "позвонил", "позвонила", "перезвонил",
		"перезвонила", "обратился", "обратилась", "обращается", "хочет", "хотел",
		"хотела", "подал", "подала", "подает", "подписал", "подписала",
		"жалуется", "жаловался", "жаловалась", "сообщил", "сообщила", "сообщает",
		"сказал", "сказала", "говорит", "заявил", "заявила", "заявляет",
		"оформил", "оформила", "оформляет", "получил", "получила", "получает",
		"открыл", "открыла", "закрыл", "закрыла", "перевел", "перевела",
		"переводит", "подтвердил", "подтвердила", "подтверждает", "пришел",
		"пришла", "написал", "написала", "пишет", "согласен", "согласна",
		"отказался", "отказалась", "интересуется", "спрашивает", "ждет",
		"ожидает", "оплатил", "оплатила", "снял", "сняла", "потерял", "потеряла",
		"утерял", "утеряла", "родился", "родилась", "проживает", "живет",
		"работает", "является", "уточнил", "уточнила", "уточняет":
		return true
	}
	return false
}

// nameBareCaseAgrees сообщает, что фамилия без суффикса и одиночное имя
// стоят в одном косвенном падеже: «Мельнику Олегу», «Коваля Игоря», «Олегом
// Мельником».
//
// Согласование — самостоятельный признак конструкции: соседнее слово с
// заглавной буквы в середине предложения само по себе — ещё не фамилия
// («Клиент Мельник Олег» решает маркер), но слово, которое склоняется вместе
// с именем, стоит с ним в одной именной группе. Именительный падеж
// согласования не показывает, поэтому имя обязано стоять в косвенном.
// Правило действует только со свидетельством регистра — Title-пара из
// nameExtendLeft/nameExtendRight.
func nameBareCaseAgrees(doc *lex.Doc, tb *nameTables, first, last int, rule string) bool {
	var bare, given int
	switch {
	case last != first+1:
		return false
	case rule == nameRuleBareGiven:
		bare, given = first, last
	case rule == nameRuleGivenBare:
		given, bare = first, last
	default:
		return false
	}
	end, ok := nameGivenOblique(tb.given, doc.NormOf(given))
	if !ok {
		return false
	}
	group := nameCaseGroup(end)
	if group < 0 {
		return false
	}
	b := doc.NormOf(bare)
	// Женская фамилия без суффикса на согласную не склоняется: «для Кац
	// Ольги», «Мельник Анне» (T-66). Род берётся из справочника имён.
	if label, _ := nameLookupGiven(tb.given, doc.NormOf(given)); label == "f" && nameConsonantEnd(b) {
		return true
	}
	for _, e := range nameCaseGroups[group] {
		if strings.HasSuffix(b, e) && utf8.RuneCountInString(b)-utf8.RuneCountInString(e) >= nameStemMinLen {
			return true
		}
	}
	return false
}

// nameConsonantEnd сообщает, что слово кончается согласной, «ь» или «й»:
// так кончается несклоняемая женская фамилия без суффикса («Кац», «Мельник»,
// «Коваль»).
func nameConsonantEnd(w string) bool {
	switch nameLastRune(w) {
	case 'а', 'е', 'и', 'о', 'у', 'ы', 'э', 'ю', 'я':
		return false
	}
	return true
}

// nameCaseGroups — окончания одного падежа у имени и у фамилии без суффикса.
// Мягкая и твёрдая основа дают разные буквы одного падежа: «Олега» и
// «Коваля», «Олегу» и «Ковалю».
var nameCaseGroups = [...][2]string{
	{"а", "я"},   // родительный мужского рода: Олега, Игоря, Мельника, Коваля
	{"у", "ю"},   // дательный мужского: Олегу, Игорю, Мельнику, Ковалю
	{"ом", "ем"}, // творительный мужского: Олегом, Игорем, Мельником, Ковалем
	{"е", "е"},   // предложный; дательный женского: Олеге, Анне, Сороке
	{"ы", "и"},   // родительный женского: Анны, Марии, Сороки
	{"ой", "ей"}, // творительный женского: Анной, Марией, Сорокой
}

// nameCaseGroup возвращает номер группы для окончания косвенного падежа или
// -1, если окончание ни в одну группу не входит.
func nameCaseGroup(end string) int {
	for g, list := range nameCaseGroups {
		if end == list[0] || end == list[1] {
			return g
		}
	}
	return -1
}

// nameGivenOblique возвращает окончание косвенного падежа, которое снимается
// с имени до формы из справочника: «Олегу» → «у», «Анне» → «е». Имя в
// именительном падеже («Олег») и слово вне справочника дают false.
func nameGivenOblique(t *dict.Table, w string) (string, bool) {
	if t.Has(w) {
		return "", false
	}
	var buf [nameKeyMax]byte
	for _, c := range nameCaseEndings {
		if !strings.HasSuffix(w, c.oblique) {
			continue
		}
		stem := w[:len(w)-len(c.oblique)]
		n := len(stem) + len(c.nominative)
		if n > len(buf) || utf8.RuneCountInString(stem) < nameGivenMinStem || !c.fits(stem) {
			continue
		}
		copy(buf[:], stem)
		copy(buf[len(stem):], c.nominative)
		if t.Has(string(buf[:n])) {
			return c.oblique, true
		}
	}
	return "", false
}

// nameSeen — фамилии из ФИО, уже выданных в этом тексте. Повтор такой
// фамилии отдельным словом — тот же человек: «Клиент Шевчук Андрей
// Петрович, паспорт … Шевчук просит перезвонить». До T-60 повтор уходил в
// модель открытым — 5000 раз из 5000 в тексте жюри.
//
// Хранится основа фамилии без падежного окончания: «Шевчука», «Ивановой»
// и «Мельнику» совпадают с «Шевчук», «Иванов» и «Мельник». Буфер
// фиксированный и лежит на стеке Scan, поэтому запоминание не аллоцирует;
// разбор остаётся однопроходным — повтор узнаётся только после полного ФИО.
type nameSeen struct {
	keys [nameSeenMax]nameSeenKey
	n    int // заполнено записей
	next int // куда писать следующую: кольцо вытесняет самую старую
}

type nameSeenKey struct {
	b [nameKeyMax]byte
	n uint8
}

// remember запоминает фамилию конструкции [first, last], собранной правилом
// rule до подъёмов. Какое слово — фамилия, решает правило: у «Имя Отчество»
// и одиночного имени фамилии нет вовсе.
func (s *nameSeen) remember(doc *lex.Doc, tb *nameTables, first, last int, rule string) {
	k := nameSurnameAt(rule, first, last)
	if k < 0 {
		return
	}
	w := doc.NormOf(k)
	// Одиночное слово запоминается, только если это не имя из справочника:
	// «Клиент Марина» — имя, а не фамилия, хоть и с суффиксом «-ина».
	if first == last {
		if _, ok := nameLookupGiven(tb.given, w); ok {
			return
		}
	}
	stem := nameSurnameStem(w)
	if len(stem) > nameKeyMax || s.has(stem) {
		return
	}
	key := &s.keys[s.next]
	copy(key.b[:], stem)
	key.n = uint8(len(stem))
	s.next = (s.next + 1) % nameSeenMax
	if s.n < nameSeenMax {
		s.n++
	}
}

// has сообщает, что основа уже запомнена. Сравнение string(b[:n]) == stem
// компилятор выполняет без копирования.
func (s *nameSeen) has(stem string) bool {
	for i := 0; i < s.n; i++ {
		key := &s.keys[i]
		if int(key.n) == len(stem) && string(key.b[:key.n]) == stem {
			return true
		}
	}
	return false
}

// repeatAt сообщает, что слово i — повтор запомненной фамилии.
//
// Слово с заглавной принимается в любом случае; строчное — только с суффиксом
// фамилии («иванов»): строчные «мороз», «жук», «гусь» в обычном тексте —
// нарицательные, даже если в этом же тексте был клиент Мороз. Маркер и
// обращение фамилией не бывают.
func (s *nameSeen) repeatAt(doc *lex.Doc, tb *nameTables, i int) bool {
	if !nameEligible(doc, i) {
		return false
	}
	t := doc.Tokens[i]
	runes := nameRunes(t)
	if runes < nameBareMinLen || runes > nameBareMaxLen {
		return false
	}
	w := doc.NormOf(i)
	// Дешёвый отсев до разбора окончания: основа — префикс слова, и если ни
	// одна запомненная основа префиксом не служит, повтора нет. Так
	// проверяется почти каждое слово с заглавной буквы в тексте, где уже
	// нашлось ФИО.
	if !s.prefixOf(w) {
		return false
	}
	if !t.Flags.Has(lex.FlagFirstUpper) && !nameSurname(w, runes) {
		return false
	}
	if nameNotNamePart(tb.markers, w) {
		return false
	}
	return s.has(nameSurnameStem(w))
}

// prefixOf сообщает, что какая-то запомненная основа — префикс слова w не
// короче его самого за вычетом самого длинного окончания.
func (s *nameSeen) prefixOf(w string) bool {
	for i := 0; i < s.n; i++ {
		key := &s.keys[i]
		n := int(key.n)
		if n <= len(w) && len(w)-n <= nameStemEndMaxBytes && w[:n] == string(key.b[:n]) {
			return true
		}
	}
	return false
}

// inConstruction сообщает, что в слабой конструкции [first, last] есть повтор
// запомненной фамилии: «Мельник Олег» после «Клиент Мельник Олег Петрович».
func (s *nameSeen) inConstruction(doc *lex.Doc, tb *nameTables, first, last int) bool {
	for k := first; k <= last; k++ {
		if doc.Tokens[k].Kind == lex.KindWord && s.repeatAt(doc, tb, k) {
			return true
		}
	}
	return false
}

// nameSurnameAt возвращает индекс фамилии в конструкции по правилу, которое
// её собрало, или -1, если фамилии в конструкции нет.
func nameSurnameAt(rule string, first, last int) int {
	switch rule {
	case nameRuleFIO, nameRuleFIOPos, nameRuleFIOBare, nameRuleSurnameGiven,
		nameRuleSurnameInitials, nameRuleSurPosInit, nameRuleSurBareInit,
		nameRuleSurPosGiven, nameRuleBareGiven, nameRuleGivenGiven,
		nameRuleGivenGivenPatronymic, nameRuleFIOCapsSurname,
		nameRuleSurGivenCapsSurn, nameRuleSurname,
		// T-66
		nameRuleBareLead, nameRuleBareLeadStart, nameRuleField, nameRuleSlot,
		nameRuleSignature, nameRuleSurBareInit1, nameRuleSurBareInitLowerMarker,
		nameRuleFIOAdj, nameRuleAdjGiven, nameRuleFIOPatrSurname, nameRuleBareGivenGiven,
		// T-80
		nameRuleFamily, nameRuleSubject, nameRuleAdjGivenPredicate, nameRuleSurnameGivenPos:
		return first
	case nameRuleIFO, nameRuleIFOPosSur, nameRuleIFOBare, nameRuleIFOPosGiven,
		nameRuleGivenSurname, nameRulePatronymicSur, nameRuleInitialsSurname,
		nameRuleInitialsBare, nameRuleGivenSurPos, nameRuleGivenBare,
		// T-66
		nameRuleGivenBareTitle, nameRuleInit1Bare, nameRuleGivenAdj,
		// T-80
		nameRuleGivenPosSurname:
		return last
	}
	return -1
}

// nameStemEndings — падежные окончания, которые снимаются с фамилии перед
// сравнением: длинные раньше коротких. «ь» и «й» снимаются тоже: «Коваль» и
// «Коваля» сводятся к «ковал», «Цой» и «Цоя» — к «цо».
var nameStemEndings = [...]string{
	"ого", wordHis, "ому", "ему", "ыми", "ими",
	"ой", "ей", "ый", "ий", "ая", "яя", "ую", "юю", "ым", "им", "ом", "ем",
	"а", "я", "у", "ю", "е", "ы", "и", "ь", "й",
}

// nameStemEndMaxBytes — длина самого длинного окончания nameStemEndings в
// байтах: три кириллические буквы.
const nameStemEndMaxBytes = 6

// nameSurnameStem возвращает основу фамилии — срез исходной строки, без
// аллокаций.
func nameSurnameStem(w string) string {
	for _, e := range nameStemEndings {
		if !strings.HasSuffix(w, e) {
			continue
		}
		stem := w[:len(w)-len(e)]
		if utf8.RuneCountInString(stem) >= nameStemMinLen {
			return stem
		}
	}
	return w
}

// --- Раунд 4 жюри (T-66) ----------------------------------------------------
//
// Семь классов утечек, и каждый — класс, а не фраза:
//
//  1. фамилия без суффикса вплотную перед именем без маркера: «Коваль Инна
//     обратилась в отделение» (nameBareLeads, в nameExtendLeft/Right);
//  2. значение поля анкеты: «Фамилия: Волк», «Девичья фамилия матери —
//     Черныш», «сменил фамилию с Корнеевой на Шаповалову» (nameFieldSlot);
//  3. одиночная фамилия в позиции лица и в подписи: «Ваш клиент, Кох.»,
//     «Перевод от Мельник, 5 000 руб.», «С уважением,⏎Шварц» (nameSlot,
//     nameSignature);
//  4. фамилия без суффикса с одним инициалом и строчная фамилия с
//     инициалами при маркере: «Клиент Мельник О.», «клиент шаповалова д.н.»;
//  5. двойная фамилия через дефис — один спан (nameScan.hyphenJoin);
//  6. нерусские имена — справочник given_names;
//  7. фамилия-прилагательное перед «Имя Отчество» и перед именем при маркере
//     или обращении: «Клиент Белый Андрей Сергеевич», «Спасибо, Тихий Роман».
//
// Всё — позиционные и морфологические правила; списков фамилий нет. Списки
// здесь только отрицательные: слова, которые на месте фамилии стоят, но
// фамилией не бывают.

const (
	// nameFieldReach — сколько токенов слева от значения просматривается в
	// поисках маркера поля: «Девичья фамилия матери — Корнеева», «сменил
	// фамилию с Корнеевой на Шаповалову». Предел держит проход линейным.
	nameFieldReach = 8

	// nameFieldQualMax — сколько уточняющих слов допускается между маркером
	// поля и значением: «Фамилия при рождении —», «Подпись клиента:».
	nameFieldQualMax = 3

	// nameAdjMinLen — минимальная длина фамилии-прилагательного перед «Имя
	// Отчество» и перед именем при маркере: «Злой», «Белый», «Лысого».
	nameAdjMinLen = 4
)

// nameFieldKind — поле анкеты, которое вводит маркер.
type nameFieldKind uint8

const (
	nameFieldNone nameFieldKind = iota
	nameFieldSurname
	nameFieldGiven
	nameFieldPatronymic
	nameFieldFIO
	nameFieldSign
	// nameFieldChange — значение в обороте смены фамилии: «фамилию с
	// Корнеевой на Шаповалову», «была Коваленко, стала Шульга». Предлог и
	// глагол — слабее разделителя поля, поэтому значение нужно с заглавной:
	// «укажите фамилию на русском» значения не содержит.
	nameFieldChange
)

// nameFieldWord возвращает поле, которое называет слово. Слова поля
// записаны и в name_markers — там они поднимают опознанного кандидата
// (фамилию с суффиксом, отчество); здесь они принимают значением и слово,
// которое само ничем не опознаётся: «Фамилия: Волк».
func nameFieldWord(w string) nameFieldKind {
	switch w {
	case "фамилия", "фамилии", "фамилию", "фамилией":
		return nameFieldSurname
	case "имя", wordNamed:
		return nameFieldGiven
	case "отчество", "отчества", "отчеству", "отчеством":
		return nameFieldPatronymic
	case "фио":
		return nameFieldFIO
	case "подпись", "подписи", "подписью":
		return nameFieldSign
	}
	return nameFieldNone
}

// nameFieldEllipsis — прилагательные, которые называют поле фамилии без
// самого слова: «Фамилия — Иванова, девичья — Коваль». Действуют только
// перед разделителем: «прежняя Анна» полем не является.
func nameFieldEllipsis(w string) bool {
	switch w {
	case "девичья", "девичьей", "прежняя", "прежней", "бывшая", "бывшей", "новая", "новой",
		// T-80: «Прежняя фамилия — Литвин, текущая — Голуб»
		"текущая", "текущей", "нынешняя", "нынешней", "настоящая", "настоящей", "действующая",
		"актуальная":
		return true
	}
	return false
}

// nameFieldQualifier — уточняющие слова между маркером поля и значением:
// «Фамилия клиента —», «Девичья фамилия матери:», «Фамилия при рождении —»,
// «Фамилия до брака:», «Фамилия по паспорту:». Маркеры лица («клиента»,
// «заявителя») читаются из name_markers.
func nameFieldQualifier(markers *dict.Table, w string) bool {
	if markers.Has(w) {
		return true
	}
	switch w {
	case "матери", "отца", "мужа", "жены", "супруга", "супруги", "родителя",
		"ребенка", "при", "рождении", "до", "брака", "замужества", "после",
		"в", "браке", "по", "паспорту", "полностью", "девичья", "прежняя",
		"бывшая", "новая", "моя", wordHis, "ее":
		return true
	}
	return false
}

// nameFieldPunct сообщает, какой знак стоит между маркером поля и значением:
// sep — разделитель поля («:», тире, дефис), ok — знак вообще допустим
// (кавычки, скобка, косая черта подписи «/Шаповалова/»).
func nameFieldPunct(doc *lex.Doc, k int) (sep, ok bool) {
	t := doc.Tokens[k]
	r, _ := utf8.DecodeRuneInString(doc.Text[t.Start:t.End])
	switch r {
	case ':', '-', '—', '–', '=', '→':
		return true, true
	case '/', '«', '"', '„', '“', '(', '\'':
		return false, true
	}
	return false, false
}

// nameFIOAbbrevEnd сообщает, что токены, кончающиеся на k, — сокращение
// «Ф.И.О.»: три однобуквенных слова с точками. k — индекс последней точки
// или буквы «О».
func nameFIOAbbrevEnd(doc *lex.Doc, k int) bool {
	if k >= 0 && doc.Tokens[k].Kind == lex.KindPunct {
		k--
	}
	// Буквы Ф, И, О через точку, справа налево.
	for n, want := 0, "оиф"; n < 3; n++ {
		if k < 0 || doc.Tokens[k].Kind != lex.KindWord {
			return false
		}
		r, size := utf8.DecodeRuneInString(want)
		want = want[size:]
		w := doc.NormOf(k)
		if got, n := utf8.DecodeRuneInString(w); n != len(w) || got != r {
			return false
		}
		if n == 2 {
			return true
		}
		k--
		if k < 0 || doc.Tokens[k].Kind != lex.KindPunct || doc.Text[doc.Tokens[k].Start] != '.' {
			return false
		}
		k--
	}
	return false
}

// nameLineStart сообщает, что токен k начинает строку.
func nameLineStart(doc *lex.Doc, k int) bool {
	return k == 0 || lex.HasLineBreak(doc.Gap(k-1))
}

// nameHyphenAt сообщает, что токен h — дефис внутри составного слова:
// вплотную к словам с обеих сторон, «Иванова-Петренко».
func nameHyphenAt(doc *lex.Doc, h int) bool {
	if h <= 0 || h+1 >= len(doc.Tokens) {
		return false
	}
	t := doc.Tokens[h]
	return t.Kind == lex.KindPunct && doc.Text[t.Start] == '-' && t.Len() == 1 &&
		doc.Adjacent(h-1) && doc.Adjacent(h) &&
		doc.Tokens[h-1].Kind == lex.KindWord && doc.Tokens[h+1].Kind == lex.KindWord
}

// nameHyphenPartOK сообщает, что слово p годится частью двойной фамилии
// рядом со словом anchor той же конструкции: тот же регистр, не маркер, не
// банк, не город, не месяц и не стоп-слово — «Альфа-Банк», «Санкт-Петербург»
// частью ФИО не становятся.
func nameHyphenPartOK(doc *lex.Doc, tb *nameTables, p, anchor int) bool {
	if !nameEligible(doc, p) || !nameSameCase(doc, anchor, p) || nameRunes(doc.Tokens[p]) < nameBareMinLen {
		return false
	}
	w := doc.NormOf(p)
	return !nameNotNamePart(tb.markers, w) && !tb.months.Has(w) && !tb.cities.Has(w) &&
		!strings.Contains(w, wordBank) && !nameBareStopWord(w) && !tb.stop.Has(w)
}

// nameHyphenBadTail сообщает, что за словом j через дефис стоит слово,
// которое частью фамилии быть не может: «Альфа-Банк».
func nameHyphenBadTail(doc *lex.Doc, tb *nameTables, j int) bool {
	return nameHyphenAt(doc, j+1) && !nameHyphenPartOK(doc, tb, j+2, j)
}

// nameLast — последний кандидат, выданный сканером: по нему двойная
// фамилия склеивается с частью, выданной раньше отдельным спаном
// («Соколова» — слабая одиночная фамилия, «Цой Елена» — пара справа).
type nameLast struct {
	idx         int // индекс в out.Spans; -1 — нет
	first, last int // токены
}

// nameAdjStop — основы прилагательных, которые стоят перед именем как
// оценка или обращение, а не как фамилия: «Новая Анна Петровна», «Милая
// Анна Петровна», «Главный Иван Петрович». Сравнение по началу слова
// покрывает род, число и падеж.
var nameAdjStop = [...]string{
	"нов", "стар", "мил", "добр", "любим", "родн", "бедн", "молод", "перв",
	"втор", "трет", "последн", "следующ", "данн", "указанн", "вышеуказанн",
	"нижеподписавш", "главн", "старш", "младш", "ведущ", "генеральн",
	"исполнительн", "ответственн", "уполномоченн", "доверенн", "законн",
	"официальн", "настоящ", "бывш", "прежн", "будущ", "нынешн", "текущ",
	"личн", "частн", "заслуженн", "народн", "почетн", "прекрасн",
	"замечательн", "сердечн", "искренн", "драгоценн", "свят", "покойн",
	"умерш", "усопш", "красив", "очаровательн", "прелестн", "несравненн",
	"великолепн", "уважаем", "дорог", "любезн", "многоуважаем", "глубокоуважаем",
	"наш", "ваш", "сам", "как", "так", "эт", "вс", "кажд", "люб", "друг", "ин",
	"нужн", "важн", "дежурн", "технич", "финансов", "коммерческ",
}

// nameAdjStopped сообщает, что прилагательное — оценка или обращение.
func nameAdjStopped(w string) bool {
	for _, s := range nameAdjStop {
		if strings.HasPrefix(w, s) {
			return true
		}
	}
	return false
}

// nameAdjPatr — согласование фамилии-прилагательного с отчеством: окончание
// отчества в падеже и роде и окончания прилагательного в том же падеже.
// Длинные окончания отчества — раньше коротких.
var nameAdjPatr = [...]struct {
	patr string
	adj  [3]string
}{
	{"ичем", [3]string{"ым", "им", ""}},    // творительный мужского: Белым Андреем Сергеевичем
	{"ича", [3]string{"ого", wordHis, ""}}, // родительный и винительный: Лысого Виктора Петровича
	{"ичу", [3]string{"ому", "ему", ""}},   // дательный: Малому Ивану Андреевичу
	{"иче", [3]string{"ом", "ем", ""}},     // предложный: о Белом Андрее Сергеевиче
	{"ич", [3]string{"ый", "ий", "ой"}},    // именительный: Белый, Тихий, Глухой
	{"ной", [3]string{"ой", "ей", ""}},     // творительный женского: Белой Анной Петровной
	{"на", [3]string{"ая", "яя", ""}},      // именительный: Рыжая Светлана Олеговна
	{"ны", [3]string{"ой", "ей", ""}},      // родительный: Лысой Анны Викторовны
	{"не", [3]string{"ой", "ей", ""}},      // дательный и предложный
	{"ну", [3]string{"ую", "юю", ""}},      // винительный
}

// nameAdjAgrees проверяет, что прилагательное w согласовано в роде и падеже
// с отчеством patr.
func nameAdjAgrees(w, patr string) bool {
	for _, a := range nameAdjPatr {
		if !strings.HasSuffix(patr, a.patr) {
			continue
		}
		for _, e := range a.adj {
			if e != "" && strings.HasSuffix(w, e) {
				return true
			}
		}
		return false
	}
	return false
}

// nameAdjBeforePair сообщает, что слово k — фамилия-прилагательное перед
// парой «Имя Отчество» с отчеством в позиции patr (раунд 4 жюри, Б4-10):
// «Клиент Белый Андрей Витальевич», «Звонила Рыжая Светлана Олеговна», «от
// Лысого Виктора Петровича».
//
// nameSurnamePos принимает такие слова только с шести-семи букв — этот
// предел защищает одиночное имя от «новая», «такой», «самым». Перед парой
// «Имя Отчество» слово держат два признака, которых у одиночного имени нет:
// согласование в роде и падеже с отчеством и свободное место фамилии в
// конструкции. Оценка и обращение («Новая», «Милая», «Главный») снимаются
// списком основ nameAdjStop.
func nameAdjBeforePair(doc *lex.Doc, tb *nameTables, k, patr int) bool {
	if !nameEligible(doc, k) || nameRunes(doc.Tokens[k]) < nameAdjMinLen {
		return false
	}
	w := doc.NormOf(k)
	if !nameBareAdjEnding(w) || nameNotNamePart(tb.markers, w) || nameBareStopWord(w) ||
		tb.stop.Has(w) || tb.roles.Has(w) || nameAdjStopped(w) {
		return false
	}
	if k > 0 && nameToponymPrep(doc, k-1) {
		return false
	}
	return nameAdjAgrees(w, doc.NormOf(patr))
}

// nameAdjWithGiven сообщает, что короткая фамилия-прилагательное k с
// заглавной в середине предложения стоит вплотную к имени first в
// именительном падеже и согласована с ним в роде: «Клиентка Белая Ольга»,
// «Спасибо, Тихий Роман», «Клиент Андрей Белый». Конструкция держится на
// одном опознанном слове, поэтому остаётся Weak: поднимают её маркер лица
// или обращение (nameAddressLeft).
func nameAdjWithGiven(doc *lex.Doc, tb *nameTables, k, first int) bool {
	t := doc.Tokens[k]
	if !nameTitle(t) || k == 0 || doc.IsSentenceBreak(k-1) || nameRunes(t) < nameAdjMinLen {
		return false
	}
	w := doc.NormOf(k)
	if nameNotNamePart(tb.markers, w) || nameLeadStop(tb, w) || nameAdjStopped(w) {
		return false
	}
	label, ok := tb.given.Get(doc.NormOf(first))
	return ok && nameAdjGenderFits(w, label)
}

// nameAddressWord — обращение и самопредставление, после которых пара слов
// с заглавной — человек: «Спасибо, Тихий Роман», «Здравствуйте, я Малая
// Ирина», «Добрый день, Рыжая Светлана».
func nameAddressWord(w string) bool {
	switch w {
	case nameWordThanks, "благодарю", "благодарим", nameWordHello, "здравствуй",
		nameWordHi, "приветствую", "я", wordThis, "день", "вечер", "утро":
		return true
	}
	return false
}

// nameAddressLeft сообщает, что слева от конструкции стоит обращение.
func nameAddressLeft(doc *lex.Doc, first int) bool {
	p, ok := namePrevWord(doc, first)
	return ok && nameAddressWord(doc.NormOf(p))
}

// namePersonPrep — предлоги из nameIntroWord. Одиночную фамилию из них
// вводит только «от» (nameSlot): «к Сбербанку», «на Газпром», «про
// Москву» — не люди.
func namePersonPrep(w string) bool {
	switch w {
	case "от", wordFor, "у", "к", "ко", "с", "со", "о", "об", wordAbout, "на":
		return true
	}
	return false
}

// nameRightBoundary сообщает, что слово i кончает именную группу: за ним
// конец текста или строки, знак препинания, строчное слово или число, но не
// ещё одно слово с заглавной и не дефис («Газпром Нефть», «Альфа-Банк»).
func nameRightBoundary(doc *lex.Doc, i int) bool {
	j := i + 1
	if j >= len(doc.Tokens) || lex.HasLineBreak(doc.Gap(i)) {
		return true
	}
	t := doc.Tokens[j]
	switch t.Kind {
	case lex.KindPunct:
		return !nameHyphenAt(doc, j)
	case lex.KindWord:
		return !t.Flags.Has(lex.FlagFirstUpper)
	}
	return true
}

// nameSlot сообщает, что одиночное слово i с заглавной буквы в середине
// предложения стоит в позиции лица (раунд 4 жюри, Б4-5): слева маркер лица,
// глагол-ввод или «от», справа — граница именной группы. «Ваш клиент,
// Кох.», «Звонила Волк, просила…», «Пишет Бондарь: …», «Перевод от
// Мельник, 5 000 руб.», «Заявление принято от Иванова».
//
// surname — у слова есть морфология фамилии: тогда граница справа не
// нужна, суффикс сам говорит, что это фамилия. Имя из справочника так не
// поднимается: «Звонила Анна» — одиночное имя, а не ФИО.
func nameSlot(doc *lex.Doc, tb *nameTables, i int, surname bool) bool {
	t := doc.Tokens[i]
	if !nameTitle(t) || i == 0 || doc.IsSentenceBreak(i-1) || nameQuoted(doc, i) {
		return false
	}
	// Опора слева — первой: её проходят единицы слов текста.
	p, ok := namePrevWord(doc, i)
	if !ok {
		return false
	}
	pw := doc.NormOf(p)
	switch {
	case pw == "от":
	case tb.markers.Has(pw):
		// Поля анкеты разбирает nameFieldSlot, «имени» — ещё и оборот «от
		// имени Правления».
		if nameFieldWord(pw) != nameFieldNone {
			return false
		}
	case nameIntroWord(pw) && !namePersonPrep(pw):
	case nameIntroducedAs(doc, p):
		// «он представился как Цой, …» (T-80).
	default:
		return false
	}
	if !surname && !nameRightBoundary(doc, i) {
		return false
	}
	w := doc.NormOf(i)
	if _, ok := nameLookupGiven(tb.given, w); ok {
		return false
	}
	if nameNotNamePart(tb.markers, w) || nameLeadStop(tb, w) || strings.Contains(w, wordBank) {
		return false
	}
	if surname {
		// «Он получил Нобелевскую премию»: прилагательное при
		// существительном, а не фамилия (T-83, P5-7).
		return !nameAdjModifiesNext(doc, tb, i)
	}
	// «от Москвы до Твери»: город в косвенном падеже восстанавливается тем
	// же разбором окончаний, что и имя.
	_, city := nameLookupGiven(tb.cities, w)
	return !city && !tb.months.Has(w) && nameRunes(t) >= nameBareBlindMinLen &&
		!nameBareVerbLike(w) && !nameFirstPersonVerb(w) && !nameOrgStem(w) &&
		(nameRunes(t) < nameBareAdjMinLen || !nameBareAdjEnding(w))
}

// nameOrgStems — начала названий организаций, которые стоят на месте лица
// после «от» и маркера: «письмо от Ростелекома», «Сотрудник Росгвардии»,
// «Перевод от Тинькофф». Читаются только для одиночного слова без суффикса
// фамилии: «от Ростова» с суффиксом разбирает морфология.
var nameOrgStems = [...]string{
	"рос", "мос", "гос", "газпром", "сбер", "тинькофф", "яндекс", "мегафон",
	"билайн", "альфа", "райффайзен", "уралсиб", "совком", "почт", "аэрофлот",
	"лукойл", "минфин", "минздрав", "минтруд", "минцифр", "минэконом", "озон",
	"вайлдберриз", "авито",
}

// nameOrgStem сообщает, что слово начинается названием организации.
func nameOrgStem(w string) bool {
	for _, s := range nameOrgStems {
		if strings.HasPrefix(w, s) {
			return true
		}
	}
	return false
}

// nameFirstPersonVerb сообщает, что слово похоже на глагол первого лица:
// «Подтверждаю», «Согласую», «Прошу». В nameBareVerbEndings этих окончаний
// нет — их носят и фамилии-прилагательные в винительном падеже, — поэтому
// отсев читается только для одиночного слова в подписи и в позиции лица.
func nameFirstPersonVerb(w string) bool {
	return strings.HasSuffix(w, "аю") || strings.HasSuffix(w, "яю") || strings.HasSuffix(w, "ую") ||
		strings.HasSuffix(w, "шу") || strings.HasSuffix(w, "жу") || strings.HasSuffix(w, "чу")
}

// nameSignOff — слова прощания, после которых в письме стоит подпись.
func nameSignOff(w string) bool {
	switch w {
	case "уважением", "пожеланиями", "доброго", "хорошего", nameWordThanks,
		"благодарностью", "благодарю", "признательностью":
		return true
	}
	return false
}

// nameSignature сообщает, что слово i — подпись письма (раунд 4 жюри):
// стоит после «С уважением,» — на той же строке или на следующей — или
// составляет последнюю строку многострочного текста: «Прошу закрыть
// счёт.⏎Черныш». Слово принимается с заглавной, в том числе капсом, если
// оно не стоп-слово, не организация, не город и не имя из справочника.
func nameSignature(doc *lex.Doc, tb *nameTables, i int, surname bool) bool {
	t := doc.Tokens[i]
	if !t.Flags.Has(lex.FlagFirstUpper) || !nameSignaturePlace(doc, i) || !nameRightBoundary(doc, i) {
		return false
	}
	w := doc.NormOf(i)
	if _, ok := nameLookupGiven(tb.given, w); ok {
		return false
	}
	return !nameNotNamePart(tb.markers, w) && !nameLeadStop(tb, w) && !strings.Contains(w, wordBank) &&
		!tb.cities.Has(w) && !tb.months.Has(w) && nameRunes(t) >= nameBareMinLen &&
		(surname || !nameBareVerbLike(w) && !nameFirstPersonVerb(w) &&
			(nameRunes(t) < nameBareAdjMinLen || !nameBareAdjEnding(w)))
}

// nameSignaturePlace сообщает, что слово i стоит на месте подписи: после
// прощания с запятой или последней строкой текста. Проверка дешёвая и идёт
// раньше отсевов слова: её проходят единицы слов текста.
func nameSignaturePlace(doc *lex.Doc, i int) bool {
	// «С уважением,⏎Шварц»: запятая и перевод строки между прощанием и
	// подписью допустимы.
	k := i - 1
	for ; k >= 0 && doc.Tokens[k].Kind == lex.KindPunct; k-- {
		if doc.Text[doc.Tokens[k].Start] != ',' {
			break
		}
	}
	if k >= 0 && k < i-1 && doc.Tokens[k].Kind == lex.KindWord && nameSignOff(doc.NormOf(k)) {
		return true
	}
	// Последняя строка многострочного текста из одного слова, и предыдущая
	// строка кончается концом предложения: «Прошу закрыть счёт.⏎Черныш».
	// Строка после двоеточия — значение поля («Статус:⏎Одобрено»), а не
	// подпись.
	if i < 2 || !lex.HasLineBreak(doc.Gap(i-1)) {
		return false
	}
	if p := doc.Tokens[i-1]; p.Kind != lex.KindPunct {
		return false
	} else if c := doc.Text[p.Start]; c != '.' && c != '!' && c != '?' {
		return false
	}
	for j := i + 1; j < len(doc.Tokens); j++ {
		if doc.Tokens[j].Kind != lex.KindPunct || doc.Text[doc.Tokens[j].Start] != '.' {
			return false
		}
	}
	return true
}

// nameDocNoun — основы слов, после которых заглавная буква с точкой —
// обозначение, а не инициал: «Корпус Б.», «Приложение А.», «Раздел В.»,
// «План Б.». Читаются только в правиле фамилии с одним инициалом.
var nameDocNoun = [...]string{
	"приложени", "раздел", "пункт", "подпункт", "корпус", "литер", "строени",
	"блок", "форм", "схем", "таблиц", "рисун", "глав", "част", "стать", "том",
	"сери", "класс", "групп", "категори", "тип", "вариант", "этап", "уровн",
	"уровен", "зон", "сектор", "ряд", "секци", "подъезд", "этаж", "лини",
	"код", "лист", "образ", "модел", "верси", "пример", "позици", "параграф",
	"абзац", "шкал", "сорт", "объект", "участ", "квартал", "микрорайон",
	"кабинет", "зал", "аудитори", "терминал", "выход", "вход", "план",
	"сценари", "витамин", "мест", "отдел", "корп", "стр", "литера", "вагон",
	"платформ", "путь", "пути", "трибун", "дом", "здани", "павильон", "склад",
}

// nameDocNounWord сообщает, что слово — обозначение из nameDocNoun.
func nameDocNounWord(w string) bool {
	for _, s := range nameDocNoun {
		if strings.HasPrefix(w, s) {
			return true
		}
	}
	return false
}

// nameBareThenInitial разбирает «Мельник О.»: фамилия без суффикса с одним
// инициалом (раунд 4 жюри, Б4-5). dot — точка инициала.
//
// Один инициал за словом с заглавной носят и обозначения — «Корпус Б.»,
// «Приложение А.», — поэтому кроме отсевов nameBareSurname действует список
// обозначений nameDocNoun, а за точкой не должно стоять слово с заглавной
// («Автор А. Пушкин» — инициал относится к «Пушкину»). Strong — при
// свидетельстве регистра, маркере или слове-вводе слева, сказуемом справа
// или в конце строки; иначе Weak, и решает кластер.
func nameBareThenInitial(doc *lex.Doc, tb *nameTables, i, dot int) (Confidence, bool) {
	if dot != i+2 || !doc.Tokens[i].Flags.Has(lex.FlagFirstUpper) {
		return 0, false
	}
	if k, ok := nameNextToken(doc, dot); ok && !lex.HasLineBreak(doc.Gap(dot)) {
		if t := doc.Tokens[k]; t.Kind == lex.KindWord && t.Flags.Has(lex.FlagFirstUpper) {
			return 0, false
		}
	}
	ok, evidence := nameBareSurname(doc, tb, i, -1, true)
	if !ok {
		return 0, false
	}
	w := doc.NormOf(i)
	if nameDocNounWord(w) || nameLeadStop(tb, w) {
		return 0, false
	}
	if evidence || nameSignatureEnd(doc, dot) || nameMarkerLeft(doc, tb.markers, i) ||
		nameIntroLeft(doc, i) || namePredicateAfter(doc, dot) {
		return Strong, true
	}
	return Weak, true
}

// nameInitialBefore сообщает, что перед токеном i стоит инициал с точкой:
// тогда i — третья буква сокращения «Ф.И.О.», а не начало инициалов.
func nameInitialBefore(doc *lex.Doc, i int) bool {
	if i < 2 || !doc.Adjacent(i-2) {
		return false
	}
	p := doc.Tokens[i-1]
	return p.Kind == lex.KindPunct && doc.Text[p.Start] == '.' &&
		doc.Tokens[i-2].Kind == lex.KindWord && nameRunes(doc.Tokens[i-2]) == 1
}

// nameInitialThenBare разбирает «О. Мельник»: один заглавный инициал и
// фамилия без суффикса. Одной буквы с точкой мало, поэтому нужна опора:
// маркер или слово-ввод слева, сказуемое справа.
func nameInitialThenBare(doc *lex.Doc, tb *nameTables, i int) (int, bool) {
	dot, ok := nameInitialAt(doc, i)
	if !ok || !doc.Tokens[i].Flags.Has(lex.FlagFirstUpper) || nameInitialBefore(doc, i) {
		return 0, false
	}
	k, ok := nameNextToken(doc, dot)
	if !ok || lex.HasLineBreak(doc.Gap(dot)) || !nameEligible(doc, k) {
		return 0, false
	}
	t := doc.Tokens[k]
	if !nameTitle(t) || nameClassify(doc, tb.given, tb.markers, k) != 0 {
		return 0, false
	}
	if n := nameRunes(t); n < nameBareBlindMinLen || n > nameBareMaxLen {
		return 0, false
	}
	w := doc.NormOf(k)
	if nameNotNamePart(tb.markers, w) || tb.months.Has(w) || tb.cities.Has(w) ||
		nameLeadStop(tb, w) || nameDocNounWord(w) || strings.Contains(w, wordBank) ||
		(nameRunes(t) >= nameBareAdjMinLen && nameBareAdjEnding(w)) {
		return 0, false
	}
	if nameMarkerLeft(doc, tb.markers, i) || nameIntroLeft(doc, i) || namePredicateAfter(doc, k) {
		return k, true
	}
	return 0, false
}

// nameBareThenInitialsLower разбирает «клиент черныш д.с.»: строчная
// фамилия без суффикса с двумя инициалами. Строчные инициалы
// свидетельством не служат («документы т. е. копии»), поэтому нужна опора
// вплотную слева — маркер лица или слово-ввод.
func nameBareThenInitialsLower(doc *lex.Doc, tb *nameTables, i, last int) bool {
	if last != i+4 || doc.Tokens[i].Flags.Has(lex.FlagFirstUpper) {
		return false
	}
	ok, _ := nameBareSurname(doc, tb, i, -1, true)
	return ok && nameBareAnchored(doc, tb, i) && !nameDocNounWord(doc.NormOf(i))
}
