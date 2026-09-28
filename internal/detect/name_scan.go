package detect

import (
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// nameScan — состояние одного прохода Scan по документу. Живёт на стеке
// Scan и передаётся методам указателем: структура не покидает стек, и
// разбор по фазам не стоит ни одной аллокации.
type nameScan struct {
	doc *lex.Doc
	out *Candidates
	tb  nameTables

	bank nameBankMemo
	// seen — фамилии из уже выданных ФИО этого текста (T-60): их повтор
	// отдельным словом — тот же человек. Буфер фиксированный, на стеке.
	seen nameSeen

	// prev — последний выданный кандидат: к нему приклеивается вторая часть
	// двойной фамилии через дефис (T-66).
	prev nameLast

	// floor — первый токен, ещё не покрытый выданным спаном. Разбор идёт
	// слева направо, но конструкция умеет достраиваться влево, и без этой
	// границы расширение залезло бы в предыдущий спан и выдало два
	// пересекающихся кандидата на одно и то же слово.
	floor int

	// pending — повтор фамилии, выдача которого отложена: за ним вплотную
	// начинается конструкция, и она может достроиться влево на это слово
	// («…Мельник Полина Романовна»). Выдать повтор сразу значило бы разрезать
	// одно ФИО на два спана — и два плейсхолдера для одного человека.
	pending     int
	pendingRule string

	// familyHi — последний токен предложения, в котором найдена общая
	// фамилия семьи («Супруги Мазур: Олег и Алла»); -1 — не найдена.
	familyHi int
}

// nameCons — конструкция, которую Scan собирает на текущей позиции: границы
// в токенах, уверенность, имя правила и признаки, от которых зависят подъёмы.
type nameCons struct {
	first, last int
	conf        Confidence
	rule        string
	// base — правило конструкции до подъёмов: по нему seen находит, какое
	// слово конструкции — фамилия. Подъёмы подменяют имя правила.
	base string
	// single — конструкция из одного слова до склейки через дефис: её
	// поднимают правила позиции (nameSingleLift).
	single bool
	// marker — маркер лица слева от слабой конструкции.
	marker bool
}

// Scan регистрирует кандидатов на ФИО.
//
// Разбор идёт слева направо; на каждой позиции подбирается самая длинная
// конструкция, и после находки разбор продолжается за её концом — конструкция
// покрывается одним спаном, как того требует контракт.
func (nameScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *Candidates) {
	s := nameScan{
		doc: doc,
		out: out,
		tb: nameTables{
			given:      dicts.Table(nameDictGiven),
			markers:    dicts.Table(nameDictMarkers),
			months:     dicts.Table(nameDictMonths),
			cities:     dicts.Table(nameDictCities),
			banking:    dicts.Table(counterDictBanking),
			roles:      dicts.Table(counterDictRoles),
			stop:       dicts.Table(nameDictStop),
			countries:  dicts.Table(nameDictCountries),
			groups:     dicts.Table(nameDictGroups),
			places:     dicts.Table(nameDictPlaces),
			requisites: dicts.Table(nameDictRequisites),
		},
		prev:     nameLast{idx: -1},
		pending:  -1,
		familyHi: -1,
	}
	for i := 0; i < len(doc.Tokens); {
		if !nameEligible(doc, i) {
			i++
			continue
		}
		last, conf, rule := nameMatch(doc, &s.tb, i)
		if last < 0 {
			i = s.unmatched(i)
			continue
		}
		i = s.construction(i, last, conf, rule)
	}
	if s.pending >= 0 {
		nameAddSingle(doc, out, &s.prev, s.pending, s.pendingRule)
	}
}

// unmatched решает судьбу слова i, которое nameMatch не опознал, и
// возвращает позицию, с которой разбор продолжается.
func (s *nameScan) unmatched(i int) int {
	doc := s.doc
	// Вторая часть двойной фамилии, которая сама ничем не опознана:
	// «Фамилия: Грум-Гржимайло», «Клиент Петрова-Цой просит…». Если за ней
	// начинается конструкция («Орлова-Шмидт Мария»), склейку делает она сама,
	// достроившись влево (nameScan.hyphenJoin).
	if s.hyphenTail(i) {
		s.out.Spans[s.prev.idx].End = doc.Tokens[i].End
		s.prev.last = i
		s.floor = i + 1
		return i + 1
	}
	// Одиночное слово, которое не опознано само, но стоит на месте фамилии:
	// повтор фамилии из уже опознанного ФИО, значение поля анкеты, рамка
	// «маркер — слово — сказуемое», позиция лица, подпись (nameSingleRule).
	r := nameSingleRule(doc, &s.tb, &s.seen, i)
	if r == "" {
		return i + 1
	}
	s.noteFamily(r, i)
	if nameStartsAfter(doc, &s.tb, i) {
		// Слово может оказаться фамилией конструкции справа («…Мельник
		// Полина Романовна», «Фамилия, имя: Волк Игорь»): его судьба
		// решается вместе с ней.
		s.pending, s.pendingRule = i, r
		return i + 1
	}
	nameAddSingle(doc, s.out, &s.prev, i, r)
	s.seen.remember(doc, &s.tb, i, i, nameRuleSurname)
	s.floor = i + 1
	return i + 1
}

// hyphenTail сообщает, что слово i — вторая часть двойной фамилии, первую
// часть которой только что выдал последний кандидат.
func (s *nameScan) hyphenTail(i int) bool {
	doc := s.doc
	return nameHyphenAt(doc, i-1) && s.prev.idx >= 0 && s.prev.idx == len(s.out.Spans)-1 &&
		s.prev.last == i-2 && nameHyphenPartOK(doc, &s.tb, i, i-2) && !nameStartsAfter(doc, &s.tb, i)
}

// construction достраивает, поднимает и выдаёт конструкцию, которую
// nameMatch опознал с позиции i, и возвращает позицию за её концом.
func (s *nameScan) construction(i, last int, conf Confidence, rule string) int {
	c := nameCons{first: i, last: last, conf: conf, rule: rule}
	s.extend(&c)
	s.flushPending(c.first)
	c.single = c.first == c.last && c.first == i
	c.base = c.rule
	s.hyphenJoin(&c)
	s.extendSyllables(&c)
	c.last = nameTurkicTail(s.doc, c.last)
	// Маркер слева поднимает одиночного кандидата: «Иванов» может быть
	// чем угодно, «клиент Иванов» — уже человек. Сам маркер в спан не
	// входит, спан держится точно по значению.
	c.marker = c.conf == Weak && nameMarkerLeft(s.doc, s.tb.markers, c.first)
	if nameHasUpper(s.doc, c.first, c.last) {
		s.liftUpper(&c)
	} else if !s.liftLower(&c) {
		return c.last + 1
	}
	s.emit(&c)
	return c.last + 1
}

// extend достраивает конструкцию одним словом слева, а если слева не
// вышло — справа.
func (s *nameScan) extend(c *nameCons) {
	if k, conf, rule, ok := nameExtendLeft(s.doc, &s.tb, c.first, c.rule, s.floor); ok {
		c.first, c.conf, c.rule = k, conf, rule
		return
	}
	if l, conf, rule, ok := nameExtendRight(s.doc, &s.tb, c.first, c.last, c.rule); ok {
		c.last, c.conf, c.rule = l, conf, rule
	}
}

// flushPending выдаёт отложенное слово, если конструкция с первым токеном
// first его не взяла.
func (s *nameScan) flushPending(first int) {
	if s.pending < 0 {
		return
	}
	if s.pending < first {
		nameAddSingle(s.doc, s.out, &s.prev, s.pending, s.pendingRule)
		s.seen.remember(s.doc, &s.tb, s.pending, s.pending, nameRuleSurname)
	}
	s.pending = -1
}

// hyphenJoin достраивает конструкцию [first, last] частями двойной
// фамилии через дефис (раунд 4 жюри, Б4-4): «Иванова-Петренко Олега
// Николаевича», «Соколова-Цой Елена», «Олег Николаевич Иванов-Петренко».
//
// Лексер режет слово по дефису, и до T-66 первая часть уходила в модель
// открытой («Иванова-[ФИО_1]»), а где обе части находились — одна фамилия
// получала две метки («[ФИО_1]-[ФИО_2]»), и модель видела двух людей.
//
// Влево часть присоединяется всегда, когда она годится частью фамилии; если
// её уже выдал отдельный кандидат, он снимается и сливается с конструкцией —
// уверенность берётся большая из двух. Вправо — только у конструкции из
// нескольких слов, которая кончается фамилией: одиночная фамилия справа от
// дефиса начинает пару («Смирнова-Ким Ольга») и достраивается влево.
func (s *nameScan) hyphenJoin(c *nameCons) {
	for c.first >= 2 && nameHyphenAt(s.doc, c.first-1) {
		if !s.hyphenLeft(c) {
			break
		}
	}
	if c.last > c.first && nameSurnameAt(c.base, c.first, c.last) == c.last {
		for nameHyphenAt(s.doc, c.last+1) && nameHyphenPartOK(s.doc, &s.tb, c.last+2, c.last) {
			c.last += 2
		}
	}
}

// hyphenLeft присоединяет к конструкции часть двойной фамилии слева от
// дефиса перед c.first и возвращает false, если присоединять нечего.
func (s *nameScan) hyphenLeft(c *nameCons) bool {
	h := c.first - 2
	if s.prev.idx >= 0 && s.prev.idx == len(s.out.Spans)-1 && s.prev.last == h {
		if sp := s.out.Spans[s.prev.idx]; sp.Conf > c.conf {
			c.conf, c.rule = sp.Conf, sp.Rule
		}
		s.out.Spans = s.out.Spans[:s.prev.idx]
		c.first = s.prev.first
		s.prev.idx = -1
		return true
	}
	if h < s.floor || !nameHyphenPartOK(s.doc, &s.tb, h, c.first) {
		return false
	}
	c.first = h
	return true
}

// liftUpper поднимает уверенность конструкции, в которой есть слово с
// заглавной буквы.
func (s *nameScan) liftUpper(c *nameCons) {
	if r := s.upperRule(c); r != "" {
		c.conf, c.rule = Strong, r
	}
	if s.liftFamily(c) {
		return
	}
	if c.conf < Strong && c.single {
		if r := nameSingleLift(s.doc, &s.tb, c.first); r != "" {
			c.conf, c.rule = Strong, r
			s.noteFamily(r, c.first)
		}
	}
}

// upperRule возвращает правило, по которому конструкция с заглавной буквой
// поднимается до Strong, или пустую строку.
func (s *nameScan) upperRule(c *nameCons) string {
	doc := s.doc
	switch {
	case c.marker:
		return nameMarkerRule(c.rule)
	case c.conf == Weak && c.last > c.first && !nameGivenPosRule(c.base) && s.bank.inSentence(doc, s.tb.banking, c.first):
		// Конструкция из двух и более слов в банковском предложении —
		// клиент. Одиночное слово так не поднимается: «Иван» или «Петров» в
		// тексте о кредите ещё не обязательно имя.
		return nameRuleBankContext
	case c.conf == Weak && c.last > c.first && c.base != nameRuleAdjGiven && c.base != nameRuleGivenAdj &&
		nameIntroduced(doc, c.first, c.last):
		// Слово, вводящее лицо, вплотную к паре: «Передайте Мельнику
		// Олегу», «Звонил Цой Артём». Одиночное слово так не поднимается —
		// «Передайте Олегу» остаётся на уровне имени. Короткое
		// прилагательное рядом с одним именем слово-ввод тоже не поднимает —
		// только маркер или обращение: «Андрей Белый написал роман» — чаще
		// писатель, чем клиент (T-66).
		return nameRuleIntro
	case c.conf == Weak && nameBareCaseAgrees(doc, &s.tb, c.first, c.last, c.base):
		return nameRuleBareCase
	case c.conf == Weak && c.last > c.first && nameAddressPair(c.base) && nameAddressLeft(doc, c.first):
		// Обращение вплотную к паре: «Спасибо, Тихий Роман», «Здравствуйте,
		// я Малая Ирина» (T-66).
		return nameRulePairAddress
	}
	return ""
}

// liftLower пересчитывает уверенность конструкции, записанной целиком
// строчными буквами, и возвращает false, если кандидата заводить не надо.
func (s *nameScan) liftLower(c *nameCons) bool {
	doc := s.doc
	switch {
	case c.base == nameRuleBareGiven || c.base == nameRuleGivenBare:
		// В строчной записи фамилия без суффикса принимается только рядом с
		// маркером или словом-вводом (nameBareAnchored), и этот якорь — то
		// же свидетельство, что маркер у пары.
		c.conf, c.rule = Strong, nameRuleBareAnchored
	case c.base == nameRuleSurBareInitLowerMarker:
		// «клиент черныш д.с.»: опору слева уже проверил
		// nameBareThenInitialsLower.
	case c.single && c.conf < Strong && nameFieldLift(doc, &s.tb, c.first):
		// «фамилия: корнеева», «отчество — никитична»: значение поля анкеты
		// после разделителя (T-66).
		c.conf, c.rule = Strong, nameRuleField
	case c.base == nameRuleGivenSurPos &&
		nameBareAnchored(doc, &s.tb, c.first) && namePredicateAfter(doc, c.last):
		// Фамилия-прилагательное строчными справа от имени в той же рамке
		// «опора — пара — сказуемое»: «клиент олег толстой просит кредит».
		// Слева от имени рамка не действует: прилагательное перед именем —
		// обычный порядок слов, и «клиентка красивая марина пришла» — не ФИО.
		c.conf, c.rule = Strong, nameRuleBareAnchored
	case c.conf == Strong && nameLowerMarkerRule(c.rule) != "" && !nameMarkerLeft(doc, s.tb.markers, c.first) &&
		!nameIntroCommon(doc, c.first, c.last) && nameIntroduced(doc, c.first, c.last):
		// Строчная пара после слова, вводящего лицо: «звонила петрова анна»,
		// «передайте смирновой ольге», «анна смирнова просит выписку» (T-60).
		c.rule = nameRuleLowerIntro
	default:
		return s.lowerDefault(c)
	}
	return true
}

// lowerDefault — общий случай строчной конструкции (nameLowerCase).
func (s *nameScan) lowerDefault(c *nameCons) bool {
	// Строчная пара из двух опознанных слов («клиент иванов иван»)
	// опускается до Weak, и маркер лица слева возвращает ей уровень
	// заглавной записи. Маркер ищется только для таких пар: у остальных
	// строчных конструкций уровень решает nameLowerCase.
	if c.conf == Strong && nameLowerMarkerRule(c.rule) != "" {
		c.marker = nameMarkerLeft(s.doc, s.tb.markers, c.first)
	}
	var ok bool
	if c.conf, c.rule, ok = nameLowerCase(c.conf, c.rule, c.marker); ok {
		return true
	}
	// Одиночная строчная фамилия отбрасывается — кроме повтора фамилии из
	// уже опознанного ФИО.
	if s.seen.n == 0 || c.first != c.last || !s.seen.repeatAt(s.doc, &s.tb, c.first) {
		return false
	}
	c.conf, c.rule = Strong, nameRuleSurnameRepeat
	return true
}

// emit выдаёт конструкцию кандидатом и запоминает её.
func (s *nameScan) emit(c *nameCons) {
	doc := s.doc
	if c.conf == Weak && s.seen.n > 0 && s.seen.inConstruction(doc, &s.tb, c.first, c.last) {
		c.conf, c.rule = Strong, nameRuleSurnameRepeat
	}
	s.out.Add(int(doc.Tokens[c.first].Start), int(doc.Tokens[c.last].End), pii.FullName, c.conf, c.rule)
	s.prev = nameLast{idx: len(s.out.Spans) - 1, first: c.first, last: c.last}
	if c.conf >= Strong {
		s.seen.remember(doc, &s.tb, c.first, c.last, c.base)
	}
	s.floor = c.last + 1
}
