package detect

import "ai-gateway/internal/lex"

// nameHas сообщает, что в наборе ролей r есть хотя бы одна из ролей bits.
func nameHas(r, bits nameRole) bool { return r&bits != 0 }

// nameConfBy — уверенность конструкции, которую держит слово на свободном
// месте: Certain со свидетельством регистра, Strong без него.
func nameConfBy(evidence bool) Confidence {
	if evidence {
		return Certain
	}
	return Strong
}

// nameMatch подбирает конструкцию ФИО, начинающуюся с токена i.
//
// Возвращается индекс последнего токена конструкции (или -1, если ничего не
// подошло), уверенность и имя сработавшего правила.
func nameMatch(doc *lex.Doc, tb *nameTables, i int) (int, Confidence, string) {
	role := nameClassify(doc, tb.given, tb.markers, i)
	// Все ветви ниже требуют непустой роли головы, поэтому без неё разбирать
	// соседние слова незачем. Без этого выхода каждый токен текста
	// классифицировался трижды — как голова, как второе слово и как третье, —
	// и две трети работы уходили в отброшенный результат.
	if role == 0 {
		// Единственное исключение — фамилия-прилагательное перед инициалами
		// (nameMatchNoRole). Инициалы ищутся здесь, до вызова: на обычном
		// слове их нет, и разбор кончается без лишнего вызова.
		last, ok := nameSurnameThenInitials(doc, i)
		if !ok {
			return -1, 0, ""
		}
		return nameMatchNoRole(doc, tb, i, last)
	}
	if nameHas(role, nameRoleInitial) {
		return nameMatchInitial(doc, tb, i)
	}
	if last, conf, rule, ok := nameMatchSurnameHead(doc, tb, i, role); ok {
		return last, conf, rule
	}
	if last, conf, rule, ok := nameMatchGivenInitials(doc, tb, i, role); ok {
		return last, conf, rule
	}
	j, ok := nameNextPart(doc, i, i)
	if !ok {
		return nameMatchSingle(i, role)
	}
	second := nameClassify(doc, tb.given, tb.markers, j)
	if k, ok := nameNextPart(doc, i, j); ok {
		if last, conf, rule, ok := nameMatchTriple(doc, tb, i, j, k, role, second); ok {
			return last, conf, rule
		}
	}
	// «Картина Ивана Петрова продана»: справа от пары «фамилия по окончанию +
	// имя» стоит более сильная пара «имя в косвенном падеже + фамилия», и
	// слово слева к ней не присоединяется (T-80).
	if nameRightPairStronger(doc, tb, i, j, role, second) {
		return nameMatchSingle(i, role)
	}
	if last, conf, rule, ok := nameMatchPair(doc, i, j, role, second); ok {
		return last, conf, rule
	}
	return nameMatchSingle(i, role)
}

// nameRightPairStronger сообщает, что слово i с ролью фамилии и имя j за ним
// — не пара: имя стоит в косвенном падеже, и за ним фамилия, с которой оно
// составляет пару «Ивана Петрова». Слово i с окончанием фамилии тогда —
// обычное существительное, которое управляет родительным падежом: «Картина
// Ивана Петрова», «Машина Анны Смирновой». В паре «Иванова Ивана» без
// фамилии справа правило молчит.
func nameRightPairStronger(doc *lex.Doc, tb *nameTables, i, j int, role, second nameRole) bool {
	if !nameHas(role, nameRoleSurname) || !nameHas(second, nameRoleGiven) || nameHas(second, nameRolePatronymic) {
		return false
	}
	k, ok := nameNextPart(doc, i, j)
	if !ok || nameClassify(doc, tb.given, tb.markers, k)&nameRoleSurname == 0 {
		return false
	}
	_, oblique := nameGivenOblique(tb.given, doc.NormOf(j))
	return oblique
}

// nameMatchNoRole разбирает голову без роли перед инициалами: «Бережного Р.
// А.». Фамилию-прилагательное таблица суффиксов не знает и знать не должна,
// но здесь конструкцию держат инициалы — два однобуквенных слова с точками
// подряд за обычным словом не встречаются. Признак прилагательного
// проверяется только после того, как инициалы найдены. last — точка
// последнего инициала, её вернул nameSurnameThenInitials.
func nameMatchNoRole(doc *lex.Doc, tb *nameTables, i, last int) (int, Confidence, string) {
	if nameSurnamePos(doc, tb.markers, i) {
		return last, Strong, nameRuleSurPosInit
	}
	// «Коваль К. Г.»: фамилия без суффикса держится на двух инициалах так
	// же, как фамилия-прилагательное.
	if c, ok := nameBareThenInitials(doc, tb, i, last); ok {
		return last, c, nameRuleSurBareInit
	}
	// «Клиент Мельник О. просит выписку»: один инициал (T-66).
	if c, ok := nameBareThenInitial(doc, tb, i, last); ok {
		return last, c, nameRuleSurBareInit1
	}
	// «клиент черныш д.с.»: строчная запись при опоре слева (T-66).
	if nameBareThenInitialsLower(doc, tb, i, last) {
		return last, Strong, nameRuleSurBareInitLowerMarker
	}
	return -1, 0, ""
}

// nameMatchInitial разбирает голову-инициал: «И. И. Иванов». Инициалы сами
// по себе значения не имеют, конструкция держится на фамилии справа. Третья
// буква сокращения «Ф.И.О.» началом инициалов не бывает.
func nameMatchInitial(doc *lex.Doc, tb *nameTables, i int) (int, Confidence, string) {
	if nameInitialBefore(doc, i) {
		return -1, 0, ""
	}
	if last, ok := nameInitialsThenSurname(doc, tb.given, tb.markers, i); ok {
		return last, Strong, nameRuleInitialsSurname
	}
	if last, ok := nameInitialsThenBare(doc, tb, i); ok {
		return last, Strong, nameRuleInitialsBare
	}
	// «Клиент О. Мельник»: один инициал при опоре (T-66).
	if last, ok := nameInitialThenBare(doc, tb, i); ok {
		return last, Strong, nameRuleInit1Bare
	}
	return -1, 0, ""
}

// nameMatchSurnameHead разбирает конструкции, которые держит голова-фамилия
// с суффиксом: «Иванов И. И.», «ПЕТРОВА анна сергеевна».
func nameMatchSurnameHead(doc *lex.Doc, tb *nameTables, i int, role nameRole) (int, Confidence, string, bool) {
	if !nameHas(role, nameRoleSurname) {
		return 0, 0, "", false
	}
	if last, ok := nameSurnameThenInitials(doc, i); ok {
		return last, Strong, nameRuleSurnameInitials, true
	}
	// «ПЕТРОВА анна сергеевна»: фамилию капсом выделяют в формах, а имя с
	// отчеством пишут как придётся. Сравнение регистра ниже разрезало бы
	// одно ФИО на два спана — и нумерация сказала бы модели о двух людях.
	return nameCapsSurnameLower(doc, tb, i)
}

// nameMatchGivenInitials разбирает «Ким О. П.»: фамилию, совпадающую с
// именем из справочника, с двумя инициалами. Имя с двумя инициалами за ним —
// не имя, а фамилия: так подписываются, а не представляются. Уровни — как у
// «Коваль К. Г.».
func nameMatchGivenInitials(doc *lex.Doc, tb *nameTables, i int, role nameRole) (int, Confidence, string, bool) {
	if !nameHas(role, nameRoleGiven) || nameHas(role, nameRoleSurname) || !nameInitialAhead(doc, i) {
		return 0, 0, "", false
	}
	last, ok := nameSurnameThenInitials(doc, i)
	if !ok {
		return 0, 0, "", false
	}
	if c, ok := nameBareThenInitials(doc, tb, i, last); ok {
		return last, c, nameRuleSurBareInit, true
	}
	return 0, 0, "", false
}

// nameMatchTriple разбирает конструкции из трёх слов i, j, k; role и second —
// роли первых двух.
func nameMatchTriple(doc *lex.Doc, tb *nameTables, i, j, k int, role, second nameRole) (int, Confidence, string, bool) {
	third := nameClassify(doc, tb.given, tb.markers, k)
	givenPatr := nameHas(role, nameRoleGiven) && nameHas(second, nameRolePatronymic)
	switch {
	// Фамилия Имя Отчество. Среднее слово проверяется только на заглавную
	// кириллицу: редкого имени может не быть в справочнике, но оно зажато
	// между опознанными фамилией и отчеством.
	case nameHas(role, nameRoleSurname) && nameHas(third, nameRolePatronymic):
		return k, Certain, nameRuleFIO, true
	// Имя Отчество Фамилия.
	case givenPatr && nameHas(third, nameRoleSurname):
		return k, Certain, nameRuleIFO, true
	// Имя Отчество плюс слово на месте фамилии: «Станислава Леонидовича
	// Бережного». Пара «Имя Отчество» самодостаточна, и третье слово
	// принимается по позиции — оно стоит вплотную за ней и занимает
	// единственное свободное место конструкции.
	case givenPatr && nameSurnamePos(doc, tb.markers, k):
		return k, Certain, nameRuleIFOPosSur, true
	// Имя Отчество плюс фамилия без русского суффикса: «Олег Петрович
	// Мельник», «Виктор Робертович Цой». Слово принимается тем же доводом —
	// свободное место конструкции, — но без морфологии, поэтому отсевы жёстче
	// (nameBareSurname). Уровень Certain — только при свидетельстве регистра;
	// без него слово едет на уровне самой пары и маскирующего решения не
	// меняет.
	case givenPatr && third == 0 && !nameStartsNext(doc, tb, i, k):
		if ok, evidence := nameBareSurname(doc, tb, k, j, false); ok {
			return k, nameConfBy(evidence), nameRuleIFOBare, true
		}
	// «Ким Олег Сергеевич»: фамилия, совпадающая с именем из справочника,
	// перед парой «Имя Отчество». Без этой ветви «Ким» оставался одиночным
	// слабым именем, а пара справа не могла достроиться влево — фамилия
	// уходила открытой (T-60).
	case nameGivenGiven(doc, i, role, second) && nameHas(third, nameRolePatronymic):
		return k, Certain, nameRuleGivenGivenPatronymic, true
	// «Бабич Олег Петрович», вторая часть «Бонч-Бруевич Андрей Сергеевич»:
	// фамилия с окончанием отчества перед парой «Имя Отчество». Двух отчеств
	// у человека не бывает, поэтому первое слово — фамилия. Без этой ветви
	// оно оставалось слабым одиночным отчеством отдельным спаном (T-66).
	case role == nameRolePatronymic && nameHas(second, nameRoleGiven) &&
		!nameHas(second, nameRolePatronymic) && nameHas(third, nameRolePatronymic):
		return k, Certain, nameRuleFIOPatrSurname, true
	}
	return 0, 0, "", false
}

// nameMatchPair разбирает конструкции из двух слов i и j; role и second —
// их роли.
func nameMatchPair(doc *lex.Doc, i, j int, role, second nameRole) (int, Confidence, string, bool) {
	switch {
	case nameHas(role, nameRoleGiven) && nameHas(second, nameRolePatronymic):
		return j, Strong, nameRuleGivenPatronymic, true
	case nameHas(role, nameRoleGiven) && nameHas(second, nameRoleSurname):
		return j, Strong, nameRuleGivenSurname, true
	case nameHas(role, nameRoleSurname) && nameHas(second, nameRoleGiven):
		return j, Strong, nameRuleSurnameGiven, true
	// Отчество Фамилия: имя слева могло не найтись в справочнике, но пара
	// «отчество плюс фамилия» сама по себе описывает человека.
	case nameHas(role, nameRolePatronymic) && nameHas(second, nameRoleSurname):
		return j, Strong, nameRulePatronymicSur, true
	// Два имени из справочника подряд: «Ким Олег», «Ли Анна». Разбор по
	// одному слову давал два спана на одного человека, а без маркера — ни
	// одного.
	case nameGivenGiven(doc, i, role, second):
		return j, Strong, nameRuleGivenGiven, true
	}
	return 0, 0, "", false
}

// nameMatchSingle — одиночное опознанное слово i с ролями role.
func nameMatchSingle(i int, role nameRole) (int, Confidence, string) {
	switch {
	case nameHas(role, nameRoleSurname):
		return i, Weak, nameRuleSurname
	case nameHas(role, nameRoleGiven):
		return i, Weak, nameRuleGiven
	case nameHas(role, nameRolePatronymic):
		return i, Weak, nameRulePatronymic
	}
	return -1, 0, ""
}
