package corpus

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// KindBare — голое значение: запись целиком состоит из одного значения ПД,
// без маркера типа и без окружающего текста — «Веретенникова»,
// «4618 507329», «VALENTINA VERETENNIKOVA».
//
// По ответам организаторов в датасете есть «как отдельные слова, так и фразы
// и предложения» (A2.1), а полное маскирование такой записи избыточным не
// считается (A4.4). Остальные виды корпуса — естественные запросы, и голых
// значений в них нет, поэтому вид нужен отдельно: без него метрика сокрытия
// эту часть датасета не измеряет (технический раунд 4, P4-3).
//
// Вид включается флагом -bare и по умолчанию выключен: корпус с тем же seed
// без флага побайтово совпадает с прежним, и прошлые прогоны остаются
// сравнимыми.
const KindBare = "bare"

// barePerType — голых записей на тип. Больше числа форм у любого типа:
// каждая форма попадает в корпус гарантированно, а не «в среднем».
const barePerType = 12

// bareStreamSalt отделяет поток ГПСЧ голых записей от основного. Поток свой,
// чтобы включение -bare не сдвинуло ни одного значения остального корпуса:
// общий генератор, продвинутый на голые записи, выдал бы после них другие
// длинные записи.
const bareStreamSalt = 0x6261726576616c75

// bareYearSuffixes — служебные слова, с которыми голая дата встречается в
// анкете. В спан они не входят (соглашение о границах, README).
var bareYearSuffixes = []string{" года", " г."}

// bareRecords строит голые записи всех обязательных типов. Результат
// определяется seed.
func bareRecords(seed uint64) []Record {
	g := &gen{r: rand.New(rand.NewPCG(seed^bareStreamSalt, seed))}
	recs := make([]Record, 0, barePerType*len(RequiredTypes))
	for _, typ := range RequiredTypes {
		for i := 0; i < barePerType; i++ {
			var b builder
			b.add(g.bareValue(typ, i)...)
			recs = append(recs, b.record(KindBare))
		}
	}
	return recs
}

// bareValue выдаёт i-ю форму голого значения типа typ.
func (g *gen) bareValue(typ string, i int) []piece {
	switch typ {
	case KFullName:
		// Сначала все стили написания ФИО, затем части имени по одной.
		p := g.person()
		switch k := i % (int(nameStyleCount) + 3); k {
		case int(nameStyleCount):
			return []piece{val(typ, p.last.nom)}
		case int(nameStyleCount) + 1:
			return []piece{val(typ, p.first.nom+" "+p.mid.nom)}
		case int(nameStyleCount) + 2:
			return []piece{val(typ, p.first.nom)}
		default:
			return []piece{val(typ, p.render(nameStyle(k), cNom))}
		}
	case KBirthDate:
		return g.bareDate(typ, g.birthDate())
	case KPassportIssueDate:
		return g.bareDate(typ, g.recentDate(2004, 20))
	case KBirthPlace:
		switch i % 5 {
		case 0:
			return []piece{val(typ, pick(g.r, cities))}
		case 1:
			return []piece{val(typ, "г. "+pick(g.r, cities))}
		case 2:
			return []piece{val(typ, pick(g.r, settlements))}
		case 3:
			return []piece{val(typ, pick(g.r, cities)+", "+pick(g.r, regions))}
		default:
			return []piece{val(typ, pick(g.r, regions))}
		}
	case KCitizenship:
		return []piece{val(typ, citizenships[i%len(citizenships)].nom)}
	case KPassportNumber:
		return []piece{val(typ, bareJoin(g.passport()))}
	case KPassportAuthority:
		switch i % 3 {
		case 0:
			return []piece{val(typ, authorities[(i/3)%len(authorities)])}
		case 1:
			return []piece{val(typ, "Отделом УФМС России по "+regionDative(pick(g.r, regions)))}
		default:
			return []piece{val(typ, "Отделением УФМС России по "+regionDative(pick(g.r, regions)))}
		}
	case KPassportDeptCode:
		return []piece{val(typ, g.deptCode())}
	case KDriverLicense:
		return []piece{val(typ, bareJoin(g.driverLicense()))}
	case KAddress:
		return []piece{val(typ, g.address())}
	case KEmail:
		return []piece{val(typ, g.email(g.person()))}
	case KPhone:
		if i%(phoneFormCount+1) == phoneFormCount {
			// Десять цифр без кода страны — форма, которой нет среди
			// вариаций телефона в запросах: там номер всегда с «+7» или «8».
			return []piece{val(typ, pick(g.r, phoneCodes)+fmt.Sprintf("%03d%02d%02d", g.r.IntN(1000), g.r.IntN(100), g.r.IntN(100)))}
		}
		return []piece{val(typ, g.phone())}
	case KINN:
		return []piece{val(typ, g.inn())}
	case KCardNumber:
		return []piece{val(typ, g.cardNumber())}
	case KCVV:
		return []piece{val(typ, g.cvv())}
	case KPIN:
		return []piece{val(typ, g.pin())}
	case KCardHolder:
		name := g.person().latin()
		if i%2 == 1 {
			name = titleWords(name)
		}
		return []piece{val(typ, name)}
	}
	panic("corpus: голое значение для типа " + typ + " не определено")
}

// bareDate выдаёт голую дату в очередной форме, иногда со словом «года» или
// «г.» после неё: так дату пишут в анкете. Слово служебное и в спан не входит.
func (g *gen) bareDate(typ string, d date) []piece {
	form := g.next(&g.dateSeq, dateFormCount)
	ps := []piece{val(typ, renderDate(d, form, cNom))}
	if form == 0 || form == 6 {
		if k := g.r.IntN(len(bareYearSuffixes) + 1); k < len(bareYearSuffixes) {
			ps = append(ps, lit(bareYearSuffixes[k]))
		}
	}
	return ps
}

// bareJoin собирает голое значение из кусков формы «серия … номер …»: слова
// между частями отбрасываются, части значения соединяются пробелом —
// «4618 507329». У однокусковых форм значение возвращается как есть.
func bareJoin(ps []piece) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.typ != "" {
			parts = append(parts, p.text)
		}
	}
	return strings.Join(parts, " ")
}

// regionDative ставит регион в дательный падеж после «по»: «Тверская
// область» → «Тверской области», «Республика Марий Эл» → «Республике Марий Эл».
func regionDative(r string) string {
	switch {
	case strings.HasSuffix(r, "ая область"):
		return strings.TrimSuffix(r, "ая область") + "ой области"
	case strings.HasPrefix(r, "Республика "):
		return "Республике " + strings.TrimPrefix(r, "Республика ")
	}
	return r
}

// titleWords переводит слова латиницей из верхнего регистра в «Title»:
// «VALENTINA VERETENNIKOVA» → «Valentina Veretennikova». Регистр имени
// держателя в анкете и в обращении бывает разный, и детектор обязан узнавать
// оба.
func titleWords(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		words[i] = w[:1] + strings.ToLower(w[1:])
	}
	return strings.Join(words, " ")
}
