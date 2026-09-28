package corpus

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// litSeries — служебное слово перед серией документа; в спан не входит.
const litSeries = "серия "

// gen — источник значений корпуса: детерминированный ГПСЧ и счётчики вариаций.
//
// Счётчики нужны, чтобы вариации написания (ТЗ §3.2.2) попадали в корпус
// гарантированно, а не «в среднем»: случайный выбор при малом -count может
// не показать, например, форму «серия … номер …» ни разу.
type gen struct {
	r        *rand.Rand
	dateSeq  int
	passSeq  int
	phoneSeq int
	cardSeq  int
	dlSeq    int
	nameSeq  int
	addrSeq  int
	emailSeq int
	codeSeq  int
	placeSeq int
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func (g *gen) next(seq *int, mod int) int {
	v := *seq % mod
	*seq++
	return v
}

// ---------- ФИО ----------

func (g *gen) person() person {
	if g.r.IntN(2) == 0 {
		return g.malePerson()
	}
	return g.femalePerson()
}

func (g *gen) malePerson() person {
	last := g.maleSurname()
	return person{
		last:  last,
		first: mascNoun(pick(g.r, firstMale)),
		mid:   mascNoun(pick(g.r, patronymicMale)),
	}
}

func (g *gen) femalePerson() person {
	var last word
	if g.r.IntN(4) == 0 {
		last = femAdj(pick(g.r, surnamesAdj))
	} else {
		last = femSur(pick(g.r, surnamesNoun))
	}
	return person{
		female: true,
		last:   last,
		first:  femNoun(pick(g.r, firstFemale)),
		mid:    femNoun(femPatronymic(pick(g.r, patronymicMale))),
	}
}

func (g *gen) maleSurname() word {
	if g.r.IntN(4) == 0 {
		return mascAdj(pick(g.r, surnamesAdj))
	}
	return mascNoun(pick(g.r, surnamesNoun))
}

// namesake — однофамилец публичной персоны: фамилия узнаваемая, человек
// синтетический, и это настоящие персональные данные, а не ловушка.
func (g *gen) namesake() person {
	return person{
		last:  mascNoun(pick(g.r, namesakeSurnames)),
		first: mascNoun(pick(g.r, firstMale)),
		mid:   mascNoun(pick(g.r, patronymicMale)),
	}
}

// fullName выдаёт ФИО, перебирая стили написания по кругу, и иногда заменяет
// «ё» на «е» — обе вариации детектор обязан переживать.
func (g *gen) fullName(p person, c grammCase) string {
	s := p.render(nameStyle(g.next(&g.nameSeq, int(nameStyleCount))), c)
	if g.r.IntN(6) == 0 {
		s = deyo(s)
	}
	return s
}

// ---------- Даты ----------

type date struct{ day, month, year int }

var monthsGen = []string{
	"января", "февраля", "марта", "апреля", "мая", "июня",
	"июля", "августа", "сентября", "октября", "ноября", "декабря",
}

var daysInMonth = []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

var ordinalUnits = []string{
	"", "первое", "второе", "третье", "четвёртое", "пятое", "шестое",
	"седьмое", "восьмое", "девятое", "десятое", "одиннадцатое", "двенадцатое",
	"тринадцатое", "четырнадцатое", "пятнадцатое", "шестнадцатое",
	"семнадцатое", "восемнадцатое", "девятнадцатое", "двадцатое",
}

// ordinalDay — день месяца словами в именительном падеже.
func ordinalDay(d int) string {
	switch {
	case d <= 20:
		return ordinalUnits[d]
	case d < 30:
		return "двадцать " + ordinalUnits[d-20]
	case d == 30:
		return "тридцатое"
	default:
		return "тридцать " + ordinalUnits[1]
	}
}

var cardinalTens = []string{
	"", "десять", "двадцать", "тридцать", "сорок",
	"пятьдесят", "шестьдесят", "семьдесят", "восемьдесят", "девяносто",
}

var ordinalTensGen = []string{
	"", "десятого", "двадцатого", "тридцатого", "сорокового",
	"пятидесятого", "шестидесятого", "семидесятого", "восьмидесятого", "девяностого",
}

var cardinalHundreds = []string{
	"", "сто", "двести", "триста", "четыреста",
	"пятьсот", "шестьсот", "семьсот", "восемьсот", "девятьсот",
}

var ordinalHundredsGen = []string{
	"", "сотого", "двухсотого", "трёхсотого", "четырёхсотого",
	"пятисотого", "шестисотого", "семисотого", "восьмисотого", "девятисотого",
}

// yearWords печатает год словами в родительном падеже: «тысяча девятьсот
// восемьдесят седьмого». Родительный потому, что в дате год стоит только так:
// «двенадцатого марта тысяча девятьсот восемьдесят седьмого года».
//
// Форма нужна корпусу отдельной строкой: запись «12 мая 1990» и запись
// «двенадцатого мая тысяча девятьсот девяностого» — это разные задачи для
// детектора, и вторая до сих пор в корпус не попадала.
func yearWords(year int) string {
	if year < 1000 || year > 2999 {
		return strconv.Itoa(year)
	}
	th, rest := year/1000, year%1000
	hundreds, rem := rest/100, rest%100
	if hundreds == 0 && rem == 0 {
		if th == 2 {
			return "двухтысячного"
		}
		return "тысячного"
	}
	head := "тысяча"
	if th == 2 {
		head = "две тысячи"
	}
	parts := []string{head}
	if hundreds > 0 {
		if rem == 0 {
			return strings.Join(append(parts, ordinalHundredsGen[hundreds]), " ")
		}
		parts = append(parts, cardinalHundreds[hundreds])
	}
	switch {
	case rem < 20:
		parts = append(parts, ordinalGen(ordinalUnits[rem]))
	case rem%10 == 0:
		parts = append(parts, ordinalTensGen[rem/10])
	default:
		parts = append(parts, cardinalTens[rem/10], ordinalGen(ordinalUnits[rem%10]))
	}
	return strings.Join(parts, " ")
}

// ordinalGen переводит порядковое числительное в родительный падеж:
// «двенадцатое» → «двенадцатого», «третье» → «третьего».
func ordinalGen(s string) string {
	switch {
	case strings.HasSuffix(s, "ье"):
		return strings.TrimSuffix(s, "е") + "его"
	case strings.HasSuffix(s, "ое"):
		return strings.TrimSuffix(s, "ое") + "ого"
	default:
		return s
	}
}

// dateFormCount — число вариаций написания даты по ТЗ §3.2.2.
const dateFormCount = 10

func (g *gen) birthDate() date {
	year := 1955 + g.r.IntN(50)
	month := 1 + g.r.IntN(12)
	return date{day: 1 + g.r.IntN(daysInMonth[month-1]), month: month, year: year}
}

func (g *gen) recentDate(fromYear, years int) date {
	month := 1 + g.r.IntN(12)
	return date{day: 1 + g.r.IntN(daysInMonth[month-1]), month: month, year: fromYear + g.r.IntN(years)}
}

// renderDate печатает дату в одной из вариаций. Падеж влияет только на запись
// словами: «двенадцатое марта 1987» против «родился двенадцатого марта 1987».
func renderDate(d date, form int, c grammCase) string {
	switch form {
	case 0:
		return fmt.Sprintf("%02d.%02d.%04d", d.day, d.month, d.year) // дд.мм.гггг
	case 1:
		return fmt.Sprintf("%02d/%02d/%04d", d.day, d.month, d.year)
	case 2:
		return fmt.Sprintf("%02d-%02d-%04d", d.day, d.month, d.year)
	case 3:
		return fmt.Sprintf("%02d.%02d.%04d", d.month, d.day, d.year) // мм.дд.гггг
	case 4:
		return fmt.Sprintf("%04d-%02d-%02d", d.year, d.month, d.day) // гггг-мм-дд
	case 5:
		return fmt.Sprintf("%04d.%02d.%02d", d.year, d.day, d.month) // гггг.дд.мм
	case 6:
		return fmt.Sprintf("%d %s %d", d.day, monthsGen[d.month-1], d.year)
	case 7:
		w := ordinalDay(d.day)
		if c == cGen {
			w = ordinalGen(w)
		}
		return fmt.Sprintf("%s %s %d", w, monthsGen[d.month-1], d.year)
	case 8:
		// Дата словами целиком, включая год: «двенадцатого марта тысяча
		// девятьсот восемьдесят седьмого».
		w := ordinalDay(d.day)
		if c == cGen {
			w = ordinalGen(w)
		}
		return fmt.Sprintf("%s %s %s", w, monthsGen[d.month-1], yearWords(d.year))
	default:
		return fmt.Sprintf("%02d.%02d.%02d", d.day, d.month, d.year%100) // дд.мм.гг
	}
}

// ---------- Паспорт ----------

// passportFormCount — вариации записи серии и номера, включая форму с
// разделяющими словами «серия … номер …» (ТЗ §3.2.2).
const passportFormCount = 5

// passport возвращает куски текста: в форме с разделяющими словами значение
// распадается на два спана, потому что слова «серия» и «номер» — служебные и
// в маску попадать не должны.
func (g *gen) passport() []piece {
	series := fmt.Sprintf("%02d%02d", 10+g.r.IntN(89), 10+g.r.IntN(89))
	number := fmt.Sprintf("%06d", g.r.IntN(1000000))
	switch g.next(&g.passSeq, passportFormCount) {
	case 0:
		return []piece{val(KPassportNumber, series+" "+number)}
	case 1:
		return []piece{val(KPassportNumber, series[:2]+" "+series[2:]+" "+number)}
	case 2:
		return []piece{val(KPassportNumber, series+number)}
	case 3:
		return []piece{
			lit(litSeries), val(KPassportNumber, series),
			lit(" номер "), val(KPassportNumber, number),
		}
	default:
		return []piece{
			lit(litSeries), val(KPassportNumber, series[:2]+" "+series[2:]),
			lit(" № "), val(KPassportNumber, number),
		}
	}
}

func (g *gen) deptCode() string {
	a, b := 100+g.r.IntN(800), g.r.IntN(100)
	if g.next(&g.codeSeq, 2) == 0 {
		return fmt.Sprintf("%03d-%03d", a, b)
	}
	return fmt.Sprintf("%03d%03d", a, b)
}

// ---------- Водительское удостоверение ----------

const licenseFormCount = 4

func (g *gen) driverLicense() []piece {
	series := fmt.Sprintf("%02d%02d", 10+g.r.IntN(89), 10+g.r.IntN(89))
	number := fmt.Sprintf("%06d", g.r.IntN(1000000))
	switch g.next(&g.dlSeq, licenseFormCount) {
	case 0:
		return []piece{val(KDriverLicense, series+" "+number)}
	case 1:
		return []piece{val(KDriverLicense, series[:2]+" "+series[2:]+" "+number)}
	case 2:
		return []piece{val(KDriverLicense, series+number)}
	default:
		return []piece{
			lit(litSeries), val(KDriverLicense, series),
			lit(" номер "), val(KDriverLicense, number),
		}
	}
}

// ---------- Контакты ----------

var phoneCodes = []string{"901", "902", "903", "904", "905", "908", "910", "915", "916", "920", "921", "925", "926", "929", "931", "950", "960", "962", "965", "977", "981", "987"}

const phoneFormCount = 6

func (g *gen) phone() string {
	code := pick(g.r, phoneCodes)
	a, b, c := g.r.IntN(1000), g.r.IntN(100), g.r.IntN(100)
	switch g.next(&g.phoneSeq, phoneFormCount) {
	case 0:
		return fmt.Sprintf("+7 (%s) %03d-%02d-%02d", code, a, b, c)
	case 1:
		return fmt.Sprintf("8 (%s) %03d-%02d-%02d", code, a, b, c)
	case 2:
		return fmt.Sprintf("+7%s%03d%02d%02d", code, a, b, c)
	case 3:
		return fmt.Sprintf("8%s%03d%02d%02d", code, a, b, c)
	case 4:
		return fmt.Sprintf("8-%s-%03d-%02d-%02d", code, a, b, c)
	default:
		return fmt.Sprintf("+7 %s %03d %02d %02d", code, a, b, c)
	}
}

const emailFormCount = 4

func (g *gen) email(p person) string {
	first, last := strings.ToLower(toLatin(p.first.nom)), strings.ToLower(toLatin(p.last.nom))
	if first == "" || last == "" {
		first, last = "client", "user"
	}
	domain := pick(g.r, emailDomains)
	var local string
	switch g.next(&g.emailSeq, emailFormCount) {
	case 0:
		local = first[:1] + "." + last
	case 1:
		local = last + "." + first
	case 2:
		local = first + fmt.Sprintf("%02d", g.r.IntN(100))
	default:
		local = last + "_" + first[:1]
	}
	addr := local + "@" + domain
	if g.r.IntN(5) == 0 {
		// Регистр не должен влиять на идентификацию (ТЗ §3.2.1).
		addr = strings.ToUpper(addr)
	}
	return addr
}

// ---------- Финансовые ----------

// luhn возвращает контрольную цифру для строки цифр. Алгоритм общеизвестный и
// реализован здесь заново: корпус не переиспользует код детектора.
func luhn(digits string) int {
	sum, double := 0, true
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		double = !double
		sum += d
	}
	return (10 - sum%10) % 10
}

const cardFormCount = 3

// cardNumber собирает номер из тестового BIN и случайного тела, затем
// дописывает контрольную цифру: номер проходит Луна, но никому не принадлежит.
func (g *gen) cardNumber() string {
	var sb strings.Builder
	sb.WriteString(pick(g.r, testBINs))
	for sb.Len() < 15 {
		sb.WriteByte(byte('0' + g.r.IntN(10)))
	}
	body := sb.String()
	full := body + fmt.Sprintf("%d", luhn(body))
	switch g.next(&g.cardSeq, cardFormCount) {
	case 0:
		return full[0:4] + " " + full[4:8] + " " + full[8:12] + " " + full[12:16]
	case 1:
		return full[0:4] + "-" + full[4:8] + "-" + full[8:12] + "-" + full[12:16]
	default:
		return full
	}
}

func (g *gen) cvv() string { return fmt.Sprintf("%03d", g.r.IntN(1000)) }

func (g *gen) pin() string { return fmt.Sprintf("%04d", g.r.IntN(10000)) }

var (
	innWeights11 = []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	innWeights12 = []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
)

func innCheck(digits string, weights []int) int {
	sum := 0
	for i, w := range weights {
		sum += int(digits[i]-'0') * w
	}
	return sum % 11 % 10
}

// inn выдаёт ИНН физического лица (12 цифр) с верными контрольными разрядами.
func (g *gen) inn() string {
	var sb strings.Builder
	for sb.Len() < 10 {
		sb.WriteByte(byte('0' + g.r.IntN(10)))
	}
	body := sb.String()
	c11 := innCheck(body, innWeights11)
	body += fmt.Sprintf("%d", c11)
	c12 := innCheck(body, innWeights12)
	return body + fmt.Sprintf("%d", c12)
}

// ---------- Место и адрес ----------

func (g *gen) birthPlace() string {
	switch g.next(&g.placeSeq, 4) {
	case 0:
		return pick(g.r, cities)
	case 1:
		return pick(g.r, settlements) + ", " + pick(g.r, regions)
	case 2:
		return pick(g.r, cities) + ", " + pick(g.r, regions)
	default:
		return pick(g.r, cities)
	}
}

func (g *gen) postIndex() string {
	return fmt.Sprintf("%03d%03d", 100+g.r.IntN(560), g.r.IntN(1000))
}

const addrFormCount = 4

// address собирает адрес целиком. Спан покрывает весь адресный блок: дробить
// его на компоненты значило бы оставить часть значения открытой, а полное
// сокрытие предпочтительнее частичного (07-clarifications.md §7.1).
func (g *gen) address() string {
	st := pick(g.r, streets)
	house := 1 + g.r.IntN(120)
	flat := 1 + g.r.IntN(250)
	city, region := pick(g.r, cities), pick(g.r, regions)
	switch g.next(&g.addrSeq, addrFormCount) {
	case 0:
		return fmt.Sprintf("%s, г. %s, %s %s, д. %d, кв. %d", g.postIndex(), city, st.kind, st.name, house, flat)
	case 1:
		return fmt.Sprintf("г. %s, %s %s, д. %d, кв. %d", city, st.kind, st.name, house, flat)
	case 2:
		return fmt.Sprintf("%s, г. %s, %s %s, д. %d, корп. %d, кв. %d", region, city, st.kind, st.name, house, 1+g.r.IntN(4), flat)
	default:
		return fmt.Sprintf("%s, %s, г. %s, %s %s, д. %dа, кв. %d", g.postIndex(), region, city, st.kind, st.name, house, flat)
	}
}

// orgAddress — адрес отделения банка: не персональные данные, только ловушка.
func (g *gen) orgAddress() string {
	st := pick(g.r, streets)
	return fmt.Sprintf("г. %s, %s %s, д. %d", pick(g.r, cities), st.kind, st.name, 1+g.r.IntN(40))
}

// hotline — номер линии поддержки: принадлежит организации, а не человеку.
func (g *gen) hotline() string {
	switch g.r.IntN(3) {
	case 0:
		return fmt.Sprintf("8 800 %03d %02d %02d", 200+g.r.IntN(700), g.r.IntN(100), g.r.IntN(100))
	case 1:
		return fmt.Sprintf("8-800-%03d-%02d-%02d", 200+g.r.IntN(700), g.r.IntN(100), g.r.IntN(100))
	default:
		return fmt.Sprintf("*%04d", 1000+g.r.IntN(8000))
	}
}

// contractNumber — номер договора: намеренно похож на серию и номер паспорта.
func (g *gen) contractNumber() string {
	switch g.r.IntN(3) {
	case 0:
		return fmt.Sprintf("%04d-%06d", 1000+g.r.IntN(8999), g.r.IntN(1000000))
	case 1:
		return fmt.Sprintf("КД-%04d/%06d", 1000+g.r.IntN(8999), g.r.IntN(1000000))
	default:
		return fmt.Sprintf("%04d %06d", 4000+g.r.IntN(2000), g.r.IntN(1000000))
	}
}
