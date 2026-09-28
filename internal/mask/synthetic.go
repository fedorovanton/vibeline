package mask

import (
	_ "embed"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/pii"
)

// syntheticNamesData — справочник вымышленных ФИО.
//
// Встраивается внутри пакета mask, а не в detect/dict: это данные
// маскирования. Детекция им не пользуется, и зависимость в обратную сторону
// заводить не надо.
//
//go:embed data/synthetic_names.txt
var syntheticNamesData string

// Synthetic — замена правдоподобными вымышленными данными (ТЗ §6).
//
// Из четырёх стратегий эта лучше всех сохраняет смысл запроса для модели:
// текст остаётся связным и грамматически целым, модель продолжает видеть
// «письмо клиенту с телефоном и адресом», а не текст, продырявленный
// скобками. Плата за это — маска неотличима по форме от настоящих данных,
// поэтому замены берутся исключительно из заведомо служебных диапазонов:
//
//   - домен example.org зарезервирован RFC 2606 именно под примеры и не
//     может принадлежать никому;
//   - телефоны собираются в диапазоне +7 900 000-…, который не выдаётся
//     абонентам;
//   - ИНН начинается с кода налогового органа 0000, которого не существует
//     (коды регионов начинаются с 01);
//   - номера карт берутся из тестового диапазона 4000 00…;
//   - номер банковского счёта несёт код валюты 000, которого нет в
//     классификаторе валют;
//   - адреса и населённые пункты — вымышленные топонимы.
//
// Ни одна замена не должна выглядеть как настоящие данные постороннего
// человека или организации: подставить чужой реальный телефон вместо чужого
// реального телефона — это не защита, а перенос проблемы.
type Synthetic struct{}

// Name возвращает имя стратегии.
func (Synthetic) Name() string { return "synthetic" }

// Mask возвращает вымышленное значение, детерминированно выбранное по номеру
// значения seq.
//
// Детерминированность обязательна: маскирование объявлено чистой функцией
// от (payload, policy), и повтор прямого шага /process обязан дать тот же
// результат побайтово. Поэтому никакого math/rand и никакого состояния между
// вызовами здесь нет — только арифметика по seq.
//
// Одинаковые значения в пределах запроса получают один seq и, значит, одну
// замену: связность текста («[ФИО_1] позвонил [ФИО_2]») сохраняется и здесь.
func (Synthetic) Mask(orig string, t pii.Type, seq int) string {
	n := seq - 1
	if n < 0 {
		n = 0
	}
	repl, ok := syntheticValue(orig, t, n)
	if !ok {
		// Для остальных типов правдоподобной замены нет: выдумывать номер
		// паспорта или код подразделения опаснее, чем честно показать
		// модели, что здесь стояли персональные данные.
		return Placeholder{}.Mask(orig, t, seq)
	}
	// Совпадение замены с исходным значением означало бы, что значение не
	// скрыто, — прямое нарушение REQ-301. Справочники конечны, и настоящий
	// Петров Пётр рано или поздно попадёт сам на себя. Сдвиг на одну позицию
	// убирает совпадение и сохраняет детерминированность: результат
	// по-прежнему зависит только от значения и его номера.
	//
	// Плата — сдвинутая замена может совпасть с заменой соседнего значения,
	// и два разных человека в тексте станут одним. Размен сознательный:
	// потеря различимости в редком случае дешевле, чем значение, оставшееся
	// в тексте открытым.
	if repl == orig {
		repl, _ = syntheticValue(orig, t, n+1)
	}
	return repl
}

// syntheticValue возвращает замену для типов, у которых она предусмотрена.
// Второе значение — признак того, что тип поддержан.
func syntheticValue(orig string, t pii.Type, n int) (string, bool) {
	switch t {
	case pii.FullName:
		return syntheticFullName(orig, n), true
	case pii.CardHolder:
		return syntheticCardHolder(orig, n), true
	case pii.Phone:
		return syntheticPhone(n), true
	case pii.Email:
		return syntheticEmail(n + 1), true
	case pii.CardNumber:
		return syntheticCard(n), true
	case pii.INN:
		return syntheticINN(n), true
	case pii.SNILS:
		return syntheticSNILS(n), true
	case pii.BankAccount:
		return syntheticAccount(n), true
	case pii.BirthDate, pii.PassportIssueDate:
		return syntheticDate(n), true
	case pii.Address:
		return syntheticAddresses[n%len(syntheticAddresses)], true
	case pii.BirthPlace:
		return syntheticCities[n%len(syntheticCities)], true
	default:
		return "", false
	}
}

// syntheticFullName собирает вымышленное ФИО по форме исходного значения.
//
// Замена повторяет исходное значение слово в слово: то же число слов, та же
// роль каждого слова (фамилия, имя, отчество, инициалы), тот же порядок и тот
// же род. «Шевчук Оксана Васильевна» становится «Петрова Анна Петровна», а
// «Инна Коваль» — «Анна Петрова». Так замена не удлиняет и не укорачивает
// фразу, модель обращается к человеку в верном роде (Б4-8: «Уважаемый Пётр
// Петрович» клиентке), и каждое слово замены однозначно соответствует слову
// исходного значения — на этом держится восстановление частичных и
// склонённых форм в ответе модели (SyntheticNameForms).
func syntheticFullName(orig string, n int) string {
	words := strings.Fields(orig)
	if len(words) == 0 {
		return synSurnames[n%len(synSurnames)]
	}
	sh := shapeOf(words)
	out := make([]string, len(words))
	initial := 0
	for i, w := range words {
		switch sh.roles[i] {
		case roleGiven:
			out[i] = synthGiven(n, sh.female)
		case rolePatronymic:
			out[i] = synthPatronymic(n, sh.female)
		case roleInitials:
			out[i], initial = synthInitials(w, n, sh.female, initial)
		default:
			out[i] = synthSurname(n, sh.female)
		}
	}
	return strings.Join(out, " ")
}

// syntheticCardHolder собирает имя держателя карты.
//
// На картах имя печатается латиницей и в порядке «имя фамилия», поэтому
// кириллическая замена смотрелась бы для модели как ошибка данных.
// Транслитерация применяется, только если в исходном значении не было
// кириллицы: иначе исходная запись была кириллической и замену незачем
// переводить в другой алфавит.
func syntheticCardHolder(orig string, n int) string {
	given, surname := pickName(n), synSurnames[n%len(synSurnames)]
	if hasCyrillic(orig) {
		return given + " " + surname
	}
	return strings.ToUpper(translit(given) + " " + translit(surname))
}

// pickName выбирает имя так, чтобы пары «фамилия + имя» не начинали
// повторяться раньше, чем закончатся оба списка: номер значения работает как
// разряды счётчика по основаниям len(synSurnames) и len(synNames).
func pickName(n int) string { return synNames[(n/len(synSurnames))%len(synNames)] }

func pickPatronymic(n int) string {
	return synPatronymics[(n/(len(synSurnames)*len(synNames)))%len(synPatronymics)]
}

// syntheticPhone возвращает номер из служебного диапазона +7 900 000-…
//
// Варьируются четыре последние цифры, а не две: при двух цифрах сто первое
// значение в запросе повторило бы первое, и два разных телефона склеились бы
// в один. Для первых ста значений форма совпадает с задокументированной
// в README: +7 900 000-00-NN.
func syntheticPhone(n int) string {
	tail := n % 10000
	var b strings.Builder
	b.Grow(len("+7 900 000-00-00"))
	b.WriteString("+7 900 000-")
	writePadded(&b, tail/100, 2)
	b.WriteByte('-')
	writePadded(&b, tail%100, 2)
	return b.String()
}

// syntheticEmail возвращает адрес в домене example.org: RFC 2606 закрепил его
// за примерами, поэтому такой адрес заведомо ничей.
func syntheticEmail(seq int) string {
	var b strings.Builder
	b.Grow(24)
	b.WriteString("user")
	writePadded(&b, seq, 1)
	b.WriteString("@example.org")
	return b.String()
}

// syntheticCard возвращает номер карты из тестового диапазона 4000 00…
// с верной контрольной суммой по Луна.
//
// Контрольная сумма важна: номер без неё отбраковывается любым валидатором,
// и модель, которой поручено проверить данные заявки, увидит заведомо битое
// значение вместо правдоподобного.
func syntheticCard(n int) string {
	digits := make([]byte, 0, 16)
	digits = append(digits, "400000"...)
	digits = appendPadded(digits, n%1_000_000_000, 9)
	digits = append(digits, byte('0'+luhnCheck(digits)))

	var b strings.Builder
	b.Grow(19)
	for i := 0; i < len(digits); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.Write(digits[i : i+4])
	}
	return b.String()
}

// syntheticINN возвращает двенадцатизначный ИНН физического лица с верными
// контрольными разрядами. Первые четыре цифры — 0000: кода налогового органа
// с таким номером не существует, поэтому номер не может совпасть с чужим.
func syntheticINN(n int) string {
	digits := make([]byte, 0, 12)
	digits = append(digits, "0000"...)
	// +1: нулевая последовательность дала бы номер из одних нулей, который
	// формально проходит проверку, но выглядит как незаполненное поле, а не
	// как данные.
	digits = appendPadded(digits, n%999_999+1, 6)
	digits = append(digits, byte('0'+innControl(digits, innWeights11[:])))
	digits = append(digits, byte('0'+innControl(digits, innWeights12[:])))
	return string(digits)
}

// syntheticSNILS возвращает СНИЛС с верной контрольной суммой в обычном
// формате NNN-NNN-NNN NN. Номера ниже 001-001-998 не выдавались, поэтому
// диапазон, начинающийся с нулей, заведомо свободен.
func syntheticSNILS(n int) string {
	digits := make([]byte, 0, 11)
	digits = appendPadded(digits, n%999_999_999+1, 9)
	digits = appendPadded(digits, snilsControl(digits), 2)

	var b strings.Builder
	b.Grow(14)
	b.Write(digits[0:3])
	b.WriteByte('-')
	b.Write(digits[3:6])
	b.WriteByte('-')
	b.Write(digits[6:9])
	b.WriteByte(' ')
	b.Write(digits[9:11])
	return b.String()
}

// syntheticAccount возвращает номер банковского счёта той же формы, что
// настоящий: двадцать цифр подряд, балансовый счёт 40817 — счёт физического
// лица. Шестая–восьмая цифры — код валюты 000: в классификаторе валют его
// нет, поэтому такой счёт ни одному банку принадлежать не может. Меняется
// номер лицевого счёта — последние семь цифр; +1, чтобы не выдать номер из
// одних нулей, похожий на незаполненное поле.
func syntheticAccount(n int) string {
	digits := make([]byte, 0, 20)
	digits = append(digits, "4081700000000"...)
	digits = appendPadded(digits, n%9_999_999+1, 7)
	return string(digits)
}

// syntheticDate возвращает дату 01.01.1970 со сдвигом на номер значения.
// Сдвиг по дням, а не по годам: так разные даты в одном запросе остаются
// разными, не уезжая в неправдоподобное будущее.
func syntheticDate(n int) string {
	d := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n%36500)
	return d.Format("02.01.2006")
}

// syntheticAddresses — вымышленные адреса. Топонимы выбраны заведомо
// несуществующими: подставлять реальный адрес вместо реального адреса нельзя,
// иначе маскирование превращается в оговор ни при чём не причастного жильца.
var syntheticAddresses = []string{
	"г. Тестоград, ул. Примерная, д. 1, кв. 1",
	"г. Образцовск, ул. Вымышленная, д. 12, кв. 5",
	"г. Условный, пр-т Синтетический, д. 7, кв. 21",
	"г. Нулевск, ул. Демонстрационная, д. 3, кв. 14",
	"г. Пробный, ул. Заполненная, д. 25, кв. 2",
	"г. Макетов, б-р Показательный, д. 9, кв. 33",
	"г. Эталонный, ул. Сгенерированная, д. 4, кв. 8",
	"г. Черновой, пер. Служебный, д. 16, кв. 7",
}

// syntheticCities — те же населённые пункты без улицы и дома: место рождения
// записывается городом, а не полным адресом.
var syntheticCities = buildCities(syntheticAddresses)

func buildCities(addrs []string) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		city, _, _ := strings.Cut(a, ",")
		out[i] = city
	}
	return out
}

// Веса контрольных разрядов двенадцатизначного ИНН. Дублируют таблицы
// пакета detect осознанно: там они неэкспортируемые, а тянуть ради двух
// массивов зависимость маскирования от внутренностей детекции не стоит.
// Совпадение результата проверяется тестом через detect.INN.
var (
	innWeights11 = [10]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	innWeights12 = [11]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
)

// innControl считает контрольный разряд ИНН по набору весов.
func innControl(digits []byte, weights []int) int {
	sum := 0
	for i, w := range weights {
		sum += int(digits[i]-'0') * w
	}
	return sum % 11 % 10
}

// snilsControl считает контрольное число СНИЛС по девяти значащим цифрам.
// Правило повторяет проверку detect.SNILS, включая обнуление значений 100
// и 101, которые не помещаются в два разряда.
func snilsControl(digits []byte) int {
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(digits[i]-'0') * (9 - i)
	}
	if sum > 101 {
		sum %= 101
	}
	if sum >= 100 {
		return 0
	}
	return sum
}

// luhnCheck возвращает контрольную цифру, дополняющую digits до верной суммы
// по алгоритму Луна.
func luhnCheck(digits []byte) int {
	sum := 0
	double := true // ближайшая слева от контрольной цифра удваивается
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

// writePadded пишет десятичное число, дополненное нулями слева до width
// знаков. Числа шире width пишутся целиком.
func writePadded(b *strings.Builder, v, width int) {
	var buf [20]byte
	b.Write(appendPadded(buf[:0], v, width))
}

// appendPadded дописывает десятичное число с дополнением нулями слева.
func appendPadded(dst []byte, v, width int) []byte {
	var buf [20]byte
	i := len(buf)
	for {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			break
		}
	}
	for n := len(buf) - i; n < width; n++ {
		dst = append(dst, '0')
	}
	return append(dst, buf[i:]...)
}

// hasCyrillic сообщает, есть ли в строке кириллическая буква.
func hasCyrillic(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return true
		}
	}
	return false
}

// translitTable — упрощённая транслитерация кириллицы в латиницу для имени
// держателя карты. Полнота стандарта здесь не нужна: справочник имён
// фиксирован и целиком покрывается таблицей, что проверяется тестом.
var translitTable = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e",
	'ж': "zh", 'з': "z", 'и': "i", 'й': "i", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
	'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "shch",
	'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "iu", 'я': "ia",
}

// translit переводит строку в латиницу. Символы вне таблицы отбрасываются:
// в замену не должно просочиться ничего, что не является буквой имени.
func translit(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if v, ok := translitTable[r]; ok {
			b.WriteString(v)
		}
	}
	return b.String()
}

var (
	synSurnames    []string
	synNames       []string
	synPatronymics []string
)

func init() {
	sections := parseNameSections(syntheticNamesData)
	synSurnames = sections["surnames"]
	synNames = sections["names"]
	synPatronymics = sections["patronymics"]
	// Пустой справочник означал бы деление на ноль в горячем пути на первом
	// же запросе. Падать лучше на старте: файл встроен в бинарник, и если он
	// испорчен, ни один запрос всё равно не будет обработан правильно.
	if len(synSurnames) == 0 || len(synNames) == 0 || len(synPatronymics) == 0 {
		panic("mask: справочник synthetic_names.txt пуст или повреждён")
	}
	Register(Synthetic{})
}

// parseNameSections разбирает справочник: строки [section] открывают секцию,
// пустые строки и строки с «#» пропускаются.
func parseNameSections(raw string) map[string][]string {
	out := make(map[string][]string, 3)
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		if section == "" {
			continue
		}
		out[section] = append(out[section], line)
	}
	return out
}

// Роли и род слов ФИО, склонение вымышленных имён и производные формы для
// восстановления ответа модели (Б4-8, T-68).

// nameRole — роль слова в ФИО.
type nameRole uint8

const (
	roleSurname nameRole = iota
	roleGiven
	rolePatronymic
	roleInitials
	roleUnknown
)

// nameShape — роли слов исходного ФИО и его род.
type nameShape struct {
	roles  []nameRole
	female bool
	// source — откуда взят род (genderUnknown…genderByPatronymic): более
	// надёжный источник переопределяет менее надёжный, но не наоборот.
	source int
}

// givenNames — справочник личных имён детекции с меткой рода.
//
// Берётся тот же файл, по которому детекция находит имена: роль слова в
// замене должна совпадать с тем, как его прочитала детекция. Загружается
// один раз при первом обращении: стратегия synthetic нужна не всем
// потребителям, и платить за неё на старте незачем.
var givenNames = sync.OnceValue(func() *dict.Table {
	set, err := dict.Load()
	if err != nil {
		// Встроенный справочник не читается — значит, испорчен бинарник.
		// Роли тогда определяются по суффиксам и позиции: замена остаётся
		// вымышленной, просто хуже повторяет форму исходного значения.
		return nil
	}
	return set.Table("given_names")
})

// Источник сведений о роде: чем больше, тем надёжнее.
const (
	genderUnknown = iota
	genderBySurname
	genderByGiven
	genderByPatronymic
)

// shapeOf определяет роль каждого слова и род ФИО.
//
// Отчество узнаётся по суффиксу, имя — по справочнику имён, инициалы — по
// форме «И.» или «И.И.». Остальные слова — фамилии. Если ни имени, ни
// отчества не нашлось, роли назначаются по позиции в порядке «фамилия, имя,
// отчество» — так пишут в анкетах, и так замена работала до T-68. Род берётся
// из отчества, затем из имени, затем из окончания фамилии; по умолчанию —
// мужской.
func shapeOf(words []string) nameShape {
	sh := nameShape{roles: make([]nameRole, len(words))}
	given := sh.markGiven(words)
	patronymic := sh.markPatronymic(words)
	if !given && !patronymic {
		sh.assignPositional()
	}
	sh.finishSurnames(words)
	return sh
}

// setGender запоминает род, если источник from надёжнее прежнего.
func (sh *nameShape) setGender(female bool, from int) {
	if from > sh.source {
		sh.female, sh.source = female, from
	}
}

// markGiven размечает инициалы и имена из справочника; остальные слова
// получают roleUnknown. Истина — нашлось хотя бы одно имя.
func (sh *nameShape) markGiven(words []string) bool {
	names := givenNames()
	known := false
	for i, w := range words {
		sh.roles[i] = roleUnknown
		if isInitials(w) {
			sh.roles[i] = roleInitials
			continue
		}
		if label, ok := names.Get(dict.Normalize(w)); ok {
			sh.roles[i] = roleGiven
			known = true
			sh.setGender(label == "f", genderByGiven)
		}
	}
	return known
}

// markPatronymic находит отчество среди неразмеченных слов. Истина —
// отчество нашлось.
//
// Отчество — не первым словом, если слов больше одного: «Мицкевич Анна»
// начинается с фамилии, похожей на отчество. И не вразрез с родом имени:
// «Анна Мицкевич» — фамилия, а не мужское отчество женщины.
func (sh *nameShape) markPatronymic(words []string) bool {
	for i, w := range words {
		if sh.roles[i] != roleUnknown || (i == 0 && len(words) > 1) {
			continue
		}
		female, ok := patronymicGender(w)
		if !ok || (sh.source == genderByGiven && female != sh.female) {
			continue
		}
		sh.roles[i] = rolePatronymic
		sh.setGender(female, genderByPatronymic)
		// Имя, которого нет в справочнике, стоит перед отчеством.
		if i > 0 && sh.roles[i-1] == roleUnknown && !hasRole(sh.roles, roleGiven) {
			sh.roles[i-1] = roleGiven
		}
		return true
	}
	return false
}

// assignPositional назначает неразмеченным словам роли по позиции в порядке
// «фамилия, имя, отчество»; слова сверх трёх — фамилии.
func (sh *nameShape) assignPositional() {
	positional := [...]nameRole{roleSurname, roleGiven, rolePatronymic}
	k := 0
	for i := range sh.roles {
		if sh.roles[i] != roleUnknown {
			continue
		}
		sh.roles[i] = roleSurname
		if k < len(positional) {
			sh.roles[i] = positional[k]
		}
		k++
	}
}

// finishSurnames делает фамилиями оставшиеся слова и уточняет род по
// окончанию фамилий.
func (sh *nameShape) finishSurnames(words []string) {
	for i, w := range words {
		if sh.roles[i] == roleUnknown {
			sh.roles[i] = roleSurname
		}
		if sh.roles[i] == roleSurname && isFemaleSurname(w) {
			sh.setGender(true, genderBySurname)
		}
	}
}

func hasRole(roles []nameRole, r nameRole) bool {
	for _, v := range roles {
		if v == r {
			return true
		}
	}
	return false
}

// patronymicGender узнаёт отчество по суффиксу и возвращает его род.
func patronymicGender(w string) (female, ok bool) {
	lw := dict.Normalize(w)
	n := utf8.RuneCountInString(lw)
	switch {
	case hasAnySuffix(lw, "вна", "чна", "кызы", "гызы"):
		return true, n >= 5
	case hasAnySuffix(lw, "вич", "оглы", "улы"):
		return false, n >= 4
	case strings.HasSuffix(lw, "ич"):
		return false, n >= 5
	}
	return false, false
}

// isFemaleSurname — фамилия в женской форме по окончанию.
func isFemaleSurname(w string) bool {
	return hasAnySuffix(dict.Normalize(w), "ова", "ева", "ина", "ына", "ская", "цкая")
}

// isInitials — слово из одного-трёх инициалов: «И.», «И.И.», «И.И».
func isInitials(w string) bool {
	letters, prevLetter, dot := 0, false, false
	for _, r := range w {
		switch {
		case unicode.IsLetter(r) && unicode.IsUpper(r):
			if prevLetter {
				return false
			}
			letters++
			prevLetter = true
		case r == '.':
			if !prevLetter {
				return false
			}
			dot, prevLetter = true, false
		default:
			return false
		}
	}
	return dot && letters <= 3
}

func synthSurname(n int, female bool) string {
	s := synSurnames[n%len(synSurnames)]
	if female {
		// Все фамилии справочника оканчиваются на -ов, -ев, -ёв или -ин:
		// женская форма получается окончанием -а, что проверяется тестом.
		return s + "а"
	}
	return s
}

func synthGiven(n int, female bool) string {
	if female {
		return synFemaleNames[(n/len(synSurnames))%len(synFemaleNames)]
	}
	return pickName(n)
}

func synthPatronymic(n int, female bool) string {
	p := pickPatronymic(n)
	if female {
		return femalePatronymic(p)
	}
	return p
}

// femalePatronymic образует женское отчество от мужского из справочника.
func femalePatronymic(p string) string {
	switch {
	case strings.HasSuffix(p, "вич"):
		return strings.TrimSuffix(p, "ич") + "на"
	case p == "Ильич":
		return "Ильинична"
	default:
		return strings.TrimSuffix(p, "ич") + "ична"
	}
}

// synthInitials заменяет инициалы инициалами вымышленных имени и отчества в
// той же записи: «И.И.» — «П.П.», «И.» — «П.». Счётчик k — сколько инициалов
// уже выдано в этом ФИО: второй инициал берётся из отчества.
func synthInitials(w string, n int, female bool, k int) (string, int) {
	parts := [...]string{synthGiven(n, female), synthPatronymic(n, female)}
	var b strings.Builder
	for _, r := range w {
		if r == '.' {
			b.WriteByte('.')
			continue
		}
		first, _ := utf8.DecodeRuneInString(parts[min(k, len(parts)-1)])
		b.WriteRune(first)
		k++
	}
	return b.String(), k
}

// synFemaleNames — вымышленные женские имена для женских ФИО.
//
// Список живёт здесь, а не в data/synthetic_names.txt: файл данных вне зоны
// задачи T-68. Ни одно имя не совпадает с нарицательным существительным (нет
// «Веры», «Надежды», «Любови»): иначе восстановление ответа модели приняло бы
// слово «Вера» в начале фразы за имя. Все имена склоняются по правилам
// inflectName, что проверяется тестом.
var synFemaleNames = []string{
	"Анна", "Мария", "Елена", "Ольга", "Наталья", "Ирина", "Татьяна", "Светлана",
	"Екатерина", "Юлия", "Анастасия", "Дарья", "Ксения", "Марина", "Галина", "Людмила",
	"Валентина", "Нина", "Алла", "Лариса", "Тамара", "Алина", "Полина", "Софья",
	"Вероника", "Виктория", "Кристина", "Евгения", "Жанна", "Инна", "Лидия", "Олеся",
	"Раиса", "Римма", "Элина", "Яна", "Алёна", "Василиса", "Варвара", "Диана",
	"Зинаида", "Карина", "Маргарита", "Милана", "Оксана", "Регина", "Снежана", "Ульяна",
	"Эвелина", "Ярослава",
}

// NameForm — производная форма вымышленного ФИО и соответствующая ей форма
// исходного значения.
type NameForm struct {
	// Synthetic — как форма может встретиться в ответе модели.
	Synthetic string
	// Original — чем её заменить при восстановлении.
	Original string
}

// nameCase — падеж.
type nameCase uint8

const (
	caseNom nameCase = iota
	caseGen
	caseDat
	caseAcc
	caseIns
	casePrep
	caseCount
)

// SyntheticNameForms перечисляет частичные и склонённые формы вымышленного
// ФИО repl, выданного вместо orig, с соответствующими формами orig (Б4-8).
//
// Модель пишет не «Петрова Анна Петровна», а «Анна Петровна», «Анне
// Петровне», «Петровой». Без этих форм ответ уходил клиенту с вымышленным
// именем, а повторная детекция принимала его за новое ФИО и маскировала
// следующей синтетикой — отсюда «Сидоров Пётр» в ответе клиентке.
//
// Формы — все непрерывные части ФИО во всех падежах, плюс написание через «е»
// вместо «ё». Слово замены соответствует слову исходного значения той же
// позиции: роли и порядок слов у них общие по построению syntheticFullName.
// Исходное значение склоняется, если его окончание склоняется по тем же
// правилам; иначе подставляется именительный падеж — «Шевчук» в женском роде
// не склоняется, и это и есть верная форма. Полная форма в именительном
// падеже не перечисляется: это сама выданная маска. Форма, у которой два
// разных прочтения исходного значения, отбрасывается.
//
// Функция чистая: тот же вход — тот же список.
func SyntheticNameForms(orig, repl string) []NameForm {
	ow, sw := strings.Fields(orig), strings.Fields(repl)
	if len(ow) == 0 || len(ow) != len(sw) {
		return nil
	}
	f := nameForms{
		orig:  ow,
		repl:  sw,
		shape: shapeOf(ow),
		synW:  make([]string, len(ow)),
		orgW:  make([]string, len(ow)),
	}
	seen := make(map[string]int, 8*len(ow))
	var out []NameForm
	for i := range ow {
		for j := i; j < len(ow); j++ {
			if !onlyInitials(f.shape.roles[i : j+1]) {
				out = f.addSpan(seen, out, i, j)
			}
		}
	}
	return keptForms(out)
}

// addForm дописывает в out форму syn с исходной формой org, если её там ещё
// нет; seen — номер каждой формы в out. У повторной syn с другим прочтением
// org исходная форма стирается: такая форма неоднозначна.
//
// Карта и срез передаются порознь, а не одной структурой: анализ побега не
// различает поля, и возврат среза из SyntheticNameForms увёл бы в кучу и
// заголовок карты.
func addForm(seen map[string]int, out []NameForm, syn, org string) []NameForm {
	if i, dup := seen[syn]; dup {
		if out[i].Original != org {
			out[i].Original = ""
		}
		return out
	}
	seen[syn] = len(out)
	return append(out, NameForm{Synthetic: syn, Original: org})
}

// keptForms отбрасывает неоднозначные формы и формы, совпавшие с исходными.
func keptForms(out []NameForm) []NameForm {
	kept := out[:0]
	for _, f := range out {
		if f.Original != "" && f.Synthetic != f.Original {
			kept = append(kept, f)
		}
	}
	return kept
}

// yoToE — написание формы через «е» вместо «ё». Replacer безопасен для
// одновременного использования и собирается один раз.
var yoToE = strings.NewReplacer("ё", "е", "Ё", "Е")

// nameForms — слова исходного значения и замены с общими ролями и буферы
// слов одной формы. Буферы длины len(orig) заполняются по индексу.
type nameForms struct {
	orig, repl []string
	shape      nameShape
	synW, orgW []string
}

// addSpan дописывает в out формы части ФИО из слов i…j во всех падежах.
// Полная форма в именительном падеже пропускается: это сама выданная маска.
func (f *nameForms) addSpan(seen map[string]int, out []NameForm, i, j int) []NameForm {
	for c := caseNom; c < caseCount; c++ {
		if i == 0 && j == len(f.orig)-1 && c == caseNom {
			continue
		}
		syn, org, ok := f.formAt(i, j, c)
		if !ok {
			continue
		}
		out = addForm(seen, out, syn, org)
		if strings.ContainsAny(syn, "ёЁ") {
			out = addForm(seen, out, yoToE.Replace(syn), org)
		}
	}
	return out
}

// formAt ставит слова i…j замены и исходного значения в падеж c. Ложь —
// слово замены в этом падеже не склоняется. Несклоняемое слово исходного
// значения остаётся в именительном падеже.
func (f *nameForms) formAt(i, j int, c nameCase) (syn, org string, ok bool) {
	n := 0
	ok = true
	for k := i; k <= j && ok; k++ {
		sv, sok := inflectName(f.repl[k], f.shape.roles[k], f.shape.female, c)
		ov, ook := inflectName(f.orig[k], f.shape.roles[k], f.shape.female, c)
		if !ook {
			ov = f.orig[k]
		}
		ok = sok
		f.synW[n], f.orgW[n] = sv, ov
		n++
	}
	if !ok {
		return "", "", false
	}
	return strings.Join(f.synW[:n], " "), strings.Join(f.orgW[:n], " "), true
}

func onlyInitials(roles []nameRole) bool {
	for _, r := range roles {
		if r != roleInitials {
			return false
		}
	}
	return true
}

// fleetingStems — мужские имена с беглой гласной: основа косвенных падежей.
var fleetingStems = map[string]string{"петр": "Петр", "павел": "Павл", "лев": "Льв"}

// inflectName ставит слово ФИО в падеж c. Второе значение ложно, если
// окончание слова не склоняется по известным правилам: вызывающий решает,
// оставить ли именительный падеж или отказаться от формы.
//
// Правила покрывают вымышленные имена целиком (это проверяется тестом) и
// обиходные русские формы исходных значений: фамилии на -ов, -ев, -ин, -ын,
// отчества на -ич и -на, имена на согласный, -й, -ь, -а, -я, -ия.
func inflectName(w string, role nameRole, female bool, c nameCase) (string, bool) {
	if c == caseNom || role == roleInitials {
		return w, true
	}
	in := inflector{
		w:      w,
		lw:     dict.Normalize(w),
		upper:  w == strings.ToUpper(w) && w != strings.ToLower(w),
		female: female,
		c:      c,
	}
	switch role {
	case roleSurname:
		return in.surname()
	case rolePatronymic:
		return in.patronymic()
	case roleGiven:
		return in.given()
	}
	return "", false
}

// caseEnds — окончания по падежам; именительный не используется.
type caseEnds [caseCount]string

// Окончания косвенных падежей: родительный, дательный, винительный,
// творительный, предложный.
var (
	endsSurnameFemale    = caseEnds{"", "ой", "ой", "у", "ой", "ой"}
	endsSurnameMale      = caseEnds{"", "а", "у", "а", "ым", "е"}
	endsPatronymicMale   = caseEnds{"", "а", "у", "а", "ем", "е"}
	endsPatronymicFemale = caseEnds{"", "ы", "е", "у", "ой", "е"}
	endsFleeting         = caseEnds{"", "а", "у", "а", "ом", "е"}
	endsGivenIy          = caseEnds{"", "я", "ю", "я", "ем", "и"}
	endsGivenSoft        = caseEnds{"", "я", "ю", "я", "ем", "е"}
	endsGivenIya         = caseEnds{"", "и", "и", "ю", "ей", "и"}
	endsGivenYa          = caseEnds{"", "и", "е", "ю", "ей", "е"}
)

// inflector — слово ФИО, которое ставится в падеж c.
type inflector struct {
	w      string // слово как есть
	lw     string // нормализованное слово
	upper  bool   // слово записано заглавными: окончание тоже заглавное
	female bool
	c      nameCase
}

// form — основа stem с окончанием падежа c из ends.
func (in inflector) form(stem string, ends caseEnds) (string, bool) {
	end := ends[in.c]
	if in.upper {
		end = strings.ToUpper(end)
	}
	return stem + end, true
}

// stem — слово без последней буквы.
func (in inflector) stem() string {
	runes := []rune(in.w)
	return string(runes[:len(runes)-1])
}

// surname склоняет фамилию на -ов, -ев, -ин, -ын и её женскую форму.
func (in inflector) surname() (string, bool) {
	if in.female {
		if hasAnySuffix(in.lw, "ова", "ева", "ина", "ына") {
			return in.form(in.stem(), endsSurnameFemale)
		}
		return "", false
	}
	if hasAnySuffix(in.lw, "ов", "ев", "ин", "ын") {
		return in.form(in.w, endsSurnameMale)
	}
	return "", false
}

// patronymic склоняет отчество на -ич и женское на -на.
func (in inflector) patronymic() (string, bool) {
	if !in.female && strings.HasSuffix(in.lw, "ич") {
		return in.form(in.w, endsPatronymicMale)
	}
	if in.female && strings.HasSuffix(in.lw, "на") {
		return in.form(in.stem(), endsPatronymicFemale)
	}
	return "", false
}

// given склоняет личное имя: беглая гласная, -ий, -й, -ь, -ия, -я, -а и
// мужские имена на согласный.
func (in inflector) given() (string, bool) {
	if stem, ok := fleetingStems[in.lw]; ok && !in.female {
		if in.upper {
			stem = strings.ToUpper(stem)
		}
		return in.form(stem, endsFleeting)
	}
	last, _ := utf8.DecodeLastRuneInString(in.lw)
	switch {
	case strings.HasSuffix(in.lw, "ий"):
		return in.form(in.stem(), endsGivenIy)
	case (last == 'й' || last == 'ь') && !in.female:
		return in.form(in.stem(), endsGivenSoft)
	case strings.HasSuffix(in.lw, "ия"):
		return in.form(in.stem(), endsGivenIya)
	case last == 'я':
		return in.form(in.stem(), endsGivenYa)
	case last == 'а':
		return in.givenA()
	case !in.female && unicode.IsLetter(last) && !strings.ContainsRune("аеиоуыэюяь", last):
		return in.givenConsonant(last)
	}
	return "", false
}

// givenA склоняет имя на -а: после шипящих и заднеязычных родительный на -и,
// после шипящих и «ц» творительный на -ей.
func (in inflector) givenA() (string, bool) {
	prev, _ := utf8.DecodeLastRuneInString(strings.TrimSuffix(in.lw, "а"))
	gen, ins := "ы", "ой"
	if strings.ContainsRune("гкхжшчщ", prev) {
		gen = "и"
	}
	if strings.ContainsRune("жшчщц", prev) {
		ins = "ей"
	}
	return in.form(in.stem(), caseEnds{"", gen, "е", "у", ins, "е"})
}

// givenConsonant склоняет мужское имя на согласный last: после шипящих и
// «ц» творительный на -ем.
func (in inflector) givenConsonant(last rune) (string, bool) {
	ins := "ом"
	if strings.ContainsRune("жшчщц", last) {
		ins = "ем"
	}
	return in.form(in.w, caseEnds{"", "а", "у", "а", ins, "е"})
}

func hasAnySuffix(s string, sufs ...string) bool {
	for _, suf := range sufs {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}
