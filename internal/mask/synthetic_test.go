package mask

import (
	"strconv"
	"strings"
	"testing"
	"unicode"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/pii"
)

var (
	syntheticStrategy   Synthetic
	placeholderStrategy Placeholder
)

// Исходные значения ниже — вымышленные: телефоны из служебного диапазона,
// адреса в example.org, ИНН и СНИЛС с произвольными цифрами.

func TestSyntheticRegistered(t *testing.T) {
	s, ok := ByName(strategySynthetic)
	if !ok {
		t.Fatal("стратегия synthetic не зарегистрирована")
	}
	if s.Name() != strategySynthetic {
		t.Fatalf("Name() = %q, ожидалось \"synthetic\"", s.Name())
	}
}

// TestSyntheticDeterministic — без этого свойства повтор прямого шага вернул бы
// другую маску и сломал идемпотентность контракта /process.
func TestSyntheticDeterministic(t *testing.T) {
	cases := []struct {
		t    pii.Type
		orig string
	}{
		{pii.FullName, fioPetrov},
		{pii.Phone, "+7 900 000-11-22"},
		{pii.Email, "user7@example.org"},
		{pii.CardNumber, "4000 0000 0000 0002"},
		{pii.INN, "000000000184"},
		{pii.SNILS, "000-000-001 01"},
		{pii.BirthDate, epochDate},
		{pii.Address, "г. Тестоград, ул. Примерная, д. 1"},
		{pii.BirthPlace, "г. Тестоград"},
		{pii.CardHolder, "PETR PETROV"},
		{pii.PIN, fourZeros},
	}
	for _, c := range cases {
		want := syntheticStrategy.Mask(c.orig, c.t, 3)
		for i := 0; i < 20; i++ {
			if got := syntheticStrategy.Mask(c.orig, c.t, 3); got != want {
				t.Fatalf("%s: вызов %d дал %q, первый — %q", c.t.Key(), i, got, want)
			}
		}
	}
}

// TestSyntheticCardPassesLuhn — AC-3. Номер без верной контрольной суммы
// отбраковывается любым валидатором, и замена перестаёт быть правдоподобной.
func TestSyntheticCardPassesLuhn(t *testing.T) {
	for seq := 1; seq <= 200; seq++ {
		card := syntheticStrategy.Mask("4000 0000 0000 0002", pii.CardNumber, seq)
		digits := digitsOf(card)
		if len(digits) != 16 {
			t.Fatalf("seq=%d: номер %q содержит %d цифр, ожидалось 16", seq, card, len(digits))
		}
		if !detect.Luhn(digits) {
			t.Fatalf("seq=%d: номер %q не проходит проверку Луна", seq, card)
		}
		if !strings.HasPrefix(digits, "400000") {
			t.Fatalf("seq=%d: номер %q вне тестового диапазона 4000 00…", seq, card)
		}
	}
}

// TestSyntheticINNChecksum — AC-3. Контрольные разряды считаются в пакете mask
// по собственной копии весов; тест сверяет результат с проверкой detect.
func TestSyntheticINNChecksum(t *testing.T) {
	for seq := 1; seq <= 200; seq++ {
		inn := syntheticStrategy.Mask("000000000184", pii.INN, seq)
		if len(inn) != 12 {
			t.Fatalf("seq=%d: ИНН %q длиной %d, ожидалось 12", seq, inn, len(inn))
		}
		if !detect.INN(inn) {
			t.Fatalf("seq=%d: ИНН %q не проходит проверку контрольных сумм", seq, inn)
		}
		// Кода налогового органа 0000 не существует: номер заведомо ничей.
		if !strings.HasPrefix(inn, fourZeros) {
			t.Fatalf("seq=%d: ИНН %q не начинается с несуществующего кода 0000", seq, inn)
		}
	}
}

func TestSyntheticSNILSChecksum(t *testing.T) {
	for seq := 1; seq <= 200; seq++ {
		snils := syntheticStrategy.Mask("000-000-001 01", pii.SNILS, seq)
		digits := digitsOf(snils)
		if len(digits) != 11 {
			t.Fatalf("seq=%d: СНИЛС %q содержит %d цифр, ожидалось 11", seq, snils, len(digits))
		}
		if !detect.SNILS(digits) {
			t.Fatalf("seq=%d: СНИЛС %q не проходит проверку контрольной суммы", seq, snils)
		}
	}
}

// TestSyntheticNoRealContacts — AC-4. Самый важный инвариант стратегии:
// замена не должна попасть в чужой настоящий почтовый ящик или телефон.
func TestSyntheticNoRealContacts(t *testing.T) {
	for seq := 1; seq <= 500; seq++ {
		email := syntheticStrategy.Mask(mailUser1, pii.Email, seq)
		if !strings.HasSuffix(email, "@example.org") {
			t.Fatalf("seq=%d: адрес %q вне зарезервированного домена example.org", seq, email)
		}
		if strings.Count(email, "@") != 1 {
			t.Fatalf("seq=%d: адрес %q собран неверно", seq, email)
		}

		phone := syntheticStrategy.Mask(phoneSynthFirst, pii.Phone, seq)
		if !strings.HasPrefix(phone, "+7 900 000-") {
			t.Fatalf("seq=%d: телефон %q вне служебного диапазона +7 900 000-…", seq, phone)
		}
		if len(digitsOf(phone)) != 11 {
			t.Fatalf("seq=%d: телефон %q содержит не 11 цифр", seq, phone)
		}
	}
}

// TestSyntheticPhoneDocumentedForm фиксирует форму из README для первых ста
// значений: +7 900 000-00-NN.
func TestSyntheticPhoneDocumentedForm(t *testing.T) {
	if got := syntheticStrategy.Mask(phoneSample, pii.Phone, 1); got != phoneSynthFirst {
		t.Fatalf("seq=1 дал %q, ожидалось \"+7 900 000-00-00\"", got)
	}
	if got := syntheticStrategy.Mask(phoneSample, pii.Phone, 8); got != "+7 900 000-00-07" {
		t.Fatalf("seq=8 дал %q, ожидалось \"+7 900 000-00-07\"", got)
	}
	// Сто первое значение не должно повторить первое.
	a := syntheticStrategy.Mask("a", pii.Phone, 1)
	b := syntheticStrategy.Mask("b", pii.Phone, 101)
	if a == b {
		t.Fatalf("значения 1 и 101 склеились в один телефон %q", a)
	}
}

func TestSyntheticEmailNumbering(t *testing.T) {
	if got := syntheticStrategy.Mask("ivan@example.org", pii.Email, 1); got != mailUser1 {
		t.Fatalf("seq=1 дал %q, ожидалось \"user1@example.org\"", got)
	}
	if got := syntheticStrategy.Mask("ivan@example.org", pii.Email, 42); got != "user42@example.org" {
		t.Fatalf("seq=42 дал %q, ожидалось \"user42@example.org\"", got)
	}
}

// TestSyntheticFullNameKeepsShape — замена не должна менять число слов:
// иначе фраза вокруг значения перестраивается сильнее, чем нужно.
func TestSyntheticFullNameKeepsShape(t *testing.T) {
	cases := map[string]int{
		surnamePetrov: 1,
		fioPetrov:     2,
		fioPetrovFull: 3,
		"Петров  Пётр Петрович": 3,
	}
	for orig, want := range cases {
		got := syntheticStrategy.Mask(orig, pii.FullName, 1)
		if n := len(strings.Fields(got)); n != want {
			t.Fatalf("%q → %q: %d слов, ожидалось %d", orig, got, n, want)
		}
		if got == orig {
			t.Fatalf("%q не было заменено", orig)
		}
	}
}

// TestSyntheticFullNameDistinct — разные значения получают разные номера
// и должны получать разные имена, иначе два человека в тексте склеятся.
//
// Исходные значения меняются вместе с номером: именно так работает Applier,
// который выдаёт новый номер каждому новому значению.
func TestSyntheticFullNameDistinct(t *testing.T) {
	seen := make(map[string]int, 512)
	for seq := 1; seq <= 500; seq++ {
		orig := "Тестовый" + strconv.Itoa(seq) + " Кандидат" + strconv.Itoa(seq)
		got := syntheticStrategy.Mask(orig, pii.FullName, seq)
		if prev, dup := seen[got]; dup {
			t.Fatalf("номера %d и %d дали одно ФИО %q", prev, seq, got)
		}
		seen[got] = seq
	}
}

// TestSyntheticNeverReturnsOriginal — REQ-301: значение скрывается целиком.
// Справочник конечен, поэтому замена рано или поздно попадает на само
// исходное значение; в этом случае стратегия обязана сдвинуться дальше.
func TestSyntheticNeverReturnsOriginal(t *testing.T) {
	for seq := 1; seq <= len(synSurnames)+1; seq++ {
		orig := synSurnames[(seq-1)%len(synSurnames)] + " " + pickName(seq-1)
		if got := syntheticStrategy.Mask(orig, pii.FullName, seq); got == orig {
			t.Fatalf("seq=%d: замена совпала с исходным значением %q", seq, orig)
		}
	}
	// То же для остальных типов: значение из служебного диапазона может
	// прийти на вход повторно, например при повторном маскировании.
	cases := []struct {
		t   pii.Type
		seq int
	}{
		{pii.Phone, 1}, {pii.Email, 1}, {pii.CardNumber, 1},
		{pii.INN, 1}, {pii.SNILS, 1}, {pii.BirthDate, 1},
		{pii.Address, 1}, {pii.BirthPlace, 1},
	}
	for _, c := range cases {
		own := syntheticStrategy.Mask("исходное значение", c.t, c.seq)
		if got := syntheticStrategy.Mask(own, c.t, c.seq); got == own {
			t.Fatalf("%s: повторное маскирование вернуло то же значение %q", c.t.Key(), own)
		}
	}
}

// TestSyntheticCardHolderScript — имя держателя печатается на карте латиницей;
// кириллическая запись заменяется кириллицей, латинская — латиницей.
func TestSyntheticCardHolderScript(t *testing.T) {
	lat := syntheticStrategy.Mask("IVAN IVANOV", pii.CardHolder, 1)
	if hasCyrillic(lat) {
		t.Fatalf("латинское имя держателя заменено кириллицей: %q", lat)
	}
	if lat != strings.ToUpper(lat) {
		t.Fatalf("имя держателя %q не в верхнем регистре", lat)
	}
	if len(strings.Fields(lat)) != 2 {
		t.Fatalf("имя держателя %q должно состоять из двух слов", lat)
	}

	cyr := syntheticStrategy.Mask(fioIvanov, pii.CardHolder, 1)
	if !hasCyrillic(cyr) {
		t.Fatalf("кириллическое имя держателя заменено латиницей: %q", cyr)
	}
}

// TestTranslitCoversDictionary подтверждает обещание комментария к таблице:
// справочник целиком покрывается транслитерацией, «дыр» в ней нет.
func TestTranslitCoversDictionary(t *testing.T) {
	for _, list := range [][]string{synSurnames, synNames, synPatronymics} {
		for _, word := range list {
			for _, r := range strings.ToLower(word) {
				if !unicode.Is(unicode.Cyrillic, r) {
					t.Fatalf("в справочнике встретился некириллический символ %q в %q", r, word)
				}
				if _, ok := translitTable[r]; !ok {
					t.Fatalf("буква %q из %q отсутствует в таблице транслитерации", r, word)
				}
			}
		}
	}
}

func TestSyntheticDates(t *testing.T) {
	if got := syntheticStrategy.Mask(birthDateSample, pii.BirthDate, 1); got != epochDate {
		t.Fatalf("seq=1 дал %q, ожидалось \"01.01.1970\"", got)
	}
	if got := syntheticStrategy.Mask(birthDateSample, pii.BirthDate, 2); got != "02.01.1970" {
		t.Fatalf("seq=2 дал %q, ожидалось \"02.01.1970\"", got)
	}
	// Дата выдачи паспорта обрабатывается тем же правилом.
	if got := syntheticStrategy.Mask("15.03.2015", pii.PassportIssueDate, 1); got != epochDate {
		t.Fatalf("дата выдачи: %q", got)
	}
}

func TestSyntheticAddressAndBirthPlace(t *testing.T) {
	addr := syntheticStrategy.Mask("г. Москва, ул. Ленина, д. 1", pii.Address, 1)
	if !contains(syntheticAddresses, addr) {
		t.Fatalf("адрес %q не из встроенного списка", addr)
	}
	city := syntheticStrategy.Mask("г. Москва", pii.BirthPlace, 1)
	if !contains(syntheticCities, city) {
		t.Fatalf("место рождения %q не из встроенного списка", city)
	}
	if strings.Contains(city, ",") {
		t.Fatalf("место рождения %q должно быть населённым пунктом без улицы", city)
	}
}

// TestSyntheticFallsBackToPlaceholder — для типов без правдоподобной замены
// выдумывать значение опаснее, чем показать плейсхолдер.
func TestSyntheticFallsBackToPlaceholder(t *testing.T) {
	for _, tp := range []pii.Type{pii.PIN, pii.CVV, pii.PassportNumber, pii.VIN} {
		got := syntheticStrategy.Mask(fourZeros, tp, 2)
		want := placeholderStrategy.Mask(fourZeros, tp, 2)
		if got != want {
			t.Fatalf("%s: %q, ожидался плейсхолдер %q", tp.Key(), got, want)
		}
	}
}

// TestSyntheticDictionarySize — требование задачи: не менее 50 фамилий
// и 50 имён, иначе замены начнут повторяться на первом же длинном документе.
func TestSyntheticDictionarySize(t *testing.T) {
	if len(synSurnames) < 50 {
		t.Fatalf("фамилий %d, требуется не менее 50", len(synSurnames))
	}
	if len(synNames) < 50 {
		t.Fatalf("имён %d, требуется не менее 50", len(synNames))
	}
	if len(synPatronymics) == 0 {
		t.Fatal("список отчеств пуст")
	}
	for _, list := range [][]string{synSurnames, synNames, synPatronymics} {
		seen := make(map[string]bool, len(list))
		for _, v := range list {
			if seen[v] {
				t.Fatalf("справочник содержит дубликат %q", v)
			}
			seen[v] = true
		}
	}
}

func TestParseNameSectionsSkipsCommentsAndBlanks(t *testing.T) {
	got := parseNameSections("# комментарий\n\n[surnames]\nПетров\n\n# ещё\nСидоров\n[names]\nПётр\n")
	if surnames := got["surnames"]; len(surnames) != 2 || surnames[0] != surnamePetrov {
		t.Fatalf("секция surnames разобрана как %v", surnames)
	}
	if len(got["names"]) != 1 {
		t.Fatalf("секция names разобрана как %v", got["names"])
	}
}

func TestSyntheticZeroSeqDoesNotPanic(t *testing.T) {
	// Номер значения всегда положителен, но стратегия вызывается и из демо-
	// стенда: отрицательный индекс массива уронил бы сервис.
	for _, seq := range []int{0, -1} {
		if got := syntheticStrategy.Mask(fioPetrov, pii.FullName, seq); got == "" {
			t.Fatalf("seq=%d дал пустую замену", seq)
		}
	}
}

// TestSyntheticBankAccount — номер банковского счёта (T-64): двадцать цифр
// той же формы, что настоящий счёт физического лица, но с несуществующим
// кодом валюты 000, поэтому заведомо ничей.
func TestSyntheticBankAccount(t *testing.T) {
	const orig = "40817810099910004312" // синтетический номер
	seen := make(map[string]int, 1000)
	for seq := 1; seq <= 1000; seq++ {
		acc := syntheticStrategy.Mask(orig, pii.BankAccount, seq)
		if len(acc) != 20 || digitsOf(acc) != acc {
			t.Fatalf("seq=%d: счёт %q — не двадцать цифр подряд", seq, acc)
		}
		if !strings.HasPrefix(acc, "40817") || acc[5:8] != "000" {
			t.Fatalf("seq=%d: счёт %q вне служебного диапазона 40817 000 …", seq, acc)
		}
		if acc == orig {
			t.Fatalf("seq=%d: замена совпала с исходным значением", seq)
		}
		if prev, ok := seen[acc]; ok {
			t.Fatalf("seq=%d и seq=%d дали один номер %q: разные счета склеились бы", prev, seq, acc)
		}
		seen[acc] = seq
		if again := syntheticStrategy.Mask(orig, pii.BankAccount, seq); again != acc {
			t.Fatalf("seq=%d: повтор дал %q, первый вызов — %q", seq, again, acc)
		}
	}
	own := syntheticStrategy.Mask(orig, pii.BankAccount, 1)
	if got := syntheticStrategy.Mask(own, pii.BankAccount, 1); got == own {
		t.Fatalf("повторное маскирование вернуло то же значение %q", own)
	}
}

// TestStrategiesMaskBankAccount — остальные стратегии от типа не зависят и
// новый тип обслуживают без правок: плейсхолдер берёт основу из реестра
// типов, звёздочки и токен тип не смотрят вовсе (T-64).
func TestStrategiesMaskBankAccount(t *testing.T) {
	const orig = "40817 810 0 9991 0004312" // синтетический номер
	if got := placeholderStrategy.Mask(orig, pii.BankAccount, 1); got != "[СЧЁТ_1]" {
		t.Errorf("placeholder: %q, ожидалось [СЧЁТ_1]", got)
	}
	if got := (Asterisks{}).Mask(orig, pii.BankAccount, 1); got != "***** *** * **** *******" {
		t.Errorf("asterisks: %q", got)
	}
	tok := (Token{}).Mask(orig, pii.BankAccount, 1)
	if !strings.HasPrefix(tok, tokenPrefix) || strings.Contains(tok, "40817") || strings.Contains(tok, "0004312") {
		t.Errorf("token: %q", tok)
	}
	for _, name := range Names() {
		s, _ := ByName(name)
		if got := s.Mask(orig, pii.BankAccount, 1); got == "" || strings.Contains(got, "0004312") {
			t.Errorf("%s: замена %q пуста или содержит исходные цифры", name, got)
		}
	}
}

func digitsOf(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// TestSyntheticFullNameMirrorsRolesAndGender — Б4-8, T-68: замена повторяет
// роли, порядок и род слов исходного ФИО. Мужское имя вместо женского
// заставляло модель писать «Уважаемый» клиентке.
func TestSyntheticFullNameMirrorsRolesAndGender(t *testing.T) {
	cases := map[string]string{
		"Шевчук Оксана Васильевна": "Петрова Анна Петровна",
		"Смирнов Олег Петрович":    fioPetrovFull,
		"Коваль Инна":              "Петрова Анна",
		"Инна Коваль":              "Анна Петрова",
		"Оксана Васильевна":        "Анна Петровна",
		"Олег Петрович Смирнов":    "Пётр Петрович Петров",
		"Иванов И.И.":              "Петров П.П.",
		"Иванова И. И.":            "Петрова А. П.",
		"Оксана":                   "Анна",
		"Мицкевич Анна":            "Петрова Анна",
		"Анна Мицкевич":            "Анна Петрова",
	}
	for orig, want := range cases {
		if got := syntheticStrategy.Mask(orig, pii.FullName, 1); got != want {
			t.Errorf("%q → %q, ожидалось %q", orig, got, want)
		}
	}
}

// TestSyntheticNameListsInflect — все вымышленные фамилии, имена и отчества
// склоняются по правилам inflectName в обоих родах: иначе частичная форма
// замены в ответе модели не нашлась бы при восстановлении.
func TestSyntheticNameListsInflect(t *testing.T) {
	for _, female := range []bool{false, true} {
		for n := 0; n < len(synSurnames); n++ {
			check(t, synthSurname(n, female), roleSurname, female)
		}
		for n := 0; n < len(synSurnames)*max(len(synNames), len(synFemaleNames)); n += len(synSurnames) {
			check(t, synthGiven(n, female), roleGiven, female)
		}
		for _, p := range synPatronymics {
			if female {
				p = femalePatronymic(p)
			}
			check(t, p, rolePatronymic, female)
		}
	}
	if got := femalePatronymic("Ильич"); got != "Ильинична" {
		t.Errorf("Ильич → %q", got)
	}
	if got := femalePatronymic("Никитич"); got != "Никитична" {
		t.Errorf("Никитич → %q", got)
	}
	if len(synFemaleNames) < 50 {
		t.Errorf("женских имён %d, требуется не менее 50", len(synFemaleNames))
	}
}

func check(t *testing.T, w string, role nameRole, female bool) {
	t.Helper()
	for c := caseGen; c < caseCount; c++ {
		got, ok := inflectName(w, role, female, c)
		if !ok || got == w || got == "" {
			t.Errorf("%q (роль %d, женский %v, падеж %d) не склоняется: %q", w, role, female, c, got)
		}
	}
}

// TestInflectNameForms — точечная проверка правил склонения.
func TestInflectNameForms(t *testing.T) {
	cases := []struct {
		w      string
		role   nameRole
		female bool
		c      nameCase
		want   string
	}{
		{"Пётр", roleGiven, false, caseDat, "Петру"},
		{"Павел", roleGiven, false, caseGen, "Павла"},
		{"Алексей", roleGiven, false, caseIns, "Алексеем"},
		{"Дмитрий", roleGiven, false, casePrep, "Дмитрии"},
		{"Игорь", roleGiven, false, caseDat, "Игорю"},
		{"Никита", roleGiven, false, caseAcc, "Никиту"},
		{"Ольга", roleGiven, true, caseGen, "Ольги"},
		{"Мария", roleGiven, true, caseDat, "Марии"},
		{"Наталья", roleGiven, true, caseIns, "Натальей"},
		{"Анна", roleGiven, true, caseDat, "Анне"},
		{surnamePetrov, roleSurname, false, caseIns, "Петровым"},
		{surnamePetrova, roleSurname, true, caseDat, "Петровой"},
		{surnamePetrova, roleSurname, true, caseAcc, "Петрову"},
		{"Петрович", rolePatronymic, false, caseDat, "Петровичу"},
		{"Петровна", rolePatronymic, true, caseGen, "Петровны"},
		{"ИВАНОВ", roleSurname, false, caseGen, "ИВАНОВА"},
	}
	for _, c := range cases {
		if got, ok := inflectName(c.w, c.role, c.female, c.c); !ok || got != c.want {
			t.Errorf("%q, падеж %d: %q, %v; ожидалось %q", c.w, c.c, got, ok, c.want)
		}
	}
	// Несклоняемое окончание — отказ: вызывающий оставит именительный падеж.
	if _, ok := inflectName("Шевчук", roleSurname, true, caseDat); ok {
		t.Error("женская фамилия Шевчук склонена")
	}
}

// TestSyntheticNameFormsMapComponents — частичные и склонённые формы замены
// сопоставлены формам исходного значения по словам.
func TestSyntheticNameFormsMapComponents(t *testing.T) {
	const orig = "Шевчук Оксана Васильевна"
	repl := syntheticStrategy.Mask(orig, pii.FullName, 1)
	forms := SyntheticNameForms(orig, repl)
	byForm := make(map[string]string, len(forms))
	for _, f := range forms {
		byForm[f.Synthetic] = f.Original
	}
	want := map[string]string{
		"Анна Петровна":          "Оксана Васильевна",
		"Анне Петровне":          "Оксане Васильевне",
		"Петровой Анне Петровне": "Шевчук Оксане Васильевне",
		surnamePetrova:           "Шевчук",
		"Анну":                   "Оксану",
		"Петровна":               "Васильевна",
	}
	for syn, org := range want {
		if got, ok := byForm[syn]; !ok || got != org {
			t.Errorf("форма %q → %q (%v), ожидалось %q", syn, got, ok, org)
		}
	}
	if _, ok := byForm[repl]; ok {
		t.Errorf("полная форма %q в именительном падеже повторяет выданную маску", repl)
	}

	male := SyntheticNameForms("Смирнов Олег Петрович", fioPetrovFull)
	found := map[string]string{}
	for _, f := range male {
		found[f.Synthetic] = f.Original
	}
	for syn, org := range map[string]string{
		"Пётр Петрович":   "Олег Петрович",
		"Петр Петрович":   "Олег Петрович",
		"Петру Петровичу": "Олегу Петровичу",
		"Петровым":        "Смирновым",
	} {
		if found[syn] != org {
			t.Errorf("форма %q → %q, ожидалось %q", syn, found[syn], org)
		}
	}
	// Одинаковые слова исходного значения и замены — не форма: «Петрович»
	// в обоих ФИО восстанавливать нечем и незачем.
	if _, ok := found["Петрович"]; ok {
		t.Error("слово, совпадающее в замене и оригинале, перечислено как форма")
	}
	if SyntheticNameForms(fioIvanov, surnamePetrov) != nil {
		t.Error("формы для замены с другим числом слов")
	}
}
