package corpus

import (
	"math/rand/v2"
	"testing"
)

// Синтетические фамилии, на которых проверяется склонение.
const (
	surMelnik        = "Мельник"
	surTsoi          = "Цой"
	surVeretennikov  = "Веретенников"
	surVeretennikova = "Веретенникова"
	surSoroka        = "Сорока"
	surZaozersky     = "Заозёрский"
)

// Все вариации написания даты по ТЗ §3.2.2 проверяются точными строками:
// перебор форм в генераторе опирается на этот порядок.
func TestRenderDateForms(t *testing.T) {
	d := date{day: 7, month: 3, year: 1987}
	want := []string{
		"07.03.1987",   // дд.мм.гггг
		"07/03/1987",   // дд/мм/гггг
		"07-03-1987",   // дд-мм-гггг
		"03.07.1987",   // мм.дд.гггг — переставлены день и месяц
		"1987-03-07",   // гггг-мм-дд
		"1987.07.03",   // гггг.дд.мм
		"7 марта 1987", // дата словами
		"седьмое марта 1987",
		"седьмое марта тысяча девятьсот восемьдесят седьмого", // дата словами целиком
		"07.03.87", // двузначный год
	}
	if len(want) != dateFormCount {
		t.Fatalf("проверяется %d форм, а объявлено %d", len(want), dateFormCount)
	}
	for i, w := range want {
		if got := renderDate(d, i, cNom); got != w {
			t.Errorf("форма %d: получено %q, ожидалось %q", i, got, w)
		}
	}
	if got := renderDate(d, 7, cGen); got != "седьмого марта 1987" {
		t.Errorf("родительный падеж словами: получено %q", got)
	}
	if got := renderDate(d, 8, cGen); got != "седьмого марта тысяча девятьсот восемьдесят седьмого" {
		t.Errorf("родительный падеж с годом словами: получено %q", got)
	}
}

// Год словами проверяется точными строками: детектор разбирает его сложением
// разрядов, и ошибка в разряде здесь дороже всего.
func TestYearWords(t *testing.T) {
	cases := map[int]string{
		1917: "тысяча девятьсот семнадцатого",
		1955: "тысяча девятьсот пятьдесят пятого",
		1987: "тысяча девятьсот восемьдесят седьмого",
		1990: "тысяча девятьсот девяностого",
		1900: "тысяча девятисотого",
		2000: "двухтысячного",
		2001: "две тысячи первого",
		2015: "две тысячи пятнадцатого",
		2020: "две тысячи двадцатого",
		2024: "две тысячи двадцать четвёртого",
	}
	for year, want := range cases {
		if got := yearWords(year); got != want {
			t.Errorf("%d: получено %q, ожидалось %q", year, got, want)
		}
	}
}

func TestOrdinalDay(t *testing.T) {
	cases := map[int][2]string{
		1:  {"первое", "первого"},
		3:  {"третье", "третьего"},
		12: {"двенадцатое", "двенадцатого"},
		20: {"двадцатое", "двадцатого"},
		21: {"двадцать первое", "двадцать первого"},
		30: {"тридцатое", "тридцатого"},
		31: {"тридцать первое", "тридцать первого"},
	}
	for day, want := range cases {
		nom := ordinalDay(day)
		if nom != want[0] {
			t.Errorf("%d: получено %q, ожидалось %q", day, nom, want[0])
		}
		if gen := ordinalGen(nom); gen != want[1] {
			t.Errorf("%d в родительном: получено %q, ожидалось %q", day, gen, want[1])
		}
	}
}

func TestDeclension(t *testing.T) {
	check := func(got word, nom, gen, acc string) {
		t.Helper()
		if got.nom != nom || got.gen != gen || got.acc != acc {
			t.Errorf("получено %q/%q/%q, ожидалось %q/%q/%q", got.nom, got.gen, got.acc, nom, gen, acc)
		}
	}
	check(mascNoun(surVeretennikov), surVeretennikov, surVeretennikova, surVeretennikova)
	check(mascNoun("Аркадий"), "Аркадий", "Аркадия", "Аркадия")
	check(mascAdj(surZaozersky), surZaozersky, "Заозёрского", "Заозёрского")
	check(mascAdj("Бережной"), "Бережной", "Бережного", "Бережного")
	check(femSur(surVeretennikov), surVeretennikova, "Веретенниковой", "Веретенникову")
	check(femAdj(surZaozersky), "Заозёрская", "Заозёрской", "Заозёрскую")
	check(femNoun("Марина"), "Марина", "Марины", "Марину")
	check(femNoun("Вероника"), "Вероника", "Вероники", "Веронику")
	check(femNoun("Ксения"), "Ксения", "Ксении", "Ксению")
	check(femNoun("Дарья"), "Дарья", "Дарьи", "Дарью")
	// Фамилии без русского суффикса (T-50): мужская склоняется, женская — нет,
	// кроме фамилий на «-а».
	check(mascNoun(surMelnik), surMelnik, "Мельника", "Мельника")
	check(mascNoun(surTsoi), surTsoi, "Цоя", "Цоя")
	check(mascNoun("Лебедь"), "Лебедь", "Лебедя", "Лебедя")
	check(mascNoun("Кравец"), "Кравец", "Кравца", "Кравца")
	check(mascNoun(surSoroka), surSoroka, "Сороки", "Сороку")
	check(femSur(surMelnik), surMelnik, surMelnik, surMelnik)
	check(femSur(surTsoi), surTsoi, surTsoi, surTsoi)
	check(femSur(surSoroka), surSoroka, "Сороки", "Сороку")
	check(femSur("Гвоздарёв"), "Гвоздарёва", "Гвоздарёвой", "Гвоздарёву")
	check(femSur("Ольхин"), "Ольхина", "Ольхиной", "Ольхину")
	if got := femPatronymic("Юрьевич"); got != "Юрьевна" {
		t.Errorf("женское отчество: получено %q", got)
	}
}

// Контрольная цифра Луна: без неё корпус не проверит достоверную детекцию карт.
func TestLuhn(t *testing.T) {
	if got := luhn("411111111111111"); got != 1 {
		t.Errorf("контрольная цифра = %d, ожидалась 1", got)
	}
	if got := luhn("555555555555444"); got != 4 {
		t.Errorf("контрольная цифра = %d, ожидалась 4", got)
	}
}

// Контрольные разряды ИНН проверяются на учебном примере из описания алгоритма.
func TestINNCheck(t *testing.T) {
	if got := innCheck("5001007322", innWeights11); got != 5 {
		t.Errorf("11-й разряд = %d, ожидался 5", got)
	}
	if got := innCheck("50010073225", innWeights12); got != 9 {
		t.Errorf("12-й разряд = %d, ожидался 9", got)
	}
}

func TestCountTokens(t *testing.T) {
	cases := map[string]int{
		"":                  0,
		"   ":               0,
		"одно":              1,
		"два  слова":        2,
		"строка\nи\tтабы  ": 3,
	}
	for in, want := range cases {
		if got := countTokens(in); got != want {
			t.Errorf("countTokens(%q) = %d, ожидалось %d", in, got, want)
		}
	}
}

// addCounted должен давать ту же сумму, что и подсчёт по всему тексту: на этом
// держится точность размеров длинных записей.
func TestAddCountedMatchesWhole(t *testing.T) {
	var b builder
	sum := b.addCounted(join(lit("первая группа слов")))
	for i := 0; i < 5; i++ {
		b.add(lit(" "))
		sum += b.addCounted(join(lit("ещё группа"), val(KCVV, "123"), lit(" хвост")))
	}
	if whole := countTokens(b.record(KindLong).Text); whole != sum {
		t.Fatalf("по группам %d токенов, по всему тексту %d", sum, whole)
	}
}

func TestToLatin(t *testing.T) {
	cases := map[string]string{
		"Пётр":          "PETR",
		surVeretennikov: "VERETENNIKOV",
		"Щукин":         "SHCHUKIN",
		"Юрий":          "IURII",
	}
	for in, want := range cases {
		if got := toLatin(in); got != want {
			t.Errorf("toLatin(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// Перебор вариаций не должен зависеть от случайности: каждая форма обязана
// встретиться, иначе при малом -count часть вариаций пропадёт из корпуса.
func TestFormCyclesCoverAllVariants(t *testing.T) {
	g := &gen{r: rand.New(rand.NewPCG(1, 2))}
	seen := map[int]bool{}
	for i := 0; i < dateFormCount*3; i++ {
		seen[g.next(&g.dateSeq, dateFormCount)] = true
	}
	if len(seen) != dateFormCount {
		t.Fatalf("перебор дал %d форм из %d", len(seen), dateFormCount)
	}
}
