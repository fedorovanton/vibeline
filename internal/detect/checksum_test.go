package detect

import "testing"

// Все номера в тестах синтетические либо публичные реквизиты юридических лиц:
// персональных данных в репозитории нет.

// caseNonDigit — имя общего для всех контрольных сумм случая: номер с
// нецифровым символом не проходит проверку.
const caseNonDigit = "нецифровой символ"

// checksumSink принимает результаты в проверке аллокаций, чтобы вызовы не
// были выброшены как не имеющие эффекта.
var checksumSink [3]bool

func TestLuhn(t *testing.T) {
	cases := []struct {
		name   string
		digits string
		want   bool
	}{
		{"карта из тестового диапазона", "4111111111111111", true},
		{"та же карта с испорченным разрядом", "4111111111111112", false},
		{"шестнадцать цифр, контрольная сумма сходится", "2200700123456781", true},
		{"шестнадцать цифр, контрольная сумма не сходится", "2200700123456789", false},
		{"восемнадцать цифр, контрольная сумма сходится", "220070012345678902", true},
		{"пустая строка", "", false},
		{"одна цифра", "7", false},
		{caseNonDigit, "4111-1111-1111-1111", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Luhn(c.digits); got != c.want {
				t.Fatalf("Luhn(%q) = %v, ожидалось %v", c.digits, got, c.want)
			}
		})
	}
}

func TestINN(t *testing.T) {
	cases := []struct {
		name   string
		digits string
		want   bool
	}{
		{"десять знаков, сумма верна", "7707083893", true},
		{"десять знаков, испорчен контрольный разряд", "7707083890", false},
		{"десять знаков, испорчен значащий разряд", "7707083993", false},
		{"двенадцать знаков, сумма верна", "500100732259", true},
		{"двенадцать знаков, испорчен последний разряд", "500100732258", false},
		{"двенадцать знаков, испорчен предпоследний разряд", "500100732249", false},
		{"одиннадцать знаков — не ИНН", "50010073225", false},
		{caseNonDigit, "77070838d3", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := INN(c.digits); got != c.want {
				t.Fatalf("INN(%q) = %v, ожидалось %v", c.digits, got, c.want)
			}
		})
	}
}

func TestSNILS(t *testing.T) {
	cases := []struct {
		name   string
		digits string
		want   bool
	}{
		{"сумма меньше ста", "11223344595", true},
		{"испорчен контрольный разряд", "11223344594", false},
		{"сумма равна ста — контрольное число ноль", "92000010000", true},
		{"сумма равна ста одному — контрольное число ноль", "92000000400", true},
		{"остаток от деления на 101 равен нулю", "99700000000", true},
		{"десять знаков — не СНИЛС", "1122334459", false},
		{caseNonDigit, "1122334459x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SNILS(c.digits); got != c.want {
				t.Fatalf("SNILS(%q) = %v, ожидалось %v", c.digits, got, c.want)
			}
		})
	}
}

// TestChecksumsNoAllocs закрепляет требование контракта: контрольные суммы
// вызываются на каждом кандидате и не аллоцируют.
func TestChecksumsNoAllocs(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() {
		checksumSink = [3]bool{Luhn("2200700123456781"), INN("500100732259"), SNILS("11223344595")}
	}); n != 0 {
		t.Fatalf("контрольные суммы аллоцируют: %.0f allocs/op", n)
	}
}
