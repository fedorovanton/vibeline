package detect

// Контрольные суммы цифровых реквизитов.
//
// Вход — строка из одних цифр: разделители снимает сканер, который и так
// разбирает число по токенам. Нецифровой символ не паника, а отрицательный
// ответ: строка приходит из пользовательского текста, а не из кода.
//
// Функции вызываются на каждом цифровом кандидате, поэтому не аллоцируют:
// ни срезов, ни строк, ни замыканий.

// innWeights10 — веса контрольного разряда десятизначного ИНН.
var innWeights10 = [9]int{2, 4, 10, 3, 5, 9, 4, 6, 8}

// innWeights11 — веса первого контрольного разряда двенадцатизначного ИНН.
var innWeights11 = [10]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}

// innWeights12 — веса второго контрольного разряда двенадцатизначного ИНН.
var innWeights12 = [11]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}

// Luhn проверяет контрольную сумму по алгоритму Луна.
//
// Длину номера карты функция не проверяет: длина — свойство формы, её
// контролирует правило сканера. Здесь проверяется только контрольная сумма,
// поэтому функцию можно переиспользовать для других номеров по Луна.
func Luhn(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d, ok := digitAt(digits, i)
		if !ok {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		double = !double
		sum += d
	}
	return sum%10 == 0
}

// INN проверяет контрольные суммы ИНН: один разряд у десятизначного номера
// организации и два разряда у двенадцатизначного номера физического лица.
func INN(digits string) bool {
	switch len(digits) {
	case 10:
		want, ok := innControl(digits, innWeights10[:])
		if !ok {
			return false
		}
		got, ok := digitAt(digits, 9)
		return ok && got == want
	case 12:
		want11, ok := innControl(digits, innWeights11[:])
		if !ok {
			return false
		}
		got11, ok := digitAt(digits, 10)
		if !ok || got11 != want11 {
			return false
		}
		want12, ok := innControl(digits, innWeights12[:])
		if !ok {
			return false
		}
		got12, ok := digitAt(digits, 11)
		return ok && got12 == want12
	default:
		return false
	}
}

// SNILS проверяет контрольную сумму одиннадцатизначного СНИЛС.
//
// Реализовано здесь вместе с остальными контрольными суммами, чтобы сканер
// СНИЛС не заводил второй набор арифметики по цифрам.
func SNILS(digits string) bool {
	if len(digits) != 11 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		d, ok := digitAt(digits, i)
		if !ok {
			return false
		}
		sum += d * (9 - i)
	}
	// Значения 100 и 101 приравнены к нулю: остаток от деления на 101 в этих
	// двух точках не помещается в два разряда контрольного числа.
	want := sum
	if want > 101 {
		want %= 101
	}
	if want >= 100 {
		want = 0
	}
	hi, ok := digitAt(digits, 9)
	if !ok {
		return false
	}
	lo, ok := digitAt(digits, 10)
	if !ok {
		return false
	}
	return hi*10+lo == want
}

// innControl считает контрольный разряд ИНН по набору весов.
// Второе значение — признак того, что все нужные позиции были цифрами.
func innControl(digits string, weights []int) (int, bool) {
	if len(digits) < len(weights) {
		return 0, false
	}
	sum := 0
	for i, w := range weights {
		d, ok := digitAt(digits, i)
		if !ok {
			return 0, false
		}
		sum += d * w
	}
	return sum % 11 % 10, true
}

// digitAt возвращает цифру строки по позиции. Второе значение — признак того,
// что символ действительно цифра.
func digitAt(s string, i int) (int, bool) {
	c := s[i]
	if c < '0' || c > '9' {
		return 0, false
	}
	return int(c - '0'), true
}

// OGRN проверяет контрольный разряд ОГРН (13 цифр) и ОГРНИП (15 цифр).
//
// Правило одно и то же: число без последнего разряда делится с остатком на
// «длина минус два», остаток берётся по модулю десять и сравнивается с
// последним разрядом. Остаток считается потоком по цифрам, а не переводом
// в целое: пятнадцать разрядов в int64 поместились бы, но поток не зависит
// от разрядности и не аллоцирует.
func OGRN(digits string) bool {
	var mod int
	switch len(digits) {
	case 13:
		mod = 11
	case 15:
		mod = 13
	default:
		return false
	}
	rem := 0
	for i := 0; i < len(digits)-1; i++ {
		d, ok := digitAt(digits, i)
		if !ok {
			return false
		}
		rem = (rem*10 + d) % mod
	}
	got, ok := digitAt(digits, len(digits)-1)
	return ok && got == rem%10
}

// vinWeights — веса позиций VIN при расчёте контрольного символа.
var vinWeights = [17]int{8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2}

// VINCheck проверяет контрольный символ VIN — девятый по счёту.
//
// Обязательным он является только в Северной Америке, поэтому провал проверки
// не означает, что строка не VIN: сканер трактует его как отсутствие
// подтверждения, а не как запрет. Регистр не важен: буквы приводятся к
// верхнему без выделения строки.
func VINCheck(vin string) bool {
	if len(vin) != 17 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		v, ok := vinValue(vin[i])
		if !ok {
			return false
		}
		sum += v * vinWeights[i]
	}
	want := sum % 11
	c := vinUpper(vin[8])
	if want == 10 {
		return c == 'X'
	}
	return c >= '0' && c <= '9' && int(c-'0') == want
}

// vinValue переводит символ VIN в число. Буквы I, O и Q в VIN не встречаются:
// их исключили, чтобы не путать с единицей и нулём.
func vinValue(c byte) (int, bool) {
	if c >= '0' && c <= '9' {
		return int(c - '0'), true
	}
	switch vinUpper(c) {
	case 'A', 'J':
		return 1, true
	case 'B', 'K', 'S':
		return 2, true
	case 'C', 'L', 'T':
		return 3, true
	case 'D', 'M', 'U':
		return 4, true
	case 'E', 'N', 'V':
		return 5, true
	case 'F', 'W':
		return 6, true
	case 'G', 'P', 'X':
		return 7, true
	case 'H', 'Y':
		return 8, true
	case 'R', 'Z':
		return 9, true
	}
	return 0, false
}

func vinUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}
