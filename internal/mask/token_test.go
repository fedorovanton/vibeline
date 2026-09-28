package mask

import (
	"strconv"
	"strings"
	"testing"

	"ai-gateway/internal/pii"
)

// tokenStrategy — стратегия под тестом. Отдельная переменная нужна потому,
// что композитный литерал Token{} в заголовке if разбирается парсером Go
// как начало блока.
var tokenStrategy Token

// Все значения в тестах — синтетические: выдуманные имена, номера из
// служебных диапазонов и адреса в example.org. Реальных ПД в репозитории нет.

func TestTokenRegistered(t *testing.T) {
	s, ok := ByName(strategyToken)
	if !ok {
		t.Fatal("стратегия token не зарегистрирована")
	}
	if s.Name() != strategyToken {
		t.Fatalf("Name() = %q, ожидалось \"token\"", s.Name())
	}
}

func TestTokenFormat(t *testing.T) {
	got := tokenStrategy.Mask(fioPetrov, pii.FullName, 1)

	if !strings.HasPrefix(got, tokenPrefix) || !strings.HasSuffix(got, "}}") {
		t.Fatalf("токен %q не соответствует форме {{pii:...}}", got)
	}
	body := got[len(tokenPrefix) : len(got)-2]
	if len(body) != 8 {
		t.Fatalf("тело токена %q длиной %d, ожидалось 8 знаков", body, len(body))
	}
	if _, err := strconv.ParseUint(body, 16, 32); err != nil {
		t.Fatalf("тело токена %q не шестнадцатеричное: %v", body, err)
	}
	if body != strings.ToLower(body) {
		t.Fatalf("тело токена %q не в нижнем регистре", body)
	}
}

// TestTokenDeterministic — AC-2. Детерминированность держит идемпотентность
// прямого шага: повтор /process с тем же payload обязан вернуть тот же текст.
func TestTokenDeterministic(t *testing.T) {
	const value = fioPetrovFull
	want := tokenStrategy.Mask(value, pii.FullName, 1)
	for i := 0; i < 100; i++ {
		if got := tokenStrategy.Mask(value, pii.FullName, 1); got != want {
			t.Fatalf("вызов %d вернул %q, первый вызов — %q", i, got, want)
		}
	}
}

// TestTokenIgnoresSeq фиксирует решение: номер значения в токен не входит,
// поэтому одно значение даёт один токен и в разных запросах тоже.
func TestTokenIgnoresSeq(t *testing.T) {
	want := tokenStrategy.Mask(mailUser1, pii.Email, 1)
	for _, seq := range []int{2, 7, 999} {
		if got := tokenStrategy.Mask(mailUser1, pii.Email, seq); got != want {
			t.Fatalf("seq=%d дал %q, ожидалось %q", seq, got, want)
		}
	}
}

// TestTokenDistinctValues — AC-2, вторая половина: разные значения в пределах
// запроса не должны склеиваться в один токен.
func TestTokenDistinctValues(t *testing.T) {
	seen := make(map[string]string, 1024)
	for i := 0; i < 1000; i++ {
		value := "user" + strconv.Itoa(i) + "@example.org"
		tok := tokenStrategy.Mask(value, pii.Email, i+1)
		if prev, dup := seen[tok]; dup {
			t.Fatalf("значения %q и %q получили один токен %q", prev, value, tok)
		}
		seen[tok] = value
	}
}

// TestTokenSeparatesTypes проверяет, что тип подмешан в хеш: одна и та же
// строка, отнесённая к разным типам, не должна давать один токен.
func TestTokenSeparatesTypes(t *testing.T) {
	const value = "1234567890"
	a := tokenStrategy.Mask(value, pii.INN, 1)
	b := tokenStrategy.Mask(value, pii.CardNumber, 1)
	if a == b {
		t.Fatalf("типы INN и CardNumber дали один токен %q", a)
	}
}

// TestTokenHidesValueAndType — смысл стратегии: из маски не видно ни значения,
// ни категории данных.
func TestTokenHidesValueAndType(t *testing.T) {
	const value = fioPetrov
	got := tokenStrategy.Mask(value, pii.FullName, 1)
	if strings.Contains(got, value) {
		t.Fatalf("токен %q содержит исходное значение", got)
	}
	if strings.Contains(got, pii.FullName.Placeholder()) || strings.Contains(got, pii.FullName.Key()) {
		t.Fatalf("токен %q раскрывает тип данных", got)
	}
}

func TestFormatTokenPadsLeadingZeros(t *testing.T) {
	if got := formatToken(0); got != "{{pii:00000000}}" {
		t.Fatalf("formatToken(0) = %q", got)
	}
	if got := formatToken(0xffffffff); got != "{{pii:ffffffff}}" {
		t.Fatalf("formatToken(max) = %q", got)
	}
}
