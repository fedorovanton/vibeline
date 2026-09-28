package lex

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Синтетические значения, которые повторяются в нескольких проверках файла.
const (
	lexIvanov     = "Иванов"
	lexNormIvanov = "иванов"
	lexZWSP       = "\u200b"
)

func TestNormIsByteAlignedWithText(t *testing.T) {
	// Ключевое свойство лексера: смещения в Norm совпадают со смещениями в
	// Text. На нём держится вся работа сканеров со справочниками.
	inputs := []string{
		"Клиент Иванов Иван Иванович",
		"ЁЛКА ёлка Ёлка",
		"Passport 4509 123456, e-mail IVAN@MAIL.RU",
		"Смешанный Текст с ЗАГЛАВНЫМИ и строчными",
		"Ünïcödé ß Straße ΑΒΓ",
		"",
	}
	for _, in := range inputs {
		d := Tokenize(in, nil)
		if len(d.Norm) != len(d.Text) {
			t.Fatalf("длина Norm (%d) не равна длине Text (%d) для %q", len(d.Norm), len(d.Text), in)
		}
		for i := range d.Tokens {
			tok := d.Tokens[i]
			if int(tok.End) > len(d.Norm) {
				t.Fatalf("токен выходит за границы Norm: %q", in)
			}
			if utf8.RuneCountInString(d.Raw(i)) != utf8.RuneCountInString(d.NormOf(i)) {
				t.Fatalf("нормализация изменила число рун токена %q в %q", d.Raw(i), in)
			}
		}
	}
}

func TestNormalizationFoldsCaseAndYo(t *testing.T) {
	d := Tokenize("Ёлка ЁЖИК Пётр", nil)
	got := []string{d.NormOf(0), d.NormOf(1), d.NormOf(2)}
	want := []string{"елка", "ежик", "петр"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("нормализация дала %q вместо %q", got[i], want[i])
		}
	}
}

func TestTokenKindsAndFlags(t *testing.T) {
	d := Tokenize("Иванов 4509 IVAN, тел.", nil)

	cases := []struct {
		idx   int
		raw   string
		kind  Kind
		flags Flags
	}{
		{0, lexIvanov, KindWord, FlagFirstUpper | FlagCyrillic},
		{1, "4509", KindDigits, 0},
		{2, "IVAN", KindWord, FlagFirstUpper | FlagAllUpper | FlagLatin},
		{3, ",", KindPunct, 0},
		{4, "тел", KindWord, FlagCyrillic},
		{5, ".", KindPunct, 0},
	}
	if len(d.Tokens) != len(cases) {
		t.Fatalf("получено %d токенов вместо %d", len(d.Tokens), len(cases))
	}
	for _, c := range cases {
		if got := d.Raw(c.idx); got != c.raw {
			t.Errorf("токен %d: текст %q вместо %q", c.idx, got, c.raw)
		}
		if got := d.Tokens[c.idx].Kind; got != c.kind {
			t.Errorf("токен %q: категория %d вместо %d", c.raw, got, c.kind)
		}
		if got := d.Tokens[c.idx].Flags; got != c.flags {
			t.Errorf("токен %q: признаки %b вместо %b", c.raw, got, c.flags)
		}
	}
}

func TestByteOffsetsOnCyrillic(t *testing.T) {
	// Кириллическая буква занимает два байта: смещения обязаны быть байтовыми,
	// иначе вырезанный по ним фрагмент окажется сдвинут.
	const text = "Клиент Иванов обратился"
	d := Tokenize(text, nil)
	tok := d.Tokens[1]
	if text[tok.Start:tok.End] != lexIvanov {
		t.Fatalf("по смещениям вырезано %q вместо \"Иванов\"", text[tok.Start:tok.End])
	}
}

func TestGapAndAdjacent(t *testing.T) {
	d := Tokenize("4509 123456", nil)
	if d.Gap(0) != " " {
		t.Errorf("промежуток %q вместо пробела", d.Gap(0))
	}
	if d.Adjacent(0) {
		t.Error("токены, разделённые пробелом, признаны соседними")
	}

	d = Tokenize("45AB", nil)
	if !d.Adjacent(0) {
		t.Error("токены без разделителя не признаны соседними")
	}
}

func TestSentenceBreaks(t *testing.T) {
	d := Tokenize("Первое предложение. Второе предложение", nil)
	found := false
	for i := range d.Tokens {
		if d.IsSentenceBreak(i) {
			found = true
			if d.Raw(i) != "." {
				t.Errorf("границей признан токен %q", d.Raw(i))
			}
		}
	}
	if !found {
		t.Error("граница предложения не найдена")
	}

	d = Tokenize("Строка один\nСтрока два", nil)
	if !d.IsSentenceBreak(1) {
		t.Error("перевод строки не признан границей предложения")
	}
}

func TestInvalidUTF8DoesNotPanic(t *testing.T) {
	d := Tokenize("текст \xff\xfe хвост", nil)
	if len(d.Norm) != len(d.Text) {
		t.Fatalf("выравнивание нарушено на некорректном UTF-8: %d против %d", len(d.Norm), len(d.Text))
	}
}

func TestDocIsReusable(t *testing.T) {
	// Doc переиспользуется через пул: повторная разметка не должна оставлять
	// следов предыдущего текста.
	d := &Doc{}
	Tokenize("Первый текст с длинным содержимым", d)
	Tokenize("Второй", d)

	if len(d.Tokens) != 1 || d.Raw(0) != "Второй" {
		t.Fatalf("после повторной разметки осталось %d токенов: %q", len(d.Tokens), d.Text)
	}
	if d.Norm != "второй" {
		t.Fatalf("нормализованный буфер не переустановлен: %q", d.Norm)
	}
}

func BenchmarkTokenize(b *testing.B) {
	text := strings.Repeat("Клиент Иванов Иван Иванович, паспорт 4509 123456, тел. +7 916 123-45-67. ", 60)
	d := &Doc{}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Tokenize(text, d)
	}
}

// TestInvisibleInsideWordKeepsToken — T-46, дефект D-4: невидимые и
// комбинируемые символы внутри слова его не разрывают. Токен накрывает слово
// целиком в байтах исходного текста, а NormOf отдаёт слово без них.
func TestInvisibleInsideWordKeepsToken(t *testing.T) {
	tests := []struct {
		name, text, norm string
	}{
		{"ударение U+0301", "Ива\u0301нов", lexNormIvanov},
		{"мягкий перенос U+00AD", "Ива\u00adнов", lexNormIvanov},
		{"ZWSP U+200B", "Ива\u200bнов", lexNormIvanov},
		{"ZWNJ U+200C", "Ива\u200cнов", lexNormIvanov},
		{"ZWJ U+200D", "Ива\u200dнов", lexNormIvanov},
		{"WORD JOINER U+2060", "Ива\u2060нов", lexNormIvanov},
		{"BOM U+FEFF", "Ива\ufeffнов", lexNormIvanov},
		{"несколько разных", "И\u0301ва\u00adно\u200bв", lexNormIvanov},
		{"серия подряд", "Ива\u200b\u200b\u00ad\u0301нов", lexNormIvanov},
		{"ударение в конце слова", "Петро\u0301в", "петров"},
		{"разложенная й", "Андреи\u0306", "андрей"},
		{"разложенная Й в начале", "И\u0306ошкар", "йошкар"},
		{"разложенная ё", "Пе\u0308тр", "петр"},
		{"латиница", "Iva\u00adnov", "ivanov"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkInvisibleInsideWord(t, tt.text, tt.norm) })
	}
}

// checkInvisibleInsideWord — один случай TestInvisibleInsideWordKeepsToken:
// слово с невидимыми символами — один токен на весь текст, NormOf без них,
// Hidden равен длине невидимой части.
func checkInvisibleInsideWord(t *testing.T, text, norm string) {
	t.Helper()
	d := Tokenize(text, nil)
	if len(d.Tokens) != 1 {
		t.Fatalf("%d токенов вместо одного: %+v", len(d.Tokens), d.Tokens)
	}
	tok := d.Tokens[0]
	if tok.Start != 0 || int(tok.End) != len(text) || d.Raw(0) != text {
		t.Fatalf("токен [%d;%d) не накрывает слово [0;%d)", tok.Start, tok.End, len(text))
	}
	if tok.Kind != KindWord || !tok.Flags.Has(FlagFirstUpper|FlagInvisible) {
		t.Fatalf("категория %d, признаки %b", tok.Kind, tok.Flags)
	}
	if tok.Flags.Has(FlagAllUpper) {
		t.Fatalf("невидимый символ сосчитан как буква: признаки %b", tok.Flags)
	}
	if got := d.NormOf(0); got != norm {
		t.Fatalf("NormOf = %q, ожидалось %q", got, norm)
	}
	if int(tok.Hidden) != len(text)-len(norm) {
		t.Fatalf("Hidden = %d, невидимых символов %d байт", tok.Hidden, len(text)-len(norm))
	}
	if len(d.Norm) != len(d.Text) {
		t.Fatalf("выравнивание нарушено: Norm %d байт, Text %d байт", len(d.Norm), len(d.Text))
	}
	if !utf8.ValidString(d.Norm) {
		t.Fatalf("Norm — некорректный UTF-8: %q", d.Norm)
	}
}

// TestInvisibleAtCaseBreakSplitsWords — форматирующий символ между строчной и
// заглавной буквой стоит на стыке двух слов: «Петрович\ufeffПогода» — два
// токена. Склейка оставляла отчество вне спана ФИО (найдено свойством эха
// T-19 после слияния T-46 и T-47).
func TestInvisibleAtCaseBreakSplitsWords(t *testing.T) {
	for _, text := range []string{"Петрович\ufeffПогода", "Иванов\u200bИван", "ivanov\u00adIvan"} {
		d := Tokenize(text, nil)
		if len(d.Tokens) != 2 || d.Tokens[0].Flags.Has(FlagInvisible) {
			t.Fatalf("%q: ожидались два слова без невидимой части, получено %+v", text, d.Tokens)
		}
	}
	// Заглавное слово целиком переходом регистра не считается.
	if d := Tokenize("ИВА\u00adНОВ", nil); len(d.Tokens) != 1 || d.NormOf(0) != lexNormIvanov {
		t.Fatalf("«ИВА\\u00adНОВ»: ожидалось одно слово, получено %+v", d.Tokens)
	}
}

// TestInvisibleKeepsAlphabetFlags — невидимый символ не меняет признаков
// алфавита: без FlagCyrillic слово не рассматривал бы сканер ФИО.
func TestInvisibleKeepsAlphabetFlags(t *testing.T) {
	d := Tokenize("Ива\u200bнов IVA\u00adNOV", nil)
	if len(d.Tokens) != 2 {
		t.Fatalf("%d токенов вместо двух", len(d.Tokens))
	}
	if f := d.Tokens[0].Flags; f != FlagFirstUpper|FlagCyrillic|FlagInvisible {
		t.Errorf("кириллица: признаки %b", f)
	}
	if f := d.Tokens[1].Flags; f != FlagFirstUpper|FlagAllUpper|FlagLatin|FlagInvisible {
		t.Errorf("латиница: признаки %b", f)
	}
}

// TestFormatCharOutsideWordIsSpace — форматирующий символ вне слова разбирается
// как пробел: он не входит ни в один токен и не рвёт цепочку слов знаком.
func TestFormatCharOutsideWordIsSpace(t *testing.T) {
	tests := []struct {
		text string
		want []string
	}{
		{"Иванов\u200b Иван", []string{lexIvanov, "Иван"}},
		{"Иванов \u200bИван", []string{lexIvanov, "Иван"}},
		{"\ufeffтекст", []string{"текст"}},
		{"ivanov@example.test\u200d", []string{"ivanov", "@", "example", ".", "test"}},
		{"4276\u200b5500", []string{"4276", "5500"}},
		{"слово\u00ad", []string{"слово"}},
		{"\u200b\u200b", nil},
	}
	for _, tt := range tests {
		d := Tokenize(tt.text, nil)
		var got []string
		for i := range d.Tokens {
			got = append(got, d.Raw(i))
		}
		if strings.Join(got, "|") != strings.Join(tt.want, "|") {
			t.Errorf("%q: токены %q, ожидалось %q", tt.text, got, tt.want)
		}
		for i := range d.Tokens {
			if d.Tokens[i].Flags.Has(FlagInvisible) {
				t.Errorf("%q: токен %q помечен FlagInvisible", tt.text, d.Raw(i))
			}
		}
	}
}

// TestCombiningMarkOutsideWordStaysPunct — комбинируемый знак без буквы слева
// видим (он рисуется над пробелом или цифрой) и остаётся знаком, как и был.
func TestCombiningMarkOutsideWordStaysPunct(t *testing.T) {
	d := Tokenize("5\u0301 \u0301", nil)
	if len(d.Tokens) != 3 {
		t.Fatalf("%d токенов вместо трёх", len(d.Tokens))
	}
	for _, i := range []int{1, 2} {
		if d.Tokens[i].Kind != KindPunct || d.Raw(i) != "\u0301" {
			t.Errorf("токен %d: %q категории %d", i, d.Raw(i), d.Tokens[i].Kind)
		}
	}
}

// TestInvisibleNormOnlyInsideToken — перестановка в Norm не выходит за
// границы токена: соседние слова и промежутки нормализованы как обычно.
func TestInvisibleNormOnlyInsideToken(t *testing.T) {
	const text = "Клиент Ива\u0301нов Ива\u00adн, тел."
	d := Tokenize(text, nil)
	want := []string{"клиент", lexNormIvanov, "иван", ",", "тел", "."}
	if len(d.Tokens) != len(want) {
		t.Fatalf("%d токенов вместо %d", len(d.Tokens), len(want))
	}
	for i, w := range want {
		if got := d.NormOf(i); got != w {
			t.Errorf("токен %d: NormOf = %q, ожидалось %q", i, got, w)
		}
	}
	if !strings.HasPrefix(d.Norm, "клиент ") || !strings.HasSuffix(d.Norm, ", тел.") {
		t.Errorf("Norm вне слов с невидимыми символами изменена: %q", d.Norm)
	}
}

// TestInvisibleLinearTime — длинная серия невидимых символов разбирается за
// линейное время: решение о серии запоминается, а перестановка в Norm идёт
// один раз на токен. Квадратичный разбор на таком входе не уложился бы в
// тайм-аут теста.
func TestInvisibleLinearTime(t *testing.T) {
	const n = 200_000
	inputs := []string{
		"а" + strings.Repeat(lexZWSP, n) + "б",
		"а" + strings.Repeat(lexZWSP, n) + " ",
		strings.Repeat("а", n) + strings.Repeat("\u200bа", n),
		strings.Repeat("а\u0301", n),
	}
	for _, in := range inputs {
		d := Tokenize(in, nil)
		if len(d.Norm) != len(d.Text) {
			t.Fatalf("выравнивание нарушено: %d и %d байт", len(d.Norm), len(d.Text))
		}
	}
}

// TestInvisibleCappedPerWord — невидимых символов в одном слове не больше, чем
// помещается в Token.Hidden; остальные разбираются как вне слова, и NormOf
// остаётся верной.
func TestInvisibleCappedPerWord(t *testing.T) {
	const zwsp = lexZWSP
	text := "а" + strings.Repeat(zwsp, 40_000) + "б"
	d := Tokenize(text, nil)
	if len(d.Tokens) != 2 {
		t.Fatalf("%d токенов вместо двух", len(d.Tokens))
	}
	first := d.Tokens[0]
	if int(first.Hidden) != maxHidden/len(zwsp)*len(zwsp) {
		t.Fatalf("Hidden = %d, ожидалось %d", first.Hidden, maxHidden/len(zwsp)*len(zwsp))
	}
	if d.NormOf(0) != "а" || d.NormOf(1) != "б" {
		t.Fatalf("NormOf: %q и %q", d.NormOf(0), d.NormOf(1))
	}
}

// TestInvisibleZeroAllocs — невидимые символы не добавляют аллокаций при
// переиспользовании Doc: перестановка идёт внутри буфера нормы.
func TestInvisibleZeroAllocs(t *testing.T) {
	text := strings.Repeat("Клиент Ива\u0301нов Ива\u00adн Ива\u200bнович, тел. +7 916 123-45-67. ", 40)
	d := &Doc{}
	Tokenize(text, d)
	got := testing.AllocsPerRun(20, func() {
		Tokenize(text, d)
		_ = d.NormOf(1)
	})
	if got != 0 {
		t.Errorf("аллокаций на разбор: %.0f, требуется 0", got)
	}
}

func BenchmarkTokenizeInvisible(b *testing.B) {
	text := strings.Repeat("Клиент Ива\u0301нов Ива\u00adн Ива\u200bнович, паспорт 4509 123456, тел. +7 916 123-45-67. ", 60)
	d := &Doc{}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Tokenize(text, d)
	}
}

// TestSentenceBreakSkipsInnerDots — точка между цифрами вплотную и после
// заглавного инициала предложение не завершает; обычная точка и точка перед
// переводом строки — завершают.
func TestSentenceBreakSkipsInnerDots(t *testing.T) {
	cases := []struct {
		text  string
		dotAt int // номер точки по порядку в тексте
		brk   bool
	}{
		{"дата 12.03.1985 г", 0, false},
		{"дата 12.03.1985 г", 1, false},
		{"Коваль И.И., 12.03.1985", 0, false},
		{"Коваль И. И., паспорт", 1, false},
		{"сумма 1.5 млн", 0, false},
		{"Конец. Начало", 0, true},
		{"итого 12. Далее", 0, true},
		{"буква И.\nНовая строка", 0, true},
		{"г. Москва", 0, true},
	}
	for _, tc := range cases {
		d := Tokenize(tc.text, nil)
		i, ok := nthDotToken(d, tc.dotAt)
		if !ok {
			continue
		}
		if got := d.IsSentenceBreak(i); got != tc.brk {
			t.Errorf("%q, точка %d: IsSentenceBreak = %v, ожидалось %v", tc.text, tc.dotAt, got, tc.brk)
		}
	}
}

// nthDotToken возвращает индекс токена n-й по порядку точки текста (с нуля).
func nthDotToken(d *Doc, n int) (int, bool) {
	seen := -1
	for i, tok := range d.Tokens {
		if tok.Kind == KindPunct && d.Text[tok.Start] == '.' {
			seen++
			if seen == n {
				return i, true
			}
		}
	}
	return 0, false
}
