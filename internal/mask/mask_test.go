package mask

import (
	"strings"
	"testing"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/pii"
)

// Тексты ниже собраны из вымышленных значений: имена из встроенного
// справочника, телефоны служебного диапазона, адреса в example.org.

// spanOf строит спан по подстроке. Смещения — в байтах, как их хранит detect:
// на кириллице rune-индексы не подходят и молча сдвинули бы границы.
func spanOf(t *testing.T, text, value string, tp pii.Type, from int) detect.Span {
	t.Helper()
	i := strings.Index(text[from:], value)
	if i < 0 {
		t.Fatalf("подстрока %q не найдена в тексте начиная с байта %d", value, from)
	}
	i += from
	return detect.Span{Start: int32(i), End: int32(i + len(value)), Type: tp}
}

func placeholders(pii.Type) Strategy { return Placeholder{} }

// TestNamesListsAllStrategies — AC-1. Четыре стратегии ТЗ §6 и REQ-302
// доступны по именам, которые указываются в config.yaml.
func TestNamesListsAllStrategies(t *testing.T) {
	want := []string{"asterisks", "placeholder", strategySynthetic, strategyToken}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, ожидалось %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names() = %v, ожидалось %v", got, want)
		}
	}
	for _, name := range want {
		s, ok := ByName(name)
		if !ok {
			t.Fatalf("стратегия %q недоступна по имени", name)
		}
		if s.Name() != name {
			t.Fatalf("ByName(%q).Name() = %q", name, s.Name())
		}
	}
	if _, ok := ByName("нет такой"); ok {
		t.Fatal("ByName вернул стратегию для неизвестного имени")
	}
}

// TestApplySameValueSameNumber — REQ-303. Повтор значения обязан получить тот
// же номер: иначе «[ФИО_1] и [ФИО_2]» прочитаются моделью как два человека
// там, где в тексте был один.
func TestApplySameValueSameNumber(t *testing.T) {
	const text = "Петров Пётр написал, что Петров Пётр согласен."
	var a Applier
	spans := []detect.Span{
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		spanOf(t, text, fioPetrov, pii.FullName, 20),
	}

	out, applied := a.Apply(text, spans, placeholders)

	if len(applied) != 2 {
		t.Fatalf("замен %d, ожидалось 2", len(applied))
	}
	if applied[0].Seq != 1 || applied[1].Seq != 1 {
		t.Fatalf("номера %d и %d, ожидалось 1 и 1", applied[0].Seq, applied[1].Seq)
	}
	if applied[0].Replacement != applied[1].Replacement {
		t.Fatalf("одно значение получило разные замены: %q и %q", applied[0].Replacement, applied[1].Replacement)
	}
	if want := "[ФИО_1] написал, что [ФИО_1] согласен."; out != want {
		t.Fatalf(msgResultWant, out, want)
	}
}

// TestApplyDifferentValuesDifferentNumbers — REQ-303, вторая половина.
func TestApplyDifferentValuesDifferentNumbers(t *testing.T) {
	const text = "Петров Пётр и Сидоров Сидор"
	var a Applier
	spans := []detect.Span{
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		spanOf(t, text, fioSidorov, pii.FullName, 0),
	}

	out, applied := a.Apply(text, spans, placeholders)

	if applied[0].Seq != 1 || applied[1].Seq != 2 {
		t.Fatalf("номера %d и %d, ожидалось 1 и 2", applied[0].Seq, applied[1].Seq)
	}
	if want := "[ФИО_1] и [ФИО_2]"; out != want {
		t.Fatalf(msgResultWant, out, want)
	}
}

// TestApplyNumbersPerType проверяет, что счётчик независим по типам:
// первый телефон — [ТЕЛЕФОН_1], а не [ТЕЛЕФОН_2] вслед за ФИО.
func TestApplyNumbersPerType(t *testing.T) {
	const text = "Петров Пётр, телефон +7 900 000-00-01"
	var a Applier
	spans := []detect.Span{
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		spanOf(t, text, "+7 900 000-00-01", pii.Phone, 0),
	}

	out, _ := a.Apply(text, spans, placeholders)

	if want := "[ФИО_1], телефон [ТЕЛЕФОН_1]"; out != want {
		t.Fatalf(msgResultWant, out, want)
	}
}

// TestApplyKeepsSurroundingBytes — REQ-304 и AC-8. Текст вне спанов
// сохраняется побайтово: пунктуация, двойные пробелы, перевод строки и
// табуляция остаются на своих местах.
func TestApplyKeepsSurroundingBytes(t *testing.T) {
	const text = "Здравствуйте,  Петров Пётр!\n\tВаш e-mail: user1@example.org — верно?\r\n"
	var a Applier
	spans := []detect.Span{
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		spanOf(t, text, mailUser1, pii.Email, 0),
	}

	out, applied := a.Apply(text, spans, placeholders)

	want := "Здравствуйте,  [ФИО_1]!\n\tВаш e-mail: [EMAIL_1] — верно?\r\n"
	if out != want {
		t.Fatalf(msgResultWant, out, want)
	}
	// Дополнительная проверка того же инварианта от обратного: если вырезать
	// из результата замены, а из исходного текста — спаны, остатки совпадут.
	if got, exp := stripReplacements(out, applied), stripSpans(text, spans); got != exp {
		t.Fatalf("окружение изменилось: %q против %q", got, exp)
	}
}

// TestApplyCyrillicOffsets — AC-8. Замена ведётся по байтовым смещениям;
// смешение их с индексами рун обрезало бы соседние кириллические буквы.
func TestApplyCyrillicOffsets(t *testing.T) {
	const text = "Клиент Петров Пётр проживает в г. Тестоград и платит вовремя"
	var a Applier
	spans := []detect.Span{spanOf(t, text, fioPetrov, pii.FullName, 0)}

	out, _ := a.Apply(text, spans, placeholders)

	want := "Клиент [ФИО_1] проживает в г. Тестоград и платит вовремя"
	if out != want {
		t.Fatalf(msgResultWant, out, want)
	}
	if !strings.HasPrefix(out, "Клиент ") {
		t.Fatalf("текст перед спаном повреждён: %q", out)
	}
	if !strings.HasSuffix(out, " проживает в г. Тестоград и платит вовремя") {
		t.Fatalf("текст после спана повреждён: %q", out)
	}
}

// TestApplyNoSpans — пустой список спанов возвращает исходный текст. Это путь
// обычного запроса без персональных данных, и лишней копии здесь быть не должно.
func TestApplyNoSpans(t *testing.T) {
	const text = "Обычный текст без персональных данных, 2026 год."
	var a Applier

	out, applied := a.Apply(text, nil, placeholders)

	if out != text {
		t.Fatalf("результат %q, ожидался исходный текст", out)
	}
	if applied != nil {
		t.Fatalf("список замен %v, ожидался nil", applied)
	}
}

// TestApplyIsIdempotentAcrossApplier — маскирование объявлено чистой функцией:
// два независимых Applier обязаны дать один результат, и повторный вызов на
// том же экземпляре тоже.
func TestApplyIsIdempotentAcrossApplier(t *testing.T) {
	const text = "Петров Пётр, карта 4000 0000 0000 0002"
	spans := []detect.Span{
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		spanOf(t, text, "4000 0000 0000 0002", pii.CardNumber, 0),
	}
	pick := func(pii.Type) Strategy { return Synthetic{} }

	var a, b Applier
	first, _ := a.Apply(text, spans, pick)
	again, _ := a.Apply(text, spans, pick)
	other, _ := b.Apply(text, spans, pick)

	if first != again {
		t.Fatalf("повтор на том же Applier дал %q вместо %q", again, first)
	}
	if first != other {
		t.Fatalf("второй Applier дал %q вместо %q", other, first)
	}
}

// TestApplyPerTypeStrategy — стратегия выбирается по типу: pick вызывается для
// каждого спана, и разные типы могут маскироваться по-разному (REQ-302).
func TestApplyPerTypeStrategy(t *testing.T) {
	const text = "Петров Пётр, телефон +7 900 000-00-01"
	var a Applier
	spans := []detect.Span{
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		spanOf(t, text, "+7 900 000-00-01", pii.Phone, 0),
	}
	pick := func(tp pii.Type) Strategy {
		if tp == pii.Phone {
			return Asterisks{}
		}
		return Placeholder{}
	}

	out, _ := a.Apply(text, spans, pick)

	if want := "[ФИО_1], телефон +* *** ***-**-**"; out != want {
		t.Fatalf(msgResultWant, out, want)
	}
}

// TestApplySkipsBrokenSpan — спан с границами вне текста не должен ронять
// обработку: на /process отказ защиты стоит дороже пропуска одного спана.
func TestApplySkipsBrokenSpan(t *testing.T) {
	const text = fioPetrov
	var a Applier
	spans := []detect.Span{
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		{Start: 0, End: int32(len(text) + 100), Type: pii.FullName},
	}

	out, applied := a.Apply(text, spans, placeholders)

	if len(applied) != 1 {
		t.Fatalf("замен %d, ожидалась 1", len(applied))
	}
	if out != "[ФИО_1]" {
		t.Fatalf(msgResult, out)
	}
}

// TestApplierResetClearsNumbering — Applier переиспользуется через пул,
// и номера прошлого запроса не должны утекать в следующий.
func TestApplierResetClearsNumbering(t *testing.T) {
	const first = fioPetrov
	const second = fioSidorov
	var a Applier

	a.Apply(first, []detect.Span{spanOf(t, first, first, pii.FullName, 0)}, placeholders)
	out, applied := a.Apply(second, []detect.Span{spanOf(t, second, second, pii.FullName, 0)}, placeholders)

	if applied[0].Seq != 1 {
		t.Fatalf("номер %d после Reset, ожидался 1", applied[0].Seq)
	}
	if out != "[ФИО_1]" {
		t.Fatalf(msgResult, out)
	}
}

// TestApplySkipsEmptyAndInvertedSpan — D-5: пустой и перевёрнутый спаны
// внутри текста пропускаются без паники, соседний целый спан применяется.
func TestApplySkipsEmptyAndInvertedSpan(t *testing.T) {
	const text = "Петров Пётр пишет"
	var a Applier
	spans := []detect.Span{
		{Start: 0, End: 0, Type: pii.FullName},
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		{Start: 25, End: 23, Type: pii.FullName},
	}
	out, applied := a.Apply(text, spans, placeholders)
	if len(applied) != 1 || out != "[ФИО_1] пишет" {
		t.Fatalf("замен %d, результат %q", len(applied), out)
	}
}

// TestApplyNumberedContinuesAcrossTexts — D-1: общая нумерация нескольких
// текстов одного запроса. Одно значение — один номер во всех текстах,
// разные значения — разные номера; Apply при этом нумерует с нуля.
func TestApplyNumberedContinuesAcrossTexts(t *testing.T) {
	texts := []string{"Клиент Петров Пётр", "Клиент Сидоров Сидор", "Снова Петров Пётр"}
	values := []string{fioPetrov, fioSidorov, fioPetrov}
	want := []string{"Клиент [ФИО_1]", "Клиент [ФИО_2]", "Снова [ФИО_1]"}

	var a Applier
	var num Numbering
	for i, text := range texts {
		out, _ := a.ApplyNumbered(text, []detect.Span{spanOf(t, text, values[i], pii.FullName, 0)}, placeholders, &num)
		if out != want[i] {
			t.Fatalf("текст %d: %q, ожидалось %q", i, out, want[i])
		}
	}
	out, _ := a.Apply(texts[1], []detect.Span{spanOf(t, texts[1], values[1], pii.FullName, 0)}, placeholders)
	if out != "Клиент [ФИО_1]" {
		t.Fatalf("Apply унаследовал чужую нумерацию: %q", out)
	}
}

// TestNumberingSkipsReservedReplacement — D-3: номер, чья замена уже
// буквально написана во входе, не выдаётся.
func TestNumberingSkipsReservedReplacement(t *testing.T) {
	const text = "[ФИО_1] и [ФИО_2] пишут: Петров Пётр"
	var a Applier
	num := Numbering{Reserved: func(r string) bool { return strings.Contains(text, r) }}
	out, applied := a.ApplyNumbered(text, []detect.Span{spanOf(t, text, fioPetrov, pii.FullName, 0)}, placeholders, &num)
	if out != "[ФИО_1] и [ФИО_2] пишут: [ФИО_3]" || applied[0].Seq != 3 {
		t.Fatalf("результат %q, номер %d", out, applied[0].Seq)
	}
}

// TestNumberingReservedTerminates — замена, не зависящая от номера (token),
// не приводит к бесконечному перебору, даже если «занято» всё.
func TestNumberingReservedTerminates(t *testing.T) {
	const text = fioPetrov
	var a Applier
	calls := 0
	num := Numbering{Reserved: func(string) bool { calls++; return true }}
	pick := func(pii.Type) Strategy { return Token{} }
	out, applied := a.ApplyNumbered(text, []detect.Span{spanOf(t, text, text, pii.FullName, 0)}, pick, &num)
	if len(applied) != 1 || out != (Token{}).Mask(text, pii.FullName, 1) {
		t.Fatalf(msgResult, out)
	}
	if calls > reservedSkipMax+1 {
		t.Fatalf("Reserved вызван %d раз", calls)
	}

	num = Numbering{Reserved: func(string) bool { return true }}
	out, applied = a.ApplyNumbered(text, []detect.Span{spanOf(t, text, text, pii.FullName, 0)}, placeholders, &num)
	if len(applied) != 1 || applied[0].Seq != reservedSkipMax+1 || !strings.HasPrefix(out, "[ФИО_") {
		t.Fatalf("placeholder при сплошь занятых номерах: %q, номер %d", out, applied[0].Seq)
	}
}

// collidingStrategy выдаёт одну и ту же замену для первых двух номеров — как
// synthetic после сдвига при совпадении замены с исходным значением.
type collidingStrategy struct{}

func (collidingStrategy) Name() string { return "colliding" }

func (collidingStrategy) Mask(_ string, _ pii.Type, seq int) string {
	if seq <= 2 {
		return "X"
	}
	return "Y" + strings.Repeat("!", seq)
}

// TestNumberingAvoidsDuplicateReplacement — D-2: в режиме запроса к модели
// двум разным значениям не выдаётся одна замена; без Reserved поведение
// прежнее (контракт /process не меняется).
func TestNumberingAvoidsDuplicateReplacement(t *testing.T) {
	const text = "Петров Пётр и Сидоров Сидор"
	spans := []detect.Span{
		spanOf(t, text, fioPetrov, pii.FullName, 0),
		spanOf(t, text, fioSidorov, pii.FullName, 0),
	}
	pick := func(pii.Type) Strategy { return collidingStrategy{} }
	var a Applier

	num := Numbering{Reserved: func(string) bool { return false }}
	out, _ := a.ApplyNumbered(text, spans, pick, &num)
	if out != "X и Y!!!" {
		t.Fatalf("с нумерацией запроса: %q", out)
	}
	out, _ = a.Apply(text, spans, pick)
	if out != "X и X" {
		t.Fatalf("без Reserved поведение изменилось: %q", out)
	}
}

// stripReplacements убирает из результата подставленные замены.
func stripReplacements(out string, applied []Applied) string {
	for _, ap := range applied {
		out = strings.Replace(out, ap.Replacement, "", 1)
	}
	return out
}

// stripSpans убирает из исходного текста значения спанов.
func stripSpans(text string, spans []detect.Span) string {
	var b strings.Builder
	prev := int32(0)
	for _, s := range spans {
		b.WriteString(text[prev:s.Start])
		prev = s.End
	}
	b.WriteString(text[prev:])
	return b.String()
}

// naiveOccurrences — все вхождения всех значений подстрочным поиском, как
// эталон для автомата Values.
func naiveOccurrences(text string, values []string) map[[3]int]bool {
	out := make(map[[3]int]bool)
	for id, v := range values {
		for i := 0; i+len(v) <= len(text); i++ {
			if text[i:i+len(v)] == v {
				out[[3]int{id, i, i + len(v)}] = true
			}
		}
	}
	return out
}

// TestValuesFindsAllOccurrences — С-5: автомат находит ровно те вхождения,
// что и подстрочный поиск по каждому значению, включая пересекающиеся и
// вложенные значения, и нумерует значения подряд без повторов.
func TestValuesFindsAllOccurrences(t *testing.T) {
	values := []string{"he", "she", "his", "hers", "ФИО", "ИО_1", "1234", "234", "12", fioIvanov}
	text := "ushers, his she; [ФИО_1] пин 12345, код 1234; Иванов Иванович, Иванов Иван"
	var v Values
	for i, s := range values {
		if id := v.Add(s); int(id) != i {
			t.Fatalf("значение %q получило номер %d, ожидался %d", s, id, i)
		}
	}
	if id := v.Add("his"); id != 2 {
		t.Fatalf("повторное добавление дало номер %d", id)
	}
	if id := v.Add(""); id != -1 || v.Len() != len(values) {
		t.Fatalf("пустая строка: номер %d, значений %d", id, v.Len())
	}
	got := make(map[[3]int]bool)
	prevEnd := 0
	v.Each(text, func(id int32, start, end int) bool {
		if end < prevEnd {
			t.Fatalf("вхождения не по возрастанию конца: %d после %d", end, prevEnd)
		}
		prevEnd = end
		got[[3]int{int(id), start, end}] = true
		return true
	})
	want := naiveOccurrences(text, values)
	if len(got) != len(want) {
		t.Fatalf("найдено %d вхождений, эталон %d", len(got), len(want))
	}
	for k := range want {
		if !got[k] {
			t.Errorf("пропущено вхождение %q на [%d:%d]", values[k[0]], k[1], k[2])
		}
	}

	// После Reset прежних значений нет, а обход останавливается по false.
	v.Reset()
	v.Add("код")
	n := 0
	v.Each(text, func(int32, int, int) bool { n++; return false })
	if n != 1 {
		t.Fatalf("после Reset и остановки обхода вызовов %d", n)
	}
}

// TestValuesRandomAgainstNaive — то же на случайных строках из маленького
// алфавита, где вхождения часто пересекаются и вкладываются.
func TestValuesRandomAgainstNaive(t *testing.T) {
	alphabet := []string{"a", "b", "ab", "я", "1"}
	seed := uint32(20260923)
	next := func(n int) int {
		seed = seed*1664525 + 1013904223
		return int(seed>>16) % n
	}
	word := func(maxLen int) string {
		var b strings.Builder
		for range 1 + next(maxLen) {
			b.WriteString(alphabet[next(len(alphabet))])
		}
		return b.String()
	}
	var v Values
	for round := range 300 {
		v.Reset()
		var values []string
		for range 1 + next(6) {
			s := word(3)
			if int(v.Add(s)) == len(values) {
				values = append(values, s)
			}
		}
		text := word(40)
		got := make(map[[3]int]bool)
		v.Each(text, func(id int32, start, end int) bool {
			got[[3]int{int(id), start, end}] = true
			return true
		})
		want := naiveOccurrences(text, values)
		if len(got) != len(want) {
			t.Fatalf("раунд %d: %q в %q — найдено %d, эталон %d", round, values, text, len(got), len(want))
		}
		for k := range want {
			if !got[k] {
				t.Fatalf("раунд %d: пропущено %q на [%d:%d] в %q", round, values[k[0]], k[1], k[2], text)
			}
		}
	}
}

// TestCoverRepeatsHidesRepeatsWithSameReplacement — С-4: повтор отобранного
// значения без маркера закрывается той же заменой, что и найденное
// вхождение, даже если стоит раньше него: номер — по первому появлению.
func TestCoverRepeatsHidesRepeatsWithSameReplacement(t *testing.T) {
	const text = "1234 — это пин-код 1234, код из смс 1234. Дата рождения 01.02.1990, договор от 01.02.1990."
	pin := spanOf(t, text, "1234", pii.PIN, strings.Index(text, "пин-код"))
	date := spanOf(t, text, birthDateSample, pii.BirthDate, 0)
	var a Applier
	spans := a.CoverRepeats(text, []detect.Span{pin, date})
	if len(spans) != 5 {
		t.Fatalf("спанов после закрытия повторов: %d, ожидалось 5: %+v", len(spans), spans)
	}
	for i := 1; i < len(spans); i++ {
		if spans[i].Start < spans[i-1].End {
			t.Fatalf("спаны пересекаются или не упорядочены: %+v", spans)
		}
	}
	out, applied := a.Apply(text, spans, placeholders)
	const want = "[ПИН_1] — это пин-код [ПИН_1], код из смс [ПИН_1]. Дата рождения [ДАТА_РОЖДЕНИЯ_1], договор от [ДАТА_РОЖДЕНИЯ_1]."
	if out != want {
		t.Fatalf("получено  %q\nожидалось %q", out, want)
	}
	repeats := 0
	for _, s := range spans {
		if s.Rule == RuleRepeat {
			repeats++
		}
	}
	if repeats != 3 || len(applied) != 5 {
		t.Fatalf("повторов %d, замен %d", repeats, len(applied))
	}
}

// TestCoverRepeatsRespectsTokenBoundaries — вхождение внутри другого числа
// или слова повтором не считается; соседство цифры с буквой и любого
// значения со знаком — граница токена.
func TestCoverRepeatsRespectsTokenBoundaries(t *testing.T) {
	const cvv = "123"
	tests := []struct {
		name, text, value string
		covered           int
	}{
		{"внутри большего числа", "CVV 123, сумма 1230, заявка 9123", cvv, 0},
		{"через дефис и точку", "CVV 123, код 123-й, 123.", cvv, 2},
		{"число вплотную к букве", "CVV 123, кодA123", cvv, 1},
		{"имя внутри другого слова", "Клиент Иван, однофамилец Иванов и Ивана", "Иван", 0},
		{"имя через дефис", "Клиент Анна, Анна-Мария", "Анна", 1},
		{"почта, прилипшая к букве", "почта ivanov@example.test, ещё Жivanov@example.test", "ivanov@example.test", 0},
		{"комбинируемый знак продолжает слово", "Клиент Анна, Анна́", "Анна", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a Applier
			first := spanOf(t, tt.text, tt.value, pii.CVV, 0)
			spans := a.CoverRepeats(tt.text, []detect.Span{first})
			if got := len(spans) - 1; got != tt.covered {
				t.Fatalf("закрыто повторов %d, ожидалось %d: %+v", got, tt.covered, spans)
			}
		})
	}
}

// TestCoverRepeatsKeepsInputWithoutRepeats — без повторов возвращается тот же
// слайс: вывод на обычных входах /process побайтово прежний.
func TestCoverRepeatsKeepsInputWithoutRepeats(t *testing.T) {
	const text = "Клиент Иванов Иван, телефон +7 916 123-45-67."
	spans := []detect.Span{
		spanOf(t, text, fioIvanov, pii.FullName, 0),
		spanOf(t, text, phoneSample, pii.Phone, 0),
	}
	var a Applier
	got := a.CoverRepeats(text, spans)
	if len(got) != len(spans) || &got[0] != &spans[0] {
		t.Fatalf("без повторов изменён список спанов: %+v", got)
	}
	if got := a.CoverRepeats(text, nil); got != nil {
		t.Fatalf("пустой список: %+v", got)
	}
}

// TestCoverRepeatsSkipsOverlapWithSelected — повтор, задевающий уже
// отобранный спан другого значения, не добавляется, а из пересекающихся
// повторов остаётся раньше начавшийся и более длинный.
func TestCoverRepeatsSkipsOverlapWithSelected(t *testing.T) {
	const text = "ПИН 5500, карта 4276 5500 1234 5678; Иванов Иван, Иванов; Иванов Иван и Иванов"
	spans := []detect.Span{
		spanOf(t, text, "5500", pii.PIN, 0),
		spanOf(t, text, "4276 5500 1234 5678", pii.CardNumber, 0),
		spanOf(t, text, fioIvanov, pii.FullName, 0),
		spanOf(t, text, "Иванов", pii.FullName, strings.Index(text, "Иван, ")+len("Иван, ")),
	}
	var a Applier
	got := a.CoverRepeats(text, spans)
	out, _ := a.Apply(text, got, placeholders)
	const want = "ПИН [ПИН_1], карта [КАРТА_1]; [ФИО_1], [ФИО_2]; [ФИО_1] и [ФИО_2]"
	if out != want {
		t.Fatalf("получено  %q\nожидалось %q", out, want)
	}
}

// BenchmarkCoverRepeats — цена закрытия повторов на запросе размером с
// обычный /process: четыре килобайта кириллицы и три значения. «без повторов»
// — каждое значение один раз, «повторы» — фраза со значениями повторена
// до четырёх килобайт, и все повторы закрываются.
func BenchmarkCoverRepeats(b *testing.B) {
	const phrase = "Клиент Иванов Иван Иванович, телефон +7 916 123-45-67, почта ivanov@example.test. "
	const filler = "Обращение по договору обслуживания, клиент просит перезвонить позже. "
	build := func(repeat bool) (string, []detect.Span) {
		var sb strings.Builder
		sb.WriteString(phrase)
		for sb.Len() < 4096 {
			if repeat {
				sb.WriteString(phrase)
			} else {
				sb.WriteString(filler)
			}
		}
		text := sb.String()
		var spans []detect.Span
		for _, v := range []string{"Иванов Иван Иванович", phoneSample, "ivanov@example.test"} {
			i := strings.Index(text, v)
			spans = append(spans, detect.Span{Start: int32(i), End: int32(i + len(v)), Type: pii.FullName})
		}
		return text, spans
	}
	for _, repeat := range []bool{false, true} {
		name := "без повторов"
		if repeat {
			name = "повторы"
		}
		b.Run(name, func(b *testing.B) {
			text, spans := build(repeat)
			var a Applier
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for b.Loop() {
				_ = a.CoverRepeats(text, spans)
			}
		})
	}
}
