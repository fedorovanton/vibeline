package mask

// Тесты инвариантов маскирования (T-19).
//
// Проверяется не «правильная маска», а свойства, которые обязаны держаться
// при любом тексте и любой стратегии: байты вне спанов не меняются, замена
// ложится ровно на место значения, Unicode и некорректный UTF-8 не роняют
// сборку результата. Все значения — синтетические.

import (
	"math/rand"
	"strings"
	"testing"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/pii"
)

// invariantSeed фиксирует генератор: провал воспроизводится запуском
// того же теста, а не ловлей удачного случая.
const invariantSeed = 19

// allStrategies — все стратегии из реестра, как их выбирает конфигурация.
func allStrategies(t *testing.T) []Strategy {
	t.Helper()
	var out []Strategy
	for _, name := range Names() {
		s, ok := ByName(name)
		if !ok {
			t.Fatalf("стратегия %q не найдена по имени", name)
		}
		out = append(out, s)
	}
	return out
}

// checkApplyInvariants проверяет результат Apply против входа:
//
//   - каждой замене соответствует ровно один входной спан, в том же порядке;
//   - результат побайтово равен «текст между спанами + замены»;
//   - обратная подстановка исходных значений по позициям даёт исходный текст.
//
// Последнее и есть round-trip на уровне маскирования: восстановление по
// сохранённым заменам обязано быть точным до байта.
func checkApplyInvariants(t *testing.T, text string, spans []detect.Span, out string, applied []Applied) {
	t.Helper()
	if len(applied) != len(spans) {
		t.Fatalf("замен %d, спанов %d", len(applied), len(spans))
	}
	var want strings.Builder
	prev := int32(0)
	for i, a := range applied {
		sp := spans[i]
		if a.Start != sp.Start || a.End != sp.End || a.Type != sp.Type {
			t.Fatalf("замена %d [%d:%d] %s не совпадает со спаном [%d:%d] %s",
				i, a.Start, a.End, a.Type.Key(), sp.Start, sp.End, sp.Type.Key())
		}
		want.WriteString(text[prev:a.Start])
		want.WriteString(a.Replacement)
		prev = a.End
	}
	want.WriteString(text[prev:])
	if out != want.String() {
		t.Fatalf("результат не равен «текст вне спанов + замены»:\nполучено  %q\nожидалось %q", out, want.String())
	}

	// Обратная подстановка по позициям в результате, а не поиском строки:
	// поиск спутал бы замену с похожим фрагментом исходного текста.
	var back strings.Builder
	pos := 0
	prev = 0
	for _, a := range applied {
		gap := int(a.Start - prev)
		back.WriteString(out[pos : pos+gap])
		pos += gap
		if !strings.HasPrefix(out[pos:], a.Replacement) {
			t.Fatalf("замена %q не найдена на ожидаемой позиции %d", a.Replacement, pos)
		}
		back.WriteString(text[a.Start:a.End])
		pos += len(a.Replacement)
		prev = a.End
	}
	back.WriteString(out[pos:])
	if back.String() != text {
		t.Fatalf("обратная подстановка не восстановила текст:\nполучено  %q\nожидалось %q", back.String(), text)
	}
}

// unicodeCase — текст и значения в нём, которые накрываются спанами по
// порядку появления.
type unicodeCase struct {
	name   string
	text   string
	values []string
	types  []pii.Type
}

// unicodeCases — тексты с трудными для смещений символами. Спаны задаются
// подстрокой, смещения считаются в байтах.
var unicodeCases = []unicodeCase{
	{
		name:   "кириллица",
		text:   "Клиент Петров Пётр Петрович, почта petrov@example.test.",
		values: []string{fioPetrovFull, mailPetrov},
		types:  []pii.Type{pii.FullName, pii.Email},
	},
	{
		name:   "эмодзи с ZWJ и модификатором тона",
		text:   "👩\u200d💻 Петров Пётр 👍🏽 тел. +7 900 000-00-01 🇷🇺",
		values: []string{fioPetrov, "+7 900 000-00-01"},
		types:  []pii.Type{pii.FullName, pii.Phone},
	},
	{
		name:   "составные символы",
		text:   "cafe\u0301 Пе\u0301тров Пётр и Ё\u0308жиков",
		values: []string{"Пе\u0301тров Пётр", "Ё\u0308жиков"},
		types:  []pii.Type{pii.FullName, pii.FullName},
	},
	{
		name:   "символы нулевой ширины",
		text:   "\u200bПетров\u200d Пётр\ufeff, почта\u2060 petrov@example.test\u200c",
		values: []string{"Петров\u200d Пётр", mailPetrov},
		types:  []pii.Type{pii.FullName, pii.Email},
	},
	{
		name:   "CRLF и табуляция",
		text:   "Клиент:\r\n\tПетров Пётр\r\n\r\nТел.:\t+7 900 000-00-01\r\n",
		values: []string{fioPetrov, "+7 900 000-00-01"},
		types:  []pii.Type{pii.FullName, pii.Phone},
	},
	{
		name:   "JSON-escapes в тексте",
		text:   `{"name":"\u041f\u0435\u0442\u0440\u043e\u0432","mail":"petrov@example.test","q":"\"x\"\\n"}`,
		values: []string{`\u041f\u0435\u0442\u0440\u043e\u0432`, mailPetrov},
		types:  []pii.Type{pii.FullName, pii.Email},
	},
	{
		name:   "некорректный UTF-8 вокруг значения",
		text:   "\xff\xfeПетров Пётр \xc3 petrov@example.test \xe2\x82",
		values: []string{fioPetrov, mailPetrov},
		types:  []pii.Type{pii.FullName, pii.Email},
	},
	{
		name:   "некорректный UTF-8 внутри значения",
		text:   "код \xffПет\xc3ров\xe2\x82 конец",
		values: []string{"\xffПет\xc3ров\xe2\x82"},
		types:  []pii.Type{pii.FullName},
	},
}

// TestInvariantApplyUnicodeRoundTrip — AC-1, AC-2, REQ-304.
//
// Для каждой стратегии: байты вне спанов сохраняются, обратная подстановка
// восстанавливает текст побайтово, а само значение в результат не попадает.
func TestInvariantApplyUnicodeRoundTrip(t *testing.T) {
	for _, tc := range unicodeCases {
		for _, st := range allStrategies(t) {
			t.Run(tc.name+"/"+st.Name(), func(t *testing.T) { checkUnicodeRoundTrip(t, tc, st) })
		}
	}
}

// checkUnicodeRoundTrip — один случай TestInvariantApplyUnicodeRoundTrip:
// инварианты Apply держатся, и ни одно значение не осталось в результате.
func checkUnicodeRoundTrip(t *testing.T, tc unicodeCase, st Strategy) {
	t.Helper()
	var spans []detect.Span
	from := 0
	for i, v := range tc.values {
		sp := spanOf(t, tc.text, v, tc.types[i], from)
		spans = append(spans, sp)
		from = int(sp.End)
	}
	var a Applier
	out, applied := a.Apply(tc.text, spans, func(pii.Type) Strategy { return st })
	checkApplyInvariants(t, tc.text, spans, out, applied)
	for _, v := range tc.values {
		if strings.Contains(out, v) {
			t.Errorf("значение %q осталось в результате %q", v, out)
		}
	}
}

// TestInvariantApplyGeneratedRoundTrip — AC-1, AC-2, свойство на
// сгенерированных входах: любой текст, любые непересекающиеся спаны, любая
// стратегия — результат собран точно и обратим.
//
// Спаны ставятся на произвольные байты, в том числе посреди многобайтовой
// руны: Applier работает с байтами и не обязан знать про UTF-8.
func TestInvariantApplyGeneratedRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(invariantSeed))
	strategies := allStrategies(t)
	types := pii.All()
	var a Applier
	for iter := 0; iter < 2000; iter++ {
		text := genText(r, r.Intn(80))
		spans := genSpans(r, len(text), types)
		picks := make(map[pii.Type]Strategy, len(types))
		for _, tp := range types {
			picks[tp] = strategies[r.Intn(len(strategies))]
		}
		out, applied := a.Apply(text, spans, func(tp pii.Type) Strategy { return picks[tp] })
		checkApplyInvariants(t, text, spans, out, applied)
		if len(spans) == 0 && out != text {
			t.Fatalf("итерация %d: текст без спанов изменён", iter)
		}
	}
}

// TestInvariantApplyBoundaries — AC-4: спан в начале, в конце, на весь
// текст, соседние спаны без разделителя, пустой и односимвольный текст.
func TestInvariantApplyBoundaries(t *testing.T) {
	const name = surnamePetrov
	const mail = mailPetrov
	const before = "пишет "
	tests := []struct {
		name  string
		text  string
		spans []detect.Span
		want  string
	}{
		{"пустой текст без спанов", "", nil, ""},
		{"один ASCII-символ", "x", nil, "x"},
		{"одна кириллическая буква", "П", nil, "П"},
		{"одна буква целиком спан", "П", []detect.Span{{Start: 0, End: 2, Type: pii.FullName}}, "[ФИО_1]"},
		{"один эмодзи", "👍", nil, "👍"},
		{"один некорректный байт", badByte, nil, badByte},
		{"спан в начале", name + " пишет", []detect.Span{{Start: 0, End: int32(len(name)), Type: pii.FullName}}, "[ФИО_1] пишет"},
		{"спан в конце", before + name, []detect.Span{{Start: int32(len(before)), End: int32(len(before + name)), Type: pii.FullName}}, "пишет [ФИО_1]"},
		{"спан на весь текст", mail, []detect.Span{{Start: 0, End: int32(len(mail)), Type: pii.Email}}, "[EMAIL_1]"},
		{
			"соседние спаны без разделителя", name + mail,
			[]detect.Span{
				{Start: 0, End: int32(len(name)), Type: pii.FullName},
				{Start: int32(len(name)), End: int32(len(name + mail)), Type: pii.Email},
			},
			"[ФИО_1][EMAIL_1]",
		},
		{
			"соседние спаны одного типа", name + name + "а",
			[]detect.Span{
				{Start: 0, End: int32(len(name)), Type: pii.FullName},
				{Start: int32(len(name)), End: int32(len(name + name + "а")), Type: pii.FullName},
			},
			"[ФИО_1][ФИО_2]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a Applier
			out, applied := a.Apply(tt.text, tt.spans, placeholders)
			if out != tt.want {
				t.Fatalf("Apply = %q, ожидалось %q", out, tt.want)
			}
			checkApplyInvariants(t, tt.text, tt.spans, out, applied)
		})
	}
}

// TestInvariantApplyBrokenSpansDoNotPanic — AC-2, AC-4: рассогласованные
// спаны не роняют сборку результата и не дают замен с битыми границами.
// Движок таких спанов не выдаёт; проверка защищает от регрессии в нём.
func TestInvariantApplyBrokenSpansDoNotPanic(t *testing.T) {
	const text = "Петров пишет"
	tests := []struct {
		name  string
		text  string
		spans []detect.Span
	}{
		{"конец за пределами текста", text, []detect.Span{{Start: 0, End: int32(len(text) + 5), Type: pii.FullName}}},
		{"отрицательное начало", text, []detect.Span{{Start: -3, End: 4, Type: pii.FullName}}},
		{"перекрытие с предыдущим", text, []detect.Span{{Start: 0, End: 12, Type: pii.FullName}, {Start: 6, End: 14, Type: pii.FullName}}},
		{"пустой текст и спан", "", []detect.Span{{Start: 0, End: 1, Type: pii.FullName}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a Applier
			out, applied := a.Apply(tt.text, tt.spans, placeholders)
			for _, ap := range applied {
				if ap.Start < 0 || int(ap.End) > len(tt.text) || ap.Start >= ap.End {
					t.Fatalf("применена замена с битыми границами [%d:%d]", ap.Start, ap.End)
				}
			}
			if len(applied) == 0 && out != tt.text {
				t.Fatalf("без применённых замен текст изменён: %q", out)
			}
		})
	}
}

// TestInvariantApplyInvertedSpanDoesNotPanic — AC-2: спан с началом после
// конца, но внутри текста.
//
// Комментарий в Apply обещает пропуск битого спана («защита от
// рассогласования»), но до T-47 условие покрывало только выход за правую
// границу и перекрытие с предыдущим, и для Start > End выражение
// text[Start:End] паниковало (дефект D-5).
func TestInvariantApplyInvertedSpanDoesNotPanic(t *testing.T) {
	const text = "Петров пишет"
	var a Applier
	out, applied := a.Apply(text, []detect.Span{{Start: 6, End: 2, Type: pii.FullName}}, placeholders)
	if len(applied) != 0 || out != text {
		t.Fatalf("битый спан применён: %q", out)
	}
}

// TestInvariantStrategiesHandleHostileValues — AC-2: стратегии не паникуют на
// Unicode-крайностях и некорректном UTF-8, а замена не повторяет исходное
// значение. У звёздочек замена совпадает со значением только тогда, когда в
// нём нет ни одного скрываемого символа.
func TestInvariantStrategiesHandleHostileValues(t *testing.T) {
	values := []string{
		badByte, "\xc3", "\xe2\x82", "Пет\xffров", "👩\u200d💻", "e\u0301", "\u200b",
		"Петров\u200dПётр", "\r\n", `\u0041`, strings.Repeat("Я", 300),
	}
	for _, st := range allStrategies(t) {
		for _, tp := range pii.All() {
			for _, v := range values {
				for _, seq := range []int{0, 1, 64, 65, 1 << 20} {
					if repl := st.Mask(v, tp, seq); repl == v {
						t.Fatalf("%s/%s/%d: замена совпала с исходным значением %q", st.Name(), tp.Key(), seq, v)
					}
				}
			}
		}
	}
}

// genText строит текст из смеси кириллицы, латиницы, цифр, эмодзи,
// составных символов, символов нулевой ширины, CRLF, JSON-escapes и
// некорректных байтов.
func genText(r *rand.Rand, n int) string {
	pieces := []string{
		"а", "Ё", "ё", "Я", "ж", "z", "Q", "7", " ", ".", ",", "-", "@", "+",
		"\r\n", "\n", "\t", "\u200b", "\u200d", "\ufeff", "\u0301", "\u00a0",
		"👍", "🏽", "👩\u200d💻", "🇷🇺", `\u0041`, `\"`, `\\`, badByte, "\xc3", "\xe2\x82",
		"[ФИО_1]", "{{pii:0000abcd}}", surnamePetrov, mailPetrov,
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(pieces[r.Intn(len(pieces))])
	}
	return b.String()
}

// genSpans строит отсортированные непересекающиеся спаны на произвольных
// байтах текста, в том числе соседние без зазора.
func genSpans(r *rand.Rand, size int, types []pii.Type) []detect.Span {
	var spans []detect.Span
	pos := 0
	for pos < size && len(spans) < 12 {
		if r.Intn(3) > 0 {
			pos += r.Intn(8) // зазор, возможно нулевой
		}
		if pos >= size {
			break
		}
		end := pos + 1 + r.Intn(min(12, size-pos))
		if end > size {
			end = size
		}
		spans = append(spans, detect.Span{
			Start: int32(pos), End: int32(end), Type: types[r.Intn(len(types))],
		})
		pos = end
	}
	return spans
}
