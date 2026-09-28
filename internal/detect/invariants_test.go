package detect

// Тесты инвариантов движка детекции (T-19).
//
// Проверяются свойства, на которые опирается маскирование и которые нельзя
// увидеть глазами на демо: спаны отсортированы и не пересекаются при любом
// наборе кандидатов, смещения — байты, а не руны, нормализация не протекает в
// границы, некорректный UTF-8 не роняет обработку. Все значения —
// синтетические; генераторы работают с фиксированным seed.

import (
	"context"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// invariantSeed фиксирует генераторы: провал воспроизводится повторным
// запуском, а не удачей.
const invariantSeed = 19

// Синтетические значения, которые повторяются в нескольких проверках файла.
const (
	invMail     = "ivanov@example.test"
	invFullName = "Иванов Иван Иванович"
	invBadByte  = "\xff"
)

// checkSpansWellFormed — общий инвариант результата движка: спаны лежат в
// пределах текста, не пустые, отсортированы по началу и не пересекаются.
func checkSpansWellFormed(t *testing.T, text string, spans []Span) {
	t.Helper()
	for i, s := range spans {
		if s.Start < 0 || s.End > int32(len(text)) || s.Start >= s.End {
			t.Fatalf("спан %d [%d:%d] вне текста длиной %d или пуст", i, s.Start, s.End, len(text))
		}
		if i > 0 && spans[i-1].End > s.Start {
			t.Fatalf("спаны %d [%d:%d] и %d [%d:%d] не отсортированы или пересекаются",
				i-1, spans[i-1].Start, spans[i-1].End, i, s.Start, s.End)
		}
		if s.Conf == Denied {
			t.Fatalf("в результат попал спан с вето [%d:%d] %s", s.Start, s.End, s.Rule)
		}
	}
}

// runeBoundaries возвращает множество байтовых смещений, на которых
// начинается очередная руна при декодировании слева направо, плюс конец
// текста. Некорректный байт декодируется как руна длиной один байт — так же,
// как его видит лексер.
func runeBoundaries(text string) map[int32]bool {
	b := make(map[int32]bool, len(text)+1)
	for i := 0; i < len(text); {
		b[int32(i)] = true
		_, size := utf8.DecodeRuneInString(text[i:])
		i += size
	}
	b[int32(len(text))] = true
	return b
}

// checkSpansOnRuneBoundaries — спан, начатый или законченный посреди руны,
// оставил бы в маске обрывок UTF-8 исходного значения.
func checkSpansOnRuneBoundaries(t *testing.T, text string, spans []Span) {
	t.Helper()
	b := runeBoundaries(text)
	for _, s := range spans {
		if !b[s.Start] || !b[s.End] {
			t.Fatalf("спан [%d:%d] %s режет руну в %q", s.Start, s.End, s.Type.Key(), text)
		}
	}
}

// spanKey — сравнимая часть спана. Имя правила в сравнение не входит: при
// одинаковых кандидатах разных сканеров оно зависит от порядка их работы,
// а на маскирование не влияет.
type spanKey struct {
	start, end int32
	typ        pii.Type
	conf       Confidence
}

func keysOf(spans []Span) []spanKey {
	out := make([]spanKey, len(spans))
	for i, s := range spans {
		out[i] = spanKey{s.Start, s.End, s.Type, s.Conf}
	}
	return out
}

// genCandidates строит случайный набор кандидатов и вето поверх текста
// длиной size: перекрытия, вложения, совпадающие границы и соседство без
// зазора возникают естественно.
func genCandidates(r *rand.Rand, size int) ([]Span, []Veto) {
	types := pii.All()
	confs := []Confidence{Denied, Weak, Strong, Certain}
	n := r.Intn(30)
	spans := make([]Span, 0, n)
	for i := 0; i < n; i++ {
		start := r.Intn(size)
		end := start + 1 + r.Intn(min(24, size-start))
		spans = append(spans, Span{
			Start: int32(start), End: int32(end),
			Type: types[r.Intn(len(types))], Conf: confs[r.Intn(len(confs))],
			Rule: "gen",
		})
	}
	// Точные дубли границ с разными типами — частый случай в реальных
	// сканерах: номер документа и номер карты на одних и тех же цифрах.
	if len(spans) > 0 && r.Intn(2) == 0 {
		d := spans[r.Intn(len(spans))]
		d.Type = types[r.Intn(len(types))]
		spans = append(spans, d)
	}
	var vetos []Veto
	for i := r.Intn(4); i > 0; i-- {
		start := r.Intn(size)
		end := start + 1 + r.Intn(min(16, size-start))
		var ts pii.Set
		if r.Intn(2) == 0 {
			ts = pii.NewSet(types[r.Intn(len(types))])
		}
		vetos = append(vetos, Veto{Start: int32(start), End: int32(end), Types: ts, Rule: "gen-veto"})
	}
	return spans, vetos
}

// vetoed повторяет правило applyVetos для проверки со стороны.
func vetoed(s Span, vetos []Veto) bool {
	for _, v := range vetos {
		if s.Start >= v.End || s.End <= v.Start {
			continue
		}
		if v.Types.Empty() || v.Types.Has(s.Type) {
			return true
		}
	}
	return false
}

// genFiller — текст-подложка для сгенерированных кандидатов. Точки дают
// несколько предложений, чтобы работал подъём по кластеру.
func genFiller(r *rand.Rand) string {
	words := []string{"слово", "текст", "ещё", "и", "клиент", "номер", "Ёж"}
	var b strings.Builder
	for b.Len() < 120+r.Intn(200) {
		b.WriteString(words[r.Intn(len(words))])
		if r.Intn(6) == 0 {
			b.WriteString(". ")
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// runDetect выполняет полный конвейер движка и возвращает копию спанов.
func runDetect(t *testing.T, e *Engine, text string, opts Options) []Span {
	t.Helper()
	doc := lex.Tokenize(text, nil)
	var (
		cand Candidates
		res  Result
	)
	out, err := e.Detect(context.Background(), doc, opts, &cand, &res)
	if err != nil {
		t.Fatalf(msgDetectFailed, err)
	}
	for _, s := range out.Spans {
		if !out.Found.Has(s.Type) {
			t.Fatalf("тип %s есть в спанах, но не в Found", s.Type.Key())
		}
	}
	return slices.Clone(out.Spans)
}

// genProfiles — профили, из которых генератор выбирает профиль итерации.
var genProfiles = []Profile{Balanced, Strict, Paranoid}

// genEngineCase — одна итерация генератора: текст, кандидаты, вето, опции
// движка и набор типов потребителя.
type genEngineCase struct {
	iter  int
	text  string
	spans []Span
	vetos []Veto
	opts  Options
	types pii.Set
}

// newGenEngineCase строит итерацию. Порядок обращений к r зафиксирован:
// от него зависит, какие входы проверяет тест при заданном seed.
func newGenEngineCase(r *rand.Rand, iter int) genEngineCase {
	text := genFiller(r)
	spans, vetos := genCandidates(r, len(text))
	opts := Options{Profile: genProfiles[r.Intn(len(genProfiles))]}
	if r.Intn(3) == 0 {
		opts.MaxSpans = 1 + r.Intn(5)
	}
	var types pii.Set
	for _, tp := range pii.All() {
		if r.Intn(2) == 0 {
			types = types.Add(tp)
		}
	}
	return genEngineCase{iter: iter, text: text, spans: spans, vetos: vetos, opts: opts, types: types}
}

// isAdmissibleCandidate сообщает, есть ли среди кандидатов допустимый
// (без вето уровня Denied) с теми же границами и типом, что у s.
func isAdmissibleCandidate(s Span, spans []Span) bool {
	for _, c := range spans {
		if c.Start == s.Start && c.End == s.End && c.Type == s.Type && c.Conf != Denied {
			return true
		}
	}
	return false
}

// assertOnlyAdmissible — каждый спан результата — один из поданных
// кандидатов, не снятый вето.
func assertOnlyAdmissible(t *testing.T, c genEngineCase, full []Span) {
	t.Helper()
	for _, s := range full {
		if !isAdmissibleCandidate(s, c.spans) || vetoed(s, c.vetos) {
			t.Fatalf("итерация %d: в результате спан [%d:%d] %s, которого не было среди допустимых кандидатов",
				c.iter, s.Start, s.End, s.Type.Key())
		}
	}
}

// assertOrderIndependent — порядок работы сканеров не влияет на результат:
// перемешанные кандидаты и вето, разнесённые по двум сканерам, дают то же
// самое. Перемешивание расходует r, поэтому вызывается ровно там же, где
// раньше стоял этот блок проверки.
func assertOrderIndependent(t *testing.T, r *rand.Rand, c genEngineCase, full []Span) {
	t.Helper()
	sh := slices.Clone(c.spans)
	r.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
	vs := slices.Clone(c.vetos)
	r.Shuffle(len(vs), func(i, j int) { vs[i], vs[j] = vs[j], vs[i] })
	half := len(sh) / 2
	shuffled := runDetect(t, New(nil,
		fixedScanner{spans: sh[half:], vetos: vs},
		fixedScanner{spans: sh[:half]},
	), c.text, c.opts)
	if !slices.Equal(keysOf(full), keysOf(shuffled)) {
		t.Fatalf("итерация %d: результат зависит от порядка кандидатов:\n%v\n%v", c.iter, keysOf(full), keysOf(shuffled))
	}
}

// coveredByAccepted сообщает, пересекается ли кандидат c с принятым спаном
// не слабее себя.
func coveredByAccepted(c Span, full []Span) bool {
	for _, s := range full {
		if s.Start < c.End && c.Start < s.End && !stronger(c, s) {
			return true
		}
	}
	return false
}

// assertGreedyComplete — жадный отбор полон: в профиле без подъёма по
// кластеру и без предела замен каждый допустимый кандидат либо принят, либо
// пересекается с принятым не слабее себя.
func assertGreedyComplete(t *testing.T, c genEngineCase, full []Span) {
	t.Helper()
	for _, cand := range c.spans {
		if cand.Conf == Denied || vetoed(cand, c.vetos) {
			continue
		}
		if !coveredByAccepted(cand, full) {
			t.Fatalf("итерация %d: допустимый кандидат [%d:%d] %s %s потерян без более сильного соперника",
				c.iter, cand.Start, cand.End, cand.Type.Key(), cand.Conf)
		}
	}
}

// assertPolicyPostFilter — политика — пост-фильтр победителей. При пределе
// замен это свойство не держится по построению (предел считается по
// заменам), поэтому вызывается только без него.
func assertPolicyPostFilter(t *testing.T, c genEngineCase, full []Span) {
	t.Helper()
	o := c.opts
	o.Types = c.types
	filtered := runDetect(t, New(nil, fixedScanner{spans: c.spans, vetos: c.vetos}), c.text, o)
	checkSpansWellFormed(t, c.text, filtered)
	var want []Span
	for _, s := range full {
		if c.types.Empty() || c.types.Has(s.Type) {
			want = append(want, s)
		}
	}
	if !slices.Equal(keysOf(want), keysOf(filtered)) {
		t.Fatalf("итерация %d: разметка потребителя не равна пост-фильтру полной разметки:\n%v\n%v",
			c.iter, keysOf(want), keysOf(filtered))
	}
}

// TestInvariantEngineGeneratedCandidates — AC-3: на сгенерированных наборах
// кандидатов результат движка отсортирован, не пересекается, не зависит от
// порядка кандидатов и вето, состоит только из допущенных кандидатов и
// подчиняется политике как пост-фильтру (REQ-206).
func TestInvariantEngineGeneratedCandidates(t *testing.T) {
	r := rand.New(rand.NewSource(invariantSeed))
	for iter := 0; iter < 3000; iter++ {
		c := newGenEngineCase(r, iter)
		full := runDetect(t, New(nil, fixedScanner{spans: c.spans, vetos: c.vetos}), c.text, c.opts)
		checkSpansWellFormed(t, c.text, full)
		assertOnlyAdmissible(t, c, full)
		assertOrderIndependent(t, r, c, full)
		if c.opts.Profile == Paranoid && c.opts.MaxSpans == 0 {
			assertGreedyComplete(t, c, full)
		}
		if c.opts.MaxSpans == 0 {
			assertPolicyPostFilter(t, c, full)
		}
	}
}

// piiFragments — синтетические значения и маркеры, из которых собираются
// тексты для прогона реальных сканеров.
var piiFragments = []string{
	"Клиент Иванов Иван Иванович", "ИВАНОВ ИВАН ИВАНОВИЧ", "Ёжиков Ёжик Ёжикович",
	"email ivanov@example.test", "ИВАНОВ@EXAMPLE.TEST", "тел. +7 916 123-45-67",
	"Карта 4276 5500 1234 5678", "CVV 123", "ИНН 500100732259",
	"паспорт серия 4509 номер 123456", "родился 12.05.1990 года",
	"г. Москва, ул. Ленина, д. 5, кв. 12", "ул. Пушкина", "поэт Пушкин",
	"[ФИО_1]", "{{pii:deadbeef}}", "[ЗАЩИЩЕНО]",
}

// noiseFragments — участки, трудные для смещений и нормализации.
var noiseFragments = []string{
	" ", ", ", ". ", "\r\n", "\n\n", "\t", "\u200b", "\u200d", "\ufeff", "\u00a0",
	"e\u0301", "Ё\u0308", "👍🏽", "👩\u200d💻", "🇷🇺", `\u0041`, `\"`, `\\n`,
	invBadByte, "\xc3", "\xe2\x82", "\x80", "ёЁ", "Ǆ", "ß", "İ", "ﬁ",
}

func genPIIText(r *rand.Rand) string {
	var b strings.Builder
	for i := r.Intn(12); i >= 0; i-- {
		if r.Intn(2) == 0 {
			b.WriteString(piiFragments[r.Intn(len(piiFragments))])
		}
		for j := r.Intn(3); j >= 0; j-- {
			b.WriteString(noiseFragments[r.Intn(len(noiseFragments))])
		}
	}
	return b.String()
}

// TestInvariantEngineRealScannersGeneratedTexts — AC-2, AC-3 на полном наборе
// сканеров: на сгенерированных текстах с Unicode-шумом и некорректным UTF-8
// результат отсортирован, не пересекается, не режет руны, воспроизводим и не
// меняет исходный текст.
func TestInvariantEngineRealScannersGeneratedTexts(t *testing.T) {
	e := newFullEngine(t)
	r := rand.New(rand.NewSource(invariantSeed))
	for iter := 0; iter < 1500; iter++ {
		text := genPIIText(r)
		orig := strings.Clone(text)
		for _, p := range []Profile{Balanced, Strict, Paranoid} {
			a := runDetect(t, e, text, Options{Profile: p})
			checkSpansWellFormed(t, text, a)
			checkSpansOnRuneBoundaries(t, text, a)
			b := runDetect(t, e, text, Options{Profile: p})
			if !slices.Equal(keysOf(a), keysOf(b)) {
				t.Fatalf("итерация %d: повторная детекция дала другой результат на %q", iter, text)
			}
		}
		if text != orig {
			t.Fatalf("итерация %d: детекция изменила исходный текст", iter)
		}
	}
}

// byteOffsetCase — текст, ожидаемое значение и его тип для проверки
// байтовых смещений.
type byteOffsetCase struct {
	name string
	text string
	want string
	typ  pii.Type
}

// hasSpanAtByte сообщает, есть ли среди спанов спан типа typ со значением
// want, начатый в байте at.
func hasSpanAtByte(text string, spans []Span, typ pii.Type, want string, at int) bool {
	for _, s := range spans {
		if s.Type == typ && text[s.Start:s.End] == want && int(s.Start) == at {
			return true
		}
	}
	return false
}

// checkSpanAtByte прогоняет один случай TestInvariantSpanOffsetsAreBytes.
func checkSpanAtByte(t *testing.T, e *Engine, tt byteOffsetCase) {
	t.Helper()
	spans := runDetect(t, e, tt.text, Options{})
	checkSpansWellFormed(t, tt.text, spans)
	checkSpansOnRuneBoundaries(t, tt.text, spans)
	at := strings.Index(tt.text, tt.want)
	if at < 0 {
		t.Fatalf("ожидаемое значение отсутствует в тексте")
	}
	if runeIdx := utf8.RuneCountInString(tt.text[:at]); runeIdx == at {
		t.Fatalf("тест бессмыслен: байтовый и рунический индексы совпали (%d)", at)
	}
	if hasSpanAtByte(tt.text, spans, tt.typ, tt.want, at) {
		return
	}
	var got []string
	for _, s := range spans {
		got = append(got, s.Type.Key()+":"+tt.text[s.Start:s.End])
	}
	t.Fatalf("спан %s %q с началом в байте %d не найден, найдено: %q", tt.typ.Key(), tt.want, at, got)
}

// TestInvariantSpanOffsetsAreBytes — смещения спанов байтовые: вырезанный по
// Start:End фрагмент равен ожидаемому значению, а Start совпадает с байтовым,
// а не с руническим индексом.
func TestInvariantSpanOffsetsAreBytes(t *testing.T) {
	e := newFullEngine(t)
	tests := []byteOffsetCase{
		{"email после кириллицы", "Клиент пишет: ivanov@example.test", invMail, pii.Email},
		{"email после эмодзи с ZWJ", "👩\u200d💻 Пишите: ivanov@example.test\r\nспасибо", invMail, pii.Email},
		{"телефон после CRLF", "👩\u200d💻 Пишите: ivanov@example.test\r\nтел. +7 916 123-45-67", "+7 916 123-45-67", pii.Phone},
		{"email между символами нулевой ширины", "\u200bпочта \u200bivanov@example.test\u200d", invMail, pii.Email},
		{"ФИО после эмодзи", "🇷🇺👍🏽 Клиент Иванов Иван Иванович", invFullName, pii.FullName},
		{"ФИО с неразрывными пробелами", "Клиент Иванов\u00a0Иван\u00a0Иванович", "Иванов\u00a0Иван\u00a0Иванович", pii.FullName},
		{"ФИО в верхнем регистре", "КЛИЕНТ: ИВАНОВ ИВАН ИВАНОВИЧ", "ИВАНОВ ИВАН ИВАНОВИЧ", pii.FullName},
		{"ФИО с ё", "Клиент Ёжиков Ёжик Ёжикович пишет", "Ёжиков Ёжик Ёжикович", pii.FullName},
		{"email в верхнем регистре", "Пишите на ИВАНОВ@EXAMPLE.TEST", "ИВАНОВ@EXAMPLE.TEST", pii.Email},
		{"дата рождения", "Иванов Иван Иванович 👍🏽 родился 01.02.1985", "01.02.1985", pii.BirthDate},
		{"ИНН после некорректного байта", "\xff\xfeИНН 500100732259", "500100732259", pii.INN},
		{"email после некорректных байтов", "\xff\xfeИванов Иван \xc3 ivanov@example.test \xe2\x82", invMail, pii.Email},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkSpanAtByte(t, e, tt) })
	}
}

// TestInvariantNormalizationStaysInsideSearch — REQ-201, REQ-304: нормализация
// (регистр, «ё» → «е») используется только для поиска.
//
// Исходный текст не меняется, норма побайтово выровнена с ним, а разметка не
// зависит от регистра: варианты одного текста, отличающиеся только регистром
// и «ё», дают спаны с теми же границами и типами. Символы, у которых нижний
// регистр другой длины в байтах (İ, Ǆ, K), не сдвигают границы соседних
// значений.
func TestInvariantNormalizationStaysInsideSearch(t *testing.T) {
	e := newFullEngine(t)
	variants := [][]string{
		{
			"Клиент Ёжиков Ёжик Ёжикович, почта ivanov@example.test",
			"КЛИЕНТ ЁЖИКОВ ЁЖИК ЁЖИКОВИЧ, ПОЧТА IVANOV@EXAMPLE.TEST",
			"клиент ежиков ежик ежикович, почта Ivanov@Example.Test",
		},
		{
			"İİİ Ǆ K Клиент Иванов Иван Иванович, тел. +7 916 123-45-67",
			"İİİ Ǆ K КЛИЕНТ ИВАНОВ ИВАН ИВАНОВИЧ, ТЕЛ. +7 916 123-45-67",
		},
	}
	for _, group := range variants {
		base := boundaryKeys(t, e, group[0])
		for _, text := range group[1:] {
			if got := boundaryKeys(t, e, text); !slices.Equal(base, got) {
				t.Fatalf("разметка зависит от регистра:\n%q -> %v\n%q -> %v", group[0], base, text, got)
			}
		}
	}
}

// boundaryKeys размечает text полным движком и возвращает границы и типы
// спанов без уровня уверенности, попутно проверяя, что норма выровнена с
// текстом, текст не изменён и хоть что-то найдено.
func boundaryKeys(t *testing.T, e *Engine, text string) []spanKey {
	t.Helper()
	orig := strings.Clone(text)
	doc := lex.Tokenize(text, nil)
	if len(doc.Norm) != len(doc.Text) {
		t.Fatalf("норма не выровнена с текстом: %d и %d байт", len(doc.Norm), len(doc.Text))
	}
	var (
		cand Candidates
		res  Result
	)
	if _, err := e.Detect(context.Background(), doc, Options{}, &cand, &res); err != nil {
		t.Fatalf(msgDetectFailed, err)
	}
	if doc.Text != orig {
		t.Fatalf("детекция изменила исходный текст")
	}
	if len(res.Spans) == 0 {
		t.Fatalf("в %q ничего не найдено — проверка границ бессмысленна", text)
	}
	got := keysOf(res.Spans)
	// Уровень уверенности может зависеть от регистра (например, от
	// заглавной буквы в имени); границы и тип — нет.
	for j := range got {
		got[j].conf = 0
	}
	return got
}

// TestInvariantInvalidUTF8DoesNotPanic — AC-2: движок вызывается напрямую,
// без recover ядра обработки, на некорректном UTF-8 любой формы. Паника здесь
// на /process была бы скрыта безопасным откатом и превратилась бы в маску на
// весь текст — потеря баллов без видимой причины.
func TestInvariantInvalidUTF8DoesNotPanic(t *testing.T) {
	e := newFullEngine(t)
	fixed := []string{
		invBadByte, "\xfe\xff", "\xc3", "\xe2\x82", "\xf0\x9f\x98", "\x80\x80\x80",
		"\xed\xa0\x80", // суррогат в UTF-8
		"\xc0\xaf",     // избыточная кодировка «/»
		"Иванов\xffИван\xfeИванович", "ivanov\xff@example.test", "+7\xc3916 123-45-67",
		"4276\xff5500\xff1234\xff5678", "\xd0", "Клиент \xd0",
	}
	for _, text := range fixed {
		spans := runDetect(t, e, text, Options{Profile: Paranoid})
		checkSpansWellFormed(t, text, spans)
		checkSpansOnRuneBoundaries(t, text, spans)
	}
	r := rand.New(rand.NewSource(invariantSeed))
	buf := make([]byte, 0, 256)
	for iter := 0; iter < 3000; iter++ {
		buf = buf[:0]
		for i := r.Intn(200); i > 0; i-- {
			switch r.Intn(4) {
			case 0:
				buf = append(buf, byte(r.Intn(256)))
			case 1:
				buf = append(buf, "Иванов "...)
			case 2:
				buf = append(buf, byte('0'+r.Intn(10)))
			default:
				buf = append(buf, byte(0x80+r.Intn(0x40)))
			}
		}
		text := string(buf)
		for _, p := range []Profile{Balanced, Paranoid} {
			spans := runDetect(t, e, text, Options{Profile: p})
			checkSpansWellFormed(t, text, spans)
			checkSpansOnRuneBoundaries(t, text, spans)
		}
	}
}

// TestInvariantEngineBoundaries — AC-4 на полном наборе сканеров: пустой и
// односимвольный текст, значение в начале, в конце, на весь текст и два
// значения вплотную без разделителя.
func TestInvariantEngineBoundaries(t *testing.T) {
	e := newFullEngine(t)
	const mail = invMail
	const phone = "+7 916 123-45-67"
	const before = "пишите "

	for _, text := range []string{"", "x", "И", "1", "@", "👍", invBadByte, "\u200b", "\r\n"} {
		spans := runDetect(t, e, text, Options{Profile: Paranoid})
		checkSpansWellFormed(t, text, spans)
	}

	tests := []struct {
		name string
		text string
		want [][2]int
	}{
		{"значение на весь текст", mail, [][2]int{{0, len(mail)}}},
		{"значение в начале", mail + " пишет", [][2]int{{0, len(mail)}}},
		{"значение в конце", before + mail, [][2]int{{len(before), len(before + mail)}}},
		{"два значения вплотную", mail + phone, [][2]int{{0, len(mail)}, {len(mail), len(mail + phone)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans := runDetect(t, e, tt.text, Options{})
			checkSpansWellFormed(t, tt.text, spans)
			checkSpanBounds(t, spans, tt.want)
		})
	}

	// Движок сам по себе: кандидат на весь текст и соседние кандидаты без
	// зазора принимаются как есть.
	const text = "abcdef"
	whole := []Span{{Start: 0, End: 6, Type: pii.Email, Conf: Certain, Rule: "t"}}
	adjacent := []Span{
		{Start: 0, End: 3, Type: pii.FullName, Conf: Strong, Rule: "t"},
		{Start: 3, End: 6, Type: pii.Phone, Conf: Strong, Rule: "t"},
	}
	for _, in := range [][]Span{whole, adjacent} {
		got := runDetect(t, New(nil, fixedScanner{spans: in}), text, Options{})
		if !slices.Equal(keysOf(got), keysOf(in)) {
			t.Fatalf("Detect = %v, ожидалось %v", keysOf(got), keysOf(in))
		}
	}
}

// checkSpanBounds сверяет число спанов и их байтовые границы с ожидаемыми.
func checkSpanBounds(t *testing.T, spans []Span, want [][2]int) {
	t.Helper()
	if len(spans) != len(want) {
		t.Fatalf("найдено %d спанов, ожидалось %d", len(spans), len(want))
	}
	for i, w := range want {
		if int(spans[i].Start) != w[0] || int(spans[i].End) != w[1] {
			t.Fatalf("спан %d [%d:%d], ожидался [%d:%d]", i, spans[i].Start, spans[i].End, w[0], w[1])
		}
	}
}

// TestInvariantMaskLookingInputIsNotPII — AC-7: текст, похожий на маску
// (плейсхолдер, токен, маркер безопасного отката), сам по себе ПД не
// считается, а соседнее настоящее значение размечается без захвата маски.
func TestInvariantMaskLookingInputIsNotPII(t *testing.T) {
	e := newFullEngine(t)
	const looks = "[ФИО_1] и [ТЕЛЕФОН_2], {{pii:deadbeef}}, [ЗАЩИЩЕНО], [EMAIL_10]"
	for _, p := range []Profile{Balanced, Strict} {
		if spans := runDetect(t, e, looks, Options{Profile: p}); len(spans) != 0 {
			t.Fatalf("профиль %s: маска во входе размечена как ПД: %v", p, keysOf(spans))
		}
	}

	const text = "[ФИО_1] пишет: Клиент Иванов Иван Иванович"
	spans := runDetect(t, e, text, Options{})
	checkSpansWellFormed(t, text, spans)
	if len(spans) != 1 || text[spans[0].Start:spans[0].End] != invFullName {
		var got []string
		for _, s := range spans {
			got = append(got, text[s.Start:s.End])
		}
		t.Fatalf("ожидался один спан ФИО, найдено %q", got)
	}
}

// TestInvariantUnicodeInsideNameDoesNotBreakDetection — пропуск ПД из-за
// символа внутри слова.
//
// Ударение (U+0301), мягкий перенос (U+00AD) и символ нулевой ширины внутри
// фамилии не видны человеку, но лексер считает их знаками препинания и режет
// слово на части. Итог — ФИО не находится целиком или находится без фамилии,
// и значение уходит наружу открытым.
func TestInvariantUnicodeInsideNameDoesNotBreakDetection(t *testing.T) {
	e := newFullEngine(t)
	tests := []struct{ text, want string }{
		{"Клиент Ива\u0301нов Ива\u0301н Ива\u0301нович", "Ива\u0301нов Ива\u0301н Ива\u0301нович"},
		{"Клиент Ива\u00adнов Иван Иванович", "Ива\u00adнов Иван Иванович"},
		{"Клиент Ива\u200bнов Иван Иванович", "Ива\u200bнов Иван Иванович"},
	}
	for _, tt := range tests {
		spans := runDetect(t, e, tt.text, Options{})
		ok := false
		for _, s := range spans {
			if s.Type == pii.FullName && tt.text[s.Start:s.End] == tt.want {
				ok = true
			}
		}
		if !ok {
			t.Errorf("ФИО %q не найдено целиком в %q", tt.want, tt.text)
		}
	}
}

// TestInvariantToponymVetoDoesNotSwallowFollowingName — пропуск ФИО после
// названия улицы без запятой.
//
// Найдено генератором текстов T-19. Контр-правило «топоним от фамилии»
// ставит вето на ФИО не только на название улицы, но и на следующие за ним
// до четырёх слов с заглавной буквы. «ул. Пушкина Иванов Иван Иванович» —
// вето накрывает и «Иванов Иван Иванович», ФИО уходит открытым. С запятой
// или переводом строки между адресом и именем значение находится.
func TestInvariantToponymVetoDoesNotSwallowFollowingName(t *testing.T) {
	e := newFullEngine(t)
	tests := []struct{ text, want string }{
		{"ул. Пушкина Иванов Иван Иванович", invFullName},
		{"ул. Ленина\tПетров Пётр Петрович", "Петров Пётр Петрович"},
		{"проживает: ул. Гагарина Сидоров Сидор Сидорович", "Сидоров Сидор Сидорович"},
	}
	for _, tt := range tests {
		spans := runDetect(t, e, tt.text, Options{})
		ok := false
		for _, s := range spans {
			if s.Type == pii.FullName && tt.text[s.Start:s.End] == tt.want {
				ok = true
			}
		}
		if !ok {
			t.Errorf("ФИО %q не найдено в %q", tt.want, tt.text)
		}
	}
}
