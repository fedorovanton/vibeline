package detect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Имена правил, повторяющиеся в тестах движка.
const (
	testRulePhone    = "phone"
	testRulePassport = "passport"
	testRuleCVVShape = "cvv/shape"
)

var (
	engineDictsOnce sync.Once
	engineDictsSet  *dict.Set
	engineDictsErr  error
)

// engineTestDicts загружает встроенные справочники один раз на пакет.
func engineTestDicts(tb testing.TB) *dict.Set {
	tb.Helper()
	engineDictsOnce.Do(func() { engineDictsSet, engineDictsErr = dict.Load() })
	if engineDictsErr != nil {
		tb.Fatalf(msgDictLoad, engineDictsErr)
	}
	return engineDictsSet
}

// newFullEngine собирает движок из всех зарегистрированных сканеров — тот же
// набор, что работает в сервисе.
func newFullEngine(tb testing.TB) *Engine {
	tb.Helper()
	return New(engineTestDicts(tb), Registered()...)
}

// detectSpans прогоняет полный конвейер и возвращает отобранные спаны.
func detectSpans(tb testing.TB, e *Engine, text string, opts Options) []Span {
	tb.Helper()
	doc := lex.Tokenize(text, nil)
	var (
		cand Candidates
		res  Result
	)
	out, err := e.Detect(context.Background(), doc, opts, &cand, &res)
	if err != nil {
		tb.Fatalf(msgDetectFailed, err)
	}
	spans := make([]Span, len(out.Spans))
	copy(spans, out.Spans)
	return spans
}

// spanAt возвращает спан, накрывающий байт off, и признак его наличия.
func spanAt(spans []Span, off int32) (Span, bool) {
	for _, s := range spans {
		if s.Start <= off && off < s.End {
			return s, true
		}
	}
	return Span{}, false
}

// crmTypes повторяет список типов потребителя crm из config.yaml: паспорта
// в нём нет, адрес есть.
var crmTypes = pii.NewSet(
	pii.FullName, pii.BirthDate, pii.Phone, pii.Email, pii.Address,
	pii.CardNumber, pii.CVV, pii.PIN, pii.INN,
)

// reproText — текст, на котором дефект T-41 воспроизведён на живом сервисе
// 22.09.2026. Данные синтетические.
const reproText = "Клиент Петров Пётр Петрович, паспорт серия 4509 номер 123456, тел +7 916 123-45-67"

// TestDetectTypesDoNotChangeMarkup — AC-1.
//
// Список типов потребителя решает, маскируется ли фрагмент, но не то, чем он
// считается. Номер паспорта, отключённый политикой, обязан остаться номером
// паспорта и удержать свои байты: всплывающий на них адресный кандидат — это
// сокрытие под чужим типом, а не защита.
func TestDetectTypesDoNotChangeMarkup(t *testing.T) {
	e := newFullEngine(t)

	off := int32(strings.Index(reproText, "123456"))
	if off != 95 {
		t.Fatalf("смещение фрагмента 123456 = %d, ожидалось 95", off)
	}

	full := detectSpans(t, e, reproText, Options{})
	got, ok := spanAt(full, off)
	if !ok {
		t.Fatalf("при полном наборе типов байт %d не накрыт ни одним спаном: %s", off, formatSpans(full))
	}
	if got.Type != pii.PassportNumber || got.Start != 95 || got.End != 101 {
		t.Fatalf("при полном наборе типов байт %d отнесён к %s [%d,%d) правилом %q, ожидался passport_number [95,101)",
			off, got.Type.Key(), got.Start, got.End, got.Rule)
	}

	crm := detectSpans(t, e, reproText, Options{Types: crmTypes})
	if s, ok := spanAt(crm, off); ok {
		t.Fatalf("под политикой crm байт %d отнесён к %s [%d,%d) правилом %q; паспорт политикой отключён, "+
			"и фрагмент обязан остаться открытым, а не быть скрытым под чужим типом",
			off, s.Type.Key(), s.Start, s.End, s.Rule)
	}

	// Разметка вне отключённого типа от политики не зависит: ФИО и телефон
	// найдены под обеими политиками одинаково.
	for _, typ := range []pii.Type{pii.FullName, pii.Phone} {
		a := spansOfType(full, typ)
		b := spansOfType(crm, typ)
		if !sameSpans(a, b) {
			t.Errorf("тип %s: при полном наборе %s, под crm %s — разметка разошлась",
				typ.Key(), formatSpans(a), formatSpans(b))
		}
	}
}

// TestSelectResolvesBeforePolicy — тот же инвариант на синтетических
// кандидатах, без зависимости от конкретных сканеров: проигравший перекрытие
// кандидат не воскресает от того, что победитель отключён политикой.
func TestSelectResolvesBeforePolicy(t *testing.T) {
	winner := Span{Start: 10, End: 20, Type: pii.PassportNumber, Conf: Certain, Rule: "passport/strong"}
	loser := Span{Start: 12, End: 18, Type: pii.Address, Conf: Strong, Rule: "address/weak"}

	tests := []struct {
		name  string
		types pii.Set
		want  []Span
	}{
		{"полный набор типов", 0, []Span{winner}},
		{"победитель разрешён политикой", pii.NewSet(pii.PassportNumber, pii.Address), []Span{winner}},
		{"победитель отключён политикой", pii.NewSet(pii.Address), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := []Span{winner, loser}
			got, _, _ := selectSpans(context.Background(), in, Options{Types: tt.types}, &Candidates{})
			if !sameSpans(got, tt.want) {
				t.Fatalf("selectSpans = %s, ожидалось %s", formatSpans(got), formatSpans(tt.want))
			}
		})
	}
}

// TestSelectProfileStaysInSelection — профиль отнесения остаётся частью
// отбора: он про уровень уверенности кандидата, а не про политику
// потребителя, и переносу за разрешение перекрытий не подлежит.
func TestSelectProfileStaysInSelection(t *testing.T) {
	strong := Span{Start: 0, End: 5, Type: pii.CardNumber, Conf: Strong, Rule: "card/marker"}
	weak := Span{Start: 10, End: 13, Type: pii.CVV, Conf: Weak, Rule: testRuleCVVShape}
	denied := Span{Start: 20, End: 26, Type: pii.FullName, Conf: Denied, Rule: "counter/public"}

	tests := []struct {
		name    string
		profile Profile
		want    []Span
	}{
		{"balanced", Balanced, []Span{strong}},
		{"strict", Strict, []Span{strong}},
		{"paranoid", Paranoid, []Span{strong, weak}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := []Span{strong, weak, denied}
			got, _, _ := selectSpans(context.Background(), in, Options{Profile: tt.profile}, &Candidates{})
			if !sameSpans(got, tt.want) {
				t.Fatalf("selectSpans = %s, ожидалось %s", formatSpans(got), formatSpans(tt.want))
			}
		})
	}
}

// TestSelectMaxSpansLimitsReplacements — предел считается по заменам, то есть
// по спанам, дошедшим до маскирования. Кандидаты, отброшенные политикой,
// бюджет замен не расходуют.
func TestSelectMaxSpansLimitsReplacements(t *testing.T) {
	in := []Span{
		{Start: 0, End: 5, Type: pii.PassportNumber, Conf: Certain, Rule: testRulePassport},
		{Start: 10, End: 15, Type: pii.Phone, Conf: Certain, Rule: testRulePhone},
		{Start: 20, End: 25, Type: pii.PassportNumber, Conf: Certain, Rule: testRulePassport},
		{Start: 30, End: 35, Type: pii.Phone, Conf: Certain, Rule: testRulePhone},
	}
	ctx := context.Background()
	got, exceeded, err := selectSpans(ctx, append([]Span(nil), in...), Options{Types: pii.NewSet(pii.Phone), MaxSpans: 2}, &Candidates{})
	want := []Span{in[1], in[3]}
	if err != nil || !sameSpans(got, want) {
		t.Fatalf("selectSpans = %s, %v, ожидалось %s", formatSpans(got), err, formatSpans(want))
	}
	// Телефонов ровно два — предел не превышен: паспорта у потребителя не
	// маскируются и замен не требуют.
	if exceeded {
		t.Fatal("предел отмечен превышенным, хотя замен ровно столько, сколько разрешено")
	}

	// При полном наборе типов бюджет забирают два сильнейших по порядку
	// предпочтения кандидата — оба паспортных: тип с меньшим порядковым
	// номером выигрывает при равных уверенности и длине.
	got, exceeded, err = selectSpans(ctx, append([]Span(nil), in...), Options{MaxSpans: 2}, &Candidates{})
	want = []Span{in[0], in[2]}
	if err != nil || !sameSpans(got, want) {
		t.Fatalf("при полном наборе типов selectSpans = %s, %v, ожидалось %s", formatSpans(got), err, formatSpans(want))
	}
	// Оба телефона остались бы открытыми — это и есть превышение (T-52).
	if !exceeded {
		t.Fatal("два телефона сверх предела не отмечены превышением: они ушли бы наружу открытыми")
	}
}

// TestSelectLimitExceededOnlyForUnmaskedValue — T-52: превышение отмечается
// тогда и только тогда, когда сверх предела остаётся значение, которое
// потребитель обязан скрыть. Проигравший перекрытие кандидат и тип вне
// списка потребителя превышением не считаются: замены они бы не заняли.
func TestSelectLimitExceededOnlyForUnmaskedValue(t *testing.T) {
	phone := func(start int32) Span {
		return Span{Start: start, End: start + 5, Type: pii.Phone, Conf: Certain, Rule: testRulePhone}
	}
	passport := Span{Start: 40, End: 45, Type: pii.PassportNumber, Conf: Strong, Rule: testRulePassport}
	// Слабее и короче телефона на [0,5): проигрывает перекрытие при любом
	// пределе.
	loser := Span{Start: 1, End: 4, Type: pii.CVV, Conf: Strong, Rule: "cvv"}

	tests := []struct {
		name     string
		in       []Span
		opts     Options
		want     int
		exceeded bool
	}{
		{"замен ровно по пределу", []Span{phone(0), phone(10)}, Options{MaxSpans: 2}, 2, false},
		{"одна замена сверх предела", []Span{phone(0), phone(10), phone(20)}, Options{MaxSpans: 2}, 2, true},
		{"без предела", []Span{phone(0), phone(10), phone(20)}, Options{}, 3, false},
		{"сверх предела только проигравший перекрытие", []Span{phone(0), phone(10), loser}, Options{MaxSpans: 2}, 2, false},
		{"сверх предела только тип вне списка", []Span{phone(0), phone(10), passport},
			Options{Types: pii.NewSet(pii.Phone), MaxSpans: 2}, 2, false},
		{"сверх предела тип из списка", []Span{phone(0), phone(10), passport},
			Options{Types: pii.NewSet(pii.Phone, pii.PassportNumber), MaxSpans: 2}, 2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, exceeded, err := selectSpans(context.Background(), append([]Span(nil), tt.in...), tt.opts, &Candidates{})
			if err != nil {
				t.Fatalf("selectSpans: %v", err)
			}
			if len(got) != tt.want || exceeded != tt.exceeded {
				t.Fatalf("selectSpans = %s, превышение %v; ожидалось %d спанов, превышение %v",
					formatSpans(got), exceeded, tt.want, tt.exceeded)
			}
		})
	}
}

// limitPhonesText — n строк с различными синтетическими телефонами, как в
// отчёте бизнес-жюри 23.09: «Клиент N: телефон +7 916 XXX-XX-XX».
func limitPhonesText(n int) string {
	var b strings.Builder
	b.Grow(n * 52)
	for i := 1; i <= n; i++ {
		d := fmt.Sprintf("%07d", i)
		fmt.Fprintf(&b, "Клиент %d: телефон +7 916 %s-%s-%s\n", i, d[:3], d[3:5], d[5:])
	}
	return b.String()
}

// TestDetectReportsSpanLimit — T-52 на полном конвейере: текст из отчёта
// бизнес-жюри поднимает флаг превышения, текст ровно по пределу — нет, и
// флаг не переживает сброс результата следующим запросом.
func TestDetectReportsSpanLimit(t *testing.T) {
	e := newFullEngine(t)
	const limit = 20_000
	var (
		cand Candidates
		res  Result
	)
	run := func(text string) *Result {
		t.Helper()
		out, err := e.Detect(context.Background(), lex.Tokenize(text, nil), Options{MaxSpans: limit}, &cand, &res)
		if err != nil {
			t.Fatalf(msgDetectFailed, err)
		}
		return out
	}

	over := run(limitPhonesText(limit + 50))
	if !over.LimitExceeded {
		t.Fatalf("20 050 телефонов при пределе %d: превышение не отмечено, спанов %d", limit, len(over.Spans))
	}
	if len(over.Spans) != limit {
		t.Fatalf("при превышении спанов %d, ожидалось %d — разметка в пределах предела изменилась", len(over.Spans), limit)
	}

	exact := run(limitPhonesText(limit))
	if exact.LimitExceeded {
		t.Fatal("ровно 20 000 телефонов при пределе 20 000 отмечены превышением")
	}
	if len(exact.Spans) != limit {
		t.Fatalf("спанов %d, ожидалось %d", len(exact.Spans), limit)
	}
}

// TestEngineLoopsHonourCancel — отмена проверяется внутри циклов движка, а
// не только между сканерами: иначе вето и отбор на десятках тысяч
// кандидатов досчитывались бы после истечения предела обработки.
func TestEngineLoopsHonourCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	spans := make([]Span, 4*cancelStride)
	for i := range spans {
		spans[i] = Span{Start: int32(i * 10), End: int32(i*10 + 5), Type: pii.Phone, Conf: Certain, Rule: testRulePhone}
	}
	vetos := []Veto{{Start: 1_000_000, End: 1_000_001, Rule: "far"}}

	if err := applyVetos(ctx, spans, vetos); !errors.Is(err, context.Canceled) {
		t.Fatalf("applyVetos на отменённом контексте: %v", err)
	}
	if _, _, err := selectSpans(ctx, slices.Clone(spans), Options{}, &Candidates{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("selectSpans на отменённом контексте: %v", err)
	}

	// Короткий вход до проверки не доходит: на горячем пути она не стоит
	// ничего, и обычный запрос отменой внутри отбора не прерывается.
	if _, _, err := selectSpans(ctx, slices.Clone(spans[:cancelStride-1]), Options{}, &Candidates{}); err != nil {
		t.Fatalf("selectSpans на коротком входе: %v", err)
	}
}

// fixedScanner — сканер-заглушка: отдаёт заранее заданные кандидатов и вето,
// не завися от текста. Нужен, чтобы проверять поведение движка, а не сканеров.
type fixedScanner struct {
	spans []Span
	vetos []Veto
}

func (fixedScanner) Name() string { return "fixed" }

func (s fixedScanner) Scan(_ *lex.Doc, _ *dict.Set, out *Candidates) {
	out.Spans = append(out.Spans, s.spans...)
	out.Vetos = append(out.Vetos, s.vetos...)
}

// TestVetoIndependentOfTypes — вето снимает кандидата независимо от списка
// типов потребителя, и снятый кандидат не воскресает под другой политикой.
//
// Инвариант важен для сканеров документов: опознанный документ забирает свой
// участок текста у кандидата «номер карты» через Candidates.Deny. Механизм не
// должен зависеть от того, есть ли карта в списке типов потребителя.
func TestVetoIndependentOfTypes(t *testing.T) {
	doc := Span{Start: 10, End: 21, Type: pii.SNILS, Conf: Certain, Rule: "snils/checksum"}
	card := Span{Start: 10, End: 21, Type: pii.CardNumber, Conf: Strong, Rule: "card/shape"}
	veto := Veto{Start: 10, End: 21, Types: pii.NewSet(pii.CardNumber), Rule: "snils/not-card"}

	e := New(engineTestDicts(t), fixedScanner{spans: []Span{doc, card}, vetos: []Veto{veto}})

	tests := []struct {
		name  string
		types pii.Set
		want  []Span
	}{
		{"полный набор типов", 0, []Span{doc}},
		{"документ и карта разрешены", pii.NewSet(pii.SNILS, pii.CardNumber), []Span{doc}},
		{"разрешена только карта", pii.NewSet(pii.CardNumber), nil},
		{"разрешён только документ", pii.NewSet(pii.SNILS), []Span{doc}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSpans(t, e, "текст без собственных кандидатов", Options{Types: tt.types})
			if !sameSpans(got, tt.want) {
				t.Fatalf("Detect = %s, ожидалось %s", formatSpans(got), formatSpans(tt.want))
			}
		})
	}
}

// TestDetectProfilesDifferByCluster — T-25, AC-2.
//
// Слабый кандидат в одном предложении с достоверным значением другого типа
// поднимается по кластеру и проходит под balanced, но не проходит под strict:
// порог допуска у профилей один, различие только в подъёме. Слабый кандидат
// вне кластера не проходит ни под одним из двух. Под paranoid проходит всё,
// и без пометки подъёма — он там не выполняется.
func TestDetectProfilesDifferByCluster(t *testing.T) {
	const text = "Карта 4276 3800 1234 5678, код 123. Заявка 456 принята."
	// at ищет значение после его уникального левого контекста: «123»
	// встречается и внутри номера карты.
	at := func(before, value string) (int32, int32) {
		i := strings.Index(text, before+value)
		if i < 0 {
			t.Fatalf("фрагмент %q не найден в тексте", before+value)
		}
		i += len(before)
		return int32(i), int32(i + len(value))
	}
	cs, ce := at("Карта ", "4276 3800 1234 5678")
	ws, we := at("код ", "123")
	xs, xe := at("Заявка ", "456")

	card := Span{Start: cs, End: ce, Type: pii.CardNumber, Conf: Certain, Rule: "card/luhn"}
	inCluster := Span{Start: ws, End: we, Type: pii.CVV, Conf: Weak, Rule: testRuleCVVShape}
	outside := Span{Start: xs, End: xe, Type: pii.CVV, Conf: Weak, Rule: testRuleCVVShape}
	promoted := inCluster
	promoted.Conf = Strong
	promoted.Rule = testRuleCVVShape + clusterSuffix

	e := New(engineTestDicts(t), fixedScanner{spans: []Span{card, inCluster, outside}})

	tests := []struct {
		profile Profile
		want    []Span
	}{
		{Balanced, []Span{card, promoted}},
		{Strict, []Span{card}},
		{Paranoid, []Span{card, inCluster, outside}},
	}
	for _, tt := range tests {
		t.Run(tt.profile.String(), func(t *testing.T) {
			got := detectSpans(t, e, text, Options{Profile: tt.profile})
			if !sameSpans(got, tt.want) {
				t.Fatalf("Detect = %s, ожидалось %s", formatSpans(got), formatSpans(tt.want))
			}
		})
	}
}

// TestDetectBareAfterCluster — голое значение опознаётся после подъёма по
// кластеру и якорем для него не становится (T-63).
//
// Слабый кандидат другого типа на тех же байтах — «9264071835» сканер цифр
// видит паспортом — иначе поднимался бы кластером до той же силы, что и
// значение, опознанное по форме строки, и выигрывал перекрытие порядком типа.
// Под paranoid кластера нет, а слабый проигрывает Strong без него.
func TestDetectBareAfterCluster(t *testing.T) {
	passport := Span{Start: 0, End: 10, Type: pii.PassportNumber, Conf: Weak, Rule: "digits/passport"}
	e := New(engineTestDicts(t), fixedScanner{spans: []Span{passport}})
	want := []Span{{Start: 0, End: 10, Type: pii.Phone, Conf: Strong, Rule: ruleBarePhone}}
	for _, profile := range []Profile{Balanced, Paranoid} {
		got := detectSpans(t, e, "9264071835", Options{Profile: profile})
		if !sameSpans(got, want) {
			t.Errorf("%s: Detect = %s, ожидалось %s", profile, formatSpans(got), formatSpans(want))
		}
	}
	if got := detectSpans(t, e, "9264071835", Options{Profile: Strict}); len(got) != 0 {
		t.Errorf("strict: Detect = %s, ожидалось без изменений", formatSpans(got))
	}
}

// TestDetectBareLiftIsOrderIndependent — подъём слабых кандидатов голого
// значения не зависит от порядка работы сканеров: при двух типах, каждый из
// которых накрывает строку, поднимается тип с меньшим порядковым номером.
func TestDetectBareLiftIsOrderIndependent(t *testing.T) {
	const text = "XQZV"
	a := Span{Start: 0, End: 4, Type: pii.Address, Conf: Weak, Rule: "a"}
	b := Span{Start: 0, End: 4, Type: pii.FullName, Conf: Weak, Rule: "b"}
	want := []Span{{Start: 0, End: 4, Type: pii.FullName, Conf: Strong, Rule: "b" + bareSuffix}}
	for _, order := range [][]Span{{a, b}, {b, a}} {
		e := New(nil, fixedScanner{spans: order})
		if got := detectSpans(t, e, text, Options{}); !sameSpans(got, want) {
			t.Errorf("порядок %s: Detect = %s, ожидалось %s", formatSpans(order), formatSpans(got), formatSpans(want))
		}
	}
	// Вето внутри строки подъём снимает, даже если оно на другой тип.
	veto := Veto{Start: 0, End: 4, Types: pii.NewSet(pii.Email), Rule: "v"}
	e := New(nil, fixedScanner{spans: []Span{a, b}, vetos: []Veto{veto}})
	if got := detectSpans(t, e, text, Options{}); len(got) != 0 {
		t.Errorf("с вето: Detect = %s, ожидалось без изменений", formatSpans(got))
	}
}

// TestRuleSuffixCaches — пометки подъёма кешируются независимо: одно имя
// правила даёт разные склейки у кластера и у голого значения.
func TestRuleSuffixCaches(t *testing.T) {
	for range 2 { // второй проход — чтение из кеша
		if got := clusterRules.of(ruleDigitsCVV); got != ruleDigitsCVV+clusterSuffix {
			t.Fatalf("clusterRules.of = %q", got)
		}
		if got := bareRules.of(ruleDigitsCVV); got != ruleDigitsCVV+bareSuffix {
			t.Fatalf("bareRules.of = %q", got)
		}
	}
}

// TestPolicyIsPostFilter — разметка потребителя есть в точности подмножество
// разметки при полном наборе типов.
//
// Это и есть проверяемое свойство: порядок предпочтения при перекрытии
// (stronger) и вето остаются как были, политика только вычёркивает
// победителей отбора и никогда не меняет их состав.
func TestPolicyIsPostFilter(t *testing.T) {
	e := newFullEngine(t)
	policies := []pii.Set{
		crmTypes,
		pii.NewSet(pii.Address),
		pii.NewSet(pii.FullName, pii.Phone),
		pii.NewSet(pii.CardNumber),
		pii.NewSet(pii.PassportNumber, pii.PassportDeptCode),
		pii.FullSet().Remove(pii.PassportNumber).Remove(pii.FullName),
	}
	for _, text := range goldenTexts {
		full := detectSpans(t, e, text, Options{})
		for _, types := range policies {
			want := full[:0:0]
			for _, s := range full {
				if types.Has(s.Type) {
					want = append(want, s)
				}
			}
			got := detectSpans(t, e, text, Options{Types: types})
			if !sameSpans(got, want) {
				t.Errorf("текст %q, types=%v:\nполучено:  %s\nожидалось: %s",
					text, types, formatSpans(got), formatSpans(want))
			}
		}
	}
}

// benchmarkGolden — разметка под потребителем benchmark (types: [all]),
// снятая на коде до правки T-41. Проверка организаторов идёт именно под этим
// потребителем, поэтому измеряемое поведение обязано остаться побайтово тем
// же: фильтр типов у него ничего не отбрасывает.
var benchmarkGolden = map[string][]Span{
	goldenTexts[0]: {
		{Start: 13, End: 51, Type: pii.FullName, Conf: Certain, Rule: "name.surname_given_patronymic"},
		{Start: 79, End: 83, Type: pii.PassportNumber, Conf: Strong, Rule: "digits/passport_series"},
		{Start: 95, End: 101, Type: pii.PassportNumber, Conf: Strong, Rule: "digits/passport_series"},
		{Start: 110, End: 126, Type: pii.Phone, Conf: Strong, Rule: "digits/phone"},
	},
	goldenTexts[1]: {
		{Start: 0, End: 44, Type: pii.FullName, Conf: Certain, Rule: "name.surname_given_patronymic"},
		{Start: 46, End: 56, Type: pii.BirthDate, Conf: Strong, Rule: "date_birth"},
		{Start: 80, End: 91, Type: pii.PassportNumber, Conf: Strong, Rule: "digits/passport"},
		{Start: 103, End: 122, Type: pii.PassportAuthority, Conf: Strong, Rule: "misc/passport_authority"},
		{Start: 123, End: 133, Type: pii.PassportIssueDate, Conf: Strong, Rule: "date_issue"},
		{Start: 169, End: 176, Type: pii.PassportDeptCode, Conf: Strong, Rule: "digits/dept_code"},
	},
	goldenTexts[2]: {
		// T-45: номер без Луна поднимается маркером «Карта», а не кластером —
		// спан и уверенность те же, изменилось только имя правила.
		{Start: 11, End: 30, Type: pii.CardNumber, Conf: Strong, Rule: "digits/card_marker"},
		{Start: 51, End: 62, Type: pii.CardHolder, Conf: Strong, Rule: "misc/card_holder_marker"},
		{Start: 68, End: 71, Type: pii.CVV, Conf: Strong, Rule: "digits/cvv"},
		{Start: 80, End: 84, Type: pii.PIN, Conf: Strong, Rule: "digits/pin"},
	},
	goldenTexts[3]: {
		{Start: 16, End: 65, Type: pii.Address, Conf: Strong, Rule: "address/components"},
		{Start: 75, End: 92, Type: pii.Phone, Conf: Strong, Rule: "digits/phone"},
		{Start: 105, End: 128, Type: pii.Email, Conf: Certain, Rule: "email"},
	},
	goldenTexts[4]: {
		{Start: 7, End: 19, Type: pii.INN, Conf: Certain, Rule: "digits/inn_checksum"},
		{Start: 32, End: 46, Type: pii.SNILS, Conf: Certain, Rule: "docs/snils_checksum"},
		{Start: 100, End: 112, Type: pii.DriverLicense, Conf: Strong, Rule: "digits/driver_license"},
	},
	// Контр-правила снимают публичную персону, топоним-производную и адрес
	// отделения: разметка пуста.
	goldenTexts[5]: nil,
	// Запись без персональных данных.
	goldenTexts[6]: nil,
}

// TestDetectBenchmarkConsumerUnchanged — AC-2.
func TestDetectBenchmarkConsumerUnchanged(t *testing.T) {
	e := newFullEngine(t)
	for _, text := range goldenTexts {
		want, ok := benchmarkGolden[text]
		if !ok {
			t.Errorf("эталон не снят для текста %q; фактическая разметка:\n%s",
				text, goldenLiteral(detectSpans(t, e, text, Options{Types: pii.FullSet()})))
			continue
		}
		// types: [all] разворачивается в полный набор; пустой набор в
		// Options означает то же самое. Обе записи обязаны совпасть.
		for _, opts := range []Options{{Types: pii.FullSet()}, {}} {
			got := detectSpans(t, e, text, opts)
			if !sameSpans(got, want) {
				t.Errorf("текст %q, types=%v: разметка изменилась\nполучено:  %s\nэталон:    %s",
					text, opts.Types, formatSpans(got), formatSpans(want))
			}
		}
	}
}

// goldenTexts — синтетические записи под эталон: типы из разных сканеров,
// перекрывающиеся кандидаты, контр-правила и запись без ПД.
var goldenTexts = []string{
	reproText,
	"Иванова Мария Сергеевна, 15.03.1985 г.р., паспорт 4509 123456 выдан ОВД Москвы 20.01.2006, код подразделения 770-001",
	"Карта 4276 3800 1234 5678, держатель IVAN PETROV, cvv 123, пин 4321",
	"Адрес: г. Москва, ул. Ленина, д. 5, кв. 12, тел. 8 (916) 123-45-67, почта ivan.petrov@example.com",
	"ИНН 500100732259, СНИЛС 112-233-445 95, водительское удостоверение 77 12 345678",
	"Поэт Александр Пушкин жил на улице Пушкина; отделение банка по адресу Москва, ул. Ленина, 5",
	"Заявка принята, срок рассмотрения пять рабочих дней, комиссия не взимается",
}

// spansOfType отбирает спаны одного типа.
func spansOfType(spans []Span, t pii.Type) []Span {
	var out []Span
	for _, s := range spans {
		if s.Type == t {
			out = append(out, s)
		}
	}
	return out
}

// sameSpans сравнивает разметку побайтово, вместе с типом, уверенностью и
// именем сработавшего правила.
func sameSpans(a, b []Span) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// formatSpans печатает разметку для сообщений об ошибке.
func formatSpans(spans []Span) string {
	if len(spans) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, s := range spans {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s.Type.Key())
		b.WriteByte('[')
		writeInt(&b, int(s.Start))
		b.WriteByte(',')
		writeInt(&b, int(s.End))
		b.WriteString(") ")
		b.WriteString(s.Conf.String())
		b.WriteString(" ")
		b.WriteString(s.Rule)
	}
	b.WriteByte(']')
	return b.String()
}

func writeInt(b *strings.Builder, v int) {
	if v == 0 {
		b.WriteByte('0')
		return
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	b.Write(buf[i:])
}

// goldenLiteral печатает разметку готовым литералом Go — чтобы эталон
// снимался прогоном, а не переписывался руками.
func goldenLiteral(spans []Span) string {
	var b strings.Builder
	for _, s := range spans {
		b.WriteString("\t{Start: ")
		writeInt(&b, int(s.Start))
		b.WriteString(", End: ")
		writeInt(&b, int(s.End))
		b.WriteString(", Type: pii.")
		b.WriteString(typeIdent(s.Type))
		b.WriteString(", Conf: ")
		b.WriteString(confIdent(s.Conf))
		b.WriteString(", Rule: \"")
		b.WriteString(s.Rule)
		b.WriteString("\"},\n")
	}
	return b.String()
}

func typeIdent(t pii.Type) string {
	for _, c := range []struct {
		t pii.Type
		n string
	}{
		{pii.FullName, "FullName"}, {pii.BirthDate, "BirthDate"}, {pii.BirthPlace, "BirthPlace"},
		{pii.Citizenship, "Citizenship"}, {pii.PassportNumber, "PassportNumber"},
		{pii.PassportAuthority, "PassportAuthority"}, {pii.PassportDeptCode, "PassportDeptCode"},
		{pii.PassportIssueDate, "PassportIssueDate"}, {pii.DriverLicense, "DriverLicense"},
		{pii.Address, "Address"}, {pii.Email, "Email"}, {pii.Phone, "Phone"}, {pii.INN, "INN"},
		{pii.CardNumber, "CardNumber"}, {pii.CVV, "CVV"}, {pii.PIN, "PIN"},
		{pii.CardHolder, "CardHolder"}, {pii.SNILS, "SNILS"},
		{pii.ForeignPassport, "ForeignPassport"}, {pii.OMSPolicy, "OMSPolicy"},
		{pii.VehicleReg, "VehicleReg"}, {pii.VIN, "VIN"}, {pii.OGRN, "OGRN"},
	} {
		if c.t == t {
			return c.n
		}
	}
	return "Unknown"
}

func confIdent(c Confidence) string {
	switch c {
	case Weak:
		return "Weak"
	case Strong:
		return "Strong"
	case Certain:
		return "Certain"
	default:
		return "Denied"
	}
}

// BenchmarkDetect — горячий путь целиком: сканеры, контр-правила, повышение
// по кластеру и отбор. Отбор после правки T-41 идёт по большему набору
// кандидатов, поэтому измеряются обе политики: полный набор типов
// (потребитель benchmark) и узкий список (потребитель crm).
func BenchmarkDetect(b *testing.B) {
	text := detectBenchText()
	doc := lex.Tokenize(text, nil)
	e := newFullEngine(b)

	cases := []struct {
		name string
		opts Options
	}{
		{"all_types", Options{Types: pii.FullSet()}},
		{"crm_types", Options{Types: crmTypes}},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			var (
				cand Candidates
				res  Result
			)
			// Прогрев: ёмкость накопителей набирается один раз, как и в пуле
			// рабочих областей сервиса.
			if _, err := e.Detect(context.Background(), doc, c.opts, &cand, &res); err != nil {
				b.Fatalf(msgDetectFailed, err)
			}
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := e.Detect(context.Background(), doc, c.opts, &cand, &res); err != nil {
					b.Fatalf(msgDetectFailed, err)
				}
			}
		})
	}
}

// detectBenchText собирает синтетический текст примерно на 4 КБ с плотной
// смесью типов ПД и перекрывающихся кандидатов.
func detectBenchText() string {
	var b strings.Builder
	for i := 0; b.Len() < 4096; i++ {
		b.WriteString(goldenTexts[i%len(goldenTexts)])
		b.WriteString(" ")
	}
	return b.String()
}
