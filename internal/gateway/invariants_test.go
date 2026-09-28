package gateway

// Тесты инвариантов ядра обработки (T-19).
//
// Здесь собраны свойства, которые легко нарушить незаметно и дорого
// обнаружить на защите: побайтовый round-trip на Unicode, изоляция
// потребителей, подделанные и истёкшие плейсхолдеры, вход, похожий на маску,
// отказ хранилища. Движок — полный набор реальных сканеров, данные —
// синтетические, генераторы — с фиксированным seed.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/llm"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/pii"
	"ai-gateway/internal/policy"
	"ai-gateway/internal/store"
)

// invariantSeed фиксирует генераторы: провал воспроизводится повторным
// запуском, а не удачей.
const invariantSeed = 19

// Форматы сообщений об ошибках, общие для тестов пакета.
const (
	fmtMaskErr           = "маскирование: %v"
	fmtForeignRestoreErr = "чужой обратный шаг: %v"
)

var (
	invDictsOnce sync.Once
	invDicts     *dict.Set
	invDictsErr  error
)

// realEngine — тот же набор сканеров и справочников, что работает в сервисе.
func realEngine(t *testing.T) *detect.Engine {
	t.Helper()
	invDictsOnce.Do(func() { invDicts, invDictsErr = dict.Load() })
	if invDictsErr != nil {
		t.Fatalf("загрузка справочников: %v", invDictsErr)
	}
	return detect.New(invDicts, detect.Registered()...)
}

// realService — ядро с реальным движком и хранилищем в памяти.
func realService(t *testing.T, opts store.Options) (*Service, *store.Memory) {
	t.Helper()
	if opts.TTL == 0 {
		opts.TTL = time.Hour
	}
	st := store.NewMemory(opts)
	t.Cleanup(func() { _ = st.Close() })
	return New(realEngine(t), st), st
}

// invConsumer собирает потребителя с полным списком типов и правом
// демаскирования.
func invConsumer(t *testing.T, id, strategy string) *policy.Consumer {
	t.Helper()
	c := mustConsumer(t, policy.Consumer{
		ID: id, Enabled: true, Types: pii.FullSet(), Demask: true, MaskingEnabled: true,
	}, strategy)
	return c
}

// strategyNames — все стратегии, которые допускает конфигурация.
var strategyNames = []string{strategyPlaceholder, strategyAsterisks, strategyToken, syntheticStrategy}

// checkMaskLayout — REQ-304 на уровне ядра: маска побайтово равна «текст вне
// спанов + замены». Нормализация для поиска и любые другие преобразования
// наружу не протекают.
func checkMaskLayout(t *testing.T, text string, mr MaskResult) {
	t.Helper()
	var b strings.Builder
	prev := int32(0)
	for _, a := range mr.Applied {
		if a.Start < prev || a.End > int32(len(text)) || a.Start >= a.End {
			t.Fatalf("замена [%d:%d] вне порядка или вне текста длиной %d", a.Start, a.End, len(text))
		}
		b.WriteString(text[prev:a.Start])
		b.WriteString(a.Replacement)
		prev = a.End
	}
	b.WriteString(text[prev:])
	if mr.Text != b.String() {
		t.Fatalf("маска не равна «текст вне спанов + замены»:\nполучено  %q\nожидалось %q", mr.Text, b.String())
	}
}

// roundTrip выполняет прямой шаг, повтор прямого шага и обратный шаг
// контракта /process и проверяет побайтовое восстановление.
func roundTrip(t *testing.T, svc *Service, c *policy.Consumer, id, text string) ProcessResult {
	t.Helper()
	ctx := context.Background()
	fwd, err := svc.Process(ctx, id, text, c)
	if err != nil {
		t.Fatalf("прямой шаг %q: %v", text, err)
	}
	if fwd.Op != obs.OpMask {
		t.Fatalf("прямой шаг определён как %s", fwd.Op)
	}
	if fwd.Degraded {
		// Безопасный откат означает, что штатная обработка упала — на
		// корректном и некорректном UTF-8 это дефект, а не норма. Исключение
		// одно — превышен предел замен потребителя (T-52): строка скрыта
		// целиком, и обратный шаг ниже обязан вернуть исходник побайтово.
		if _, err := svc.Mask(ctx, text, c); !errors.Is(err, ErrSpanLimit) {
			t.Fatalf("прямой шаг ушёл в безопасный откат на %q", text)
		}
	} else {
		checkMaskLayout(t, text, fwd.Mask)
	}

	retry, err := svc.Process(ctx, id, text, c)
	if err != nil {
		t.Fatalf("повтор прямого шага: %v", err)
	}
	if retry.Result != fwd.Result {
		t.Fatalf("повтор дал другую маску: %q вместо %q", retry.Result, fwd.Result)
	}

	back := mustBackward(t, svc, id, fwd.Result, c)
	if back.Result != text {
		t.Fatalf("восстановление не побайтовое:\nполучено  %q\nожидалось %q", back.Result, text)
	}
	return fwd
}

// unicodeCorpus — тексты с трудными для смещений символами и значения,
// которые обязаны исчезнуть из маски у потребителя с полным набором типов.
var unicodeCorpus = []struct {
	name   string
	text   string
	hidden []string
}{
	{"кириллица", "Клиент Иванов Иван Иванович, email ivanov@example.test",
		[]string{fioIvanov, emailIvanov}},
	{"эмодзи с ZWJ и флагом", "👩\u200d💻🇷🇺 Пишите: ivanov@example.test 👍🏽, тел. +7 916 123-45-67",
		[]string{emailIvanov, "+7 916 123-45-67"}},
	{"составные символы", "cafe\u0301 и Ё\u0308 — Клиент Иванов Иван Иванович\u0301",
		[]string{fioIvanov}},
	{"символы нулевой ширины", "\u200bКлиент\u200d Иванов Иван Иванович\ufeff, почта\u2060 ivanov@example.test\u200c",
		[]string{fioIvanov, emailIvanov}},
	{"CRLF", "Клиент:\r\nИванов Иван Иванович\r\n\r\nКарта 4276 5500 1234 5678, CVV 123\r\n",
		[]string{fioIvanov, "4276 5500 1234 5678"}},
	{"JSON-escapes", `{"fio":"\u0418\u0432\u0430\u043d\u043e\u0432","q":"\"x\"\\n"} ИНН 500100732259`,
		[]string{"500100732259"}},
	{"неразрывные пробелы", "Клиент Иванов\u00a0Иван\u00a0Иванович", []string{"Иванов\u00a0Иван\u00a0Иванович"}},
	{"верхний регистр и ё", "КЛИЕНТ ЁЖИКОВ ЁЖИК ЁЖИКОВИЧ, ПОЧТА IVANOV@EXAMPLE.TEST",
		[]string{"ЁЖИКОВ ЁЖИК ЁЖИКОВИЧ", "IVANOV@EXAMPLE.TEST"}},
	{"документы", "паспорт серия 4509 номер 123456, родился 12.05.1990 года, г. Москва, ул. Ленина, д. 5, кв. 12",
		[]string{"4509", "123456", "12.05.1990", "Ленина, д. 5, кв. 12"}},
}

// TestInvariantProcessUnicodeRoundTrip — AC-1: цикл маскирование —
// демаскирование восстанавливает текст побайтово на кириллице, эмодзи,
// составных символах, символах нулевой ширины, CRLF и JSON-escapes — для
// каждой стратегии. Попутно проверяется, что размеченные значения из маски
// исчезли и байты вне спанов не изменились.
func TestInvariantProcessUnicodeRoundTrip(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	for _, strat := range strategyNames {
		c := invConsumer(t, policy.DefaultConsumerID, strat)
		for i, tc := range unicodeCorpus {
			t.Run(strat+"/"+tc.name, func(t *testing.T) {
				fwd := roundTrip(t, svc, c, fmt.Sprintf("%s-%d", strat, i), tc.text)
				for _, v := range tc.hidden {
					if strings.Contains(fwd.Result, v) {
						t.Errorf("значение %q осталось в маске %q", v, fwd.Result)
					}
				}
			})
		}
	}
}

// Фрагменты генератора текстов: синтетические значения ПД, маркеры и
// Unicode-шум.
var (
	gwPIIFragments = []string{
		clientIvanov, fioPetrov, "ИВАНОВ ИВАН ИВАНОВИЧ",
		"email ivanov@example.test", "тел. +7 916 123-45-67", "Карта 4111 1111 1111 1111",
		"CVV 123", "ПИН 4321", "ИНН 500100732259", "паспорт серия 4509 номер 123456",
		"родился 12.05.1990 года", "г. Москва, ул. Ленина, д. 5, кв. 12", "ул. Пушкина",
		"поэт Пушкин", "отделение банка", "Погода хорошая", "номер заявки 42",
	}
	gwNoise = []string{
		" ", ", ", ". ", "\r\n", "\n", "\t", "\u200b", "\u200d", "\ufeff", "\u00a0",
		"e\u0301", "👍🏽", "👩\u200d💻", "🇷🇺", `\u0041`, `\"`, badByte, "\xc3", "\xe2\x82", "ё",
	}
	gwMaskLike = []string{placeholderFIO1, "[EMAIL_2]", "{{pii:deadbeef}}", protectedWhole}
)

// genGatewayText собирает текст из фрагментов. withMaskLike добавляет в
// словарь фрагменты, похожие на маски.
func genGatewayText(r *rand.Rand, withMaskLike bool) string {
	var b strings.Builder
	for i := r.Intn(10); i >= 0; i-- {
		switch k := r.Intn(10); {
		case k < 5:
			b.WriteString(gwPIIFragments[r.Intn(len(gwPIIFragments))])
		case k == 9 && withMaskLike:
			b.WriteString(gwMaskLike[r.Intn(len(gwMaskLike))])
		}
		for j := r.Intn(3); j >= 0; j-- {
			b.WriteString(gwNoise[r.Intn(len(gwNoise))])
		}
	}
	return b.String()
}

// genPolicy строит случайного потребителя: стратегия, список типов, профиль,
// переопределение стратегии по типу, правило комбинации.
func genPolicy(t *testing.T, r *rand.Rand) *policy.Consumer {
	t.Helper()
	types := pii.FullSet()
	if r.Intn(2) == 0 {
		types = 0
		for _, tp := range pii.All() {
			if r.Intn(2) == 0 {
				types = types.Add(tp)
			}
		}
		if types.Empty() {
			types = pii.NewSet(pii.FullName)
		}
	}
	perType := map[pii.Type]string{}
	if r.Intn(3) == 0 {
		perType[pii.All()[r.Intn(len(pii.All()))]] = strategyNames[r.Intn(len(strategyNames))]
	}
	var combos []policy.Combo
	if r.Intn(3) == 0 {
		combos = []policy.Combo{{Mask: pii.NewSet(pii.PIN, pii.CVV), OnlyWith: pii.NewSet(pii.CardNumber)}}
	}
	profiles := []detect.Profile{detect.Balanced, detect.Strict, detect.Paranoid}
	c, err := policy.NewConsumer(policy.Consumer{
		ID:             policy.DefaultConsumerID,
		Enabled:        true,
		Types:          types,
		Demask:         true,
		Profile:        profiles[r.Intn(len(profiles))],
		MaskingEnabled: r.Intn(10) != 0,
		MaxSpans:       []int{0, 0, 0, 1, 3}[r.Intn(5)],
	}, strategyNames[r.Intn(len(strategyNames))], perType, combos)
	if err != nil {
		t.Fatalf("сборка потребителя: %v", err)
	}
	return c
}

// TestInvariantProcessRoundTripProperty — AC-1, свойство round-trip: для любого
// сгенерированного текста и любой политики unmask(mask(T)) == T побайтово,
// повтор прямого шага идемпотентен, байты вне спанов не меняются.
func TestInvariantProcessRoundTripProperty(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	r := rand.New(rand.NewSource(invariantSeed))
	for iter := 0; iter < 600; iter++ {
		text := genGatewayText(r, true)
		c := genPolicy(t, r)
		roundTrip(t, svc, c, fmt.Sprintf("prop-%d", iter), text)
	}
}

// echoModel — фальшивая модель, возвращающая последнее сообщение запроса как
// есть. Эхо — самый жёсткий случай восстановления: каждая выданная маска
// возвращается на своё место.
type echoModel struct{ calls atomic.Int32 }

func (m *echoModel) Chat(_ context.Context, req llm.Request) (*llm.Response, error) {
	m.calls.Add(1)
	var parts []string
	for _, msg := range req.Messages {
		parts = append(parts, msg.Content)
	}
	return &llm.Response{Choices: []llm.Choice{{
		Message: llm.Message{Role: roleAssistant, Content: strings.Join(parts, "\n")},
	}}}, nil
}

func proxyText(t *testing.T, svc *Service, c *policy.Consumer, id string, msgs ...string) (ProxyResult, string) {
	t.Helper()
	req := ProxyRequest{ID: id}
	for _, m := range msgs {
		req.Chat.Messages = append(req.Chat.Messages, llm.Message{Role: roleUser, Content: m})
	}
	res := mustProxy(t, svc, &echoModel{}, req, c)
	return res, replyOf(res)
}

// TestInvariantProxyEchoRoundTripProperty — AC-1 в продуктовом режиме: модель
// возвращает защищённый текст без изменений.
//
// Ответ модели обязан проходить детекцию заново (REQ-502). После T-47
// восстановление выполняется до повторной детекции, а найденное внутри
// восстановленных значений не маскируется, поэтому свойство проверяется в
// полной форме: каждая выданная маска восстановлена и эхо равно входу
// побайтово.
//
// Стратегии — placeholder, token и synthetic: у них разные значения получают
// разные маски (для synthetic это обеспечивает сквозная нумерация прокси, см.
// дефект D-2). Звёздочки неоднозначны по построению. Фрагменты, похожие на
// маску, в генераторе есть — см. дефект D-3.
func TestInvariantProxyEchoRoundTripProperty(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	r := rand.New(rand.NewSource(invariantSeed))
	for _, strat := range []string{strategyPlaceholder, strategyToken, syntheticStrategy} {
		echoRoundTripStrategy(t, svc, r, strat)
	}
}

// echoRoundTripStrategy прогоняет свойство эха для одной стратегии. Генератор
// r общий для стратегий: последовательность входов та же, что и прежде.
func echoRoundTripStrategy(t *testing.T, svc *Service, r *rand.Rand, strat string) {
	t.Helper()
	c := invConsumer(t, consumerCRM, strat)
	exact, closed := 0, 0
	for iter := 0; iter < 400; iter++ {
		text := genGatewayText(r, true)
		if text == "" {
			continue
		}
		if echoRoundTripOnce(t, svc, c, fmt.Sprintf("%s-%d", strat, iter), text) {
			exact++
		} else {
			closed++
		}
	}
	t.Logf("%s: побайтово проверено %d входов, отказов защиты %d", strat, exact, closed)
	if exact < 250 || closed > 100 {
		t.Fatalf("%s: побайтово проверено %d входов, отказов защиты %d — генератор выродился", strat, exact, closed)
	}
}

// echoRoundTripOnce проверяет один вход: false — отказ защиты без единого
// исходящего запроса, true — эхо восстановлено побайтово и полностью.
func echoRoundTripOnce(t *testing.T, svc *Service, c *policy.Consumer, id, text string) bool {
	t.Helper()
	model := &recordingModel{}
	if _, err := svc.Proxy(context.Background(), model, userRequest(id, text), c); err != nil {
		// Отказ защиты допустим — например, когда одно из вхождений
		// значения не распознано (см. также дефект D-8). Недопустимо
		// только одно: отказ, после которого что-то ушло наружу.
		if !errors.Is(err, ErrFailClosed) || model.calls() != 0 {
			t.Fatalf("%s: отказ %v, запросов в модель %d", id, err, model.calls())
		}
		return false
	}
	sent := model.got[0].Messages[0].Content

	res, got := proxyText(t, svc, c, id+"-echo", text)
	issued, err := svc.Mask(context.Background(), text, c)
	if err != nil {
		t.Fatalf(fmtMaskErr, err)
	}
	if res.Restored != len(issued.Applied) {
		t.Fatalf("%s: восстановлено %d масок из %d выданных:\nотправлено %q\nполучено   %q",
			id, res.Restored, len(issued.Applied), sent, got)
	}
	if got != text {
		t.Fatalf("%s: эхо восстановлено не побайтово:\nполучено  %q\nожидалось %q", id, got, text)
	}
	return true
}

// TestInvariantProcessInvalidUTF8 — AC-2: некорректный UTF-8 не приводит к
// панике (в том числе скрытой безопасным откатом), не искажает текст вне
// спанов и восстанавливается побайтово.
func TestInvariantProcessInvalidUTF8(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)
	fixed := []struct{ text, hidden string }{
		{"\xff\xfeКлиент Иванов Иван Иванович \xc3 ivanov@example.test \xe2\x82", emailIvanov},
		{"\xed\xa0\x80 ИНН 500100732259 \xc0\xaf", "500100732259"},
		{"Иванов\xffИван\xfeИванович", ""},
		{"\x80\x80\x80", ""},
		{"Клиент \xd0", ""},
	}
	for i, tc := range fixed {
		fwd := roundTrip(t, svc, c, fmt.Sprintf("bad-%d", i), tc.text)
		if tc.hidden != "" && strings.Contains(fwd.Result, tc.hidden) {
			t.Errorf("значение %q осталось в маске %q", tc.hidden, fwd.Result)
		}
	}
	r := rand.New(rand.NewSource(invariantSeed))
	buf := make([]byte, 0, 256)
	for iter := 0; iter < 400; iter++ {
		buf = buf[:0]
		for i := r.Intn(120); i > 0; i-- {
			switch r.Intn(4) {
			case 0:
				buf = append(buf, byte(r.Intn(256)))
			case 1:
				buf = append(buf, gwPIIFragments[r.Intn(len(gwPIIFragments))]...)
			default:
				buf = append(buf, byte(0x80+r.Intn(0x40)))
			}
		}
		roundTrip(t, svc, c, fmt.Sprintf("rnd-%d", iter), string(buf))
	}
}

// TestInvariantProcessBoundaries — AC-4: пустой и односимвольный текст,
// значение в начале, в конце, на весь текст и два значения вплотную.
func TestInvariantProcessBoundaries(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)
	tests := []struct{ name, text, want string }{
		{"пустой текст", "", ""},
		{"один ASCII-символ", "x", "x"},
		{"одна кириллическая буква", "И", "И"},
		{"один эмодзи", "👍", "👍"},
		{"один некорректный байт", badByte, badByte},
		{"значение на весь текст", emailIvanov, "[EMAIL_1]"},
		{"значение в начале", "ivanov@example.test — почта", "[EMAIL_1] — почта"},
		{"значение в конце", "почта: ivanov@example.test", "почта: [EMAIL_1]"},
		{"два значения вплотную", "ivanov@example.test+7 916 123-45-67", "[EMAIL_1][ТЕЛЕФОН_1]"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd := roundTrip(t, svc, c, fmt.Sprintf("edge-%d", i), tt.text)
			if fwd.Result != tt.want {
				t.Fatalf("маска %q, ожидалось %q", fwd.Result, tt.want)
			}
		})
	}
}

// piiValues — значения, которые не должны появиться ни в одном ответе на
// подделанный вход.
var piiValues = []string{surnameIvanov, emailIvanov, "916 123-45-67"}

func assertNoPII(t *testing.T, where, got string) {
	t.Helper()
	for _, v := range piiValues {
		if strings.Contains(got, v) {
			t.Fatalf("%s: раскрыто значение %q в %q", where, v, got)
		}
	}
}

// TestInvariantProcessForgedPlaceholders — AC-5: плейсхолдер, которого сервис
// не выдавал, и подделка выданной маски ничего не раскрывают ни по известному,
// ни по неизвестному payload_id, а запись владельца остаётся целой.
func TestInvariantProcessForgedPlaceholders(t *testing.T) {
	ctx := context.Background()
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)
	const original = "Клиент Иванов Иван Иванович, почта ivanov@example.test, тел. +7 916 123-45-67"

	fwd := mustForward(t, svc, testID1, original, c)
	assertNoPII(t, "маска", fwd.Result)

	forged := []string{
		placeholderFIO1,                          // фрагмент выданной маски
		"[ФИО_2]",                                // номер, которого не выдавали
		"[фио_1]",                                // другой регистр
		"[ФИО_01]",                               // ведущий ноль
		"[ ФИО_1 ]",                              // пробелы
		"{{pii:00000000}}",                       // токен, которого не выдавали
		fwd.Result + " ",                         // маска с лишним пробелом
		strings.ToLower(fwd.Result),              // маска в другом регистре
		strings.Replace(fwd.Result, "1", "2", 1), // маска с чужими номерами
		fwd.Result + "\r\n",                      // маска с CRLF
		"\ufeff" + fwd.Result,                    // маска с BOM
	}
	for _, p := range forged {
		for _, id := range []string{testID1, "id-unknown"} {
			res, err := svc.Process(ctx, id, p, c)
			if err != nil {
				t.Fatalf("подделка %q по %s: %v", p, id, err)
			}
			assertNoPII(t, "ответ на подделку по "+id, res.Result)
			if res.Op == obs.OpUnmask {
				t.Fatalf("подделка %q по %s распознана как обратный шаг", p, id)
			}
		}
	}

	back := mustBackward(t, svc, testID1, fwd.Result, c)
	if back.Result != original {
		t.Fatalf("подделки разрушили запись владельца: %q", back.Result)
	}
}

// TestInvariantProxyForgedPlaceholders — AC-5 в продуктовом режиме:
// плейсхолдеры и токены, которых этот запрос не выдавал, и искажённые копии
// выданной маски в ответе модели остаются как есть и ничего не раскрывают.
func TestInvariantProxyForgedPlaceholders(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	const msg = clientIvanovEmail
	for _, strat := range []string{strategyPlaceholder, strategyToken} {
		c := invConsumer(t, consumerCRM, strat)
		// Первый вызов — узнать выданную маску ФИО, чтобы подделать её.
		probe := &recordingModel{reply: "ок"}
		mustProxy(t, svc, probe, ProxyRequest{ID: "probe-" + strat,
			Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: msg}}}}, c)
		issued := strings.TrimPrefix(strings.SplitN(probe.got[0].Messages[0].Content, ",", 2)[0], "Клиент ")

		var forged []string
		switch strat {
		case strategyPlaceholder:
			forged = []string{"[ФИО_2]", "[фио_1]", "[ФИО_01]", "[ ФИО_1 ]", "[ФИО_1 ]", "ФИО_1]", "[ФИО_1", "[ФИО-1]"}
		case strategyToken:
			hex := strings.TrimSuffix(strings.TrimPrefix(issued, tokenPrefix), "}}")
			forged = []string{
				tokenPrefix + strings.ToUpper(hex) + "}}", "{{PII:" + hex + "}}", tokenPrefix + hex[:7] + "}}",
				"{{pii: " + hex + "}}", "{pii:" + hex + "}", tokenPrefix + hex + "}",
			}
		}
		forged = append(forged, "[EMAIL_2]", "[ТЕЛЕФОН_1]", "{{pii:00000000}}", protectedWhole)
		// Ключ токенизации случайный на процесс (T-54), и тело токена бывает
		// из одних цифр: тогда «копия в верхнем регистре» совпадает с выданной
		// маской и подделкой не является. Такие варианты отбрасываются, а не
		// валят тест.
		kept := forged[:0]
		for _, f := range forged {
			if !strings.Contains(f, issued) {
				kept = append(kept, f)
			}
		}
		forged = kept
		if len(forged) < 6 {
			t.Fatalf("после отсева осталось %d подделок — тест бессмыслен", len(forged))
		}

		model := &recordingModel{reply: strings.Join(forged, " | ")}
		res := mustProxy(t, svc, model, ProxyRequest{ID: "forged-" + strat,
			Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: msg}}}}, c)
		content := replyOf(res)
		assertNoPII(t, strat, content)
		if res.Restored != 0 {
			t.Fatalf("%s: восстановлено %d подделанных плейсхолдеров: %q", strat, res.Restored, content)
		}
		if content != model.reply {
			t.Fatalf("%s: ответ с подделками изменён: %q", strat, content)
		}
	}
}

// TestInvariantConsumerIsolation — AC-6: плейсхолдер, выданный одному
// потребителю, не раскрывается другому по тому же payload_id; чужой
// потребитель не разрушает запись владельца, а его собственная запись с тем
// же payload_id живёт независимо.
func TestInvariantConsumerIsolation(t *testing.T) {
	ctx := context.Background()
	svc, _ := realService(t, store.Options{})
	owner := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)
	other := invConsumer(t, consumerOther, strategyPlaceholder)
	const mine = clientIvanovEmail
	const theirs = "Клиент Петров Пётр Петрович, почта petrov@example.test"

	fwd, err := svc.Process(ctx, sharedID, mine, owner)
	if err != nil {
		t.Fatalf("прямой шаг владельца: %v", err)
	}

	// Чужой потребитель знает payload_id и маску — этого недостаточно.
	res, err := svc.Process(ctx, sharedID, fwd.Result, other)
	if err != nil {
		t.Fatalf(fmtForeignRestoreErr, err)
	}
	assertNoPII(t, "чужой обратный шаг", res.Result)
	if res.Op == obs.OpUnmask {
		t.Fatal("чужой потребитель выполнил обратный шаг по записи владельца")
	}

	// Собственная запись чужого потребителя с тем же payload_id.
	otherFwd, err := svc.Process(ctx, "shared-id-2", theirs, other)
	if err != nil {
		t.Fatalf("прямой шаг чужого: %v", err)
	}
	if _, err := svc.Process(ctx, sharedID, theirs, other); err != nil {
		t.Fatalf("прямой шаг чужого по общему id: %v", err)
	}

	back, err := svc.Process(ctx, sharedID, fwd.Result, owner)
	if err != nil {
		t.Fatalf("обратный шаг владельца: %v", err)
	}
	if back.Result != mine {
		t.Fatalf("запись владельца разрушена чужим потребителем: %q", back.Result)
	}
	otherBack, err := svc.Process(ctx, "shared-id-2", otherFwd.Result, other)
	if err != nil {
		t.Fatalf("обратный шаг чужого: %v", err)
	}
	if otherBack.Result != theirs {
		t.Fatalf("запись чужого потребителя повреждена: %q", otherBack.Result)
	}
	if strings.Contains(otherBack.Result, surnameIvanov) {
		t.Fatal("запись чужого потребителя раскрыла значение владельца")
	}
}

// TestInvariantProxyScopeIsPerRequest — AC-6 в продуктовом режиме: маска,
// выданная в одном запросе, не восстанавливается в ответе на другой — ни
// того же потребителя, ни чужого.
func TestInvariantProxyScopeIsPerRequest(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	owner := invConsumer(t, consumerCRM, strategyPlaceholder)
	other := invConsumer(t, consumerOther, strategyPlaceholder)

	first := &recordingModel{reply: "ок"}
	if _, err := svc.Proxy(context.Background(), first, ProxyRequest{ID: "a",
		Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: clientIvanov}}}}, owner); err != nil {
		t.Fatalf("первый запрос: %v", err)
	}
	issued := strings.TrimPrefix(first.got[0].Messages[0].Content, "Клиент ")
	if issued != placeholderFIO1 {
		t.Fatalf("неожиданная маска первого запроса: %q", issued)
	}

	for _, c := range []*policy.Consumer{owner, other} {
		for _, id := range []string{"a", "b"} {
			m := &recordingModel{reply: "Ответ для " + issued}
			res, err := svc.Proxy(context.Background(), m, ProxyRequest{ID: id,
				Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: "Без персональных данных"}}}}, c)
			if err != nil {
				t.Fatalf("второй запрос: %v", err)
			}
			content := replyOf(res)
			if strings.Contains(content, surnameIvanov) || res.Restored != 0 {
				t.Fatalf("%s/%s: маска чужого запроса раскрыта: %q", c.ID, id, content)
			}
		}
	}
}

// TestInvariantScopedKeyIsInjective — AC-6: ключ области корреляции
// однозначен для любой пары «потребитель, payload_id».
//
// payload_id приходит извне и может содержать нулевой байт (JSON \u0000), а
// идентификатор потребителя из конфигурации на нулевой байт не проверяется.
// До T-47 ключ склеивался через нулевой байт, пары («a», «b\x00c») и
// («a\x00b», «c») давали один ключ, и один потребитель получал исходную
// строку другого (дефект D-6). Теперь перед идентификатором стоит его длина.
func TestInvariantScopedKeyIsInjective(t *testing.T) {
	ctx := context.Background()
	svc, _ := realService(t, store.Options{})
	victim := invConsumer(t, "a\x00b", strategyPlaceholder)
	attacker := invConsumer(t, "a", strategyPlaceholder)
	const original = clientIvanov

	fwd := mustForward(t, svc, "c", original, victim)
	res, err := svc.Process(ctx, "b\x00c", fwd.Result, attacker)
	if err != nil {
		t.Fatalf(fmtForeignRestoreErr, err)
	}
	if res.Result == original {
		t.Fatal("чужой потребитель получил исходную строку через совпадение ключей")
	}
}

// TestInvariantExpiredRecordRevealsNothing — AC-5: плейсхолдер из истёкшей
// записи не раскрывается — ни исходным значением, ни значением другой,
// ещё живой записи с такой же маской.
func TestInvariantExpiredRecordRevealsNothing(t *testing.T) {
	ctx := context.Background()
	var now atomic.Int64
	now.Store(time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC).UnixNano())
	clock := func() time.Time { return time.Unix(0, now.Load()) }
	advance := func(d time.Duration) { now.Add(int64(d)) }

	svc, st := realService(t, store.Options{TTL: time.Minute, Now: clock, SweepInterval: time.Hour})
	svc.SetClock(clock)
	c := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)

	const expiring = clientIvanov
	const alive = clientPetrov
	old := mustForward(t, svc, oldID, expiring, c)
	advance(50 * time.Second)
	fresh := mustForward(t, svc, "id-fresh", alive, c)
	if old.Result != fresh.Result {
		t.Fatalf("маски должны совпадать, чтобы проверка «чем-то похожим» имела смысл: %q и %q", old.Result, fresh.Result)
	}
	advance(20 * time.Second) // первая запись истекла, вторая жива

	if _, ok := st.Get(scopedKey(c.ID, oldID)); ok {
		t.Fatal("истёкшая запись видна в хранилище")
	}
	res, err := svc.Process(ctx, oldID, old.Result, c)
	if err != nil {
		t.Fatalf("обратный шаг по истёкшей записи: %v", err)
	}
	if res.Op == obs.OpUnmask || strings.Contains(res.Result, surnameIvanov) || strings.Contains(res.Result, "Петров") {
		t.Fatalf("истёкшая запись раскрыла данные: %s %q", res.Op, res.Result)
	}
	if res.Result != old.Result {
		t.Fatalf("маска истёкшей записи обработана не как новый вход: %q", res.Result)
	}

	back, err := svc.Process(ctx, "id-fresh", fresh.Result, c)
	if err != nil {
		t.Fatalf("обратный шаг живой записи: %v", err)
	}
	if back.Result != alive {
		t.Fatalf("живая запись не восстановлена: %q", back.Result)
	}
}

// TestInvariantMaskLookingInput — AC-7: вход, который сам выглядит как маска,
// не ломает автомат /process: прямой шаг распознаётся как прямой, повтор
// идемпотентен, обратный шаг возвращает вход побайтово, чужие данные не
// раскрываются.
func TestInvariantMaskLookingInput(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)

	// Запись с настоящими данными: её маска будет подана как вход под
	// другим payload_id.
	genuine := mustForward(t, svc, "id-real", clientIvanov, c)

	inputs := []string{
		placeholderFIO1,
		protectedWhole,
		"{{pii:deadbeef}}",
		genuine.Result,
		"[ФИО_1] пишет: Клиент Иванов Иван Иванович",
		"[EMAIL_1] и ivanov@example.test и [EMAIL_1]",
		"[ФИО_1][ФИО_1][ФИО_2]",
	}
	for i, in := range inputs {
		fwd := roundTrip(t, svc, c, fmt.Sprintf("looks-%d", i), in)
		assertNoPII(t, "маска входа, похожего на маску", fwd.Result)
	}

	back := mustBackward(t, svc, "id-real", genuine.Result, c)
	if back.Result != clientIvanov {
		t.Fatalf("исходная запись повреждена: %q", back.Result)
	}
}

// TestInvariantProxyLiteralPlaceholderInInput — AC-7 в продуктовом режиме:
// плейсхолдер, написанный во входе буквально, не должен превращаться в
// значение при восстановлении.
//
// До T-47 нумерация начиналась с единицы без учёта того, что «[ФИО_1]» уже
// есть в тексте: модель получала два одинаковых «[ФИО_1]», а восстановление
// подставляло ФИО на место обоих (дефект D-3). Теперь нумерация прокси
// пропускает номера, буквально написанные во входе.
func TestInvariantProxyLiteralPlaceholderInInput(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, consumerCRM, strategyPlaceholder)
	const text = "[ФИО_1] пишет: Клиент Иванов Иван Иванович"
	_, got := proxyText(t, svc, c, "lit", text)
	if got != text {
		t.Fatalf("эхо восстановлено неверно:\nполучено  %q\nожидалось %q", got, text)
	}
}

// TestInvariantProxyNumberingAcrossMessages — REQ-303 и AC-1 в продуктовом
// режиме: разные значения в разных сообщениях одного запроса получают разные
// плейсхолдеры и восстанавливаются.
//
// До T-47 нумерация начиналась заново в каждом сообщении: два разных
// человека уходили в модель как «[ФИО_1]», область корреляции помечала маску
// неоднозначной, и ни одно значение не восстанавливалось (дефект D-1).
func TestInvariantProxyNumberingAcrossMessages(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, consumerCRM, strategyPlaceholder)
	model := &recordingModel{reply: "ок"}
	mustProxy(t, svc, model, ProxyRequest{ID: "multi", Chat: llm.Request{Messages: []llm.Message{
		{Role: roleUser, Content: clientIvanov},
		{Role: roleUser, Content: clientPetrov},
	}}}, c)
	a, b := model.got[0].Messages[0].Content, model.got[0].Messages[1].Content
	if a == b {
		t.Fatalf("разные люди ушли в модель под одной маской: %q и %q", a, b)
	}
	res, got := proxyText(t, svc, c, "multi-echo", clientIvanov, clientPetrov)
	if want := "Клиент Иванов Иван Иванович\nКлиент Петров Пётр Петрович"; got != want {
		t.Fatalf("эхо восстановлено неверно (восстановлено %d):\nполучено  %q\nожидалось %q", res.Restored, got, want)
	}
}

// TestInvariantProxySyntheticEchoRestores — AC-1 в продуктовом режиме для
// стратегии synthetic: синтетические значения, выданные в запросе,
// восстанавливаются в ответе модели.
//
// До T-47 ответ модели сканировался заново до восстановления, и
// синтетическое значение (правдоподобное ФИО, валидная по Луну карта, ИНН с
// верной контрольной суммой) распознавалось как новые ПД: клиент получал
// вторую порцию синтетики вместо своих данных (дефект D-2).
func TestInvariantProxySyntheticEchoRestores(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, consumerCRM, syntheticStrategy)
	const text = "Клиент Иванов Иван Иванович, карта 4276 5500 1234 5678, ИНН 500100732259"
	_, got := proxyText(t, svc, c, "syn", text)
	if got != text {
		t.Fatalf("эхо восстановлено неверно:\nполучено  %q\nожидалось %q", got, text)
	}
}

// TestInvariantProxyShortValueInsideOtherNumber — отказ защиты не должен
// срабатывать на значении, которое встречается только как часть другого,
// более длинного числа.
//
// До T-47 VerifyReplaced искал каждое заменённое значение подстрокой во всём
// защищённом тексте: CVV «123» находился внутри суммы «1230», и запрос
// отклонялся целиком (HTTP 500 на /v1/*), хотя открытого значения CVV в
// тексте нет (дефект D-8). Теперь вхождение ищется по границам цифрового
// токена; открытое значение по-прежнему ловится — см.
// TestVerifyReplacedTokenBoundaries.
func TestInvariantProxyShortValueInsideOtherNumber(t *testing.T) {
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, consumerCRM, strategyPlaceholder)
	model := &recordingModel{reply: "ок"}
	const text = "Карта 4111 1111 1111 1111, CVV 123, сумма заказа 1230 рублей"
	_, err := svc.Proxy(context.Background(), model, ProxyRequest{ID: "short",
		Chat: llm.Request{Messages: []llm.Message{{Role: roleUser, Content: text}}}}, c)
	if err != nil {
		t.Fatalf("запрос отклонён: %v", err)
	}
	if model.calls() != 1 {
		t.Fatalf("модель получила %d запросов", model.calls())
	}
}

// panicScanner имитирует отказ штатной обработки.
type panicScanner struct{}

func (panicScanner) Name() string { return "panic" }

func (panicScanner) Scan(*lex.Doc, *dict.Set, *detect.Candidates) {
	panic("отказ сканера (тест)")
}

// TestInvariantStoreFailureIsExplicit — AC-8: если соответствие не
// сохранено, прямой шаг возвращает ошибку, а не маску. Проверяются отказ
// хранилища, одна запись сверх бюджета, путь безопасного отката и контур
// прокси.
func TestInvariantStoreFailureIsExplicit(t *testing.T) {
	c := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)
	cases := []struct {
		name string
		run  func(t *testing.T, c *policy.Consumer)
	}{
		{"хранилище отказывает", storeFailureRefusesMask},
		{"безопасный откат при отказе хранилища", storeFailureRefusesFallback},
		{"безопасный откат сохраняет соответствие", fallbackKeepsCorrespondence},
		{"запись сверх бюджета объёма", recordOverByteBudget},
		{"вытеснение не лишает свежую запись соответствия", evictionKeepsFreshRecord},
		{"прокси при переполнении не отправляет запрос", proxyStoreOverflowSendsNothing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, c) })
	}
}

// bigStoreText не помещается в сегмент хранилища с бюджетом 64 * 256 байт.
var bigStoreText = strings.Repeat("Клиент Иванов Иван Иванович. ", 20)

// assertStoreFull — прямой шаг вернул store.ErrFull и не выдал маску.
func assertStoreFull(t *testing.T, res ProcessResult, err error, what string) {
	t.Helper()
	if !errors.Is(err, store.ErrFull) {
		t.Fatalf(fmtStoreFull, err)
	}
	if res.Result != "" {
		t.Fatalf("%s: %q", what, res.Result)
	}
}

func storeFailureRefusesMask(t *testing.T, c *policy.Consumer) {
	svc := New(realEngine(t), failingStore{})
	res, err := svc.Process(context.Background(), testID1, clientIvanov, c)
	assertStoreFull(t, res, err, "при отказе хранилища выдана маска")
}

func storeFailureRefusesFallback(t *testing.T, c *policy.Consumer) {
	svc := New(detect.New(nil, panicScanner{}), failingStore{})
	res, err := svc.Process(context.Background(), testID1, clientIvanov, c)
	assertStoreFull(t, res, err, "при отказе хранилища выдана маска отката")
}

func fallbackKeepsCorrespondence(t *testing.T, c *policy.Consumer) {
	ctx := context.Background()
	st := store.NewMemory(store.Options{TTL: time.Hour})
	t.Cleanup(func() { _ = st.Close() })
	svc := New(detect.New(nil, panicScanner{}), st)
	res, err := svc.Process(ctx, testID1, clientIvanov, c)
	if err != nil || !res.Degraded || strings.Contains(res.Result, surnameIvanov) {
		t.Fatalf("откат: err=%v degraded=%v result=%q", err, res.Degraded, res.Result)
	}
	back, err := svc.Process(ctx, testID1, res.Result, c)
	if err != nil || back.Result != clientIvanov {
		t.Fatalf("обратный шаг после отката: err=%v result=%q", err, back.Result)
	}
}

func recordOverByteBudget(t *testing.T, c *policy.Consumer) {
	// Бюджет делится на сегменты: 64 * 256 байт даёт 256 байт на сегмент.
	svc, st := realService(t, store.Options{MaxBytes: 64 * 256})
	res, err := svc.Process(context.Background(), "id-big", bigStoreText, c)
	assertStoreFull(t, res, err, "выдана маска без сохранённого соответствия")
	if st.Stats().Entries != 0 {
		t.Fatalf("в хранилище осталась запись: %+v", st.Stats())
	}
}

func evictionKeepsFreshRecord(t *testing.T, c *policy.Consumer) {
	// Лимит записей вытесняет самые старые. Свежая запись при этом
	// обязана быть сохранена: обратный шаг сразу после прямого работает
	// при любой заполненности.
	ctx := context.Background()
	svc, st := realService(t, store.Options{MaxEntries: 64})
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("ev-%d", i)
		orig := fmt.Sprintf("Клиент Иванов Иван Иванович, заявка %d", i)
		fwd, err := svc.Process(ctx, id, orig, c)
		if err != nil {
			t.Fatalf("прямой шаг %d: %v", i, err)
		}
		back, err := svc.Process(ctx, id, fwd.Result, c)
		if err != nil || back.Result != orig {
			t.Fatalf("обратный шаг %d сразу после прямого: err=%v result=%q", i, err, back.Result)
		}
	}
	if n := st.Stats().Entries; n > 64 {
		t.Fatalf("лимит записей не соблюдён: %d", n)
	}
}

func proxyStoreOverflowSendsNothing(t *testing.T, _ *policy.Consumer) {
	svc, _ := realService(t, store.Options{MaxBytes: 64 * 256})
	model := &recordingModel{reply: "ок"}
	_, err := svc.Proxy(context.Background(), model, userRequest("big", bigStoreText), invConsumer(t, consumerCRM, strategyPlaceholder))
	if !errors.Is(err, ErrFailClosed) {
		t.Fatalf("ожидалась ErrFailClosed, получено %v", err)
	}
	if model.calls() != 0 {
		t.Fatalf("при переполнении хранилища модель получила %d запросов", model.calls())
	}
}

// TestInvariantConcurrentSameIDIsIdempotent — AC-9: параллельные повторы
// прямого шага с одним payload_id дают одну маску и не мешают обратному шагу.
// Смысл проверки — под go test -race.
func TestInvariantConcurrentSameIDIsIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, _ := realService(t, store.Options{})
	c := invConsumer(t, policy.DefaultConsumerID, strategyPlaceholder)
	const text = clientIvanovEmail

	const workers = 32
	results := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := svc.Process(ctx, "same-id", text, c)
			results[i], errs[i] = res.Result, err
		}()
	}
	wg.Wait()
	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("параллельный прямой шаг %d: %v", i, errs[i])
		}
		if results[i] != results[0] {
			t.Fatalf("параллельные повторы дали разные маски: %q и %q", results[0], results[i])
		}
	}
	back, err := svc.Process(ctx, "same-id", results[0], c)
	if err != nil || back.Result != text {
		t.Fatalf("обратный шаг после параллельных повторов: err=%v result=%q", err, back.Result)
	}
}
