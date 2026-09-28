package detect

import (
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Все тексты в этом файле синтетические: имена, номера и адреса вымышлены,
// реальные персональные данные в репозиторий не попадают (AGENTS.md,
// «Инварианты приватности»).

// Синтетические значения, которые повторяются в нескольких проверках файла.
const (
	latinTestIvanov = "Ivan Ivanov"
	latinTestPetrov = "Ivan Petrov"
	latinTestPhone  = ", телефон +7 916 123-45-67."
	latinTestPhoneE = ", phone +7 916 123-45-67."
	latinTestMelnik = "Oleg Melnik"
	latinTestGold   = "Master Card Gold"
	latinTestBank   = "Please call the bank"
)

// latinSpans прогоняет полный конвейер: решение о маске принимает движок,
// а не сканер, и подъём по кластеру — часть правила.
func latinSpans(tb testing.TB, text string) []Span {
	tb.Helper()
	return detectSpans(tb, newFullEngine(tb), text, Options{})
}

// latinExact возвращает спан, границы которого совпадают с value.
func latinExact(spans []Span, text, value string) (Span, bool) {
	at := strings.Index(text, value)
	if at < 0 {
		return Span{}, false
	}
	for _, s := range spans {
		if int(s.Start) == at && int(s.End) == at+len(value) {
			return s, true
		}
	}
	return Span{}, false
}

// latinTouched сообщает, что какой-либо спан задевает value.
func latinTouched(spans []Span, text, value string) bool {
	at := strings.Index(text, value)
	if at < 0 {
		return false
	}
	for _, s := range spans {
		if int(s.Start) < at+len(value) && at < int(s.End) {
			return true
		}
	}
	return false
}

// TestLatinMasksFullName — входы из замечания жюри 23.09 и их вариации:
// имя латиницей маскируется ровно по границам, типом ФИО.
func TestLatinMasksFullName(t *testing.T) {
	cases := []struct{ text, value string }{
		{"Клиент Ivan Ivanov" + latinTestPhone, latinTestIvanov},
		{"Client Ivan Ivanov" + latinTestPhoneE, latinTestIvanov},
		{"Client Ivan Petrov asks to reissue his card.", latinTestPetrov},
		{"Перевод от Dmitry Tsoy, телефон +7 926 330-40-50.", "Dmitry Tsoy"},
		{"Customer: Anna Schmidt, email anna.schmidt@example.com, DOB 1987-03-15", "Anna Schmidt"},
		{"Please call Mr. Oleg Melnik at +7 916 700-80-90 regarding his loan.", latinTestMelnik},
		{"Получатель SWIFT-перевода: IVANOVA ELENA, клиент банка.", "IVANOVA ELENA"},
		// ПРОПИСНЫЕ, обратный порядок, инициал, конец предложения.
		{"Клиент IVAN IVANOV" + latinTestPhone, "IVAN IVANOV"},
		{"Клиент Ivanov Ivan" + latinTestPhone, "Ivanov Ivan"},
		{"Client Ivan I. Ivanov asks to reissue his card.", "Ivan I. Ivanov"},
		{"Клиент Ivanov Ivan Ivanovich просит выписку.", "Ivanov Ivan Ivanovich"},
		{"Письмо пришло от Anna Schmidt.", "Anna Schmidt"},
		{"Транзакцию подтвердил клиент Oleg Melnik", latinTestMelnik},
		// Без маркера, но с реквизитом в том же предложении.
		{"Ivan Ivanov, passport 4509 123456", latinTestIvanov},
		{latinTestPetrov + latinTestPhoneE, latinTestPetrov},
		// Подпись, транслитерация в скобках, частицы и составные фамилии.
		{"Best regards, Polina Grin", "Polina Grin"},
		{"Переписка с Шульце Томасом (Thomas Schulze) по поводу SWIFT-перевода.", "Thomas Schulze"},
		{"Dear Mrs. Anna van der Berg, your card is ready.", "Anna van der Berg"},
		{"Client Jean-Pierre Dupont" + latinTestPhoneE, "Jean-Pierre Dupont"},
		{"Client Sean O'Brien" + latinTestPhoneE, "Sean O'Brien"},
		{"Please call Mr.Oleg Melnik today.", latinTestMelnik},
	}
	for _, c := range cases {
		spans := latinSpans(t, c.text)
		s, ok := latinExact(spans, c.text, c.value)
		if !ok {
			t.Errorf("%q: %q не замаскировано ровно по границам: %v", c.text, c.value, spans)
			continue
		}
		if s.Type != pii.FullName {
			t.Errorf("%q: %q замаскировано как %v, ожидалось ФИО", c.text, c.value, s.Type)
		}
	}
}

// TestLatinKeepsCardHolder — держатель карты латиницей остаётся зоной
// сканера держателя: тип маски не меняется, соседние реквизиты не ломаются.
func TestLatinKeepsCardHolder(t *testing.T) {
	cases := []struct{ text, value string }{
		{"Держатель карты: MARIA KOVAL, карта 4279 0187 4509 4845, срок 08/29.", "MARIA KOVAL"},
		{"Имя на карте — SERGEY KIM, карта 4890 4993 0970 4699, cvv 417.", "SERGEY KIM"},
		{"Клиент указал имя латиницей: Olga Bondar, паспорт 4512 667788.", "Olga Bondar"},
		{"Клиент просит перевыпустить карту 5105107000066700 (держатель PETR ZHUK).", "PETR ZHUK"},
		{"Имя на карте Daria Shapovalova, номер 2200 7012 3456 7896.", "Daria Shapovalova"},
	}
	for _, c := range cases {
		spans := latinSpans(t, c.text)
		s, ok := latinExact(spans, c.text, c.value)
		if !ok || s.Type != pii.CardHolder {
			t.Errorf("%q: %q ожидался держателем карты, получено %v", c.text, c.value, spans)
		}
	}
}

// TestLatinKeepsEmail — латиница внутри адреса почты остаётся зоной сканера
// email: ФИО поверх адреса не появляется, адрес маскируется целиком.
func TestLatinKeepsEmail(t *testing.T) {
	cases := []struct{ text, email string }{
		{"Customer: Anna Schmidt, email anna.schmidt@example.com, DOB 1987-03-15", "anna.schmidt@example.com"},
		{"Пишите на Anna.Schmidt@Example.com, телефон +7 916 123-45-67.", "Anna.Schmidt@Example.com"},
		{"Контакт: Ivan.Petrov@mail.example.org", "Ivan.Petrov@mail.example.org"},
	}
	for _, c := range cases {
		spans := latinSpans(t, c.text)
		s, ok := latinExact(spans, c.text, c.email)
		if !ok || s.Type != pii.Email {
			t.Errorf("%q: адрес %q ожидался спаном email, получено %v", c.text, c.email, spans)
		}
	}
}

// TestLatinFalsePositives — продукты, бренды, города, произведения и
// английский текст без имён не маскируются, даже рядом с реквизитом.
func TestLatinFalsePositives(t *testing.T) {
	cases := []struct{ text, keep string }{
		{"Оплата через Apple Pay" + latinTestPhone, "Apple Pay"},
		{"Покупка в Google Play" + latinTestPhone, "Google Play"},
		{"Карта Visa Classic" + latinTestPhone, "Visa Classic"},
		{"Карта " + latinTestGold + latinTestPhone, latinTestGold},
		{latinTestGold, latinTestGold},
		{"Карта Tinkoff Black" + latinTestPhone, "Tinkoff Black"},
		{"Перевод в Sber Bank" + latinTestPhone, "Sber Bank"},
		{"Перевод в Alfa-Bank" + latinTestPhone, "Alfa-Bank"},
		{"Офис в Saint Petersburg" + latinTestPhone, "Saint Petersburg"},
		{"Офис в New York" + latinTestPhone, "New York"},
		{"Клиент читает роман Anna Karenina" + latinTestPhone, "Anna Karenina"},
		{"Anna Karenina is a novel" + latinTestPhoneE, "Anna Karenina"},
		{"Проект «Oleg Melnik» стартовал" + latinTestPhone, latinTestMelnik},
		{"Магазин Hugo Boss" + latinTestPhone, "Hugo Boss"},
		{"Jacket made by Calvin Klein" + latinTestPhoneE, "Calvin Klein"},
		{"Лежит в Calvin Klein Jeans" + latinTestPhone, "Calvin Klein Jeans"},
		{"Встреча у Victoria Station" + latinTestPhone, "Victoria Station"},
		{"Офис на Ivan Petrov Street" + latinTestPhone, latinTestPetrov},
		{latinTestBank + ".", latinTestBank},
		{latinTestBank + latinTestPhoneE, latinTestBank},
		{"Dear Anna, thank you" + latinTestPhoneE, "Anna"},
		{"Anna Maria" + latinTestPhoneE, "Anna Maria"},
		{"Ivan Petrov says hello.", latinTestPetrov},
	}
	for _, c := range cases {
		spans := latinSpans(t, c.text)
		if latinTouched(spans, c.text, c.keep) {
			t.Errorf("%q: %q не должно маскироваться: %v", c.text, c.keep, spans)
		}
	}
}

// TestLatinUpperWithoutMarker — ПРОПИСНЫЕ без маркера лица — форма имени на
// карте: ФИО этот сканер не регистрирует, решение за сканером держателя.
func TestLatinUpperWithoutMarker(t *testing.T) {
	const text = "IVAN PETROV" + latinTestPhoneE
	var cand Candidates
	latinScanner{}.Scan(lex.Tokenize(text, nil), engineTestDicts(t), &cand)
	if len(cand.Spans) != 0 {
		t.Fatalf("%q: кандидаты не ожидались: %v", text, cand.Spans)
	}
}

// TestLatinConfidence — уверенность по контексту: маркер даёт Strong, форма
// без маркера — Weak, до маски её поднимает только движок.
func TestLatinConfidence(t *testing.T) {
	cases := []struct {
		text string
		conf Confidence
		rule string
	}{
		{"Client Ivan Petrov asks.", Strong, latinRuleMarker},
		{"Please call Mr. Oleg Melnik.", Strong, latinRuleMarker},
		{"Переписка с Шульце Томасом (Thomas Schulze).", Strong, latinRuleTranslit},
		{"Имя: Ivan I. Petrov.", Strong, latinRuleHolder},
		{"Ivan Petrov says hello.", Weak, latinRuleForm},
	}
	for _, c := range cases {
		var cand Candidates
		latinScanner{}.Scan(lex.Tokenize(c.text, nil), engineTestDicts(t), &cand)
		if len(cand.Spans) != 1 {
			t.Errorf("%q: кандидатов %d, ожидался один", c.text, len(cand.Spans))
			continue
		}
		if s := cand.Spans[0]; s.Conf != c.conf || s.Rule != c.rule {
			t.Errorf("%q: получено %v/%s, ожидалось %v/%s", c.text, s.Conf, s.Rule, c.conf, c.rule)
		}
	}
}

// TestLatinStrictProfile — под strict форма без маркера не маскируется:
// профиль маскирует только то, что сканер нашёл достоверным сам.
func TestLatinStrictProfile(t *testing.T) {
	const text = latinTestPetrov + latinTestPhoneE
	spans := detectSpans(t, newFullEngine(t), text, Options{Profile: Strict})
	if latinTouched(spans, text, latinTestPetrov) {
		t.Fatalf("%q: под strict имя без маркера не маскируется: %v", text, spans)
	}
}

func TestLatinRegistered(t *testing.T) {
	for _, s := range Registered() {
		if s.Name() == "latin" {
			return
		}
	}
	t.Fatal("сканер latin не зарегистрирован")
}

// TestLatinDictSizes — справочники на месте: пустой справочник имён молча
// выключил бы сканер.
func TestLatinDictSizes(t *testing.T) {
	dicts := engineTestDicts(t)
	if n := dicts.Table(latinDictGiven).Len(); n < 500 {
		t.Errorf("%s: %d записей, ожидалось не меньше 500", latinDictGiven, n)
	}
	if n := dicts.Table(latinDictContext).Len(); n < 100 {
		t.Errorf("%s: %d записей, ожидалось не меньше 100", latinDictContext, n)
	}
	for _, w := range []string{"ivan", "elena", "dmitry", "dmitriy", "sergey", "sergei", "anna", "thomas"} {
		if !dicts.Table(latinDictGiven).Has(w) {
			t.Errorf("%s: нет записи %q", latinDictGiven, w)
		}
	}
}

// latinBenchBlock — синтетический фрагмент со всеми ветками разбора.
const latinBenchBlock = "Клиент Ivan Ivanov, телефон +7 916 123-45-67. Please call Mr. Oleg Melnik at the office. " +
	"Получатель SWIFT-перевода: IVANOVA ELENA, клиент банка. Оплата через Apple Pay и Google Play. " +
	"Customer: Anna van der Berg, email anna.berg@example.com. Роман Anna Karenina, Victoria Station. " +
	"Держатель карты MARIA KOVAL, карта 2200 7001 2345 6781. Ivan Petrov, passport 4509 123456.\n"

var latinBenchText = strings.Repeat(latinBenchBlock, 4096/len(latinBenchBlock)+1)

// TestLatinScanNoAllocs — горячий путь: разбор по токенам и срезам Norm,
// временных строк не собирается.
func TestLatinScanNoAllocs(t *testing.T) {
	doc := lex.Tokenize(latinBenchText, nil)
	dicts := engineTestDicts(t)
	var cand Candidates
	s := latinScanner{}
	s.Scan(doc, dicts, &cand)
	if len(cand.Spans) == 0 {
		t.Fatal("в тексте не найдено ни одного кандидата")
	}
	if got := testing.AllocsPerRun(20, func() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}); got != 0 {
		t.Errorf(msgAllocsWant, got)
	}
}

func BenchmarkScanLatin(b *testing.B) {
	if len(latinBenchText) < 4096 || len(latinBenchText) > 8192 {
		b.Fatalf(msgBenchTextSize, len(latinBenchText))
	}
	doc := lex.Tokenize(latinBenchText, nil)
	dicts := engineTestDicts(b)
	var cand Candidates
	s := latinScanner{}
	// Прогрев: накопитель набирает ёмкость, чтобы в измерении остался только
	// разбор.
	s.Scan(doc, dicts, &cand)
	b.SetBytes(int64(len(latinBenchText)))
	b.ReportAllocs()
	for b.Loop() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}
}

// TestLatinLinearTime — строка из повторов имени без границ предложения
// разбирается за линейное время: поиск маркера и номера карты ограничен
// окном и запоминанием по предложению.
func TestLatinLinearTime(t *testing.T) {
	for _, block := range []string{"Client Ivan Petrov, ", "Клиент IVAN PETROV, "} {
		text := strings.Repeat(block, 50000)
		doc := lex.Tokenize(text, nil)
		var cand Candidates
		begin := time.Now()
		latinScanner{}.Scan(doc, engineTestDicts(t), &cand)
		if d := time.Since(begin); d > 2*time.Second {
			t.Errorf("%q ×50000: разбор %v, ожидалось линейное время", block, d)
		}
		if len(cand.Spans) != 50000 {
			t.Errorf("%q ×50000: кандидатов %d", block, len(cand.Spans))
		}
	}
}
