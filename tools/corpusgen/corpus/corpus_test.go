package corpus

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// testSeed фиксирован: тесты обязаны проверять один и тот же корпус, иначе
// падение невозможно воспроизвести.
const testSeed = 20260922

var (
	once   sync.Once
	sample []Record
)

// corpusOnce строит полный корпус (включая длинные записи) один раз на пакет.
func corpusOnce(t *testing.T) []Record {
	t.Helper()
	once.Do(func() {
		sample = Generate(Options{Count: DefaultCount, Seed: testSeed, Long: true})
	})
	return sample
}

// AC-6: смещения байтовые и указывают ровно на значение.
func TestSpanOffsetsAreBytes(t *testing.T) {
	recs := corpusOnce(t)
	cyrillic := 0
	for i := range recs {
		cyrillic += checkRecordOffsets(t, &recs[i])
	}
	if cyrillic == 0 {
		t.Fatal("в корпусе нет ни одного спана с многобайтовыми символами: проверка байтовых смещений ничего не доказывает")
	}
	t.Logf("спанов с многобайтовыми символами: %d", cyrillic)
}

// checkRecordOffsets проверяет границы спанов и ловушек записи и возвращает
// число спанов с многобайтовыми символами.
func checkRecordOffsets(t *testing.T, r *Record) int {
	t.Helper()
	cyrillic := 0
	prev := 0
	for _, s := range r.Spans {
		checkBounds(t, r, "spans", s.Start, s.End, s.Value, s.Type)
		if s.Start < prev {
			t.Fatalf("%s: спаны не упорядочены или перекрываются на %d", r.ID, s.Start)
		}
		prev = s.End
		// Разница байтов и рун доказывает, что смещения именно байтовые.
		if n := utf8.RuneCountInString(s.Value); n != len(s.Value) {
			cyrillic++
		}
	}
	for _, tr := range r.Traps {
		checkBounds(t, r, "traps", tr.Start, tr.End, tr.Value, tr.Type)
	}
	return cyrillic
}

// checkBounds проверяет, что [start, end) лежит в тексте, указывает ровно на
// значение и не рассекает руну.
func checkBounds(t *testing.T, r *Record, kind string, start, end int, value, typ string) {
	t.Helper()
	switch {
	case start < 0 || end > len(r.Text) || start >= end:
		t.Fatalf("%s: %s %s: границы [%d,%d) вне текста длиной %d", r.ID, kind, typ, start, end, len(r.Text))
	case r.Text[start:end] != value:
		t.Fatalf("%s: %s %s: text[%d:%d]=%q, ожидалось %q", r.ID, kind, typ, start, end, r.Text[start:end], value)
	case !utf8.RuneStart(r.Text[start]):
		t.Fatalf("%s: %s %s: начало спана рассекает руну", r.ID, kind, typ)
	case !utf8.ValidString(value):
		t.Fatalf("%s: %s %s: значение не UTF-8", r.ID, kind, typ)
	}
}

// AC-6: отдельная проверка на заведомо кириллическом тексте — здесь смещение
// значения заведомо не совпадает с номером символа.
func TestCyrillicOffsetsExplicit(t *testing.T) {
	var b builder
	b.add(lit(litFindClient), val(KFullName, "Иванова Ивана Ивановича"), lit(litPassport), val(KPassportNumber, "4509 123456"), lit("."))
	rec := b.record(KindMulti)

	if got := rec.Spans[0].Start; got != len(litFindClient) {
		t.Fatalf("начало ФИО = %d, ожидалось %d", got, len(litFindClient))
	}
	if rec.Spans[0].Start == utf8.RuneCountInString(litFindClient) {
		t.Fatal("смещение совпало с номером символа: значит, оно не байтовое")
	}
	for _, s := range rec.Spans {
		if rec.Text[s.Start:s.End] != s.Value {
			t.Fatalf("text[%d:%d]=%q, ожидалось %q", s.Start, s.End, rec.Text[s.Start:s.End], s.Value)
		}
	}
}

// AC-5: один seed даёт побайтово одинаковый корпус.
func TestDeterministicBySeed(t *testing.T) {
	render := func(seed uint64) []byte {
		var buf bytes.Buffer
		if err := Write(&buf, Generate(Options{Count: 300, Seed: seed, Long: true})); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	a, b := render(testSeed), render(testSeed)
	if !bytes.Equal(a, b) {
		t.Fatal("два прогона с одним seed дали разные корпуса: метрики прогонов несравнимы")
	}
	if bytes.Equal(a, render(testSeed+1)) {
		t.Fatal("разные seed дали одинаковый корпус: -seed ни на что не влияет")
	}
}

// AC-2: все 17 обязательных типов, каждый не менее чем в MinPerType записях.
func TestTypeCoverage(t *testing.T) {
	s := Summarize(corpusOnce(t))
	if len(s.Types) != 17 {
		t.Fatalf("типов в сводке %d, ожидалось 17", len(s.Types))
	}
	for _, ts := range s.Types {
		if ts.Records < MinPerType {
			t.Errorf("тип %s встречается в %d записях, требуется не менее %d", ts.Type, ts.Records, MinPerType)
		}
	}
}

// AC-3: ловушки всех пяти обязательных видов размечены в traps, а не в spans.
func TestTrapKinds(t *testing.T) {
	recs := corpusOnce(t)
	required := []string{ReasonPublicFigure, ReasonToponym, ReasonOrgAddress, ReasonHotline, ReasonContractNumber}
	seen := map[string]int{}
	for i := range recs {
		for _, tr := range recs[i].Traps {
			seen[tr.Reason]++
			// Ловушка не может быть одновременно размеченными ПД.
			for _, s := range recs[i].Spans {
				if s.Start < tr.End && tr.Start < s.End {
					t.Fatalf("%s: ловушка [%d,%d) пересекается со спаном [%d,%d)", recs[i].ID, tr.Start, tr.End, s.Start, s.End)
				}
			}
		}
	}
	for _, r := range required {
		if seen[r] == 0 {
			t.Errorf("ловушка вида %s отсутствует", r)
		}
	}
	t.Logf("ловушки: %v", seen)
}

// AC-4: записи без ПД и длинные записи на 50 000 и 100 000 токенов.
func TestCleanAndLongRecords(t *testing.T) {
	recs := corpusOnce(t)
	clean, long := 0, map[int]int{}
	for i := range recs {
		r := &recs[i]
		switch r.Kind {
		case KindClean:
			checkCleanRecord(t, r)
			clean++
		case KindLong:
			long[longRecordSize(t, r)]++
		}
	}
	if clean == 0 {
		t.Fatal("в корпусе нет записей без ПД: ложные срабатывания не на чем считать")
	}
	if long[50_000] == 0 || long[100_000] == 0 {
		t.Fatalf("нет длинных записей нужных размеров: %v", long)
	}
	t.Logf("записей без ПД: %d, длинных: %v", clean, long)
}

func checkCleanRecord(t *testing.T, r *Record) {
	t.Helper()
	if len(r.Spans) != 0 || len(r.Traps) != 0 {
		t.Fatalf("%s: запись без ПД содержит разметку", r.ID)
	}
}

// longRecordSize проверяет длинную запись и возвращает её номинальный размер
// в токенах: 50 000 или 100 000.
func longRecordSize(t *testing.T, r *Record) int {
	t.Helper()
	size := 0
	n := countTokens(r.Text)
	switch {
	case n >= 50_000 && n < 50_100:
		size = 50_000
	case n >= 100_000 && n < 100_100:
		size = 100_000
	default:
		t.Fatalf("%s: длинная запись на %d токенов не попадает в требуемые размеры", r.ID, n)
	}
	if len(r.Spans) == 0 {
		t.Fatalf("%s: длинная запись без ПД не проверяет детекцию на крупном входе", r.ID)
	}
	return size
}

// AC-7: вариации написания по ТЗ §3.2.2 для дат и паспорта.
func TestWritingVariations(t *testing.T) {
	v := newVariations()
	recs := corpusOnce(t)
	for i := range recs {
		v.addRecord(&recs[i])
	}
	v.check(t)
	t.Logf("формы дат: %d, паспорта: %d, «серия … номер …»: %d", len(v.shapes), len(v.passportShapes), v.splitPassport)
}

// variations — встретившиеся в корпусе формы написания значений.
type variations struct {
	shapes               map[string]bool
	words, ordinal       int
	passportShapes       map[string]bool
	splitPassport        int
	upperName, lowerName int
}

func newVariations() *variations {
	return &variations{shapes: map[string]bool{}, passportShapes: map[string]bool{}}
}

func (v *variations) addRecord(r *Record) {
	byType := map[string]int{}
	for _, s := range r.Spans {
		byType[s.Type]++
		v.addSpan(s)
	}
	// Форма «серия … номер …» даёт два спана одного типа в одной записи.
	if byType[KPassportNumber] == 2 && strings.Contains(r.Text, litSeries) {
		v.splitPassport++
	}
}

func (v *variations) addSpan(s Span) {
	switch s.Type {
	case KBirthDate, KPassportIssueDate:
		v.addDate(s.Value)
	case KPassportNumber:
		v.passportShapes[shape(s.Value)] = true
	case KFullName:
		letters := strings.TrimFunc(s.Value, func(r rune) bool { return r == ' ' || r == '.' })
		if letters == strings.ToUpper(letters) {
			v.upperName++
		}
		if letters == strings.ToLower(letters) {
			v.lowerName++
		}
	}
}

func (v *variations) addDate(value string) {
	v.shapes[shape(value)] = true
	if !strings.ContainsAny(value, "абвгдеёжзийклмнопрстуфхцчшщэюя") {
		return
	}
	v.words++
	if strings.HasSuffix(value, "ого") || strings.Contains(value, "ое ") {
		v.ordinal++
	}
}

func (v *variations) check(t *testing.T) {
	t.Helper()
	for _, want := range []string{"DD.DD.DDDD", "DD/DD/DDDD", "DD-DD-DDDD", "DDDD-DD-DD", "DDDD.DD.DD", "DD.DD.DD"} {
		if !v.shapes[want] {
			t.Errorf("не встретилась запись даты вида %s", want)
		}
	}
	if v.words == 0 {
		t.Error("нет дат, записанных словами")
	}
	if v.ordinal == 0 {
		t.Error("нет дат с числом-порядковым словом")
	}
	for _, want := range []string{"DDDD DDDDDD", "DD DD DDDDDD", "DDDDDDDDDD"} {
		if !v.passportShapes[want] {
			t.Errorf("не встретилась запись паспорта вида %s", want)
		}
	}
	if v.splitPassport == 0 {
		t.Error("нет паспорта с разделяющими словами «серия … номер …»")
	}
	if v.upperName == 0 || v.lowerName == 0 {
		t.Errorf("нет вариаций регистра ФИО: верхний %d, нижний %d", v.upperName, v.lowerName)
	}
}

// shape сводит значение к скелету: цифра → D, буква → W, остальное как есть.
func shape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			b.WriteByte('D')
		case r == ' ' || r == '.' || r == '-' || r == '/' || r == '№':
			b.WriteRune(r)
		default:
			b.WriteByte('W')
		}
	}
	return b.String()
}

// Служебные слова в спан не входят: их маскирование штрафуется как избыточное
// (07-clarifications.md §7.1).
func TestSpansExcludeServiceWords(t *testing.T) {
	recs := corpusOnce(t)
	for i := range recs {
		for _, s := range recs[i].Spans {
			checkNoServiceWords(t, recs[i].ID, s)
		}
	}
}

var (
	serviceWordPrefixes = []string{"серия", "номер", "паспорт", "ИНН", "CVV", "пин", "ПИН", "гражданство", "телефон"}
	serviceWordSuffixes = []string{" года", " г.", ",", " "}
)

func checkNoServiceWords(t *testing.T, id string, s Span) {
	t.Helper()
	if strings.TrimSpace(s.Value) != s.Value {
		t.Fatalf("%s: спан %s обрамлён пробелами: %q", id, s.Type, s.Value)
	}
	for _, p := range serviceWordPrefixes {
		if strings.HasPrefix(s.Value, p) {
			t.Fatalf("%s: спан %s начинается со служебного слова: %q", id, s.Type, s.Value)
		}
	}
	for _, p := range serviceWordSuffixes {
		if strings.HasSuffix(s.Value, p) {
			t.Fatalf("%s: спан %s заканчивается служебным фрагментом: %q", id, s.Type, s.Value)
		}
	}
}

// Формат вывода: JSON Lines, одна запись на строку, идентификаторы уникальны.
func TestWriteJSONLines(t *testing.T) {
	recs := Generate(Options{Count: 200, Seed: testSeed, Long: false})
	var buf bytes.Buffer
	if err := Write(&buf, recs); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != len(recs) {
		t.Fatalf("строк %d, записей %d", len(lines), len(recs))
	}
	seen := map[string]bool{}
	for i, line := range lines {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("строка %d не разбирается: %v", i+1, err)
		}
		if r.ID == "" || seen[r.ID] {
			t.Fatalf("строка %d: пустой или повторный идентификатор %q", i+1, r.ID)
		}
		seen[r.ID] = true
		if r.Text == "" {
			t.Fatalf("%s: пустой текст", r.ID)
		}
		if !json.Valid([]byte(line)) {
			t.Fatalf("%s: строка не является корректным JSON", r.ID)
		}
	}
}

// Все данные синтетические: карты только из тестовых BIN, почта только в
// зарезервированных доменах. Реальные ПД в репозиторий попадать не должны.
func TestSyntheticValuesOnly(t *testing.T) {
	checkSyntheticValues(t, corpusOnce(t))
}

// checkSyntheticValues проверяет синтетичность значений набора записей.
func checkSyntheticValues(t *testing.T, recs []Record) {
	t.Helper()
	for i := range recs {
		for _, s := range recs[i].Spans {
			switch s.Type {
			case KCardNumber:
				checkSyntheticCard(t, recs[i].ID, s.Value)
			case KEmail:
				checkSyntheticEmail(t, recs[i].ID, s.Value)
			case KINN:
				checkSyntheticINN(t, recs[i].ID, s.Value)
			}
		}
	}
}

// checkSyntheticCard: номер из тестового BIN и проходит проверку Луна.
func checkSyntheticCard(t *testing.T, id, value string) {
	t.Helper()
	digits := strings.NewReplacer(" ", "", "-", "").Replace(value)
	if !slices.ContainsFunc(testBINs, func(bin string) bool { return strings.HasPrefix(digits, bin) }) {
		t.Fatalf("%s: номер карты %q не из тестового диапазона", id, value)
	}
	if luhn(digits[:len(digits)-1]) != int(digits[len(digits)-1]-'0') {
		t.Fatalf("%s: номер карты %q не проходит Луна", id, value)
	}
}

// checkSyntheticEmail: домен из зарезервированных RFC 2606.
func checkSyntheticEmail(t *testing.T, id, value string) {
	t.Helper()
	at := strings.LastIndex(value, "@")
	if at < 0 {
		t.Fatalf("%s: адрес без @: %q", id, value)
	}
	domain := strings.ToLower(value[at+1:])
	if !slices.Contains(emailDomains, domain) {
		t.Fatalf("%s: домен %q не из зарезервированных RFC 2606", id, domain)
	}
}

// checkSyntheticINN: 12 цифр с верными контрольными разрядами.
func checkSyntheticINN(t *testing.T, id, value string) {
	t.Helper()
	if len(value) != 12 {
		t.Fatalf("%s: ИНН физлица должен быть 12 цифр: %q", id, value)
	}
	if innCheck(value[:10], innWeights11) != int(value[10]-'0') ||
		innCheck(value[:11], innWeights12) != int(value[11]-'0') {
		t.Fatalf("%s: контрольные разряды ИНН %q неверны", id, value)
	}
}

// Записи-однофамильцы: фамилия публичной персоны у обычного клиента остаётся
// персональными данными (AC-203), поэтому размечается в spans.
func TestNamesakeIsNotTrap(t *testing.T) {
	recs := corpusOnce(t)
	found := 0
	for i := range recs {
		if recs[i].Kind != KindNamesake {
			continue
		}
		found++
		if len(recs[i].Traps) != 0 {
			t.Fatalf("%s: однофамилец размечен как ловушка", recs[i].ID)
		}
		has := false
		for _, s := range recs[i].Spans {
			if s.Type == KFullName {
				has = true
			}
		}
		if !has {
			t.Fatalf("%s: в записи об однофамильце нет спана ФИО", recs[i].ID)
		}
	}
	if found == 0 {
		t.Fatal("в корпусе нет записей об однофамильцах публичных персон")
	}
}

// T-50: фамилии без русского суффикса попадают в корпус во всех регистрах.
// До T-50 их не было вовсе, и прогон качества не мог увидеть утечку
// «Клиент [ФИО_1] Мельник» — её нашло бизнес-жюри.
func TestBareSurnamesInCorpus(t *testing.T) {
	recs := corpusOnce(t)
	forms := bareSurnameForms()
	total, upper, lower := 0, 0, 0
	for i := range recs {
		for _, s := range recs[i].Spans {
			if s.Type != KFullName || !hasAnyForm(s.Value, forms) {
				continue
			}
			total++
			switch s.Value {
			case strings.ToUpper(s.Value):
				upper++
			case strings.ToLower(s.Value):
				lower++
			}
		}
	}
	if total < 50 || upper == 0 || lower == 0 {
		t.Fatalf("спанов ФИО с фамилией без суффикса %d (капсом %d, строчными %d): корпус их почти не видит",
			total, upper, lower)
	}
	t.Logf("спанов ФИО с фамилией без суффикса: %d, капсом %d, строчными %d", total, upper, lower)
}

// bareSurnameForms — все падежные формы фамилий без русского суффикса,
// в нижнем регистре и с «е» вместо «ё».
func bareSurnameForms() map[string]bool {
	forms := map[string]bool{}
	for _, s := range surnamesBare {
		m, f := mascNoun(s), femSur(s)
		for _, w := range []string{m.nom, m.gen, m.acc, f.nom, f.gen, f.acc} {
			forms[strings.ToLower(deyo(w))] = true
		}
	}
	return forms
}

// hasAnyForm сообщает, есть ли среди слов значения одна из форм.
func hasAnyForm(value string, forms map[string]bool) bool {
	for _, w := range strings.Fields(value) {
		if forms[strings.ToLower(deyo(w))] {
			return true
		}
	}
	return false
}

// T-63: голые значения включаются только флагом, и корпус без флага —
// побайтовый префикс корпуса с флагом. Так прошлые прогоны на seed 20260922
// остаются сравнимыми, а флаг ничего не сдвигает в остальных записях.
func TestBareOffByDefaultAndSuffix(t *testing.T) {
	render := func(opt Options) []byte {
		var buf bytes.Buffer
		if err := Write(&buf, Generate(opt)); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	for _, long := range []bool{false, true} {
		plain := render(Options{Count: 300, Seed: testSeed, Long: long})
		withBare := render(Options{Count: 300, Seed: testSeed, Long: long, Bare: true})
		if bytes.Contains(plain, []byte(`"kind":"`+KindBare+`"`)) {
			t.Fatalf("long=%v: голые записи попали в корпус без флага", long)
		}
		if !bytes.HasPrefix(withBare, plain) {
			t.Fatalf("long=%v: корпус без флага — не префикс корпуса с флагом: флаг сдвинул прежние записи", long)
		}
		if len(withBare) == len(plain) {
			t.Fatalf("long=%v: флаг -bare не добавил ни одной записи", long)
		}
	}
}

// T-63: голая запись — одно значение целиком, без окружающего текста. Снаружи
// спана допускается только служебное слово года после даты.
func TestBareRecordsAreSingleValues(t *testing.T) {
	recs := bareRecords(testSeed)
	perType := map[string]int{}
	for i := range recs {
		perType[checkBareRecord(t, i, &recs[i])]++
	}
	for _, typ := range RequiredTypes {
		if perType[typ] != barePerType {
			t.Errorf("тип %s: голых записей %d, ожидалось %d", typ, perType[typ], barePerType)
		}
	}
	checkSyntheticValues(t, recs)
}

// checkBareRecord проверяет голую запись с номером i и возвращает тип её значения.
func checkBareRecord(t *testing.T, i int, r *Record) string {
	t.Helper()
	if r.Kind != KindBare {
		t.Fatalf("запись %d: вид %q, ожидался %q", i, r.Kind, KindBare)
	}
	if len(r.Spans) != 1 || len(r.Traps) != 0 {
		t.Fatalf("запись %q: спанов %d, ловушек %d — ожидалось одно значение", r.Text, len(r.Spans), len(r.Traps))
	}
	s := r.Spans[0]
	if s.Start != 0 || r.Text[s.Start:s.End] != s.Value {
		t.Fatalf("запись %q: спан [%d,%d) не с начала записи или не равен значению", r.Text, s.Start, s.End)
	}
	if tail := r.Text[s.End:]; tail != "" && !bareTailAllowed(s.Type, tail) {
		t.Fatalf("запись %q: за значением %q лишний текст %q", r.Text, s.Value, tail)
	}
	if strings.TrimSpace(s.Value) != s.Value || s.Value == "" {
		t.Fatalf("запись %q: значение с пробелами по краям или пустое", r.Text)
	}
	return s.Type
}

// bareTailAllowed: за голым значением допустимо только слово года после даты.
func bareTailAllowed(typ, tail string) bool {
	return (typ == KBirthDate || typ == KPassportIssueDate) && slices.Contains(bareYearSuffixes, tail)
}

// T-63: вариации голых значений действительно разные — у каждого типа
// несколько форм написания, а не одна, повторённая barePerType раз.
func TestBareRecordsVaryForms(t *testing.T) {
	shapes := map[string]map[string]bool{}
	for _, r := range bareRecords(testSeed) {
		typ := r.Spans[0].Type
		if shapes[typ] == nil {
			shapes[typ] = map[string]bool{}
		}
		shapes[typ][shape(r.Text)] = true
	}
	// У ИНН, CVV, ПИН, почты и держателя форма одна по природе значения
	// (держатель различается регистром, который shape не видит).
	single := map[string]bool{KINN: true, KCVV: true, KPIN: true, KEmail: true, KCardHolder: true}
	for _, typ := range RequiredTypes {
		if !single[typ] && len(shapes[typ]) < 2 {
			t.Errorf("тип %s: у голых записей одна форма написания", typ)
		}
	}
}

// T-63: в сводке корпуса с флагом есть строка вида bare, и записи этого
// вида учитываются в покрытии типов.
func TestBareSummary(t *testing.T) {
	s := Summarize(Generate(Options{Count: 300, Seed: testSeed, Bare: true}))
	found := false
	for _, k := range s.Kinds {
		if k.Kind == KindBare {
			found = true
			if k.Records != barePerType*len(RequiredTypes) {
				t.Fatalf("записей вида bare в сводке %d, ожидалось %d", k.Records, barePerType*len(RequiredTypes))
			}
		}
	}
	if !found {
		t.Fatal("в сводке нет строки вида bare")
	}
}
