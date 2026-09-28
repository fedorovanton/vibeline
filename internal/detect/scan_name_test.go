package detect

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

var (
	nameDictsOnce sync.Once
	nameDictsSet  *dict.Set
	nameDictsErr  error
)

// nameDicts загружает справочники один раз на весь прогон: сборка таблиц
// заметно дороже самого сканирования.
func nameDicts(tb testing.TB) *dict.Set {
	tb.Helper()
	nameDictsOnce.Do(func() { nameDictsSet, nameDictsErr = dict.Load() })
	if nameDictsErr != nil {
		tb.Fatalf(msgDictLoad, nameDictsErr)
	}
	return nameDictsSet
}

// nameScanText прогоняет только сканер ФИО, без движка: проверяются сырые
// кандидаты, включая слабых, которых профиль по умолчанию отбросил бы.
func nameScanText(tb testing.TB, text string) (*lex.Doc, []Span) {
	tb.Helper()
	doc := lex.Tokenize(text, nil)
	var out Candidates
	nameScanner{}.Scan(doc, nameDicts(tb), &out)
	return doc, out.Spans
}

type nameWant struct {
	text string
	conf Confidence
}

// nameConstructionCase — строка таблицы TestNameScannerConstructions.
type nameConstructionCase struct {
	name  string
	text  string
	want  []nameWant
	total int // ожидаемое число спанов; -1 — не проверять
}

// nameCheckConstruction проверяет число спанов и тип и уровень каждого
// ожидаемого спана ФИО.
func nameCheckConstruction(t *testing.T, tc nameConstructionCase) {
	t.Helper()
	doc, spans := nameScanText(t, tc.text)
	if tc.total >= 0 && len(spans) != tc.total {
		t.Fatalf("спанов %d, ожидалось %d: %s", len(spans), tc.total, nameDump(doc, spans))
	}
	for _, w := range tc.want {
		s, ok := nameFind(doc, spans, w.text)
		if !ok {
			t.Fatalf(msgSpanNotFound, w.text, nameDump(doc, spans))
		}
		if s.Type != pii.FullName {
			t.Errorf("спан %q: тип %v, ожидался %v", w.text, s.Type, pii.FullName)
		}
		if s.Conf != w.conf {
			t.Errorf("спан %q: уверенность %v, ожидалась %v", w.text, s.Conf, w.conf)
		}
	}
}

func TestNameScannerConstructions(t *testing.T) {
	tests := []nameConstructionCase{
		{
			name:  "фамилия имя отчество",
			text:  "Иванов Иван Иванович обратился в банк.",
			want:  []nameWant{{nameFxIvanovFull, Certain}},
			total: 1,
		},
		{
			name:  "имя отчество фамилия",
			text:  "Иван Иванович Иванов обратился в банк.",
			want:  []nameWant{{"Иван Иванович Иванов", Certain}},
			total: 1,
		},
		{
			name:  "фамилия и инициалы",
			text:  "Заявку подписал Иванов И. И.",
			want:  []nameWant{{"Иванов И. И.", Strong}},
			total: 1,
		},
		{
			name:  "инициалы и фамилия",
			text:  "И. И. Иванов подписал заявку.",
			want:  []nameWant{{"И. И. Иванов", Strong}},
			total: 1,
		},
		{
			name:  "маркер слева в спан не входит",
			text:  "клиент Петрова Анна Сергеевна",
			want:  []nameWant{{nameFxPetrovaFull, Certain}},
			total: 1,
		},
		{
			name:  "родительный падеж всей конструкции",
			text:  "Оформите справку для Иванова Ивана Ивановича.",
			want:  []nameWant{{"Иванова Ивана Ивановича", Certain}},
			total: 1,
		},
		{
			name:  "дательный падеж фамилии и имени",
			text:  "передайте Ивановой Анне документы",
			want:  []nameWant{{"Ивановой Анне", Strong}},
			total: 1,
		},
		{
			name:  "верхний регистр целиком",
			text:  "ИВАНОВ ИВАН ИВАНОВИЧ",
			want:  []nameWant{{"ИВАНОВ ИВАН ИВАНОВИЧ", Certain}},
			total: 1,
		},
		{
			// ТЗ §3.2.1: идентификация не должна зависеть от регистра.
			// Конструкция опознана, но на ступень ниже: признак заглавной
			// буквы не сработал, свидетельств осталось два из трёх.
			name:  "строчное ФИО опознаётся с пониженной уверенностью",
			text:  "иванов иван иванович",
			want:  []nameWant{{"иванов иван иванович", Strong}},
			total: 1,
		},
		{
			// Без маркера и без сказуемого лица рядом. «иван иванович
			// подтвердил перевод» поднимается сказуемым (T-60) — см.
			// TestNameLowerPairIntro.
			name:  "строчные имя и отчество опускаются до Weak",
			text:  "иван иванович, перевод подтверждён",
			want:  []nameWant{{"иван иванович", Weak}},
			total: 1,
		},
		{
			// «иванов» строчными — это и фамилия, и родительный падеж
			// множественного числа от «иван». Одной морфологии суффикса мало.
			name:  "одиночное строчное слово кандидатом не становится",
			text:  "в списке иванов не оказалось",
			total: 0,
		},
		{
			name:  "маркер возвращает одиночное строчное слово на уровне Weak",
			text:  "клиент иванов подтвердил перевод",
			want:  []nameWant{{nameFxIvanovLower, Weak}},
			total: 1,
		},
		{
			// Слева от настоящего ФИО стоит обычное слово с суффиксом
			// фамилии. Единообразие регистра внутри конструкции не даёт ему
			// приклеиться: разбор начинается с «Иванов».
			name:  "обычное слово слева в конструкцию не входит",
			text:  "проверь список документов Иванов Иван Иванович",
			want:  []nameWant{{nameFxIvanovFull, Certain}},
			total: 1,
		},
		{
			name:  "имя и отчество",
			text:  "Иван Иванович подтвердил перевод.",
			want:  []nameWant{{nameFxIvanIvanovich, Strong}},
			total: 1,
		},
		{
			name:  "имя и фамилия",
			text:  "Заявитель Иван Иванов ожидает ответа.",
			want:  []nameWant{{"Иван Иванов", Strong}},
			total: 1,
		},
		{
			name:  "маркер поднимает одиночную фамилию",
			text:  "Клиент Иванов подтвердил перевод.",
			want:  []nameWant{{nameFxIvanov, Strong}},
			total: 1,
		},
		{
			name:  "одиночная фамилия без маркера остаётся слабой",
			text:  "Справка: Иванов",
			want:  []nameWant{{nameFxIvanov, Weak}},
			total: 1,
		},
		{
			// С T-66 «подпись» — маркер поля анкеты (раунд 4 жюри, P4-2).
			name:  "поле подписи поднимает одиночную фамилию",
			text:  "Подпись: Иванов",
			want:  []nameWant{{nameFxIvanov, Strong}},
			total: 1,
		},
		{
			name:  "одиночное имя без маркера остаётся слабым",
			text:  "Встречу проводит Екатерина",
			want:  []nameWant{{"Екатерина", Weak}},
			total: 1,
		},
		{
			name:  "фамилия на -ский",
			text:  "Достоевский Фёдор Михайлович значится в списке.",
			want:  []nameWant{{"Достоевский Фёдор Михайлович", Certain}},
			total: 1,
		},
		{
			name:  "фамилия на -ко в дательном падеже",
			text:  "Выплату получил Петренко Олег Петрович.",
			want:  []nameWant{{"Петренко Олег Петрович", Certain}},
			total: 1,
		},
		{
			name:  "фамилия на -швили",
			text:  "Договор с Иашвили Давидом Георгиевичем расторгнут.",
			want:  []nameWant{{"Иашвили Давидом Георгиевичем", Certain}},
			total: 1,
		},
		{
			name:  "имя перед фамилией в женском роде",
			text:  "Марина Иванова перевела средства.",
			want:  []nameWant{{"Марина Иванова", Strong}},
			total: 1,
		},
		{
			name:  "имя с беглой гласной в косвенном падеже",
			text:  "Счёт открыт на Павла Смирнова.",
			want:  []nameWant{{"Павла Смирнова", Strong}},
			total: 1,
		},
		{
			name:  "отчество на -ич подтверждается основой имени",
			text:  "Обращение принял Ильич Кузнецов.",
			want:  []nameWant{{"Ильич Кузнецов", Strong}},
			total: 1,
		},
		{
			name: "две конструкции в одном предложении",
			text: "Иванов Иван Иванович и Петрова Анна Сергеевна.",
			want: []nameWant{
				{nameFxIvanovFull, Certain},
				{nameFxPetrovaFull, Certain},
			},
			total: 2,
		},
		{
			name:  "имя из справочника в творительном падеже",
			text:  "Согласовано с Сергеем Николаевичем Орловым.",
			want:  []nameWant{{"Сергеем Николаевичем Орловым", Certain}},
			total: 1,
		},
		{
			name:  "обычное слово с суффиксом фамилии без заглавной не ловится",
			text:  "магазин закрыт, карантин снят",
			total: 0,
		},
		{
			name:  "слово слева от пары имя-отчество достраивает фамилию",
			text:  "Клиент Задворная Людмила Платоновна",
			want:  []nameWant{{"Задворная Людмила Платоновна", Certain}},
			total: 1,
		},
		{
			name:  "фамилия-прилагательное в мужском роде слева",
			text:  "Клиент Бережной Пётр Матвеевич",
			want:  []nameWant{{"Бережной Пётр Матвеевич", Certain}},
			total: 1,
		},
		{
			name:  "фамилия-прилагательное справа от пары имя-отчество",
			text:  "Оформи доверенность на Станислава Леонидовича Бережного.",
			want:  []nameWant{{"Станислава Леонидовича Бережного", Certain}},
			total: 1,
		},
		{
			// ТЗ §3.2.1: конструкция опознаётся и строчными, на ступень ниже.
			name:  "фамилия-прилагательное строчными",
			text:  "клиент бережной кирилл родионович",
			want:  []nameWant{{"бережной кирилл родионович", Strong}},
			total: 1,
		},
		{
			// «Зорислава» намеренно нет ни в справочнике имён, ни в таблице
			// суффиксов фамилий: слово принимается по позиции — оно стоит
			// вплотную слева от опознанной пары «Отчество Фамилия».
			name:  "пара отчество-фамилия достраивает имя слева",
			text:  "Клиент Зорислава Матвеевна Гвоздарёва",
			want:  []nameWant{{"Зорислава Матвеевна Гвоздарёва", Certain}},
			total: 1,
		},
		{
			name:  "фамилия-прилагательное с инициалами",
			text:  "Заявку подписал Бережного Р. А.",
			want:  []nameWant{{"Бережного Р. А.", Strong}},
			total: 1,
		},
		{
			// Пара держится на одном опознанном слове, поэтому остаётся
			// слабой: маскировать «Красивая Марина» в отрыве от контекста
			// нельзя, а маркер слева и кластер её поднимут.
			name:  "фамилия-прилагательное с одиночным именем остаётся слабой",
			text:  "В анкете: Задворная Марина",
			want:  []nameWant{{"Задворная Марина", Weak}},
			total: 1,
		},
		{
			name:  "маркер поднимает фамилию-прилагательное с одиночным именем",
			text:  "Клиент Задворная Марина",
			want:  []nameWant{{"Задворная Марина", Strong}},
			total: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { nameCheckConstruction(t, tc) })
	}
}

// TestNameScannerDoesNotSwallowNeighbour — обратный контроль к достраиванию
// конструкции по позиции.
//
// Расширение влево и вправо принимает слово за то, что оно стоит рядом с
// опознанными частями имени. Это ровно тот приём, который легко съедает
// соседнее служебное слово, поэтому каждая строка таблицы называет спан
// целиком: важно не только что ФИО найдено, но и где именно оно кончается.
//
// Данные синтетические: ни одно значение не принадлежит живому человеку.
func TestNameScannerDoesNotSwallowNeighbour(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		// Ролевые слова слева от пары «Отчество Фамилия». Каждое отсекается
		// сразу двумя признаками: справочником маркеров и морфологией —
		// все они мужского рода, а отчество «Матвеевна» женского.
		{"заявитель", "Заявитель Матвеевна Гвоздарёва", nameFxMatveevnaGvozd},
		{"клиент", "Клиент Матвеевна Гвоздарёва", nameFxMatveevnaGvozd},
		{"сотрудник", "Сотрудник Матвеевна Гвоздарёва", nameFxMatveevnaGvozd},
		{"гражданин", "Гражданин Матвеевна Гвоздарёва", nameFxMatveevnaGvozd},
		{"господин", "Господин Матвеевна Гвоздарёва", nameFxMatveevnaGvozd},
		// «Абонента» в справочнике маркеров нет: его держит суффикс
		// существительного-деятеля.
		{"абонент", "Абонент Матвеевна Гвоздарёва", nameFxMatveevnaGvozd},
		{"абонент в родительном падеже", "Для абонента Матвеевна Гвоздарёва",
			nameFxMatveevnaGvozd},
		// Обращение с окончанием прилагательного — то самое слово, которое
		// достраивание фамилии приняло бы за фамилию.
		{"уважаемый", "Уважаемый Иван Иванович, сообщаем", nameFxIvanIvanovich},
		{"уважаемая", "Уважаемая Анна Петровна, сообщаем", nameFxAnnaPetrovna},
		{"дорогая", "Дорогая Анна Петровна, поздравляем", nameFxAnnaPetrovna},
		// Справа от пары «Имя Отчество» обычное слово тоже не принимается.
		{"глагол справа", "Иван Иванович сказал", nameFxIvanIvanovich},
		{"глагол справа в верхнем регистре", "ИВАН ИВАНОВИЧ ПРИБЫЛ", "ИВАН ИВАНОВИЧ"},
		// Короткое прилагательное под минимальную длину не подходит.
		{"короткое прилагательное", "Новая Анна Петровна", nameFxAnnaPetrovna},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, spans := nameScanText(t, tc.text)
			if len(spans) != 1 {
				t.Fatalf(msgOneSpanGot, len(spans), nameDump(doc, spans))
			}
			if got := tc.text[spans[0].Start:spans[0].End]; got != tc.want {
				t.Errorf(msgSpanWant, got, tc.want)
			}
		})
	}
}

// TestNameScannerMarkerIsNotAName фиксирует контекстное ложное срабатывание,
// найденное на живом сервисе: «Клиент гражданин Республики Казахстан» давал
// кандидата на слово «гражданин».
//
// Слово оканчивается на «-ин», как фамилия, и маркер «Клиент» слева поднимал
// его с Weak. Тот же текст без «Клиента» разбирался верно, поэтому одним
// словарём дефект не ловился — вето ставится на роль, а не на форму слова.
func TestNameScannerMarkerIsNotAName(t *testing.T) {
	tests := []string{
		"Клиент гражданин Республики Казахстан",
		"Клиент заявитель подтвердил перевод",
		"ФИО клиента уточняется",
	}
	for _, text := range tests {
		t.Run(text, func(t *testing.T) {
			doc, spans := nameScanText(t, text)
			if len(spans) != 0 {
				t.Errorf("кандидатов %d, ожидалось ноль: %s", len(spans), nameDump(doc, spans))
			}
		})
	}
}

// TestNameAdjSurnameEndingsNeverStandAlone сторожит главное ограничение
// задачи T-29.
//
// Окончания «-ный», «-ная», «-ной» как самостоятельный признак фамилии
// запрещены: после снятия требования заглавной буквы их носят тысячи обычных
// прилагательных (QUALITY.md §7.3 п. 7). Таблица nameAdjSurnameEndings
// существует отдельно и читается только из nameSurnamePos, то есть при
// разборе уже опознанной конструкции. Тест проверяет это с двух сторон: ни
// одно её окончание не попало в таблицу фамилий, и слово с таким окончанием
// само по себе кандидатом не становится.
func TestNameAdjSurnameEndingsNeverStandAlone(t *testing.T) {
	for _, a := range nameAdjSurnameEndings {
		for _, s := range nameSurnameEndings {
			if a.end == s.end {
				t.Errorf("окончание %q попало в таблицу фамилий: признак стал самостоятельным", a.end)
			}
		}
	}
	alone := []string{
		"Бережной отчёт закрыт",
		"Задворная часть склада",
		"Толстая папка на столе",
		"передан Бережному складу",
	}
	for _, text := range alone {
		doc, spans := nameScanText(t, text)
		if len(spans) != 0 {
			t.Errorf("%q: кандидатов %d, ожидалось ноль: %s", text, len(spans), nameDump(doc, spans))
		}
	}
}

// TestNameScannerReportsTraps фиксирует границу с контр-правилами.
//
// Ловушки — «поэт Пушкин», «улица Пушкина» — здесь не исключаются намеренно:
// сканер сообщает находку, вето ставит отдельное контр-правило, решение
// принимает движок. Тест страхует от соблазна отфильтровать их тут.
func TestNameScannerReportsTraps(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{"поэт Пушкин написал стихотворение", "Пушкин"},
		{"улица Пушкина, дом 5", "Пушкина"},
		{"встреча в отделении на улице Гагарина", "Гагарина"},
	}
	for _, tc := range tests {
		doc, spans := nameScanText(t, tc.text)
		s, ok := nameFind(doc, spans, tc.want)
		if !ok {
			t.Errorf("кандидат %q не зарегистрирован: %s", tc.want, nameDump(doc, spans))
			continue
		}
		if s.Conf != Weak {
			t.Errorf("кандидат %q: уверенность %v, ожидалась weak", tc.want, s.Conf)
		}
	}
}

// TestNameScannerByteOffsets проверяет, что смещения спана — байтовые.
// Кириллическая буква занимает два байта, поэтому байтовое и рунное
// смещения расходятся, и подмена одного другим видна сразу.
func TestNameScannerByteOffsets(t *testing.T) {
	const text = "Здравствуйте! Иванов Иван Иванович ожидает ответа."
	const want = nameFxIvanovFull

	doc, spans := nameScanText(t, text)
	if len(spans) != 1 {
		t.Fatalf(msgOneSpanGot, len(spans), nameDump(doc, spans))
	}
	s := spans[0]

	if got := text[s.Start:s.End]; got != want {
		t.Fatalf("вырезка по спану %q, ожидалось %q", got, want)
	}
	if want, got := strings.Index(text, want), int(s.Start); got != want {
		t.Errorf(msgSpanStartWant, got, want)
	}
	if runes := utf8.RuneCountInString(text[:s.Start]); runes == int(s.Start) {
		t.Errorf("смещение %d совпало с числом рун: похоже на рунное, а не байтовое", s.Start)
	}
}

// TestNameScannerSpanExcerpts повторяет проверку байтовых границ на всех
// конструкциях сразу: вырезка из исходного текста должна читаться как ФИО.
func TestNameScannerSpanExcerpts(t *testing.T) {
	const text = "Клиент Петрова Анна Сергеевна и Иванов И. И. подтвердили перевод."
	want := []string{nameFxPetrovaFull, "Иванов И. И."}

	doc, spans := nameScanText(t, text)
	if len(spans) != len(want) {
		t.Fatalf("спанов %d, ожидалось %d: %s", len(spans), len(want), nameDump(doc, spans))
	}
	for i, w := range want {
		if got := text[spans[i].Start:spans[i].End]; got != w {
			t.Errorf("спан %d: %q, ожидалось %q", i, got, w)
		}
	}
}

func TestNameScannerRegistered(t *testing.T) {
	for _, s := range Registered() {
		if s.Name() == "name" {
			return
		}
	}
	t.Fatal("сканер name не зарегистрирован")
}

// nameCloseFile закрывает файл справочника и сообщает об ошибке закрытия.
func nameCloseFile(t *testing.T, f *os.File) {
	t.Helper()
	if err := f.Close(); err != nil {
		t.Errorf("закрытие справочника: %v", err)
	}
}

// TestNameGivenDictionary проверяет справочник имён как данные: формат,
// метки рода, отсутствие дубликатов и объём.
func TestNameGivenDictionary(t *testing.T) {
	f, err := os.Open("dict/data/given_names.txt")
	if err != nil {
		t.Fatalf("открытие справочника: %v", err)
	}
	defer nameCloseFile(t, f)

	seen := make(map[string]string, 2048)
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		raw, label, ok := strings.Cut(text, "\t")
		if !ok {
			t.Fatalf("строка %d: нет метки рода: %q", line, text)
		}
		label = strings.TrimSpace(label)
		if label != "m" && label != "f" {
			t.Fatalf("строка %d: метка %q, ожидалась m или f", line, label)
		}
		key := dict.Normalize(strings.TrimSpace(raw))
		if _, dup := seen[key]; dup {
			t.Errorf("строка %d: дубликат записи %q", line, key)
		}
		seen[key] = label
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("чтение справочника: %v", err)
	}
	if len(seen) < 1200 {
		t.Errorf("имён в справочнике %d, требуется не менее 1200", len(seen))
	}

	table := nameDicts(t).Table("given_names")
	if table.Len() != len(seen) {
		t.Errorf("в таблице %d записей, в файле %d", table.Len(), len(seen))
	}
}

// TestNameLookupGiven проверяет разбор падежных форм имени: справочник хранит
// только именительный падеж, остальное восстанавливается правилом.
func TestNameLookupGiven(t *testing.T) {
	table := nameDicts(t).Table("given_names")
	tests := []struct {
		word string
		want bool
	}{
		{"иван", true},
		{"ивана", true},
		{"ивану", true},
		{"иваном", true},
		{"иване", true},
		{"анна", true},
		{"анны", true},
		{"анне", true},
		{"анну", true},
		{"анной", true},
		{"мария", true},
		{"марии", true},
		{"марией", true},
		{"сергей", true},
		{"сергея", true},
		{"сергеем", true},
		{"игорь", true},
		{"игоря", true},
		{"игорем", true},
		{"павел", true},
		{"павла", true},
		{"павлом", true},
		{"лев", true},
		{"льва", true},
		{"льву", true},
		{"львом", true},
		{"льве", true},
		{"львы", false},
		{"любовь", true},
		{"любови", true},
		{"тимур", true},
		{"артур", true},
		{"карина", true},
		{"амина", true},
		{"давид", true},
		{"стол", false},
		{"банк", false},
		{nameFxIvanovLower, false},
		{"договор", false},
		{"платеж", false},
	}
	for _, tc := range tests {
		if _, got := nameLookupGiven(table, tc.word); got != tc.want {
			t.Errorf("nameLookupGiven(%q) = %v, ожидалось %v", tc.word, got, tc.want)
		}
	}
}

// TestNameMarkersDictionary проверяет, что маркеры загружаются и покрывают
// падежные формы: сканер морфологию маркеров не разбирает.
func TestNameMarkersDictionary(t *testing.T) {
	table := nameDicts(t).Table("name_markers")
	for _, w := range []string{
		"клиент", "клиента", "фио", "заявитель", "имя", "плательщик",
		"получатель", "гражданин", "господин", "сотрудник", "владелец",
		"держатель",
	} {
		if !table.Has(w) {
			t.Errorf("маркер %q отсутствует в справочнике", w)
		}
	}
	if table.Has(nameFxIvanovLower) {
		t.Error("фамилия не должна быть маркером")
	}
}

// nameFind ищет спан по его тексту в исходном документе.
func nameFind(doc *lex.Doc, spans []Span, text string) (Span, bool) {
	for _, s := range spans {
		if doc.Text[s.Start:s.End] == text {
			return s, true
		}
	}
	return Span{}, false
}

// nameDump печатает найденные спаны для сообщения об ошибке.
func nameDump(doc *lex.Doc, spans []Span) string {
	var b strings.Builder
	b.WriteString("найдено: ")
	for i, s := range spans {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("[")
		b.WriteString(doc.Text[s.Start:s.End])
		b.WriteString("/")
		b.WriteString(s.Conf.String())
		b.WriteString("/")
		b.WriteString(s.Rule)
		b.WriteString("]")
	}
	return b.String()
}

// nameBenchBlock — синтетический фрагмент делового текста. Реальных
// персональных данных в репозитории нет: все ФИО вымышлены.
const nameBenchBlock = `Клиент Иванов Иван Иванович обратился за выпиской по счёту.
Заявление принял сотрудник Петрова Анна Сергеевна, копия передана в архив.
Справку для Иванова Ивана Ивановича подготовить до конца рабочего дня.
Согласовано: Достоевский Фёдор Михайлович, руководитель отделения.
Доверенность оформлена на Сергея Николаевича Орлова сроком на один год.
Реквизиты уточнил Петренко Олег Петрович, подпись получена.
Ответ направлен по адресу, указанному в заявлении, сопроводительное письмо
подписал Смирнов И. И., второй экземпляр остался у получателя.
Передайте документы Ивановой Анне до пятницы, вопрос на контроле.
`

// nameBenchText собирает текст примерно на четыре килобайта.
func nameBenchText() string {
	var b strings.Builder
	for b.Len() < 4096 {
		b.WriteString(nameBenchBlock)
	}
	return b.String()
}

// Ноль аллокаций в Scan — инвариант всех сканеров (AGENTS.md §8), но у
// сканера имён он единственный не был закреплён тестом: о нём говорил только
// ReportAllocs в бенчмарке, а бенчмарк в наборе проверок не участвует.
//
// Место хрупкое: поиск по справочнику идёт через t.Get(string(buf[:n])), и
// конверсия байтов в строку не уезжает в кучу лишь потому, что Get не
// выпускает аргумент наружу. Стоит этому измениться — аллокация вернётся
// молча.
func TestNameScanAllocations(t *testing.T) {
	dicts := nameDicts(t)
	doc := lex.Tokenize(nameBenchText(), nil)
	var out Candidates
	var s nameScanner
	s.Scan(doc, dicts, &out) // прогрев: накопитель набирает ёмкость до замера

	got := testing.AllocsPerRun(20, func() {
		out.Reset()
		s.Scan(doc, dicts, &out)
	})
	if got != 0 {
		t.Errorf("аллокаций на проход: %.0f, требуется 0", got)
	}
}

func BenchmarkScanName(b *testing.B) {
	dicts := nameDicts(b)
	text := nameBenchText()
	doc := lex.Tokenize(text, nil)

	var out Candidates
	var s nameScanner
	// Прогрев: накопитель набирает ёмкость до замера, иначе первый прогон
	// покажет рост слайса, а не работу сканера.
	s.Scan(doc, dicts, &out)
	if len(out.Spans) == 0 {
		b.Fatal("сканер ничего не нашёл на тестовом тексте")
	}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Reset()
		s.Scan(doc, dicts, &out)
	}
}

// TestNameSuffixTailsCoverEndings сторожит отсев по последней букве.
//
// Отсев стоит перед перебором таблиц суффиксов и снимает большинство слов, не
// доходя до сравнения строк. Забытая в наборе буква не сломала бы ни один
// тест на конструкциях, но молча выключила бы целую группу фамилий или
// отчеств, и увидеть это можно было бы только по полноте на корпусе.
func TestNameSuffixTailsCoverEndings(t *testing.T) {
	for _, s := range nameSurnameEndings {
		if r := nameLastRune(s.end); !nameSurnameTail(r) {
			t.Errorf("суффикс фамилии %q отсеивается по последней букве %q", s.end, r)
		}
	}
	for _, s := range namePatronymicEndings {
		if r := nameLastRune(s.end); !namePatronymicTail(r) {
			t.Errorf("суффикс отчества %q отсеивается по последней букве %q", s.end, r)
		}
	}
	for _, s := range nameShortPatronymicEndings {
		if r := nameLastRune(s.end); !namePatronymicTail(r) {
			t.Errorf("короткий суффикс отчества %q отсеивается по последней букве %q", s.end, r)
		}
	}
}

// TestNameScannerDecomposedLetterInsideGivenName проверяет, что имя с
// разложенной «й» (и + U+0306, артефакт NFD) сверяется со справочником по
// очищенной форме слова: прямой срез Norm содержал невидимую часть префиксом,
// и «Андрей» в справочнике не находилось — имя уходило открытым (T-46).
func TestNameScannerDecomposedLetterInsideGivenName(t *testing.T) {
	text := "Клиент Андрей Петров"
	_, spans := nameScanText(t, text)
	want := "Андрей Петров"
	for _, s := range spans {
		if s.Type == pii.FullName && text[s.Start:s.End] == want {
			return
		}
	}
	t.Fatalf("ожидался спан ФИО %q, найдено %v", want, spans)
}

// nameBareSurnames — фамилии без русского суффикса: одиннадцать из отчёта
// бизнес-жюри 23.09 и пять того же вида. Ни одну не знает ни таблица
// суффиксов, ни окончания прилагательных; сочетания с именами синтетические.
var nameBareSurnames = []string{
	nameFxMelnik, nameFxKoval, "Бондарь", "Кравец", "Гончар", "Цой", "Шульц", "Мороз",
	"Сорока", "Жук", "Лебедь", "Ткач", "Кушнир", "Пастернак", "Гоголь", "Шмидт",
}

// TestNameBareSurnameOrders — T-50: фамилия без суффикса рядом с опознанным
// именем входит в спан ФИО целиком во всех трёх порядках записи.
//
// Пара «Имя Отчество» самодостаточна, и слово рядом с ней держится на
// позиции — уровень как у конструкции ФИО. Одиночное имя держит конструкцию
// одно, поэтому пара с ним поднимается до Strong только маркером слева.
func TestNameBareSurnameOrders(t *testing.T) {
	for _, w := range nameBareSurnameOrderCases() {
		text := "Клиент " + w.text + ", телефон уточняется."
		t.Run(w.text, func(t *testing.T) { nameExpectOne(t, text, w) })
	}
}

// nameBareSurnameOrderCases собирает для каждой фамилии без суффикса и
// каждого имени с отчеством все четыре порядка записи с ожидаемым уровнем.
func nameBareSurnameOrderCases() []nameWant {
	people := []struct{ given, patronymic string }{
		{"Олег", "Петрович"},
		{"Анна", "Сергеевна"},
	}
	var out []nameWant
	for _, sur := range nameBareSurnames {
		for _, p := range people {
			out = append(out,
				nameWant{p.given + " " + p.patronymic + " " + sur, Certain},
				nameWant{sur + " " + p.given + " " + p.patronymic, Certain},
				nameWant{sur + " " + p.given, Strong},
				nameWant{p.given + " " + sur, Strong},
			)
		}
	}
	return out
}

// TestNameBareSurnameWithoutMarker — пара «Фамилия Имя» и «Имя Фамилия» с
// заглавной буквы в именительном падеже без маркера — ФИО уровня Strong
// (T-66, раунд 4 жюри, Б4-1).
//
// До T-66 пара держалась на одном опознанном слове и оставалась Weak, пока
// её не поднимут маркер или кластер, — и «Коваль Инна обратилась в
// отделение» уходила в модель открытой, хотя «Петрова Анна» с суффиксом
// маскировалась без всякого маркера. Заглавная буква вплотную к имени — тот
// же довод, что суффикс.
func TestNameBareSurnameWithoutMarker(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"Вчера на прогулке Мельник Олег, погода хорошая", "Мельник Олег"},
		{"Вчера на прогулке Олег Мельник, погода хорошая", "Олег Мельник"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			nameExpectOne(t, tc.text, nameWant{tc.want, Strong})
		})
	}
}

// TestNameBareSurnameForms — падежи, регистр и начало предложения.
//
// Без свидетельства регистра — строчная запись, капс, начало предложения —
// слово принимается, но уровень конструкции не поднимается выше уровня самой
// пары: оно едет вместе с парой и решения о маскировании не меняет.
func TestNameBareSurnameForms(t *testing.T) {
	tests := []struct {
		name string
		text string
		want nameWant
	}{
		{"родительный слева", "Оформи доверенность на Мельника Олега Петровича.",
			nameWant{"Мельника Олега Петровича", Certain}},
		{"дательный справа", "Передайте Олегу Петровичу Ковалю документы.",
			nameWant{"Олегу Петровичу Ковалю", Certain}},
		{"женская фамилия не склоняется", "Справка для Анны Сергеевны Мельник готова.",
			nameWant{"Анны Сергеевны Мельник", Certain}},
		{"начало текста", "Мельник Олег Петрович обратился в банк.",
			nameWant{"Мельник Олег Петрович", Strong}},
		{"после точки", "Заявка принята. Цой Виктор Робертович ждёт ответа.",
			nameWant{"Цой Виктор Робертович", Strong}},
		{"капс", "КЛИЕНТ ОЛЕГ ПЕТРОВИЧ МЕЛЬНИК", nameWant{"ОЛЕГ ПЕТРОВИЧ МЕЛЬНИК", Strong}},
		{"строчные с маркером", "клиент мельник олег петрович",
			nameWant{"мельник олег петрович", Strong}},
		{"строчные справа с маркером", "клиент олег петрович мельник",
			nameWant{"олег петрович мельник", Strong}},
		// Строчные без маркера — на уровне строчной пары, решает кластер.
		{"строчные в родительном", "справка мельника олега петровича лежит в папке",
			nameWant{"мельника олега петровича", Weak}},
		// Предлог лица «для» поднимает строчную пару (T-60).
		{"строчные в родительном после «для»", "справка для мельника олега петровича",
			nameWant{"мельника олега петровича", Strong}},
		{"фамилия-прилагательное справа от имени", "Клиент Лев Толстой",
			nameWant{"Лев Толстой", Strong}},
		{"прилагательное на -кий справа от имени", "Клиент Максим Горький",
			nameWant{"Максим Горький", Strong}},
		{"двухбуквенная фамилия", "Клиент Анна Сергеевна Ли, телефон уточняется.",
			nameWant{"Анна Сергеевна Ли", Certain}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { nameExpectOne(t, tc.text, tc.want) })
	}
}

// TestNameBareSurnameDoesNotSwallowNeighbour — обратный контроль к T-50.
//
// Фамилию без суффикса не отличить от соседнего слова ни морфологией, ни
// справочником: у правила нет положительных признаков, одни отсевы. Каждая
// строка называет спан целиком — важно, где именно ФИО кончается.
func TestNameBareSurnameDoesNotSwallowNeighbour(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		// Справа: глагол строчной отсеивает сравнение регистра; в капсе и
		// строчной записи — окончания глагола и наречия.
		{"глагол справа", "Иван Петрович сказал", "Иван Петрович"},
		{"глагол в капсе", "ОЛЕГ ПЕТРОВИЧ ПЕРЕЗВОНИТ", "ОЛЕГ ПЕТРОВИЧ"},
		{"глагол строчными", "олег петрович сказал", nameFxOlegPetrovichLow},
		{"будущее время строчными", "олег петрович перезвонит", nameFxOlegPetrovichLow},
		{"наречие строчными", "олег петрович лично", nameFxOlegPetrovichLow},
		{"предлог строчными", "олег петрович из офиса", nameFxOlegPetrovichLow},
		// Топонимы и месяцы.
		{"город справа", "Иван Петрович Москва", "Иван Петрович"},
		{"город справа в капсе", "ОЛЕГ ПЕТРОВИЧ МОСКВА", "ОЛЕГ ПЕТРОВИЧ"},
		{"месяц справа в капсе", "ОТ ОЛЕГА ПЕТРОВИЧА ИЮНЯ", "ОЛЕГА ПЕТРОВИЧА"},
		{"топоним после предлога слева", "в Твери Олег Петрович родился", nameFxOlegPetrovich},
		{"город в начале предложения", "Москва Олег Петрович", nameFxOlegPetrovich},
		// Начало предложения: заглавная буква ничего не говорит.
		{"наречие в начале", "Сегодня Олег Петрович пришёл", nameFxOlegPetrovich},
		{"наречие в начале, женский род", "Вчера Анна Сергеевна звонила", "Анна Сергеевна"},
		{"повелительное -и", "Найди Олега Петровича", "Олега Петровича"},
		{"повелительное -ь", "Проверь Анну Петровну", "Анну Петровну"},
		{"повелительное -й", "Передай Анне Петровне", "Анне Петровне"},
		{"повелительное -те", "Позвоните Олегу Петровичу", "Олегу Петровичу"},
		{"повелительное строчными", "найди олега петровича", "олега петровича"},
		{"должность в начале", "Директор Олег Петрович сообщил", nameFxOlegPetrovich},
		{"обиходное слово при маркере", "клиент банка олег петрович", nameFxOlegPetrovichLow},
		// Прилагательное короче предела nameSurnamePos не проходит и сюда.
		{"короткое прилагательное", "Клиент Новая Анна Петровна", nameFxAnnaPetrovna},
		// Перевод строки — граница поля формы.
		{"следующее поле формы", "ФИО: Олег Петрович\nТелефон: уточняется", nameFxOlegPetrovich},
		// Одиночное имя без свидетельства регистра не достраивается.
		{"одиночное имя в начале", "Сегодня Олег пришёл", "Олег"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, spans := nameScanText(t, tc.text)
			if len(spans) != 1 {
				t.Fatalf(msgOneSpanGot, len(spans), nameDump(doc, spans))
			}
			if got := tc.text[spans[0].Start:spans[0].End]; got != tc.want {
				t.Errorf("спан %q, ожидался %q (%s)", got, tc.want, spans[0].Rule)
			}
		})
	}
}

// TestNameBareSurnameStartsNextPerson — слово перед отчеством начинает
// следующую конструкцию и в текущую не входит.
func TestNameBareSurnameStartsNextPerson(t *testing.T) {
	const text = "Олег Петрович Зорислава Матвеевна"
	doc, spans := nameScanText(t, text)
	if len(spans) == 0 || text[spans[0].Start:spans[0].End] != nameFxOlegPetrovich {
		t.Fatalf("первый спан должен кончаться на отчестве: %s", nameDump(doc, spans))
	}
}

// TestNameBareSurnameKeepsPairLevel сторожит главное свойство правила:
// фамилия без суффикса расширяет спан, но не меняет решения о маскировании.
//
// Пара, которая без соседнего слова не маскировалась бы (уровень ниже
// Strong), не должна маскироваться и с ним, и наоборот. Иначе любое слово
// рядом с именем становилось бы поводом замаскировать то, что без него
// оставалось открытым.
//
// Исключение с T-66 — одиночное имя с заглавной и фамилия с заглавной
// вплотную («Олег Мельник»): заглавная буква — свидетельство, и такая пара
// маскируется, как «Олег Петров» с суффиксом (TestNameBareSurnameWithoutMarker).
// Без свидетельства регистра — строчные и капс — свойство прежнее.
func TestNameBareSurnameKeepsPairLevel(t *testing.T) {
	pairs := []string{
		"Клиент Олег Петрович", nameFxOlegPetrovich, "Клиент Олег",
		"клиент олег петрович", nameFxOlegPetrovichLow, "КЛИЕНТ ОЛЕГ ПЕТРОВИЧ", "олег", "ОЛЕГ",
	}
	for _, pair := range pairs {
		for _, sur := range []string{nameFxMelnik, "Цой"} {
			switch {
			case strings.ToLower(pair) == pair:
				sur = strings.ToLower(sur)
			case strings.ToUpper(pair) == pair:
				sur = strings.ToUpper(sur)
			}
			text := pair + " " + sur
			_, alone := nameScanText(t, pair)
			_, joined := nameScanText(t, text)
			if len(alone) > 1 || len(joined) > 1 {
				t.Fatalf("%q: спанов %d и %d, ожидалось не больше одного", text, len(alone), len(joined))
			}
			// Одиночное строчное слово кандидатом не становится вовсе.
			strongAlone := len(alone) == 1 && alone[0].Conf >= Strong
			strongJoined := len(joined) == 1 && joined[0].Conf >= Strong
			if strongAlone != strongJoined {
				doc := lex.Tokenize(text, nil)
				t.Errorf("%q: решение о маскировании изменилось: %s", text, nameDump(doc, joined))
			}
		}
	}
}

// TestNameLowerPairWithMarker — строчная пара «фамилия имя» / «имя фамилия»
// / «имя отчество» после маркера лица получает уровень заглавной записи.
// Дополнение технического жюри к T-50: «Клиент иванов иван» не маскировался.
func TestNameLowerPairWithMarker(t *testing.T) {
	tests := []struct {
		text string
		want nameWant
	}{
		{"Клиент иванов иван", nameWant{nameFxIvanovIvanLower, Strong}},
		{"клиент иван иванов", nameWant{"иван иванов", Strong}},
		{"заявитель петрова анна", nameWant{"петрова анна", Strong}},
		{"клиент иван иванович", nameWant{"иван иванович", Strong}},
		// Маркер в окне из трёх слов: «банка» в спан не входит.
		{"клиент банка иван петров", nameWant{"иван петров", Strong}},
		// Без маркера и без слова лица рядом строчная пара остаётся на
		// ступень ниже; сказуемое лица поднимает её (TestNameLowerPairIntro).
		{"иванов иван, перевод подтверждён", nameWant{nameFxIvanovIvanLower, Weak}},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) { nameExpectOne(t, tc.text, tc.want) })
	}
}

// TestNameLowerPairWithMarkerNoFalsePositive — маркер поднимает только пару
// из двух опознанных слов: одиночное строчное имя рядом с обычным словом так
// и остаётся Weak.
func TestNameLowerPairWithMarkerNoFalsePositive(t *testing.T) {
	for _, text := range []string{
		"клиент иван сказал",
		"клиент банка иван сказал",
		"клиент банка иван",
		"клиент готов ждать ответа",
	} {
		t.Run(text, func(t *testing.T) { nameExpectNotStrong(t, text) })
	}
}

// nameExpectNotStrong проверяет, что ни один кандидат ФИО в тексте не
// достиг уровня Strong.
func nameExpectNotStrong(t *testing.T, text string) {
	t.Helper()
	doc, spans := nameScanText(t, text)
	for _, s := range spans {
		if s.Conf >= Strong {
			t.Errorf(msgCandidateLevel, text[s.Start:s.End], s.Conf, nameDump(doc, spans))
		}
	}
}

// TestNameBareSurnameInitials — фамилия без суффикса с двумя инициалами
// (стиль «Фамилия И. О.» корпуса): 18 из 25 утечек ФИО на новом корпусе
// T-50 были этой формы.
func TestNameBareSurnameInitials(t *testing.T) {
	found := []struct {
		text string
		want nameWant
	}{
		{"Подготовь ответ: заявитель Коваль К. Г., гражданство РФ.", nameWant{"Коваль К. Г.", Strong}},
		{"Найди клиента Кравца Т. Е., паспорт уточняется.", nameWant{"Кравца Т. Е.", Strong}},
		{"Клиент Цой У. Г. просит открытку.", nameWant{"Цой У. Г.", Strong}},
		{"К. Г. Коваль подписал заявку.", nameWant{"К. Г. Коваль", Strong}},
		// В начале предложения — слабый, решают маркер и кластер. Банковское
		// слово в том же предложении поднимает до Strong: после того как
		// точка инициала перестала рвать предложение, «заявку» стало видно.
		{"Шульц Т. М. вчера пришёл.", nameWant{nameFxShultsInitials, Weak}},
		// Сказуемое лица вплотную поднимает до Strong (T-60).
		{"Шульц Т. М. пришёл вчера.", nameWant{nameFxShultsInitials, Strong}},
		{"Шульц Т. М. подписал заявку.", nameWant{nameFxShultsInitials, Strong}},
		// Подпись в конце письма или строки — Strong без маркера.
		{"Прошу закрыть счёт. Мельник О. П.", nameWant{"Мельник О. П.", Strong}},
		{"Прошу закрыть счёт.\nМельник О.П.\nСпасибо", nameWant{"Мельник О.П.", Strong}},
		// Один инициал при маркере — ФИО (T-66, раунд 4 жюри, Б4-5). До T-66
		// эта строка стояла в обратном контроле: один инициал без опоры
		// носят и обозначения — «Корпус Б.», — но маркер лица слева и
		// заглавная буква в середине предложения такую опору дают.
		{"Клиент Коваль К. уточняет детали.", nameWant{"Коваль К.", Strong}},
	}
	for _, tc := range found {
		t.Run(tc.text, func(t *testing.T) {
			doc, spans := nameScanText(t, tc.text)
			s, ok := nameFind(doc, spans, tc.want.text)
			if !ok {
				t.Fatalf(msgSpanNotFound, tc.want.text, nameDump(doc, spans))
			}
			if s.Conf != tc.want.conf {
				t.Errorf(msgConfWantRule, s.Conf, tc.want.conf, s.Rule)
			}
		})
	}

	// Обратный контроль: слово перед инициалами, которые относятся к
	// фамилии справа; один инициал; строчные «т. е.».
	notFound := []struct{ text, bad string }{
		{"Автор А. С. Пушкин написал письмо.", "Автор А. С."},
		{"Корпус Б. закрыт на ремонт.", "Корпус Б."},
		{"документы т. е. копии паспорта", "документы т. е."},
	}
	for _, tc := range notFound {
		t.Run(tc.text, func(t *testing.T) {
			doc, spans := nameScanText(t, tc.text)
			if _, ok := nameFind(doc, spans, tc.bad); ok {
				t.Errorf("лишний спан %q: %s", tc.bad, nameDump(doc, spans))
			}
		})
	}
}

// --- T-60: раунд 3 технического жюри ----------------------------------------
//
// Данные синтетические: ни одно ФИО не принадлежит живому человеку.

// nameExpectOne проверяет, что в тексте найден ровно один кандидат ФИО с
// заданным текстом и уровнем.
func nameExpectOne(t *testing.T, text string, want nameWant) {
	t.Helper()
	doc, spans := nameScanText(t, text)
	if len(spans) != 1 {
		t.Fatalf(msgOneSpanGot, len(spans), nameDump(doc, spans))
	}
	if got := text[spans[0].Start:spans[0].End]; got != want.text {
		t.Fatalf("спан %q, ожидался %q (%s)", got, want.text, nameDump(doc, spans))
	}
	if spans[0].Conf != want.conf {
		t.Errorf(msgConfWantRule, spans[0].Conf, want.conf, spans[0].Rule)
	}
}

// TestNameLowerPairIntro — строчная пара «фамилия имя» / «имя фамилия» после
// слова, вводящего лицо, или перед сказуемым лица поднимается до Strong.
// Входы — пробы жюри (casecases.py: 13 из 20 строчных вариантов открыты).
func TestNameLowerPairIntro(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{"Звонила петрова анна, просила перезвонить.", "петрова анна"},
		{"Звонил иван петров по поводу кредита.", "иван петров"},
		{"Передайте смирновой ольге, что карта готова.", "смирновой ольге"},
		{"Позвоните анне смирновой после обеда.", "анне смирновой"},
		{"Позвоните, пожалуйста, анне смирновой.", "анне смирновой"},
		{"От бондаренко ирины поступил перевод.", "бондаренко ирины"},
		{"Уведомить иванову марию о задолженности.", "иванову марию"},
		{"Перевод для иванова ивана.", "иванова ивана"},
		{"Карту получит иванова виктория.", "иванова виктория"},
		{"анна смирнова просит выписку.", "анна смирнова"},
		{"иванов иван подтвердил перевод", nameFxIvanovIvanLower},
		{"звонил ким олег по поводу кредита", "ким олег"},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			nameExpectOne(t, tc.text, nameWant{tc.want, Strong})
		})
	}
}

// TestNameLowerPairIntroNoFalsePositive — обратный контроль: слово-ввод
// поднимает только пару из двух опознанных частей имени; одиночное строчное
// имя, пара без ввода и обычные слова рядом с вводом не становятся Strong.
func TestNameLowerPairIntroNoFalsePositive(t *testing.T) {
	for _, text := range []string{
		"клиент иван сказал",
		"клиент иван доволен обслуживанием",
		"звонила анна, просила перезвонить",
		"передайте документы в отдел кадров",
		"Позвоните утром анне, она ждёт.",
		"Передайте нашей анне документы.",
		"Передайте слова благодарности коллегам.",
		"Для веры, надежды и любви.",
		"иванов иван, перевод подтверждён",
		"Клиентка красивая марина пришла в отделение.",
		"работаем для славы других",
	} {
		t.Run(text, func(t *testing.T) { nameExpectNotStrong(t, text) })
	}
}

// TestNameBareSurnameIntro — фамилия без суффикса рядом с именем: «Ким» из
// справочника имён перед другим именем, слово-ввод, согласование в падеже,
// опора вплотную при строчной записи и капсе.
func TestNameBareSurnameIntro(t *testing.T) {
	tests := []struct {
		text string
		want nameWant
	}{
		{"Звонил Ким Олег по поводу кредита.", nameWant{nameFxKimOleg, Strong}},
		{"Ким Олег просит перезвонить.", nameWant{nameFxKimOleg, Strong}},
		{"Клиент Ким Олег просит перезвонить.", nameWant{nameFxKimOleg, Strong}},
		{"ФИО: Ким Олег", nameWant{nameFxKimOleg, Strong}},
		{"Звонил Ким Олег Сергеевич по поводу кредита.", nameWant{"Ким Олег Сергеевич", Certain}},
		{"Карту получит Цой Виктория", nameWant{"Цой Виктория", Strong}},
		{"Карту получит Виктория Цой", nameWant{"Виктория Цой", Strong}},
		{"Передайте Мельнику Олегу", nameWant{"Мельнику Олегу", Strong}},
		{"Справка для Мельника Олега", nameWant{"Мельника Олега", Strong}},
		{"Справка для Олега Мельника", nameWant{"Олега Мельника", Strong}},
		// Согласование в косвенном падеже без слова-ввода.
		{"Напомним Мельнику Олегу о платеже.", nameWant{"Мельнику Олегу", Strong}},
		{"Документы подписаны Олегом Мельником вчера.", nameWant{"Олегом Мельником", Strong}},
		// Строчные и капс: опора вплотную слева.
		{"звонил цой артём, просил перезвонить", nameWant{"цой артём", Strong}},
		{"ЗВОНИЛ ЦОЙ АРТЁМ, ПРОСИЛ ПЕРЕЗВОНИТЬ.", nameWant{"ЦОЙ АРТЁМ", Strong}},
		{"Клиентка гусь анна жалуется на списание.", nameWant{"гусь анна", Strong}},
		{"КЛИЕНТКА ГУСЬ АННА ЖАЛУЕТСЯ НА СПИСАНИЕ.", nameWant{"ГУСЬ АННА", Strong}},
		{"звонила мельник марина олеговна", nameWant{"мельник марина олеговна", Strong}},
		// Справа от имени — рамка «опора — пара — сказуемое».
		{"клиент олег мельник просит кредит", nameWant{"олег мельник", Strong}},
		{"клиент олег толстой просит кредит", nameWant{"олег толстой", Strong}},
		// Одиночная фамилия между маркером и сказуемым.
		{"Клиент Мельник просит перезвонить.", nameWant{nameFxMelnik, Strong}},
		// Подпись фамилией-именем с инициалами.
		{"Прошу закрыть счёт. Ким О.П.", nameWant{"Ким О.П.", Strong}},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			nameExpectOne(t, tc.text, tc.want)
		})
	}
}

// TestNameBareSurnameIntroNoFalsePositive — обратный контроль к
// TestNameBareSurnameIntro.
func TestNameBareSurnameIntroNoFalsePositive(t *testing.T) {
	notStrong := []string{
		// Одиночное имя после слова-ввода остаётся на уровне имени.
		"Передайте Олегу документы.",
		// Название банка на месте фамилии.
		"Перевод от Сбербанка Олегу не пришёл.",
		"Клиент Сбербанка просит перевести деньги.",
		// Справа от имени без сказуемого и в строчной записи — не фамилия:
		// краткое прилагательное — сказуемое. «клиент олег мельник» с
		// границей группы справа — ФИО (T-80, TestNameLowerSubject).
		"клиент олег доволен",
		"клиент олег доволен результатом",
	}
	for _, text := range notStrong {
		t.Run(text, func(t *testing.T) { nameExpectNotStrong(t, text) })
	}
	// Слово рядом с именем в спан не входит.
	for _, tc := range []struct{ text, want string }{
		{"Позвоните сегодня Анне Смирновой.", "Анне Смирновой"},
		{"звонил вчера олег петрович", nameFxOlegPetrovichLow},
		{"клиентка наша анна петрова", "анна петрова"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			doc, spans := nameScanText(t, tc.text)
			if len(spans) != 1 || tc.text[spans[0].Start:spans[0].End] != tc.want {
				t.Errorf("ожидался один спан %q: %s", tc.want, nameDump(doc, spans))
			}
		})
	}
}

// TestNameSurnameRepeat — фамилия из опознанного ФИО, повторённая отдельно в
// той же или другой форме, — тот же человек. Входы — пробы жюри N6.
func TestNameSurnameRepeat(t *testing.T) {
	tests := []struct {
		text   string
		repeat string
	}{
		{"Клиент Шевчук Андрей Петрович, паспорт 4509 123456. Шевчук просит перезвонить.", nameFxShevchuk},
		{"Клиент Иванов Иван Иванович, телефон +7 916 123-45-67. Иванов просил перезвонить.", nameFxIvanov},
		{"Клиент Мельник Марина Олеговна, телефон +7 916 555-44-33. Мельник подтвердила перевод.", nameFxMelnik},
		{"Клиент Шевчук Андрей Петрович просит закрыть счёт. Передайте Шевчуку, что счёт закрыт.", "Шевчуку"},
		{"Клиентка Иванова Анна Сергеевна просит выписку. Ивановой отправлено письмо.", "Ивановой"},
		{"Клиент Коваль Олег Петрович. Заявление Коваля принято.", "Коваля"},
		{"Звонил Цой Виктор Робертович. Цою перезвонят завтра.", "Цою"},
		{"клиент иванов иван иванович просит выписку. иванов ждёт ответа.", nameFxIvanovLower},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) { nameCheckRepeat(t, tc.text, tc.repeat) })
	}
}

// nameCheckRepeat проверяет, что последнее вхождение repeat в тексте накрыто
// спаном ровно по своим границам и уровнем не ниже Strong.
func nameCheckRepeat(t *testing.T, text, repeat string) {
	t.Helper()
	doc, spans := nameScanText(t, text)
	at := strings.LastIndex(text, repeat)
	var found bool
	for _, s := range spans {
		if int(s.Start) != at || int(s.End) != at+len(repeat) {
			continue
		}
		found = true
		if s.Conf < Strong {
			t.Errorf("повтор %q уровня %v (%s)", repeat, s.Conf, s.Rule)
		}
	}
	if !found {
		t.Errorf("повтор %q не найден: %s", repeat, nameDump(doc, spans))
	}
}

// TestNameSurnameRepeatNoFalsePositive — повтор узнаётся только после
// полного ФИО, только по основе целиком и не разрезает следующее ФИО той же
// фамилии на два спана.
func TestNameSurnameRepeatNoFalsePositive(t *testing.T) {
	notStrong := []struct{ text, word string }{
		// Строчное нарицательное совпадает с фамилией клиента.
		{"Клиент Мороз Олег Петрович просит кредит. На улице сильный мороз.", "мороз"},
		// Повтор до полного ФИО однопроходный разбор не видит. «Шевчук
		// просит…» перед сказуемым — фамилия и без повтора (T-83, P5-6),
		// поэтому первое упоминание стоит вне позиции лица.
		{"Документы для Шевчук готовы. Клиент Шевчук Андрей Петрович.", nameFxShevchuk},
		// Другая основа.
		{"Клиент Ким Олег Сергеевич. Кимберли не звонила.", "Кимберли"},
		// Имя, а не фамилия: одиночное «Марина» после маркера не запоминается.
		{"Клиент Марина. Марина перезвонит.", "Марина перезвонит"},
	}
	for _, tc := range notStrong {
		t.Run(tc.text, func(t *testing.T) { nameCheckWordNotStrong(t, tc.text, tc.word) })
	}
	// Повтор фамилии в начале следующего ФИО: один спан на ФИО целиком.
	for _, tc := range []struct{ text, want string }{
		{"Клиент Мельник Олег Петрович. Позже Мельник Полина Романовна подписала заявку.",
			"Мельник Полина Романовна"},
		{"Клиент Гончар Олег Петрович. Позже звонила Гончар Марина.", "Гончар Марина"},
		{"Клиент Лебедь Олег Петрович. Оформи доверенность на Лебедь Людмилу Глебовну.",
			"Лебедь Людмилу Глебовну"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameCheckFoundStrong(t, tc.text, tc.want) })
	}
}

// nameCheckWordNotStrong проверяет, что первое вхождение word в тексте не
// лежит под кандидатом уровня Strong и выше.
func nameCheckWordNotStrong(t *testing.T, text, word string) {
	t.Helper()
	doc, spans := nameScanText(t, text)
	at := strings.Index(text, word)
	for _, s := range spans {
		if int(s.Start) <= at && at < int(s.End) && s.Conf >= Strong {
			t.Errorf("слово %q под кандидатом уровня %v: %s", word, s.Conf, nameDump(doc, spans))
		}
	}
}

// nameCheckFoundStrong проверяет, что спан want найден и его уровень не ниже
// Strong.
func nameCheckFoundStrong(t *testing.T, text, want string) {
	t.Helper()
	doc, spans := nameScanText(t, text)
	s, ok := nameFind(doc, spans, want)
	if !ok {
		t.Fatalf(msgSpanNotFound, want, nameDump(doc, spans))
	}
	if s.Conf < Strong {
		t.Errorf("спан %q уровня %v (%s)", want, s.Conf, s.Rule)
	}
}

// TestNameSurnameRepeatCounterRules — повтор фамилии не обходит контр-правила:
// рядом с клиентом Пушкиным «поэт Пушкин» и «ул. Пушкина» не маскируются.
func TestNameSurnameRepeatCounterRules(t *testing.T) {
	e := newFullEngine(t)
	text := "Клиент Пушкин Иван Петрович, паспорт 4509 123456. " +
		"Поэт Пушкин родился в Москве. Офис на ул. Пушкина. Пушкин просит перезвонить."
	spans := detectSpans(t, e, text, Options{})
	names := 0
	for _, s := range spans {
		if s.Type != pii.FullName {
			continue
		}
		names++
		got := text[s.Start:s.End]
		if s.Start > int32(strings.Index(text, "Поэт")) && s.End < int32(strings.LastIndex(text, "Пушкин просит")) {
			t.Errorf("под маской ловушка %q (%s)", got, s.Rule)
		}
	}
	if names != 2 {
		t.Errorf("ФИО замаскировано %d раз, ожидалось 2 (клиент и повтор): %v", names, spans)
	}
}

// TestNameCapsSurnameLowerRest — «ПЕТРОВА анна сергеевна»: фамилия капсом,
// имя и отчество строчными — одно ФИО, один спан (дополнение оркестратора к
// T-60: раньше два плейсхолдера говорили модели о двух людях).
func TestNameCapsSurnameLowerRest(t *testing.T) {
	nameExpectOne(t, "ПЕТРОВА анна сергеевна, дата рождения 12.31.1985",
		nameWant{"ПЕТРОВА анна сергеевна", Certain})
	nameExpectOne(t, "ПЕТРОВА анна, дата рождения 12.31.1985",
		nameWant{"ПЕТРОВА анна", Strong})
	// Капс-заголовок над строчным текстом без имени не склеивается.
	doc, spans := nameScanText(t, "ИВАНОВ пришёл в отделение")
	for _, s := range spans {
		if s.End > int32(len("ИВАНОВ")) {
			t.Errorf("спан захватил строчное слово: %s", nameDump(doc, spans))
		}
	}
}

// --- T-66: раунд 4 жюри ----------------------------------------------------
//
// Тесты проверяют решение полного движка — то, что уйдёт в модель, — а не
// сырых кандидатов сканера: вместе с контр-правилами, кластером и отбором.
// Входы — фразы из таблицы задачи и новые вариации того же класса: другие
// фамилии без суффикса, имена, глаголы, падежи, пунктуация. Все значения
// синтетические.

// nameEngineFIO возвращает тексты спанов ФИО, которые полный движок отобрал
// к маскированию.
func nameEngineFIO(t *testing.T, e *Engine, text string) []string {
	t.Helper()
	var out []string
	for _, s := range detectSpans(t, e, text, Options{}) {
		if s.Type == pii.FullName {
			out = append(out, text[s.Start:s.End])
		}
	}
	return out
}

// nameExpectMasked проверяет, что каждое значение из want накрыто ровно
// одним спаном ФИО целиком — не частично и не двумя метками.
func nameExpectMasked(t *testing.T, e *Engine, text string, want ...string) {
	t.Helper()
	got := nameEngineFIO(t, e, text)
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%q: значение %q не накрыто одним спаном ФИО целиком; спаны ФИО: %q", text, w, got)
		}
	}
}

// nameExpectKept проверяет, что ни один спан ФИО не задевает фрагмент keep.
func nameExpectKept(t *testing.T, e *Engine, text, keep string) {
	t.Helper()
	at := strings.Index(text, keep)
	if at < 0 {
		t.Fatalf("%q: фрагмента %q нет в тексте", text, keep)
	}
	for _, s := range detectSpans(t, e, text, Options{}) {
		if s.Type == pii.FullName && int(s.Start) < at+len(keep) && at < int(s.End) {
			t.Errorf("%q: фрагмент %q под маской ФИО %q (%s)", text, keep, text[s.Start:s.End], s.Rule)
		}
	}
}

// TestNameBareSurnameLeadsGiven — класс 1 (Б4-1, стоп-сигнал на живой модели):
// фамилия без суффикса вплотную перед именем без маркера.
func TestNameBareSurnameLeadsGiven(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, want string }{
		// Фразы жюри.
		{"Коваль Инна обратилась в отделение за выпиской.", "Коваль Инна"},
		{"Пономарь Кирилл просит перевыпустить карту.", "Пономарь Кирилл"},
		{"Жук Константин оформил вклад на полгода.", "Жук Константин"},
		{"Шин Артур потерял карту в метро.", "Шин Артур"},
		{"Нойман Алиса оспаривает списание 3 000 руб.", "Нойман Алиса"},
		{"Мельник Ольга, телефон +7 916 303-40-50, просит перезвонить.", "Мельник Ольга"},
		{"Бондарь Игорь, паспорт 4509 121314, хочет закрыть счёт.", "Бондарь Игорь"},
		{"Шульц Роман закрыл счёт в понедельник.", "Шульц Роман"},
		// Вариации: другие фамилии, глаголы, позиция, пунктуация.
		{"Гусь Анна оформила карту.", "Гусь Анна"},
		{"Бык Олег закрыл вклад досрочно.", "Бык Олег"},
		{"Ворон Игорь потерял паспорт в такси.", "Ворон Игорь"},
		{"Черныш Денис оспаривает платёж.", "Черныш Денис"},
		{"Пак Елена хочет открыть счёт.", "Пак Елена"},
		{"Хан Тимур — перевыпуск карты.", "Хан Тимур"},
		{"Кац Ольга интересуется ипотекой.", "Кац Ольга"},
		{"Рудь Василий подал жалобу на банкомат.", "Рудь Василий"},
		{"Карась Павел пополнил вклад.", "Карась Павел"},
		{"Лось Виктор хочет закрыть карту.", "Лось Виктор"},
		{"Жалоба. Бык Наталья не получила перевод.", "Бык Наталья"},
		{"Сегодня в отделение пришёл Гусь Анатолий и попросил выписку.", "Гусь Анатолий"},
		{"Добрый день, Шварц Михаил, прошу перезвонить.", "Шварц Михаил"},
		{"Уважаемая Сом Ирина, ваша карта готова.", "Сом Ирина"},
		{"Отправитель: Дуб Геннадий.", "Дуб Геннадий"},
		// Косвенный падеж: согласование и предлог лица.
		{"Документы для Кац Ольги готовы.", "Кац Ольги"},
		{"Письмо для Шварца Михаила отправлено.", "Шварца Михаила"},
		{"Ждём ответа от Гуся Анатолия.", "Гуся Анатолия"},
		// Обратный порядок.
		{"Инна Коваль оспаривает списание.", "Инна Коваль"},
		{"Вчера Ольга Кац закрыла вклад.", "Ольга Кац"},
		// Строчные при маркере: винительный падеж женского отчества не
		// снимает фамилию на «-й», «-ь» (корпус seed 20260924, c-1204).
		{"Найди клиента цой алевтину кирилловну, паспорт 31 11 488973.", "цой алевтину кирилловну"},
		{"Найди клиента бондарь алевтину захаровну, паспорт 68 75 925328.", "бондарь алевтину захаровну"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectMasked(t, e, tc.text, tc.want) })
	}
}

// TestNameFormFieldValue — класс 2 (P4-2, стоп-сигнал технического жюри):
// значение поля анкеты — ФИО даже одним словом, маркер в маску не входит.
func TestNameFormFieldValue(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct {
		text string
		want []string
	}{
		{"Фамилия: Шаповалова; Имя: Дарья; Отчество: Никитична", []string{"Шаповалова", "Дарья", "Никитична"}},
		{"Девичья фамилия матери: Корнеева", []string{nameFxKorneeva}},
		{"Прежняя фамилия: Корнеева", []string{nameFxKorneeva}},
		{"Фамилия при рождении — Корнеева.", []string{nameFxKorneeva}},
		{"Клиент сменил фамилию с Корнеевой на Шаповалову.", []string{"Корнеевой", "Шаповалову"}},
		{"Моя фамилия Заяц, зовут Пётр Ильич.", []string{"Заяц", "Пётр Ильич"}},
		{"Фамилия клиента — Сорока, имя — Дарья.", []string{"Сорока", "Дарья"}},
		{"Моя фамилия Шевчук.", []string{nameFxShevchuk}},
		{"Подпись: /Шаповалова/", []string{"Шаповалова"}},
		{"Подпись: Шмидт / Шмидт Андрей Карлович", []string{"Шмидт", "Шмидт Андрей Карлович"}},
		{"Фамилия: Волк. Имя: Игорь. Отчество: Сергеевич.", []string{"Волк", "Игорь", "Сергеевич"}},
		{"Фамилия — Иванова, девичья — Коваль.", []string{"Иванова", nameFxKoval}},
		// Вариации.
		{"Фамилия — Бык, имя — Роман, отчество — Ильич.", []string{"Бык", "Роман", "Ильич"}},
		{"фамилия: лемешко", []string{"лемешко"}},
		{"фамилия: корнеева", []string{"корнеева"}},
		{"ФАМИЛИЯ: ШВАРЦ", []string{"ШВАРЦ"}},
		{"Девичья фамилия матери — Черныш.", []string{nameFxChernysh}},
		{"Прежняя фамилия Ворон.", []string{"Ворон"}},
		{"Фамилия до брака: Кац.", []string{"Кац"}},
		{"Фамилия заёмщика: Дуб", []string{"Дуб"}},
		{"Прежняя фамилия — Баран, новая — Сом.", []string{"Баран", "Сом"}},
		{"Сменила фамилию с Гусевой на Рудь.", []string{"Гусевой", "Рудь"}},
		{"Сменил фамилию на Грин.", []string{"Грин"}},
		{"Прошу перевыпустить карту на новую фамилию: была Коваленко, стала Шульга Дарья Ивановна.",
			[]string{"Коваленко", "Шульга Дарья Ивановна"}},
		{"Отчество: Ренатович", []string{"Ренатович"}},
		{"Подпись клиента: Мирошник", []string{"Мирошник"}},
		{"Ф.И.О.: Кац Ольга", []string{"Кац Ольга"}},
		{"ФИО: Рудь", []string{"Рудь"}},
		{"Фамилия, имя, отчество: Бык Роман Ильич", []string{"Бык Роман Ильич"}},
		{"Фамилия\nЧерныш\nИмя\nДенис", []string{nameFxChernysh, "Денис"}},
		{"Имя: Айгерим; фамилия: Жаксылык.", []string{"Айгерим", "Жаксылык"}},
		{"Фамилия, имя: Волк Игорь", []string{"Волк Игорь"}},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectMasked(t, e, tc.text, tc.want...) })
	}
}

// TestNameFormFieldValueNoFalsePositive — поле без значения: слово после
// маркера поля не маскируется, если это стоп-слово, глагол, наречие или
// прилагательное после «подписи».
func TestNameFormFieldValueNoFalsePositive(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, keep string }{
		{"Фамилия не указана.", "указана"},
		{"Фамилия и имя обязательны для заполнения.", "обязательны"},
		{"Укажите фамилию полностью.", "полностью"},
		{"Укажите фамилию на русском языке.", "русском"},
		{"Подпись: Отсутствует", "Отсутствует"},
		{"Подпись: Электронная", "Электронная"},
		{"Подпись: электронная", "электронная"},
		{"Подпись клиента: Имеется", "Имеется"},
		{"Отчество: Нет", "Нет"},
		{"Имя: Не указано", "указано"},
		{"Карта оформлена на имя Банка.", "Банка"},
		{"Фамилия, Имя, Отчество", "Фамилия, Имя, Отчество"},
		{"Фамилия должна совпадать с паспортом.", "совпадать"},
		{"Смените фамилию в профиле.", "профиле"},
		{"Фамилия изменена в связи с браком.", "изменена"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectKept(t, e, tc.text, tc.keep) })
	}
}

// TestNamePersonSlotSurname — класс 3 (Б4-5): одиночная фамилия в позиции лица —
// после маркера, глагола-ввода или «от» и перед границей фразы — и в
// подписи письма.
func TestNamePersonSlotSurname(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, want string }{
		{"Спасибо за помощь! Ваш клиент, Кох.", "Кох"},
		{"С уважением, Коваль.", nameFxKoval},
		{"Перевод от Мельник, 5 000 руб.", nameFxMelnik},
		{"Заявление принято от Иванова.", "Иванова"},
		{"Обращение от гражданина Цоя по поводу вклада.", "Цоя"},
		{"Звонила Волк, просила закрыть счёт.", "Волк"},
		{"Пишет Бондарь: деньги не пришли.", "Бондарь"},
		// Вариации.
		{"С уважением, Гусь.", "Гусь"},
		{"С уважением, Лемешко", "Лемешко"},
		{"Прошу перезвонить.\nС уважением,\nШварц", "Шварц"},
		{"С наилучшими пожеланиями,\nГриц", "Гриц"},
		{"Ваша клиентка, Сом.", "Сом"},
		{"Перевод от Кац, 3 000 руб.", "Кац"},
		{"Перевод от Лося, 700 руб.", "Лося"},
		{"Заявление от Рудь принято.", "Рудь"},
		{"Принято от Шварца.", "Шварца"},
		{"Получено от Петровой.", "Петровой"},
		{"Звонил Бык, просил перезвонить.", "Бык"},
		{"Звонил Карась по поводу кредита.", "Карась"},
		{"Звонила Смирнова по поводу кредита.", "Смирнова"},
		{"Клиентка Гусь, телефон не оставила.", "Гусь"},
		{"Прошу закрыть счёт.\nЧерныш", nameFxChernysh},
		{"Прошу вернуть комиссию.\nКарась", "Карась"},
		{"Спасибо, Лось.", "Лось"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectMasked(t, e, tc.text, tc.want) })
	}
}

// TestNamePersonSlotNoFalsePositive — организация, город и обычное слово на
// месте лица не маскируются.
func TestNamePersonSlotNoFalsePositive(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, keep string }{
		{"Перевод от Сбербанка поступил.", "Сбербанка"},
		{"С уважением, команда банка.", "команда"},
		{"С уважением, Отдел кредитования", "Отдел"},
		{"С уважением, Служба поддержки.", "Служба"},
		{"Ответ от Банка России пришёл.", "Банка России"},
		{"Прошу закрыть счёт.\nСпасибо", "Спасибо"},
		{"Клиент Сбербанка, пенсионер.", "Сбербанка"},
		{"Письмо пришло от Москвы.", "Москвы"},
		{"Звонил Сбербанк, предложил кредит.", "Сбербанк"},
		{"Пишет Госуслуги: заявление принято.", "Госуслуги"},
		{"Перевод от Тинькофф поступил.", "Тинькофф"},
		{"Пришло письмо от Ростелекома.", "Ростелекома"},
		{"Сотрудник Росгвардии пришёл в отделение.", "Росгвардии"},
		{"Лев Толстой написал «Войну и мир»", "Войну"},
		{"Звонила Анна, просила перезвонить.", "Анна"},
		{"Статус:\nОдобрено", "Одобрено"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectKept(t, e, tc.text, tc.keep) })
	}
}

// TestNameSingleAndLowerInitials — класс 4 (Б4-5, P4-4): один инициал при фамилии
// без суффикса и строчные инициалы при маркере или слове-вводе.
func TestNameSingleAndLowerInitials(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, want string }{
		{"Клиент Мельник О. просит выписку.", "Мельник О."},
		{"Выписка: 15.09 перевод Шмидт А. — 2 000,00.", "Шмидт А."},
		{"Получатель: Коваль И.", "Коваль И."},
		{"Кох А. оплатил кредит.", "Кох А."},
		{"клиент шаповалова д.н. просит выписку.", "шаповалова д.н."},
		{"звонил мкртчян а.а.", "мкртчян а.а."},
		{"фио: громов а. и.", "громов а. и."},
		{"передайте д. н. шаповаловой документы.", "д. н. шаповаловой"},
		// Вариации.
		{"Клиент Гусь А. просит выписку.", "Гусь А."},
		{"Кац О. оплатила кредит.", "Кац О."},
		{"Лось В. оплатил счёт.", "Лось В."},
		{"Подписал: Гриц Е.", "Гриц Е."},
		{"клиент гусева о.п. просит выписку", "гусева о.п."},
		{"звонила лемешко м.и.", "лемешко м.и."},
		{"клиент черныш д.с. ждёт звонка", "черныш д.с."},
		{"звонила сом и. в.", "сом и. в."},
		{"фио: карась п. и.", "карась п. и."},
		{"Клиент А. Мельник просит перезвонить.", "А. Мельник"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectMasked(t, e, tc.text, tc.want) })
	}
	for _, tc := range []struct{ text, keep string }{
		{"Корпус Б. закрыт на ремонт.", "Корпус"},
		{"Смотрите Приложение А. к договору.", "Приложение"},
		{"документы т. е. копии паспорта", "документы"},
		{"Условия описаны в Разделе Б. договора.", "Разделе"},
		{"Вагон Б. прибудет позже.", "Вагон"},
		{"План Б. утверждён.", "План"},
		{"Ф.И.О. заполняется печатными буквами.", "Ф.И.О."},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectKept(t, e, tc.text, tc.keep) })
	}
}

// TestNameHyphenatedSurname — класс 5 (Б4-4): двойная фамилия через дефис — один
// спан целиком, а не «Иванова-[ФИО_1]» и не «[ФИО_1]-[ФИО_2]».
func TestNameHyphenatedSurname(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, want string }{
		{"Заявка от Иванова-Петренко Олега Николаевича.", "Иванова-Петренко Олега Николаевича"},
		{"Смирнова-Ким Ольга, тел. +7 916 111-20-30.", "Смирнова-Ким Ольга"},
		{"Соколова-Цой Елена оспаривает операцию.", "Соколова-Цой Елена"},
		{"Грум-Гржимайло Павел открывает счёт.", "Грум-Гржимайло Павел"},
		{"Клиентка Петрова-Сидорова Анна Ивановна просит выписку.", "Петрова-Сидорова Анна Ивановна"},
		{"Кузнецов-Мельник Игорь Павлович оформил вклад.", "Кузнецов-Мельник Игорь Павлович"},
		{"Орлова-Шмидт Мария просит закрыть карту.", "Орлова-Шмидт Мария"},
		{"Бонч-Бруевич Андрей Сергеевич, паспорт 4509 565758.", "Бонч-Бруевич Андрей Сергеевич"},
		// Вариации.
		{"Гусева-Кац Ольга Петровна оформила вклад.", "Гусева-Кац Ольга Петровна"},
		{"Клиент Шварц-Лемешко Анна просит выписку.", "Шварц-Лемешко Анна"},
		{"Заявка от Черныш-Рудь Марии Олеговны.", "Черныш-Рудь Марии Олеговны"},
		{"Олег Николаевич Иванов-Петренко подписал договор.", "Олег Николаевич Иванов-Петренко"},
		{"Анна-Мария Петрова открыла счёт.", "Анна-Мария Петрова"},
		{"Римская-Корсакова Ольга Петровна подписала договор.", "Римская-Корсакова Ольга Петровна"},
		{"Клиент Дуб-Лось Павел оформил карту.", "Дуб-Лось Павел"},
		{"Фамилия: Грум-Гржимайло", "Грум-Гржимайло"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectMasked(t, e, tc.text, tc.want) })
	}
	for _, tc := range []struct{ text, keep string }{
		{"Альфа-Банк выдал карту Анне.", "Альфа-Банк"},
		{"Офис в Санкт-Петербурге закрыт.", "Санкт-Петербурге"},
		{"Рейс Ростов-на-Дону — Москва задержан.", "Ростов-на-Дону"},
		{"Интернет-Банк временно недоступен.", "Интернет-Банк"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectKept(t, e, tc.text, tc.keep) })
	}
}

// TestNameForeignGivenNames — класс 6 (Б4-9): имена народов России, СНГ и
// частые иностранные — в справочнике, и пара с фамилией без суффикса
// маскируется.
func TestNameForeignGivenNames(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, want string }{
		{"Поступил перевод от Жаксылык Айгерим на сумму 25 000 тенге.", "Жаксылык Айгерим"},
		{"Операция по карте держателя Алиоглу Мехмет оспорена клиентом.", "Алиоглу Мехмет"},
		{"Поручитель: Ахмедов Руслан Эльдарович, заёмщик: Нгуен Ван Тхань.", "Нгуен Ван Тхань"},
		{"Клиент Эрдэнэ Батбаяр из Монголии открывает счёт нерезидента.", "Эрдэнэ Батбаяр"},
		// Вариации.
		{"Клиент Нурланов Айбек открыл счёт.", "Нурланов Айбек"},
		{"Перевод от Жумабаева Ерлана поступил.", "Жумабаева Ерлана"},
		{"Ооржак Айдыс оформил кредит.", "Ооржак Айдыс"},
		{"Цыбиков Жаргал просит выписку.", "Цыбиков Жаргал"},
		{"Заёмщик: Нгуен Тхи Лан.", "Нгуен Тхи Лан"},
		{"Джаксыбеков Нурсултан открыл вклад.", "Джаксыбеков Нурсултан"},
		{"Звонил Мамедов Турал по поводу кредита.", "Мамедов Турал"},
		{"Перевод получила Доржиева Сэсэг.", "Доржиева Сэсэг"},
		{"Клиент Шмидт Юрген открыл счёт.", "Шмидт Юрген"},
		{"Звонил Коэн Моше.", "Коэн Моше"},
		{"Батбаяр Ганбаатар перевёл деньги.", "Батбаяр Ганбаатар"},
		{"Айдыс Ооржак пополнил счёт.", "Айдыс Ооржак"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectMasked(t, e, tc.text, tc.want) })
	}
}

// TestNameAdjSurnameWithGiven — класс 7 (Б4-10): фамилия-прилагательное перед
// «Имя Отчество» — всегда, перед одним именем — при маркере или обращении.
func TestNameAdjSurnameWithGiven(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, want string }{
		{"Клиент Белый Андрей Сергеевич, паспорт уточняется.", "Белый Андрей Сергеевич"},
		{"Заявление от Лысого Виктора Петровича о смене паспорта.", "Лысого Виктора Петровича"},
		{"Звонила Рыжая Светлана Олеговна по поводу страховки.", "Рыжая Светлана Олеговна"},
		{"Спасибо, Тихий Роман, ваша заявка принята.", "Тихий Роман"},
		{"Здравствуйте, я Малая Ирина, хочу закрыть кредитную карту.", "Малая Ирина"},
		// Вариации.
		{"Рыжий Олег Петрович оформил кредит.", "Рыжий Олег Петрович"},
		{"Заявление от Лысой Анны Викторовны.", "Лысой Анны Викторовны"},
		{"Клиентка Белая Ольга просит выписку.", "Белая Ольга"},
		{"Документы передать Малому Ивану Андреевичу.", "Малому Ивану Андреевичу"},
		{"Клиент Глухой Павел Ильич просит перезвонить.", "Глухой Павел Ильич"},
		{"От Белого Андрея Витальевича поступила жалоба.", "Белого Андрея Витальевича"},
		{"Документы для Рыжей Анны Сергеевны.", "Рыжей Анны Сергеевны"},
		{"Клиент Злой Артём Павлович просит перезвонить.", "Злой Артём Павлович"},
		// Справа от одного имени — тоже при маркере (раунды 2 и 3 жюри).
		{"Клиент Андрей Белый", "Андрей Белый"},
		{"Клиентка Ольга Белая, телефон уточняется.", "Ольга Белая"},
		// Существительные на месте фамилии.
		{"Звонил Волк Игорь Петрович.", "Волк Игорь Петрович"},
		{"Зима Екатерина Андреевна просит справку.", "Зима Екатерина Андреевна"},
		{"Соловей Артём Игоревич оплатил кредит.", "Соловей Артём Игоревич"},
		{"Здравствуйте, это Зима Екатерина, у меня не приходят смс-коды.", "Зима Екатерина"},
		{"Добрый день, на связи Мороз Алексей.", "Мороз Алексей"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectMasked(t, e, tc.text, tc.want) })
	}
}

// TestNameCapitalNeighbourNoFalsePositive — обратный контроль ко всем классам T-66:
// слова, которые с заглавной стоят рядом с именем или на месте фамилии, но
// фамилией не являются, и ловушки контр-правил.
func TestNameCapitalNeighbourNoFalsePositive(t *testing.T) {
	e := newFullEngine(t)
	for _, tc := range []struct{ text, keep string }{
		// Список задачи.
		{"Спасибо, Инна, за обращение.", "Спасибо"},
		{"Привет Олег, как дела?", "Привет"},
		{"Банк Открытие выдал кредит.", "Банк Открытие"},
		{"Москва Сити — деловой центр.", "Москва Сити"},
		{"Поэт Пушкин написал стихотворение.", "Пушкин"},
		{"Улица Пушкина перекрыта.", "Пушкина"},
		{"Лев Толстой писал романы.", "Лев Толстой"},
		{"Офис на проспекте Мира закрыт.", "Мира"},
		{"Зима выдалась холодной.", "Зима"},
		{"Белый дом находится в Вашингтоне.", "Белый"},
		{"Малый театр открыл сезон.", "Малый"},
		// Начало предложения перед именем.
		{"Сегодня Олег пришёл в офис.", "Сегодня"},
		{"Здравствуйте, Анна!", "Здравствуйте"},
		{"Дорогая Анна, поздравляем!", "Дорогая"},
		{"Коллега Ирина подготовит ответ.", "Коллега"},
		{"Менеджер Ольга перезвонит.", "Менеджер"},
		{"Заявка Олега поступила вчера.", "Заявка"},
		{"Карта Анны заблокирована.", "Карта"},
		{"Поздравляем Анну с днём рождения!", "Поздравляем"},
		{"Скажи Инне, что карта готова.", "Скажи"},
		{"Где Анна? Её ждут в офисе.", "Где"},
		{"Слава Богу, всё обошлось.", "Богу"},
		{"Мама Ольга звонила утром.", "Мама"},
		{"Художник Олег нарисовал логотип.", "Художник"},
		{"Однажды Анна пришла без паспорта.", "Однажды"},
		{"Понедельник Олег провёл в офисе.", "Понедельник"},
		{"Отзыв Ирины о работе отделения.", "Отзыв"},
		{"Внимание Ольга, срок истекает.", "Внимание"},
		{"Бабушка Нина передала привет.", "Бабушка"},
		{"Команда Сергея выиграла конкурс.", "Команда"},
		{"Клиника Мария работает до 20:00.", "Клиника"},
		{"Тётя Валя передала документы.", "Тётя"},
		// Прилагательное-оценка перед «Имя Отчество».
		{"Новая Анна Петровна пришла в отдел.", "Новая"},
		{"Милая Анна Петровна, спасибо за помощь!", "Милая"},
		{"Красная площадь закрыта.", "Красная"},
		{"Святая Анна покровительствует путникам.", "Святая"},
		// Без маркера пара «имя + прилагательное» остаётся слабой.
		{"Андрей Белый написал роман «Петербург».", "Белый"},
		// Контр-правила публичной персоны.
		{"Юрий Гагарин полетел в космос в 1961 году.", "Юрий Гагарин"},
		{"Композитор Сергей Рахманинов родился в 1873 году.", "Сергей Рахманинов"},
		{"Писатель Виктор Пелевин выступит на форуме банка.", "Виктор Пелевин"},
	} {
		t.Run(tc.text, func(t *testing.T) { nameExpectKept(t, e, tc.text, tc.keep) })
	}
}
