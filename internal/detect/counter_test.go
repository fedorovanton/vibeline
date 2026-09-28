package detect

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

var (
	counterDictsOnce sync.Once
	counterDictsSet  *dict.Set
	counterDictsErr  error
)

// counterDicts загружает справочники один раз на весь прогон: сборка таблиц
// дороже самого сканирования.
func counterDicts(tb testing.TB) *dict.Set {
	tb.Helper()
	counterDictsOnce.Do(func() { counterDictsSet, counterDictsErr = dict.Load() })
	if counterDictsErr != nil {
		tb.Fatalf(msgDictLoad, counterDictsErr)
	}
	return counterDictsSet
}

// counterScan прогоняет только контр-правила и возвращает выставленные вето.
func counterScan(tb testing.TB, text string) (*lex.Doc, []Veto) {
	tb.Helper()
	doc := lex.Tokenize(text, nil)
	var out Candidates
	counterScanner{}.Scan(doc, counterDicts(tb), &out)
	if len(out.Spans) != 0 {
		tb.Fatalf("контр-правила не должны добавлять кандидатов, получено %d", len(out.Spans))
	}
	return doc, out.Vetos
}

// counterExpect — ожидание для одного гипотетического кандидата: накрыл бы
// его запрет или нет. Проверка повторяет правило движка (applyVetos): вето
// действует при любом пересечении и при совпадении типа.
type counterExpect struct {
	span   string
	typ    pii.Type
	denied bool
}

// counterDenied решает, был бы кандидат span/typ снят выставленными вето.
func counterDenied(tb testing.TB, doc *lex.Doc, vetos []Veto, span string, typ pii.Type) bool {
	tb.Helper()
	at := strings.Index(doc.Text, span)
	if at < 0 {
		tb.Fatalf("фрагмент %q не найден в тексте %q", span, doc.Text)
	}
	start, end := int32(at), int32(at+len(span))
	for _, v := range vetos {
		if start >= v.End || end <= v.Start {
			continue
		}
		if !v.Types.Empty() && !v.Types.Has(typ) {
			continue
		}
		return true
	}
	return false
}

// counterDump печатает выставленные вето для сообщения об ошибке.
func counterDump(doc *lex.Doc, vetos []Veto) string {
	if len(vetos) == 0 {
		return "вето не выставлено"
	}
	var b strings.Builder
	b.WriteString("вето: ")
	for i, v := range vetos {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("[")
		b.WriteString(doc.Text[v.Start:v.End])
		b.WriteString("/")
		b.WriteString(v.Types.String())
		b.WriteString("/")
		b.WriteString(v.Rule)
		b.WriteString("]")
	}
	return b.String()
}

func TestCounterRules(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []counterExpect
	}{
		// --- Правило 1: ролевые слова публичных персон ---
		{
			name: "AC-1 роль слева снимает ФИО",
			text: "поэт Александр Пушкин написал роман",
			want: []counterExpect{{cfxAlexPushkin, pii.FullName, true}},
		},
		{
			name: "роль в косвенном падеже",
			text: "Сборник стихов поэта Александра Блохина издан в прошлом году",
			want: []counterExpect{{"Александра Блохина", pii.FullName, true}},
		},
		{
			name: "цепочка ролей и союз",
			text: "поэт, писатель и драматург Александр Грибов известен всем",
			want: []counterExpect{{"Александр Грибов", pii.FullName, true}},
		},
		{
			name: "роль и фамилия с инициалами",
			text: "композитор А. С. Дроздов дирижировал оркестром",
			want: []counterExpect{{"А. С. Дроздов", pii.FullName, true}},
		},
		{
			name: "между ролью и именем обычный текст — вето нет",
			text: "поэт написал письмо Иванову Ивану",
			want: []counterExpect{{"Иванову Ивану", pii.FullName, false}},
		},
		{
			name: "роль закончила предложение",
			text: "Он известный поэт. Иванов Иван Иванович подписал заявление",
			want: []counterExpect{{cfxIvanovFull, pii.FullName, false}},
		},
		{
			name: "должность сотрудника ролью не является",
			text: "врач Синицына Ольга Петровна приняла пациента",
			want: []counterExpect{{"Синицына Ольга Петровна", pii.FullName, false}},
		},

		// --- Правило 2: топонимы-производные ---
		{
			name: "AC-3 улица снимает ФИО, но не адрес",
			text: cfxPushkinStreet,
			want: []counterExpect{
				{cfxPushkin, pii.FullName, true},
				{cfxPushkinHouse, pii.Address, false},
				{cfxPushkinStreet, pii.Address, false},
			},
		},
		{
			name: "AC-4 музей",
			text: "музей Пушкина открыт до шести",
			want: []counterExpect{{cfxPushkin, pii.FullName, true}},
		},
		{
			name: "AC-4 имени",
			text: "Конструкторское бюро имени Королёва",
			want: []counterExpect{{cfxKoroleva, pii.FullName, true}},
		},
		{
			name: "сокращение с точкой",
			text: "ул. им. Королёва, дом 5, квартира 7",
			want: []counterExpect{
				{cfxKoroleva, pii.FullName, true},
				{"Королёва, дом 5, квартира 7", pii.Address, false},
			},
		},
		{
			name: "площадь и набережная",
			text: "площадь Гагарина и набережная Лермонтова закрыты",
			want: []counterExpect{
				{cfxGagarina, pii.FullName, true},
				{"Лермонтова", pii.FullName, true},
			},
		},
		{
			name: "метро и аэропорт",
			text: "метро Маяковская, аэропорт Шереметьево",
			want: []counterExpect{
				{"Маяковская", pii.FullName, true},
				{"Шереметьево", pii.FullName, true},
			},
		},
		{
			name: "топоним закончил предложение",
			text: "Рядом была школа. Соколова Мария Ивановна ждала у входа",
			want: []counterExpect{{"Соколова Мария Ивановна", pii.FullName, false}},
		},

		// --- Правило 2: граница названия объекта (T-46, дефект D-7) ---
		{
			name: "ФИО сразу за названием улицы вето не получает",
			text: "ул. Пушкина Иванов Иван Иванович",
			want: []counterExpect{
				{cfxPushkin, pii.FullName, true},
				{cfxIvanovFull, pii.FullName, false},
			},
		},
		{
			name: "ФИО за табуляцией после названия улицы",
			text: "ул. Ленина\tПетров Пётр Петрович",
			want: []counterExpect{
				{"Ленина", pii.FullName, true},
				{cfxPetrovFull, pii.FullName, false},
			},
		},
		{
			name: "женская фамилия за названием площади",
			text: "площадь Гагарина Сидорова Анна Петровна",
			want: []counterExpect{
				{cfxGagarina, pii.FullName, true},
				{"Сидорова Анна Петровна", pii.FullName, false},
			},
		},
		{
			name: "составное название: имя и фамилия в родительном падеже",
			text: "ул. Льва Толстого, д. 5",
			want: []counterExpect{
				{"Льва", pii.FullName, true},
				{"Толстого", pii.FullName, true},
			},
		},
		{
			name: "составное название: звание",
			text: "проспект Маршала Жукова, 12",
			want: []counterExpect{{"Маршала Жукова", pii.FullName, true}, {"Жукова", pii.FullName, true}},
		},
		{
			name: "составное название: звание и отчество",
			text: "музей Академика Сергея Павловича Королёва открыт",
			want: []counterExpect{{cfxKoroleva, pii.FullName, true}},
		},
		{
			name: "составное название: имя и отчество",
			text: "музей Александра Сергеевича Пушкина открыт до шести",
			want: []counterExpect{{cfxPushkin, pii.FullName, true}},
		},
		{
			name: "составное название: инициал",
			text: "ул. М. Горького, 3",
			want: []counterExpect{{"Горького", pii.FullName, true}},
		},
		{
			name: "составное название: несклоняемая фамилия",
			text: "ул. Тараса Шевченко, 3",
			want: []counterExpect{{"Шевченко", pii.FullName, true}},
		},
		{
			name: "название через дефис",
			text: "ул. Салтыкова-Щедрина Иванов Иван",
			want: []counterExpect{
				{"Щедрина", pii.FullName, true},
				{"Иванов Иван", pii.FullName, false},
			},
		},
		{
			name: "за составным названием ФИО — вето сужается до первого слова",
			text: "ул. Льва Толстого Иванов Иван Иванович",
			want: []counterExpect{
				{"Льва", pii.FullName, true},
				{cfxIvanovFull, pii.FullName, false},
			},
		},
		{
			name: "слово не в родительном падеже составное название не продолжает",
			text: "ул. Ивана Иванов",
			want: []counterExpect{
				{"Ивана", pii.FullName, true},
				{"Иванов", pii.FullName, false},
			},
		},

		// --- Правило 3: адреса и контакты организаций ---
		{
			name: "AC-5 адрес отделения банка",
			text: "отделение банка по адресу Москва, ул. Ленина, 5",
			want: []counterExpect{
				{cfxLeninAddr, pii.Address, true},
				{cfxLeninHouse, pii.Address, true},
			},
		},
		{
			name: "AC-6 адрес человека вето не получает",
			text: "проживает по адресу Москва, ул. Ленина, 5",
			want: []counterExpect{
				{cfxLeninAddr, pii.Address, false},
				{cfxLeninHouse, pii.Address, false},
			},
		},
		{
			name: "AC-7 горячая линия",
			text: "горячая линия 8-800-555-35-35 работает круглосуточно",
			want: []counterExpect{{"8-800-555-35-35", pii.Phone, true}},
		},
		{
			name: "AC-8 телефон клиента",
			text: "телефон клиента +7 916 123-45-67",
			want: []counterExpect{{cfxClientPhone, pii.Phone, false}},
		},
		{
			name: "телефон отделения",
			text: "отделение банка, телефон +7 495 123-45-67",
			want: []counterExpect{{"+7 495 123-45-67", pii.Phone, true}},
		},
		{
			name: "почта службы поддержки",
			text: "служба поддержки support@bank.example отвечает за сутки",
			want: []counterExpect{{"support@bank.example", pii.Email, true}},
		},
		{
			name: "юридический адрес",
			text: "юридический адрес: Москва, ул. Тверская, 7",
			want: []counterExpect{{"Москва, ул. Тверская, 7", pii.Address, true}},
		},
		{
			name: "маркер человека слева отменяет правило организации",
			text: "клиент банка Ерохин, телефон +7 916 123-45-67",
			want: []counterExpect{{cfxClientPhone, pii.Phone, false}},
		},
		{
			name: "данные человека после маркера организации",
			text: "наш клиент Ерохин, телефон +7 916 123-45-67",
			want: []counterExpect{{cfxClientPhone, pii.Phone, false}},
		},
		{
			name: "call me at — телефон человека, не call-центра",
			text: "Please call me at +7 916 700-80-91 tomorrow.",
			want: []counterExpect{{"+7 916 700-80-91", pii.Phone, false}},
		},
		{
			name: "call Mr. — телефон человека",
			text: "Please call Mr. Oleg Melnik at +7 916 700-80-91.",
			want: []counterExpect{{"+7 916 700-80-91", pii.Phone, false}},
		},
		{
			name: "call-центр по-прежнему снимает телефон",
			text: "Наш call-центр: +7 495 123-45-67.",
			want: []counterExpect{{"+7 495 123-45-67", pii.Phone, true}},
		},
		{
			name: "телефон человека за окном маркера организации",
			text: "Филиал на Тверской обслуживает Ерохина Ивана, его телефон +7 916 123-45-67",
			want: []counterExpect{{cfxClientPhone, pii.Phone, false}},
		},
		{
			name: "маркер организации не снимает ФИО",
			text: "отделение банка обслуживает Ерохина Ивана Петровича",
			want: []counterExpect{{"Ерохина Ивана Петровича", pii.FullName, false}},
		},
		{
			name: "адрес сотрудника организации остаётся личным",
			text: "Наш сотрудник Ерохин проживает по адресу Москва, ул. Ленина, 5",
			want: []counterExpect{{cfxLeninAddr, pii.Address, false}},
		},
		{
			name: "граница предложения обрывает окно организации",
			text: "Работает отделение банка. Ерохин живёт по адресу Москва, ул. Ленина, 5",
			want: []counterExpect{{cfxLeninAddr, pii.Address, false}},
		},

		// --- Правило 4: известные публичные персоны ---
		{
			name: "одиночное упоминание публичного лица",
			text: "Пушкина изучают в старших классах",
			want: []counterExpect{{cfxPushkin, pii.FullName, true}},
		},
		{
			name: "AC-2 однофамилец-клиент защищается",
			text: "клиент Александр Пушкин, паспорт 4509 123456",
			want: []counterExpect{{cfxAlexPushkin, pii.FullName, false}},
		},
		{
			name: "AC-2 маркер клиента справа от фамилии",
			text: "Пушкин Александр Сергеевич, паспорт 4509 123456",
			want: []counterExpect{{"Пушкин Александр Сергеевич", pii.FullName, false}},
		},
		{
			name: "AC-2 заявитель без цифр",
			text: "заявитель Пушкина Мария Олеговна просит выдать справку",
			want: []counterExpect{{"Пушкина Мария Олеговна", pii.FullName, false}},
		},
		{
			name: "AC-2 реквизиты рядом без слова-маркера",
			text: "Пушкин А. С., 4509 123456, выдан отделом внутренних дел",
			want: []counterExpect{{"Пушкин А. С.", pii.FullName, false}},
		},
		{
			name: "AC-2 почтовый адрес рядом с фамилией",
			text: "Лермонтов Михаил, lermontov@example.test",
			want: []counterExpect{{"Лермонтов Михаил", pii.FullName, false}},
		},
		{
			name: "AC-2 карта на имя однофамильца",
			text: "карта оформлена на имя Гагарина Юрия Алексеевича",
			want: []counterExpect{{"Гагарина Юрия Алексеевича", pii.FullName, false}},
		},
		{
			name: "распространённая фамилия в справочник не входит",
			text: "Попов приходил вчера",
			want: []counterExpect{{"Попов", pii.FullName, false}},
		},
		{
			name: "строчное написание вето не даёт",
			text: "в тексте встречается слово менделеев",
			want: []counterExpect{{"менделеев", pii.FullName, false}},
		},

		// --- Правило 4: банковское слово — признак клиента (T-51) ---
		{
			name: "AC-1 вклад",
			text: "Юрий Гагарин хочет открыть вклад на год",
			want: []counterExpect{{cfxYuriGagarin, pii.FullName, false}},
		},
		{
			name: "AC-1 кредит",
			text: "Лев Толстой оформил кредит",
			want: []counterExpect{{"Лев Толстой", pii.FullName, false}},
		},
		{
			name: "AC-1 перевод",
			text: "Перевод от Александра Пушкина не дошёл",
			want: []counterExpect{{"Александра Пушкина", pii.FullName, false}},
		},
		{
			name: "банковское слово справа за фамилией",
			text: "Антон Чехов спрашивает, почему списали комиссию",
			want: []counterExpect{{"Антон Чехов", pii.FullName, false}},
		},
		{
			name: "основа покрывает словоформы",
			text: "Ипотеку Михаила Лермонтова одобрили вчера",
			want: []counterExpect{{"Михаила Лермонтова", pii.FullName, false}},
		},
		{
			name: "exact: «долги» — банковское",
			text: "Сергей Есенин хочет закрыть долги",
			want: []counterExpect{{"Сергей Есенин", pii.FullName, false}},
		},
		{
			name: "exact: «долго» банковским не является",
			text: "Сергей Есенин долго жил в Москве",
			want: []counterExpect{{cfxEsenin, pii.FullName, true}},
		},
		{
			name: "except: переводчик — не перевод",
			text: "Переводчик Пушкина на английский был англичанином",
			want: []counterExpect{{cfxPushkin, pii.FullName, true}},
		},
		{
			name: "except: договорился — не договор",
			text: "Александр Пушкин договорился с издателем",
			want: []counterExpect{{"Пушкин", pii.FullName, true}},
		},
		{
			name: "idiom: вклад в науку",
			text: "Дмитрий Менделеев внёс огромный вклад в науку",
			want: []counterExpect{{cfxMendeleev, pii.FullName, true}},
		},
		{
			name: "idiom: вклад персоны в литературу",
			text: "Вклад Александра Пушкина в русскую литературу огромен",
			want: []counterExpect{{cfxPushkin, pii.FullName, true}},
		},
		{
			name: "idiom: вклад в банке остаётся банковским",
			text: "Юрий Гагарин держит вклад в банке",
			want: []counterExpect{{cfxYuriGagarin, pii.FullName, false}},
		},
		{
			name: "idiom: вклад в названии банка остаётся банковским",
			text: "Юрий Гагарин открыл вклад в Сбербанке",
			want: []counterExpect{{cfxYuriGagarin, pii.FullName, false}},
		},
		{
			name: "idiom: вклад в рублях остаётся банковским",
			text: "Юрий Гагарин хочет вклад в рублях",
			want: []counterExpect{{cfxYuriGagarin, pii.FullName, false}},
		},
		{
			name: "знаменитость без банковских слов",
			text: "Юрий Гагарин первым полетел в космос",
			want: []counterExpect{{cfxGagarin, pii.FullName, true}},
		},
		{
			name: "ловушка корпуса: финансовая грамотность банковским словом не является",
			text: "Подбери материалы про Александра Пушкина для школьной программы финансовой грамотности.",
			want: []counterExpect{{cfxPushkin, pii.FullName, true}},
		},
		{
			name: "банковское слово в соседнем предложении не действует",
			text: "Юрий Гагарин первым полетел в космос. Оформите кредит онлайн.",
			want: []counterExpect{{cfxGagarin, pii.FullName, true}},
		},
		{
			name: "правило 1 сильнее банковского слова",
			text: "Поэт Александр Пушкин открыл вклад",
			want: []counterExpect{{cfxAlexPushkin, pii.FullName, true}},
		},
		{
			name: "правило 1 сильнее банковского слова: кредит",
			text: "Писатель Лев Толстой оформил кредит",
			want: []counterExpect{{"Лев Толстой", pii.FullName, true}},
		},

		// --- Правило 1: маркер клиента перед ролью (стоп-сигнал жюри) ---
		{
			name: "маркер клиента перед ролью отменяет вето",
			text: cfxClientIsPoet,
			want: []counterExpect{
				{cfxIvanPetrov, pii.FullName, false},
				{"14.02.1979", pii.BirthDate, false},
			},
		},
		{
			name: "маркер клиента перед цепочкой ролей",
			text: "наш клиент, поэт и писатель Иван Петров",
			want: []counterExpect{{cfxIvanPetrov, pii.FullName, false}},
		},
		{
			name: "маркер клиента при другом имени вето не отменяет",
			text: "Клиент Иванов Иван просит открытку, где изображён композитор Пётр Чайковский",
			want: []counterExpect{{cfxPyotrTchaikovsky, pii.FullName, true}},
		},

		// --- Правило 1, биография: признаки клиента в предложении ---
		{
			name: "дата клиента после имени поэта не снимается",
			text: cfxClientLikePoet,
			want: []counterExpect{
				{cfxAlexPushkin, pii.FullName, true},
				{cfxBirthDate, pii.BirthDate, false},
				{cfxMoscowLoc, pii.BirthPlace, false},
			},
		},
		{
			name: "имя другого человека до роли без слова «клиент»",
			text: "Иванов Иван Иванович, как и поэт Александр Пушкин, родился 06.06.1985 в Москве.",
			want: []counterExpect{
				{cfxBirthDate, pii.BirthDate, false},
				{cfxMoscowLoc, pii.BirthPlace, false},
			},
		},
		{
			name: "явное поле «дата рождения» не снимается",
			text: "Поэт Александр Пушкин, дата рождения 06.06.1985",
			want: []counterExpect{{cfxBirthDate, pii.BirthDate, false}},
		},
		{
			name: "биография персоны снимается",
			text: "Поэт Александр Пушкин родился 6 июня 1799 года в Москве",
			want: []counterExpect{
				{"6 июня 1799", pii.BirthDate, true},
				{cfxMoscowLoc, pii.BirthPlace, true},
			},
		},
		{
			name: "топоним до роли именем другого человека не считается",
			text: "В Нижнем Новгороде поэт Александр Пушкин родился в Москве",
			want: []counterExpect{{cfxMoscowLoc, pii.BirthPlace, true}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkCounterExpect(t, tt.text, tt.want) })
	}
}

// checkCounterExpect прогоняет контр-правила по тексту и сверяет каждое
// ожидание: накрыл бы выставленный запрет гипотетического кандидата или нет.
func checkCounterExpect(t *testing.T, text string, want []counterExpect) {
	t.Helper()
	doc, vetos := counterScan(t, text)
	for _, w := range want {
		if got := counterDenied(t, doc, vetos, w.span, w.typ); got != w.denied {
			t.Errorf("кандидат %q типа %s: вето=%v, ожидалось %v; %s",
				w.span, w.typ.Key(), got, w.denied, counterDump(doc, vetos))
		}
	}
}

// TestCounterToponymEngine — правило 2 сквозь полный движок (T-46, D-7):
// ФИО за названием улицы находится целиком, а сами названия улиц, в том
// числе составные, ФИО не становятся.
func TestCounterToponymEngine(t *testing.T) {
	e := newFullEngine(t)
	found := []struct{ text, want string }{
		{"ул. Пушкина Иванов Иван Иванович", cfxIvanovFull},
		{"ул. Ленина\tПетров Пётр Петрович", cfxPetrovFull},
		{"проживает: ул. Гагарина Сидоров Сидор Сидорович", "Сидоров Сидор Сидорович"},
		{"проспект Ленина Смирнова Ольга Сергеевна", "Смирнова Ольга Сергеевна"},
		{"ул. Льва Толстого Ерохин Иван Петрович", "Ерохин Иван Петрович"},
	}
	for _, tt := range found {
		ok := false
		for _, s := range runDetect(t, e, tt.text, Options{}) {
			if s.Type == pii.FullName && tt.text[s.Start:s.End] == tt.want {
				ok = true
			}
		}
		if !ok {
			t.Errorf("ФИО %q не найдено в %q", tt.want, tt.text)
		}
	}

	traps := []string{
		"Ближайшее отделение — на улице Пушкина, уточни часы работы в субботу.",
		"Банкомат на площади Гагарина не выдаёт наличные.",
		"Ближайшее отделение — на проспекте Ленина, уточни часы работы.",
		"Банкомат на бульваре Менделеева не выдаёт наличные.",
		"Отделение на улице Льва Толстого работает до восьми.",
		"Офис на проспекте Маршала Жукова закрыт на ремонт.",
		"Филиал на улице Салтыкова-Щедрина переехал.",
		"Музей Александра Сергеевича Пушкина открыт до шести.",
		"Доставка на ул. М. Горького задерживается.",
	}
	for _, text := range traps {
		for _, s := range runDetect(t, e, text, Options{}) {
			if s.Type == pii.FullName {
				t.Errorf("название объекта размечено как ФИО: %q в %q", text[s.Start:s.End], text)
			}
		}
	}
}

// counterStub — минимальный сканер-заглушка: регистрирует кандидатов по
// заранее заданным фрагментам текста. Нужен для сквозной проверки через
// движок: контр-правила сами кандидатов не добавляют, а зависеть в тесте от
// поведения соседнего сканера значило бы проверять не своё правило.
type counterStub struct {
	items []counterStubItem
}

type counterStubItem struct {
	text string
	typ  pii.Type
}

// Name возвращает имя заглушки.
func (counterStub) Name() string { return "counter_stub" }

// Scan регистрирует по одному кандидату на каждый заданный фрагмент.
func (s counterStub) Scan(doc *lex.Doc, _ *dict.Set, out *Candidates) {
	for _, it := range s.items {
		at := strings.Index(doc.Text, it.text)
		if at < 0 {
			continue
		}
		out.Add(at, at+len(it.text), it.typ, Strong, "stub")
	}
}

// TestCounterEngineDropsDeniedType — AC-9: вето не просто регистрируется,
// а действительно убирает тип из Result.Found.
func TestCounterEngineDropsDeniedType(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		items []counterStubItem
		typ   pii.Type
		found bool
	}{
		{
			name:  "поэт снимает ФИО",
			text:  "поэт Александр Пушкин написал роман",
			items: []counterStubItem{{cfxAlexPushkin, pii.FullName}},
			typ:   pii.FullName,
			found: false,
		},
		{
			name: "однофамилец-клиент остаётся в результате",
			text: "клиент Александр Пушкин, паспорт 4509 123456",
			items: []counterStubItem{
				{cfxAlexPushkin, pii.FullName},
				{"4509 123456", pii.PassportNumber},
			},
			typ:   pii.FullName,
			found: true,
		},
		{
			name: "улица снимает ФИО, но адрес остаётся",
			text: cfxPushkinStreet,
			items: []counterStubItem{
				{cfxPushkin, pii.FullName},
				{cfxPushkinHouse, pii.Address},
			},
			typ:   pii.FullName,
			found: false,
		},
		{
			name: "адрес при топониме сохраняется",
			text: cfxPushkinStreet,
			items: []counterStubItem{
				{cfxPushkin, pii.FullName},
				{cfxPushkinHouse, pii.Address},
			},
			typ:   pii.Address,
			found: true,
		},
		{
			// Фамилия публичной персоны бывает и названием города. Вето по
			// ролевому слову обязано снять оба прочтения: иначе ловушка
			// срабатывает под чужим типом — «композитор Пётр [АДРЕС_1]».
			name: "роль снимает и ФИО, и город-однофамилец",
			text: "композитор Пётр Чайковский написал балет",
			items: []counterStubItem{
				{cfxPyotrTchaikovsky, pii.FullName},
				{cfxTchaikovsky, pii.Address},
			},
			typ:   pii.Address,
			found: false,
		},
		{
			name: "роль снимает ФИО у города-однофамильца",
			text: "композитор Пётр Чайковский написал балет",
			items: []counterStubItem{
				{cfxPyotrTchaikovsky, pii.FullName},
				{cfxTchaikovsky, pii.Address},
			},
			typ:   pii.FullName,
			found: false,
		},
		{
			// Обратный контроль: вето правила 1 не должно доставать до
			// адреса клиента, стоящего дальше по предложению.
			name: "адрес клиента после ролевого слова сохраняется",
			text: "композитор Пётр Чайковский, доставка на Москва, ул. Ленина, 5",
			items: []counterStubItem{
				{cfxPyotrTchaikovsky, pii.FullName},
				{cfxLeninAddr, pii.Address},
			},
			typ:   pii.Address,
			found: true,
		},
		{
			name:  "адрес отделения снимается",
			text:  "отделение банка по адресу Москва, ул. Ленина, 5",
			items: []counterStubItem{{cfxLeninAddr, pii.Address}},
			typ:   pii.Address,
			found: false,
		},
		{
			name:  "адрес человека остаётся",
			text:  "проживает по адресу Москва, ул. Ленина, 5",
			items: []counterStubItem{{cfxLeninAddr, pii.Address}},
			typ:   pii.Address,
			found: true,
		},
		{
			name:  "телефон горячей линии снимается",
			text:  "горячая линия 8-800-555-35-35 работает круглосуточно",
			items: []counterStubItem{{"8-800-555-35-35", pii.Phone}},
			typ:   pii.Phone,
			found: false,
		},
		{
			name:  "телефон клиента остаётся",
			text:  "телефон клиента +7 916 123-45-67",
			items: []counterStubItem{{cfxClientPhone, pii.Phone}},
			typ:   pii.Phone,
			found: true,
		},
	}

	engineDicts := counterDicts(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(engineDicts, counterScanner{}, counterStub{items: tt.items})
			doc := lex.Tokenize(tt.text, nil)
			var cand Candidates
			var res Result
			_, _ = e.Detect(context.Background(), doc, Options{}, &cand, &res)

			if got := res.Found.Has(tt.typ); got != tt.found {
				t.Fatalf("тип %s в результате: %v, ожидалось %v (найдено: %s)",
					tt.typ.Key(), got, tt.found, res.Found)
			}
		})
	}
}

// counterDictWords — проверка набора слов одного справочника: у каждого
// слова либо ожидаемая метка, либо ожидаемое наличие записи.
type counterDictWords struct {
	table string
	words []string
	// label — ожидаемая метка; пустая строка — проверяется только наличие.
	label string
	// present — слово обязано быть в справочнике (при пустой label).
	present bool
	// why — пояснение для сообщения об ошибке.
	why string
}

// counterDictWordChecks — ожидания AC-10 по словам справочников.
var counterDictWordChecks = []counterDictWords{
	{
		table: counterDictOrg,
		words: []string{"улица", "площадь", "музей", "имени", "им", "ул", "метро", "аэропорт"},
		label: counterLabelToponym,
	},
	{
		table: counterDictOrg,
		words: []string{"отделение", "филиал", "офис", "горячая", "поддержки", "юридический"},
		label: counterLabelOrg,
	},
	// Слово «адрес» маркером организации быть не должно: иначе «проживает по
	// адресу …» перестанет маскироваться.
	{
		table: counterDictOrg,
		words: []string{"адрес", "адреса", "адресу", "фактический", "телефон"},
		why:   "не должно быть маркером организации",
	},
	// Маркеры человека ролевыми словами не являются.
	{
		table: counterDictRoles,
		words: []string{"клиент", "заявитель", "сотрудник", "гражданин", "плательщик", "врач", "директор"},
		why:   "не должно быть ролевым словом публичной персоны",
	},
	// Распространённые фамилии в справочник публичных лиц не входят: список
	// не должен отнимать защиту у клиента-однофамильца.
	{
		table: counterDictPublic,
		words: []string{"иванов", "попов", "павлов", "смирнов", "кузнецов", "волков", "морозов", "жуков"},
		why:   "распространённая фамилия, её не должно быть в справочнике публичных лиц",
	},
	// Падежные формы основы обязаны присутствовать.
	{
		table: counterDictPublic,
		words: []string{"пушкин", "пушкина", "пушкину", "пушкиным", "пушкине",
			"достоевского", "толстого", "королева", "гагарина", "менделеева"},
		present: true,
		why:     "форма отсутствует в справочнике публичных лиц",
	},
}

// TestCounterDictionaries — AC-10: справочники заполнены содержательно и
// метки правильные.
func TestCounterDictionaries(t *testing.T) {
	dicts := counterDicts(t)
	checkCounterDictSizes(t, dicts)
	for _, c := range counterDictWordChecks {
		checkCounterDictWords(t, dicts, c)
	}
}

// checkCounterDictSizes проверяет, что справочники контр-правил загружены
// и не пусты.
func checkCounterDictSizes(t *testing.T, dicts *dict.Set) {
	t.Helper()
	sizes := []struct {
		name string
		min  int
	}{
		{counterDictRoles, 60},
		{counterDictOrg, 40},
		{counterDictPublic, 150},
	}
	for _, s := range sizes {
		table := dicts.Table(s.name)
		if table == nil {
			t.Fatalf("справочник %s не загружен", s.name)
		}
		if table.Len() < s.min {
			t.Errorf("справочник %s: %d записей, требуется не менее %d", s.name, table.Len(), s.min)
		}
	}
}

// checkCounterDictWords сверяет слова одного справочника с ожиданием c.
func checkCounterDictWords(t *testing.T, dicts *dict.Set, c counterDictWords) {
	t.Helper()
	table := dicts.Table(c.table)
	for _, w := range c.words {
		label, ok := table.Get(w)
		switch {
		case c.label != "":
			if !ok || label != c.label {
				t.Errorf("%s: %q — метка %q, ожидалась %q", c.table, w, label, c.label)
			}
		case ok != c.present:
			t.Errorf("%s: %q — %s", c.table, w, c.why)
		}
	}
}

// counterDictEntry — запись справочника в исходном файле: ключ и метка.
type counterDictEntry struct {
	key, label string
}

// counterDictEntries читает записи справочника из исходного файла, без
// пустых строк и комментариев. Метки и длина основ проверяются по файлу:
// у Table нет обхода.
func counterDictEntries(t *testing.T, name string) []counterDictEntry {
	t.Helper()
	raw, err := os.ReadFile("dict/data/" + name + ".txt")
	if err != nil {
		t.Fatalf("чтение справочника: %v", err)
	}
	var entries []counterDictEntry
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, label, _ := strings.Cut(line, "\t")
		entries = append(entries, counterDictEntry{key: key, label: label})
	}
	return entries
}

// TestCounterBankingDictionary — справочник банковских слов правила 4
// (T-51): загружен, метки допустимые, основы не слишком короткие, а слова из
// ловушек корпуса и рассказов о знаменитостях банковскими не считаются.
func TestCounterBankingDictionary(t *testing.T) {
	banking := counterDicts(t).Table(counterDictBanking)
	if banking.Len() < 80 {
		t.Fatalf("справочник %s: %d записей, требуется не менее 80", counterDictBanking, banking.Len())
	}
	for _, e := range counterDictEntries(t, counterDictBanking) {
		checkCounterBankingEntry(t, e)
	}
	checkCounterBankingWords(t, banking, true, "вклад", "вклады", "кредит", "кредитную", "кредитку", "перевод", "переводом",
		"ипотеку", "платёж", "платежи", "баланс", "задолженность", "договор", "договору", "заявку",
		"списали", "оформить", "оформил", "долги", "займ", "рублей", "банкомат", "банкомате", "банковскую", "кэшбэк")
	checkCounterBankingWords(t, banking, false, "финансовой", "грамотности", "программы", "открыл", "открыть", "закончил",
		"поступление", "долго", "займусь", "переводчик", "переводчика", "договорился", "банкет",
		"платина", "Европу", "рассылки", "материалы", "произведение",
		// Учреждение, а не операция (метка venue, T-82).
		"банк", "банке", "банка", "банков", "банкир")
}

// checkCounterBankingEntry проверяет запись справочника банковских слов:
// метка допустимая, а основа без метки exact не короче counterStemMin.
func checkCounterBankingEntry(t *testing.T, e counterDictEntry) {
	t.Helper()
	switch e.label {
	case "", counterLabelExact, counterLabelExcept, counterLabelIdiom, counterLabelVenue:
	default:
		t.Errorf("%q: неизвестная метка %q", e.key, e.label)
	}
	if e.label != counterLabelExact && utf8.RuneCountInString(e.key) < counterStemMin {
		t.Errorf("%q: основа короче четырёх букв ловит случайные слова — нужна метка exact", e.key)
	}
}

// checkCounterBankingWords проверяет, что каждое слово распознаётся как
// банковское (want) или не распознаётся (!want).
func checkCounterBankingWords(t *testing.T, banking *dict.Table, want bool, words ...string) {
	t.Helper()
	for _, w := range words {
		doc := lex.Tokenize(w, nil)
		if counterBankingWord(doc, banking, 0, len(doc.Tokens)-1) == want {
			continue
		}
		if want {
			t.Errorf("%q должно быть банковским словом", w)
		} else {
			t.Errorf("%q не должно быть банковским словом", w)
		}
	}
}

// TestCounterScannerRegistered проверяет, что сканер подключён к сборке
// через init: список сканеров общий, и забытая регистрация означала бы
// молча не работающие контр-правила.
func TestCounterScannerRegistered(t *testing.T) {
	for _, s := range Registered() {
		if s.Name() == "counter" {
			return
		}
	}
	t.Fatal("сканер counter не зарегистрирован")
}

// TestCounterScanAllocations фиксирует требование нулевых аллокаций: горячий
// путь детекции не должен собирать временные строки.
func TestCounterScanAllocations(t *testing.T) {
	dicts := counterDicts(t)
	doc := lex.Tokenize(counterBenchText(), nil)
	var out Candidates
	var s counterScanner
	s.Scan(doc, dicts, &out) // прогрев: накопитель набирает ёмкость до замера

	got := testing.AllocsPerRun(20, func() {
		out.Reset()
		s.Scan(doc, dicts, &out)
	})
	if got != 0 {
		t.Errorf("аллокаций на проход: %.0f, требуется 0", got)
	}
}

// counterBenchBlock — синтетический фрагмент делового текста. Реальных
// персональных данных в репозитории нет: все ФИО, адреса и телефоны
// вымышлены.
const counterBenchBlock = `Экскурсия проходит по маршруту: музей Пушкина, площадь Гагарина, набережная Лермонтова.
Поэт Александр Пушкин написал роман в стихах, а композитор Чайковский сочинил оперу.
Отделение банка по адресу Москва, ул. Ленина, 5 работает до восьми вечера.
Горячая линия 8-800-555-35-35 и служба поддержки support@bank.example принимают обращения.
Клиент Ерохин Иван Петрович, паспорт 4509 123456, телефон +7 916 123-45-67, проживает по адресу Москва, ул. Тверская, 12.
Заявитель Синицына Ольга Сергеевна просит перевести обслуживание в филиал на улице Королёва.
Конструкторское бюро имени Королёва расположено рядом со станцией метро Маяковская.
Юридический адрес компании: Москва, ул. Тверская, 7, офис 401.
Юрий Гагарин хочет открыть вклад на год, а Дмитрий Менделеев внёс огромный вклад в науку.
Клиент — поэт Иван Петров; писатель Лев Толстой родился в Ясной Поляне.
`

// counterBenchText собирает текст примерно на четыре килобайта.
func counterBenchText() string {
	var b strings.Builder
	for b.Len() < 4096 {
		b.WriteString(counterBenchBlock)
	}
	return b.String()
}

func BenchmarkScanCounter(b *testing.B) {
	dicts := counterDicts(b)
	text := counterBenchText()
	doc := lex.Tokenize(text, nil)

	var out Candidates
	var s counterScanner
	// Прогрев: накопитель набирает ёмкость до замера, иначе первый прогон
	// покажет рост слайса, а не работу сканера.
	s.Scan(doc, dicts, &out)
	if len(out.Vetos) == 0 {
		b.Fatal("контр-правила ничего не нашли на тестовом тексте")
	}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Reset()
		s.Scan(doc, dicts, &out)
	}
}

// TestCounterRoleBioEngine — место и дата рождения в остатке предложения
// после публичной персоны с ролевым словом — биография, а не реквизиты
// клиента. Вето не переходит границу предложения и имя другого человека.
func TestCounterRoleBioEngine(t *testing.T) {
	e := newFullEngine(t)
	clean := []string{
		"Поэт Александр Пушкин родился в Москве",
		"Писатель Лев Толстой родился в Ясной Поляне",
		"Композитор Пётр Чайковский родился 7 мая 1840 года в Воткинске",
	}
	for _, text := range clean {
		for _, s := range runDetect(t, e, text, Options{}) {
			t.Errorf("в биографии публичной персоны размечено %v: %q в %q", s.Type, text[s.Start:s.End], text)
		}
	}
	kept := []struct {
		text string
		typ  pii.Type
		want string
	}{
		{"Поэт Пушкин родился в Москве. Клиент Иванов Иван Иванович родился в Твери", pii.BirthPlace, "Твери"},
		{"Клиент Иванов Иван Иванович родился в Москве", pii.BirthPlace, cfxMoscowLoc},
	}
	for _, tt := range kept {
		ok := false
		for _, s := range runDetect(t, e, tt.text, Options{}) {
			if s.Type == tt.typ && tt.text[s.Start:s.End] == tt.want {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%v %q не найдено в %q", tt.typ, tt.want, tt.text)
		}
	}
}

// counterFullNames возвращает тексты найденных полным движком ФИО.
func counterFullNames(t *testing.T, e *Engine, text string) []string {
	t.Helper()
	var names []string
	for _, s := range runDetect(t, e, text, Options{}) {
		if s.Type == pii.FullName {
			names = append(names, text[s.Start:s.End])
		}
	}
	return names
}

// TestCounterBankingEngine — T-51 сквозь полный движок: банковское слово в
// предложении снимает правило 4 так же, как маркер клиента, а знаменитость
// без банковских слов и персона с ролевым словом остаются без маски.
func TestCounterBankingEngine(t *testing.T) {
	e := newFullEngine(t)

	masked := []struct{ text, surname string }{
		// Сквозь движок — после T-50: фамилия «Толстой» рядом с именем
		// теперь достраивается сканером имён.
		{"Лев Толстой оформил кредит", cfxTolstoy},
		{"Юрий Гагарин хочет открыть вклад на год", cfxGagarin},
		{"Перевод от Александра Пушкина не дошёл", cfxPushkin},
		{"У Антона Чехова списали деньги с карты", "Чехова"},
		{"Сергей Есенин просит перевести пенсию в наш банк", cfxEsenin},
		{"Александр Пушкин открыл вклад в банке", "Пушкин"},
		{"Дмитрий Менделеев не может погасить ипотеку", cfxMendeleev},
	}
	for _, tt := range masked {
		covered := false
		for _, name := range counterFullNames(t, e, tt.text) {
			if strings.Contains(name, tt.surname) {
				covered = true
			}
		}
		if !covered {
			t.Errorf("AC-1: фамилия %q не замаскирована в %q", tt.surname, tt.text)
		}
	}

	clean := []string{
		"Поэт Александр Пушкин родился в Москве",
		"Музей Пушкина открыт до шести",
		"Юрий Гагарин первым полетел в космос",
		"Лев Толстой написал роман «Война и мир»",
		"Дмитрий Менделеев внёс огромный вклад в науку",
		"Вклад Александра Пушкина в русскую литературу огромен",
		"Поэт Александр Пушкин открыл вклад",
		"Писатель Лев Толстой оформил кредит",
		// Ловушки корпуса public_figure (tools/corpusgen), по одной на шаблон.
		"Подбери материалы про Александра Пушкина для школьной программы финансовой грамотности.",
		"Подбери материалы про Юрия Гагарина для школьной программы финансовой грамотности.",
		"Расскажи, в каком году химик Дмитрий Менделеев закончил самое известное произведение, нужна цитата для рассылки.",
		"Клиент спрашивает, есть ли карта с портретом, на котором художник Иван Шишкин — уточни в каталоге дизайнов.",
	}
	for _, text := range clean {
		if names := counterFullNames(t, e, text); len(names) != 0 {
			t.Errorf("AC-2: лишняя маска ФИО %q в %q", names, text)
		}
	}

	// Ловушка корпуса с клиентом и персоной в одном предложении: персона
	// остаётся открытой.
	trap := "Клиент Марина Тимофеевна Задворная просит открытку, где изображён композитор Пётр Чайковский; доставка на г. Бугуруслан, ул. Садовая, д. 7, кв. 81."
	for _, name := range counterFullNames(t, e, trap) {
		if strings.Contains(name, cfxTchaikovsky) {
			t.Errorf("ловушка: персона с ролевым словом замаскирована: %q", name)
		}
	}
}

// TestCounterRoleClientEngine — стоп-сигнал технического жюри после T-49:
// маркер клиента перед ролевым словом и дата клиента после имени поэта.
func TestCounterRoleClientEngine(t *testing.T) {
	e := newFullEngine(t)
	tests := []struct {
		text string
		typ  pii.Type
		want string
	}{
		{cfxClientLikePoet, pii.BirthDate, cfxBirthDate},
		{cfxClientLikePoet, pii.FullName, cfxIvanovFull},
		{cfxClientIsPoet, pii.FullName, cfxIvanPetrov},
		{cfxClientIsPoet, pii.BirthDate, "14.02.1979"},
	}
	for _, tt := range tests {
		ok := false
		for _, s := range runDetect(t, e, tt.text, Options{}) {
			if s.Type == tt.typ && strings.Contains(tt.text[s.Start:s.End], tt.want) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%v %q не замаскировано в %q", tt.typ, tt.want, tt.text)
		}
	}
}

// counterLinearInputs — входы, на которых прежние циклы сканера были
// квадратичными: шаг назад по серии заглавных слов в биографии (С-1),
// пересчёт предложения на каждую фамилию публичного лица (С-2), окно
// организации через серию маркеров, серии ролевых слов и ролевых персон.
func counterLinearInputs(size int) map[string]string {
	rep := func(head, unit string) string {
		var b strings.Builder
		b.WriteString(head)
		for b.Len() < size {
			b.WriteString(unit)
		}
		return b.String()
	}
	return map[string]string{
		"биография: серия заглавных слов":  rep("Поэт Пушкин родился в ", "Москва "),
		"правило 4: серия фамилий":         rep("", "Пушкин и "),
		"правило 4: серия с банком":        rep("", "Пушкин и вклад "),
		"правило 3: серия маркеров":        rep("", "офис, "),
		"правило 1: серия ролей":           rep("", "поэт "),
		"правило 1: серия персон":          rep("", "поэт Пушкин в Поэт "),
		"правило 1: роли через пунктуацию": rep("", "поэт , , , "),
		// T-67: должности, произведения, контакты организации.
		"должность: серия через пунктуацию": rep("", "министр , , , "),
		"должность: серия дополнений":       rep("", "председатель ЦБ "),
		"должность: серия органов":          rep("председатель ", "Московской области "),
		"произведение: незакрытые кавычки":  rep("", "роман « "),
		"произведение: серия предлогов":     rep("", "фильм о "),
		"память: серия имён":                rep("", "памяти Виктора Цоя "),
		"контакт слева: серия оборотов":     rep("", "Москва — адрес нашего офиса "),
		"блок реквизитов организации":       rep("отделение банка: ", "ул. Ленина, д. 5, тел. 8 800 100-00-00, "),
		"почта: серия точек":                rep("Юрий Гагарин, почта ", "a.b."),
		// T-82: составные роли, профессии fame, упоминания через предлог.
		"составная роль: серия":          rep("", "пресс-секретарь "),
		"fame: серия персон":             rep("", "вратарь Акинфеев "),
		"упоминание: серия предлогов":    rep("", "цитата дня от "),
		"упоминание: серия имён":         rep("", "цитата от Льва Толстого "),
		"произведение с заглавной буквы": rep("", "Картина Ильи Репина "),
	}
}

// TestCounterScanLinear — сторож сложности: мегабайт однородного текста в
// одном предложении сканер обязан пройти за доли секунды. Квадратичный цикл
// на таком входе работает минуты, линейный — десятки миллисекунд, поэтому
// предел в секунду не зависит от машины. Детектор гонок замедляет проход в
// десятки раз и под нагрузкой соседних сборок дотягивал его до секунды —
// под ним предел растёт на raceSlowdown.
func TestCounterScanLinear(t *testing.T) {
	dicts := counterDicts(t)
	for name, text := range counterLinearInputs(1 << 20) {
		doc := lex.Tokenize(text, nil)
		var out Candidates
		start := time.Now()
		counterScanner{}.Scan(doc, dicts, &out)
		if d, limit := time.Since(start), raceSlowdown*time.Second; d > limit {
			t.Errorf("%s: %d КБ за %v, предел %v — проход не линеен", name, len(text)>>10, d, limit)
		}
	}
}

// counterEngineFound сообщает, что полный движок нашёл в тексте значение
// типа typ, которое содержит фрагмент want.
func counterEngineFound(t *testing.T, e *Engine, text string, typ pii.Type, want string) bool {
	t.Helper()
	for _, s := range runDetect(t, e, text, Options{}) {
		if s.Type == typ && strings.Contains(text[s.Start:s.End], want) {
			return true
		}
	}
	return false
}

// counterEngineMasked возвращает все значения, найденные полным движком, в
// виде «тип: фрагмент» — для сообщений об ошибке.
func counterEngineMasked(t *testing.T, e *Engine, text string) []string {
	t.Helper()
	var got []string
	for _, s := range runDetect(t, e, text, Options{}) {
		got = append(got, s.Type.Key()+": "+text[s.Start:s.End])
	}
	return got
}

// TestCounterNamesakeEngine — строки 1 и 3 T-67 (раунд 4 бизнес-жюри, Б4-3):
// однофамилец знаменитости или чиновника с реквизитом, маркером клиента или
// банковской операцией в том же предложении — клиент, его ФИО скрывается.
// Кроме фраз жюри — вариации: другие персоны из справочника, другие
// реквизиты, порядок слов.
func TestCounterNamesakeEngine(t *testing.T) {
	e := newFullEngine(t)
	tests := []struct{ text, want string }{
		// Фразы жюри.
		{"Анна Цой, тел. +7 916 202-30-40, хочет открыть вклад.", cfxAnnaTsoi},
		{"Прошу заблокировать карту. Николай Гоголь, тел. +7 916 202-30-41.", "Гоголь"},
		{"Юрий Гагарин, почта yuri.g1985@example.ru, хочет открыть вклад.", cfxGagarin},
		// Почта: точка внутри адреса предложение не рвёт.
		{"Юрий Гагарин, e-mail gagarin.yu@example.com, просит выписку.", cfxGagarin},
		{"Юрий Гагарин, email: yuri77@example.org", cfxGagarin},
		{"Звонил Юрий Гагарин, почта yg@example.ru, просит перезвонить.", cfxGagarin},
		// Другие реквизиты и персоны.
		{"Сергей Есенин, паспорт 4510 223344, просит перевыпустить карту.", cfxEsenin},
		{"Антон Чехов, СНИЛС 112-233-445 95, спрашивает про пенсию.", "Чехов"},
		{"Дмитрий Менделеев, телефон 8 (926) 111-22-33, просит перезвонить.", cfxMendeleev},
		{"Получатель: Лев Толстой, счёт 40817810099910004312.", cfxTolstoy},
		// Чиновник из справочника (метка official) с реквизитом, маркером
		// клиента или банковской операцией — клиент.
		{"Эльвира Набиуллина, тел. +7 916 555-66-77, хочет открыть вклад.", "Набиуллина"},
		{"Антон Силуанов, паспорт 4509 123456, оформил кредит.", "Силуанов"},
		{"Клиент Сергей Собянин просит закрыть счёт.", "Собянин"},
		{"Перевод от Эльвиры Набиуллиной не дошёл.", "Набиуллин"},
		// Строка 3: банковская операция с лицом. «Перевод от Льва Толстого»
		// сюда не входит: сканер имён не находит «Льва» (журнал T-67).
		{"Перевод от Александра Пушкина на 5000 рублей не дошёл.", cfxPushkin},
		{"Платёж для Юрия Гагарина завис.", cfxGagarina},
	}
	for _, tt := range tests {
		if !counterEngineFound(t, e, tt.text, pii.FullName, tt.want) {
			t.Errorf(cfxMsgNameOpen, tt.want, tt.text, counterEngineMasked(t, e, tt.text))
		}
	}
}

// TestCounterPublicMentionEngine — строки 2 и 4 T-67 (Б4-11): знаменитость и
// чиновник в не-клиентском контексте ПД не являются. «Памяти X», «в честь
// X», «к юбилею X», произведение и должность снимают маску только с того,
// кто за ними назван: клиент в том же предложении остаётся под маской.
func TestCounterPublicMentionEngine(t *testing.T) {
	e := newFullEngine(t)
	clean := []string{
		// Фразы жюри.
		"Министр финансов Антон Силуанов заявил о снижении ключевой ставки.",
		"Министр финансов Антон Силуанов рассказал о налоговом вычете по вкладам.",
		"Председатель Банка России Эльвира Набиуллина прокомментировала инфляцию.",
		"Эльвира Набиуллина сообщила о ключевой ставке — вклады подорожают.",
		"К юбилею Юрия Гагарина банк выпустил карту с его портретом.",
		"В 1961 году Юрий Гагарин совершил первый полёт в космос — к юбилею выпущена карта с его портретом.",
		"Концерт памяти Виктора Цоя: оплата картой со скидкой.",
		"Роман «Анна Каренина» есть в подборке для держателей премиальных карт.",
		"Роман «Анна Каренина» Толстого вошёл в подборку книг для клиентов премиум-сегмента.",
		"В кинотеатре показывают фильм о Владимире Высоцком — скидка по карте банка 10%.",
		"Скидка по карте банка на спектакль о Владимире Высоцком.",
		"Экскурсия по местам Михаила Лермонтова для держателей премиальных карт.",
		// Вариации: другие должности, органы, произведения.
		"Председатель ЦБ Эльвира Набиуллина прокомментировала инфляцию.",
		"Глава ЦБ Эльвира Набиуллина выступила на форуме.",
		"Глава Минфина Антон Силуанов предложил новый налог.",
		"Мэр Москвы Сергей Собянин открыл новую станцию метро.",
		"Губернатор Московской области Андрей Воробьёв открыл школу.",
		"Премьер-министр Михаил Мишустин провёл совещание по ипотеке.",
		"Депутат Госдумы Анатолий Аксаков предложил ограничить ставки по кредитам.",
		"Министр экономического развития Максим Решетников оценил рост кредитования.",
		"Герман Греф рассказал о росте ставок по вкладам.",
		"К 90-летию Юрия Гагарина банк выпустил карту.",
		"Акция в честь Юрия Гагарина: кешбэк по картам 12 апреля.",
		"Карта с портретом Юрия Гагарина доступна в отделениях.",
		"Держателям карт — скидка на оперу «Евгений Онегин».",
		"Клиентам со скидкой — билеты на балет «Анна Каренина» в Большом театре.",
		"Выставка картин Ивана Шишкина для держателей карт.",
		"Кешбэк на книги Фёдора Достоевского по карте банка.",
	}
	for _, text := range clean {
		for _, s := range runDetect(t, e, text, Options{}) {
			if s.Type == pii.FullName || s.Type == pii.Address {
				t.Errorf("лишняя маска %v %q в %q", s.Type, text[s.Start:s.End], text)
			}
		}
	}

	// Клиент и публичная персона в одном предложении: персона открыта,
	// клиент под маской.
	mixed := []struct{ text, client, public string }{
		{"Анна Цой, тел. +7 916 202-30-40, хочет купить билеты на концерт памяти Виктора Цоя.", cfxAnnaTsoi, "Виктора Цоя"},
		{"Мария Высоцкая, тел. +7 903 111-22-33, спрашивает про вечер памяти Владимира Высоцкого.", "Мария Высоцкая", "Владимира Высоцкого"},
		{"Клиент Гагарин Олег Петрович, тел. +7 915 222-33-44, спросил про выставку в честь Юрия Гагарина.", "Гагарин Олег Петрович", "Юрия Гагарина"},
		{"Клиент Толстой Андрей Викторович спрашивает, можно ли оплатить картой билеты на спектакль по роману Льва Толстого.", "Толстой Андрей Викторович", "Льва Толстого"},
	}
	for _, tt := range mixed {
		if !counterEngineFound(t, e, tt.text, pii.FullName, tt.client) {
			t.Errorf("клиент %q не замаскирован в %q", tt.client, tt.text)
		}
		if counterEngineFound(t, e, tt.text, pii.FullName, tt.public) {
			t.Errorf("публичная персона %q замаскирована в %q", tt.public, tt.text)
		}
	}

	// Должность и юбилей бывают и у клиента: без органа при должности, при
	// реквизите в предложении и без публичной фамилии за «юбилеем» маска
	// остаётся.
	private := []struct{ text, want string }{
		{"Председатель ТСЖ Иванова Мария Петровна просит открыть счёт.", cfxIvanovaFull},
		{"Председатель ТСЖ Иванова Мария Петровна пришла в отделение.", cfxIvanovaFull},
		{"Глава отдела Петров Пётр Петрович согласовал заявку.", cfxPetrovFull},
		{"Депутат Иванов Иван Иванович, паспорт 4509 123456, просит кредит.", cfxIvanovFull},
		{"Министр Сидоров Семён Семёнович, тел. +7 916 777-88-99, хочет вклад.", "Сидоров Семён Семёнович"},
		{"Роман Иванов хочет кредит.", "Роман Иванов"},
		{"Мария Кац, тел. +7 916 202-30-40, спрашивает про юбилей Ивана Петрова.", "Мария Кац"},
		{"Мария Кац, тел. +7 916 202-30-40, спрашивает про юбилей Ивана Петрова.", "Ивана Петрова"},
	}
	for _, tt := range private {
		if !counterEngineFound(t, e, tt.text, pii.FullName, tt.want) {
			t.Errorf(cfxMsgNameOpen, tt.want, tt.text, counterEngineMasked(t, e, tt.text))
		}
	}
}

// TestCounterOrgContactsEngine — строки 5–6 T-67 (раунд 2, F3; P4-11
// технического жюри): адрес и телефон организации без маски — и справа от
// маркера организации, и слева от оборота «— адрес нашего офиса». Контакты
// клиента в том же тексте остаются под маской.
func TestCounterOrgContactsEngine(t *testing.T) {
	e := newFullEngine(t)
	clean := []string{
		"Улица Гагарина, дом 5 — адрес нашего офиса",
		"Улица Льва Толстого, 16 — адрес партнёра",
		"Улица Льва Толстого, 16 — адрес нашего партнёра, компании «Яндекс».",
		"г. Казань, ул. Баумана, д. 12 — это адрес нашего отделения.",
		"+7 495 100-20-30 — телефон нашего офиса.",
		"Адрес нашего офиса: г. Москва, ул. Тверская, д. 7.",
		"Отделение банка: 620014, Екатеринбург, ул. Малышева, 31, тел. +7 343 000-00-00",
		"Отделение банка: г. Санкт-Петербург, Невский проспект, д. 28, тел. +7 812 300-20-10.",
		"Филиал: 420111, Казань, ул. Баумана, 12, телефон +7 843 200-10-10, факс +7 843 200-10-11.",
		"Офис компании: Москва, ул. Тверская, д. 7, 3 этаж, тел. 8 800 100-20-30.",
	}
	for _, text := range clean {
		for _, s := range runDetect(t, e, text, Options{}) {
			switch s.Type {
			case pii.Address, pii.Phone, pii.Email, pii.FullName:
				t.Errorf("контакт организации замаскирован: %v %q в %q", s.Type, text[s.Start:s.End], text)
			}
		}
	}

	both := "Клиент Петров Пётр Петрович, тел. +7 916 111-22-33; отделение банка: Екатеринбург, ул. Малышева, 31, тел. +7 343 000-00-00."
	masked := []struct {
		text string
		typ  pii.Type
		want string
	}{
		{both, pii.Phone, "916 111-22-33"},
		{both, pii.FullName, cfxPetrovFull},
		{"Клиент Петров Пётр Петрович, тел. +7 916 111-22-33, обратился в отделение банка на ул. Малышева, 31.", pii.Phone, "916 111-22-33"},
		// Посторонний текст закрывает блок реквизитов, местоимение — окно.
		{"Отделение банка на ул. Ленина, д. 5 обслуживает Иванова Ивана, тел. +7 916 333-44-55.", pii.Phone, "916 333-44-55"},
		{"Филиал на Тверской обслуживает Иванова, его телефон +7 916 444-55-66.", pii.Phone, "916 444-55-66"},
		{"Клиент спросил адрес нашего офиса, сам он живёт по адресу г. Тверь, ул. Советская, д. 3, кв. 7.", pii.Address, "Советская"},
	}
	for _, tt := range masked {
		if !counterEngineFound(t, e, tt.text, tt.typ, tt.want) {
			t.Errorf("%v %q не замаскировано в %q; найдено %q", tt.typ, tt.want, tt.text, counterEngineMasked(t, e, tt.text))
		}
	}
	// Телефон клиента маскируется, а телефон отделения в том же тексте — нет.
	if counterEngineFound(t, e, both, pii.Phone, "343 000-00-00") {
		t.Errorf("телефон отделения замаскирован в %q", both)
	}
}

// TestCounterContextRules — вето T-67 на уровне сканера: границы и условия,
// при которых новые правила молчат.
func TestCounterContextRules(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []counterExpect
	}{
		{
			name: "должность с дополнением",
			text: "Министр финансов Антон Силуанов заявил",
			want: []counterExpect{{"Антон Силуанов", pii.FullName, true}},
		},
		{
			name: "должность с органом-прилагательным: и орган, и имя",
			text: "губернатор Московской области Андрей Воробьёв открыл школу",
			want: []counterExpect{{"Андрей Воробьёв", pii.FullName, true}, {"Московской", pii.Address, true}},
		},
		{
			name: "за одиночной фамилией окно должности кончается",
			text: "министр Толстой заявил, что Иванов Иван опоздал",
			want: []counterExpect{{cfxTolstoy, pii.FullName, true}, {"Иванов Иван", pii.FullName, false}},
		},
		{
			name: "должность без органа (chair) — вето нет",
			text: "председатель ТСЖ Иванова Мария Петровна пришла",
			want: []counterExpect{{cfxIvanovaFull, pii.FullName, false}},
		},
		{
			name: "должность и реквизит в предложении — вето нет",
			text: "министр Сидоров Семён, тел. +7 916 777-88-99",
			want: []counterExpect{{"Сидоров Семён", pii.FullName, false}},
		},
		{
			name: "маркер клиента перед должностью — вето нет",
			text: "Клиент — министр Сидоров Семён Семёнович",
			want: []counterExpect{{"Сидоров Семён Семёнович", pii.FullName, false}},
		},
		{
			name: "чиновник и банковские слова — вето есть",
			text: "Эльвира Набиуллина сообщила о ключевой ставке по вкладам",
			want: []counterExpect{{"Набиуллина", pii.FullName, true}},
		},
		{
			name: "чиновник и операция с лицом — вето нет",
			text: "Перевод от Эльвиры Набиуллиной не дошёл",
			want: []counterExpect{{"Набиуллиной", pii.FullName, false}},
		},
		{
			name: "обычная знаменитость и банковское слово — вето нет, как в T-51",
			text: "Юрий Гагарин хочет открыть вклад",
			want: []counterExpect{{cfxGagarin, pii.FullName, false}},
		},
		{
			name: "юбилей без имени за словом снимает вето по всему предложению",
			text: "Юрий Гагарин совершил полёт — к юбилею выпущена карта",
			want: []counterExpect{{cfxGagarin, pii.FullName, true}},
		},
		{
			name: "юбилей с именем за словом другим вето не даёт",
			text: "Юрий Гагарин хочет карту к юбилею Ивана Петрова",
			want: []counterExpect{{cfxGagarin, pii.FullName, false}, {"Ивана Петрова", pii.FullName, false}},
		},
		{
			name: "памяти — только имя за словом",
			text: "Анна Цой хочет билеты на концерт памяти Виктора Цоя",
			want: []counterExpect{{"Виктора Цоя", pii.FullName, true}, {cfxAnnaTsoi, pii.FullName, false}},
		},
		{
			name: "произведение с заглавной буквы без кавычки — имя",
			text: "Роман Иванов хочет кредит",
			want: []counterExpect{{"Иванов", pii.FullName, false}},
		},
		{
			name: "название в кавычках и автор за ним",
			text: "роман «Анна Каренина» Толстого",
			want: []counterExpect{{"Анна Каренина", pii.FullName, true}, {"Толстого", pii.FullName, true}},
		},
		{
			name: "незакрытая кавычка — вето нет",
			text: "роман «Анна Каренина",
			want: []counterExpect{{"Анна Каренина", pii.FullName, false}},
		},
		{
			name: "почта: точка внутри адреса не рвёт предложение",
			text: "Юрий Гагарин, почта yuri.g1985@example.ru",
			want: []counterExpect{{cfxGagarin, pii.FullName, false}},
		},
		{
			name: "почти — не почта",
			text: "Юрий Гагарин почти долетел",
			want: []counterExpect{{cfxGagarin, pii.FullName, true}},
		},
		{
			name: "оборот «— адрес нашего офиса»: адрес слева",
			text: "Улица Гагарина, дом 5 — адрес нашего офиса",
			want: []counterExpect{{"Гагарина, дом 5", pii.Address, true}},
		},
		{
			name: "без тире оборота нет",
			text: "Клиент спросил адрес нашего офиса",
			want: []counterExpect{{"Клиент спросил", pii.Address, false}},
		},
		{
			name: "маркер человека слева закрывает оборот",
			text: "Клиент живёт на ул. Ленина, 5 — адрес нашего офиса рядом",
			want: []counterExpect{{"Клиент", pii.Address, false}, {cfxLeninHouse, pii.Address, true}},
		},
		{
			name: "партнёр справа окна не открывает",
			text: "Партнёр Иван Петров, тел. +7 916 202-30-40",
			want: []counterExpect{{"+7 916 202-30-40", pii.Phone, false}},
		},
		{
			name: "блок реквизитов: число из групп — одно значение",
			text: "Отделение банка: 620014, Екатеринбург, ул. Малышева, 31, тел. +7 343 000-00-00",
			want: []counterExpect{{"+7 343 000-00-00", pii.Phone, true}, {"ул. Малышева, 31", pii.Address, true}},
		},
		{
			name: "блок реквизитов: посторонний текст закрывает окно",
			text: "Отделение банка на ул. Ленина, д. 5 обслуживает Иванова, тел. +7 916 333-44-55",
			want: []counterExpect{{"ул. Ленина, д. 5", pii.Address, true}, {"+7 916 333-44-55", pii.Phone, false}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkCounterExpect(t, tt.text, tt.want) })
	}
}

// TestCounterDictionaryLabels — метки записей справочников допустимые, а
// органы (метка body) ролью не считаются.
func TestCounterDictionaryLabels(t *testing.T) {
	dicts := counterDicts(t)
	checkCounterDictLabels(t, counterDictRoles, "", counterLabelOffice, counterLabelChair, counterLabelBody, counterLabelFame)
	checkCounterDictLabels(t, counterDictOrg, counterLabelToponym, counterLabelOrg, counterLabelOwner,
		counterLabelMemorial, counterLabelTribute, counterLabelMention, counterLabelWork)
	checkCounterDictLabels(t, counterDictPublic, "", counterLabelOfficial)

	roles := dicts.Table(counterDictRoles)
	checkCounterRoleWords(t, roles, true, "должно быть должностью",
		"министр", "губернатор", "мэр", "председатель", "глава", "депутат", "премьер", "президент")
	checkCounterRoleWords(t, roles, false, "— орган, а не роль",
		"цб", "минфина", "области", "правительства")
	// Партнёр — владелец контакта только слева: окна справа он не открывает.
	if label, _ := dicts.Table(counterDictOrg).Get("партнера"); label != counterLabelOwner {
		t.Errorf("«партнёра»: метка %q, ожидалась %q", label, counterLabelOwner)
	}
}

// checkCounterDictLabels проверяет, что у каждой записи справочника name
// метка из списка allowed.
func checkCounterDictLabels(t *testing.T, name string, allowed ...string) {
	t.Helper()
	for _, e := range counterDictEntries(t, name) {
		if !slices.Contains(allowed, e.label) {
			t.Errorf("%s: %q — неизвестная метка %q", name, e.key, e.label)
		}
	}
}

// checkCounterRoleWords проверяет, что каждое слово считается ролью (want)
// или не считается (!want); why поясняет ожидание в сообщении.
func checkCounterRoleWords(t *testing.T, roles *dict.Table, want bool, why string, words ...string) {
	t.Helper()
	for _, w := range words {
		if counterIsRole(roles, w) != want {
			t.Errorf("%q %s", w, why)
		}
	}
}
