package detect

import (
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
	"ai-gateway/internal/pii"
)

// Все тексты в этом файле синтетические: имена, номера и учреждения вымышлены,
// реальные персональные данные в репозиторий не попадают (AGENTS.md,
// «Инварианты приватности»).

// Синтетические значения, которые повторяются в нескольких проверках файла.
const (
	miscHolder = "IVAN IVANOV"
	miscPlace  = "г. Казань"
)

func miscDicts(tb testing.TB) *dict.Set {
	tb.Helper()
	set, err := dict.Load()
	if err != nil {
		tb.Fatalf(msgDictLoad, err)
	}
	return set
}

// miscScan прогоняет сканер по тексту и отдаёт найденных кандидатов.
func miscScan(tb testing.TB, dicts *dict.Set, text string) []Span {
	tb.Helper()
	var cand Candidates
	miscScanner{}.Scan(lex.Tokenize(text, nil), dicts, &cand)
	return cand.Spans
}

// miscOnly возвращает единственного кандидата нужного типа.
//
// Кандидаты других типов намеренно не мешают: перекрытия разрешает движок,
// и регистрировать «Россию» внутри названия органа выдачи сканеру не запрещено.
func miscOnly(tb testing.TB, spans []Span, text string, t pii.Type) Span {
	tb.Helper()
	found := -1
	count := 0
	for i, s := range spans {
		if s.Type != t {
			continue
		}
		count++
		found = i
	}
	if count != 1 {
		tb.Fatalf("кандидатов типа %v: %d, ожидался один в %q", t, count, text)
	}
	return spans[found]
}

// miscNone проверяет, что кандидатов указанного типа нет.
func miscNone(tb testing.TB, spans []Span, text string, t pii.Type) {
	tb.Helper()
	for _, s := range spans {
		if s.Type == t {
			tb.Fatalf("кандидат типа %v не ожидался в %q: спан %q", t, text, text[s.Start:s.End])
		}
	}
}

func TestMiscCitizenship(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
		span string
		conf Confidence
	}{
		{"полное название", "гражданство: Российская Федерация", "Российская Федерация", Strong},
		{"аббревиатура", "гражданин РФ", "РФ", Strong},
		{"родительный падеж", "гражданин Российской Федерации", "Российской Федерации", Strong},
		{"женский род маркера", "гражданка Украины", "Украины", Strong},
		// Родовое слово официального названия страны входит в значение:
		// справочник хранит «Республика Казахстан» в именительном падеже, а
		// в тексте склоняется всё название целиком. Оставлять «Республики»
		// снаружи — частичная утечка по строгой метрике сокрытия (T-29).
		{"родовое слово в названии страны", "гражданка Республики Казахстан",
			"Республики Казахстан", Strong},
		{"родовое слово в именительном падеже", "гражданство: Республика Беларусь",
			"Республика Беларусь", Strong},
		{"родовое слово в творительном падеже", "подданство Королевством Испания",
			"Королевством Испания", Strong},
		{"подданство", "подданство Великобритании", "Великобритании", Strong},
		{"прилагательное", "гражданство российское", "российское", Strong},
		{"верхний регистр", "ГРАЖДАНСТВО: РОССИЙСКАЯ ФЕДЕРАЦИЯ", "РОССИЙСКАЯ ФЕДЕРАЦИЯ", Strong},
		{"тире после маркера", "Гражданство — Узбекистан", "Узбекистан", Strong},
		{"без маркера", "поставки в Казахстан", "Казахстан", Weak},
		{"аббревиатура без маркера", "перевод средств в РФ", "РФ", Weak},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := miscOnly(t, miscScan(t, dicts, tt.text), tt.text, pii.Citizenship)
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
			if s.Conf != tt.conf {
				t.Errorf(msgConfWant, s.Conf, tt.conf)
			}
		})
	}
}

// TestMiscCitizenshipRejected фиксирует контексты, в которых название страны
// обозначает учреждение или географию, а не гражданство человека.
func TestMiscCitizenshipRejected(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
	}{
		{"ведомство", "обращение в МВД России рассмотрено"},
		{"предлог по", "доставка по России занимает неделю"},
		{"банк", "Банк России опубликовал ставку"},
		{"гражданский иск", "подан гражданский иск"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			miscNone(t, miscScan(t, dicts, tt.text), tt.text, pii.Citizenship)
		})
	}
}

func TestMiscBirthPlace(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
		span string
	}{
		{"место рождения", "место рождения: г. Казань", miscPlace},
		{"полное обозначение", "Место рождения — город Новосибирск", "город Новосибирск"},
		{"родился в", "родился в Новосибирске", "Новосибирске"},
		{"родилась в", "родилась в г. Твери", "г. Твери"},
		{"уроженец", "уроженец Казани", "Казани"},
		{"уроженка села", "уроженка с. Ивановка", "с. Ивановка"},
		{"сокращение м.р.", "м.р. г. Казань", miscPlace},
		{"с регионом", "место рождения: г. Казань, Республика Татарстан", "г. Казань, Республика Татарстан"},
		{"с областью", "родился в Клину Московской области", "Клину Московской области"},
		{"составное название", "родился в Комсомольске-на-Амуре", "Комсомольске-на-Амуре"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := miscOnly(t, miscScan(t, dicts, tt.text), tt.text, pii.BirthPlace)
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
			if s.Conf != Strong {
				t.Errorf(msgConfWant, s.Conf, Strong)
			}
		})
	}
}

// TestMiscBirthPlaceRejected: город без маркера рождения местом рождения не
// является, иначе любой топоним в тексте стал бы персональными данными.
func TestMiscBirthPlaceRejected(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
	}{
		{"переезд", "переехал в Новосибирск в прошлом году"},
		{"работа", "работает в Казани третий год"},
		{"город сам по себе", "Казань принимает форум"},
		{"значение не указано", "место рождения не указано"},
		{"дата без топонима", "родился 12.05.1990"},
		{"доставка", "доставка в Тверь занимает два дня"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			miscNone(t, miscScan(t, dicts, tt.text), tt.text, pii.BirthPlace)
		})
	}
}

func TestMiscPassportAuthority(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
		span string
	}{
		{"с датой выдачи", "паспорт выдан ГУ МВД России по г. Москве 20.03.2015", "ГУ МВД России по г. Москве"},
		{"область", "выдан УФМС России по Тверской области", "УФМС России по Тверской области"},
		{"кем выдан", "кем выдан: ОВД Центрального района г. Москвы", "ОВД Центрального района г. Москвы"},
		{"служебное слово перед органом", "выдано отделом УФМС России, дата 20.03.2015", "УФМС России"},
		{"конец предложения", "Паспорт выдан ТП УФМС России по Тверской области. Далее текст.", "ТП УФМС России по Тверской области"},
		{"нижний регистр", "паспорт выдан увд города Твери", "увд города Твери"},
		{"код подразделения следом", "выдан ОМВД России по району 770-001", "ОМВД России по району"},
		// Дата выдачи словами состоит из обычных слов, и цифровой группы, на
		// которой разбор останавливался, в ней нет. Без отдельной остановки
		// название тянулось по словам даты, упиралось в предел длины и
		// обрывало дату: последнее её слово оставалось вне обоих спанов и
		// уходило в модель открытым (T-29).
		{"дата выдачи словами следом",
			"паспорт выдан ГУ МВД России по Свердловской области двадцать пятого декабря две тысячи седьмого, код подразделения 770-053",
			"ГУ МВД России по Свердловской области"},
		{"месяц словами следом",
			"выдан УФМС России по Тверской области марта две тысячи седьмого",
			"УФМС России по Тверской области"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := miscOnly(t, miscScan(t, dicts, tt.text), tt.text, pii.PassportAuthority)
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
			if s.Conf != Strong {
				t.Errorf(msgConfWant, s.Conf, Strong)
			}
		})
	}
}

func TestMiscPassportAuthorityRejected(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
	}{
		{"нет органа в справочнике", "выдан сотрудником отделения банка"},
		{"справка", "справка выдана бухгалтерией"},
		{"нет маркера", "ГУ МВД России по г. Москве проводит приём"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			miscNone(t, miscScan(t, dicts, tt.text), tt.text, pii.PassportAuthority)
		})
	}
}

func TestMiscCardHolder(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
		span string
		conf Confidence
	}{
		{"маркер слева", "Держатель карты IVAN IVANOV", miscHolder, Strong},
		{"cardholder", "Cardholder: IVAN PETROV", "IVAN PETROV", Strong},
		{"имя на карте", "имя на карте PETR SIDOROV", "PETR SIDOROV", Strong},
		{"рядом номер карты", "IVAN IVANOV, карта 2200 7001 2345 6781", miscHolder, Strong},
		{"номер слитно", "IVAN IVANOV 2200700123456781", miscHolder, Strong},
		{"три слова", "Держатель IVAN IVANOVICH IVANOV", "IVAN IVANOVICH IVANOV", Strong},
		{"без маркера и без карты", "PETR PETROV", "PETR PETROV", Weak},
		{"служебные слова перед именем", "CARD HOLDER IVAN IVANOV", miscHolder, Strong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := miscOnly(t, miscScan(t, dicts, tt.text), tt.text, pii.CardHolder)
			if got := tt.text[s.Start:s.End]; got != tt.span {
				t.Errorf(msgSpanWant, got, tt.span)
			}
			if s.Conf != tt.conf {
				t.Errorf(msgConfWant, s.Conf, tt.conf)
			}
		})
	}
}

// TestMiscCardHolderRejected: аббревиатуры реквизитов и технические сокращения
// набираются заглавной латиницей ровно так же, как имя на карте.
func TestMiscCardHolderRejected(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
	}{
		{"cvv и pin", "CVV PIN"},
		{"api и json", "API JSON"},
		{"http и pdf", "HTTP PDF"},
		{"sms и url", "SMS URL"},
		{"ok и id", "OK ID"},
		{"платёжная система", "VISA CLASSIC"},
		{"три аббревиатуры", "JSON API HTTP"},
		{"одно слово", "PIN IVANOV"},
		{"нижний регистр", "держатель карты ivan ivanov"},
		{"кириллица", "ДЕРЖАТЕЛЬ ИВАН ИВАНОВ"},
		{"слишком длинный ряд", "PLEASE SEND ME THE REPORT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			miscNone(t, miscScan(t, dicts, tt.text), tt.text, pii.CardHolder)
		})
	}
}

// TestMiscExtendedFormsEngine — входы T-65 на полном конвейере (T-65,
// строки 6, 7, 8, 11): орган выдачи после даты выдачи, город рождения после
// даты, держатель латиницей в обычном регистре, «РФ» в названии документа.
func TestMiscExtendedFormsEngine(t *testing.T) {
	cases := []struct{ name, text, want string }{
		{"орган после даты словами",
			"Паспорт 4618 507329 выдан 14 марта 2019 г. ГУ МВД России по Республике Татарстан, код подр. 160-004",
			"Паспорт [ПАСПОРТ] выдан [ДАТА_ВЫДАЧИ] г. [ОРГАН_ВЫДАЧИ], код подр. [КОД_ПОДРАЗДЕЛЕНИЯ]"},
		{"орган после даты цифрами",
			"Паспорт 4618 507329 выдан 02.09.2016 ОУФМС России по г. Москве, код подразделения 770-095",
			"Паспорт [ПАСПОРТ] выдан [ДАТА_ВЫДАЧИ] [ОРГАН_ВЫДАЧИ], код подразделения [КОД_ПОДРАЗДЕЛЕНИЯ]"},
		{"город рождения после даты", "Родился 27.03.1988 в Новосибирске.",
			"Родился [ДАТА_РОЖДЕНИЯ] в [МЕСТО_РОЖДЕНИЯ]."},
		{"город рождения после даты словами", "Кузьмин Роман Олегович родился 03 мая 1988 года в г. Туле.",
			"[ФИО] родился [ДАТА_РОЖДЕНИЯ] года в [МЕСТО_РОЖДЕНИЯ]."},
		{"держатель в обычном регистре", "Имя на карте Daria Shapovalova, номер 2200 7012 3456 7896",
			"Имя на карте [ДЕРЖАТЕЛЬ_КАРТЫ], номер [КАРТА]"},
		{"держатель после маркера", "Держатель карты: Ivan Petrov", "Держатель карты: [ДЕРЖАТЕЛЬ_КАРТЫ]"},
		{"держатель заглавными как раньше", "Держатель карты: ARSEN MKRTCHYAN, карта 4276 0198 7654 3215",
			"Держатель карты: [ДЕРЖАТЕЛЬ_КАРТЫ], карта [КАРТА]"},
		{"РФ в названии документа", "Паспорт РФ № 4618507329", "Паспорт РФ № [ПАСПОРТ]"},
		{"паспорт гражданина РФ", "Паспорт гражданина РФ: 4618 507329", "Паспорт гражданина [ГРАЖДАНСТВО]: [ПАСПОРТ]"},
		{"гражданство РФ", "Клиент Петров Иван, гражданство: РФ", "Клиент [ФИО], гражданство: [ГРАЖДАНСТВО]"},
		// Попутно закрытые классы корпуса качества: дата словами между
		// «родился» и «в городе», вставка между «место рождения» и
		// значением, регион после запятой, орган после «подразделение».
		{"город рождения после даты словами и г.",
			"Заполни карточку клиента: Мельник Олег, родился девятого июня 1961 г. в городе Кинешма, почта m@example.com.",
			"Заполни карточку клиента: [ФИО], родился [ДАТА_РОЖДЕНИЯ] г. в [МЕСТО_РОЖДЕНИЯ], почта [EMAIL]."},
		{"вставка после место рождения", "Место рождения в заявлении — Шадринск. Это влияет на проверку?",
			"Место рождения в заявлении — [МЕСТО_РОЖДЕНИЯ]. Это влияет на проверку?"},
		{"графа место рождения", "В анкете графа «место рождения» заполнена как Ливны — сверь с паспортом.",
			"В анкете графа «место рождения» заполнена как [МЕСТО_РОЖДЕНИЯ] — сверь с паспортом."},
		{"регион после запятой", "Укажи в справке место рождения: ст. Лесная, Ростовская область.",
			"Укажи в справке место рождения: [МЕСТО_РОЖДЕНИЯ]."},
		{"орган после подразделение", "Уточни, действует ли ещё подразделение УМВД России по Псковской области.",
			"Уточни, действует ли ещё подразделение [ОРГАН_ВЫДАЧИ]."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { expectPipelineMask(t, c.text, c.want) })
	}
}

// TestMiscExtendedFormsRejected — новые правила не заводят кандидатов там, где их
// нет: держатель в обычном регистре без маркера и названия продуктов после
// маркера, место рождения после даты без «родился».
func TestMiscExtendedFormsRejected(t *testing.T) {
	dicts := miscDicts(t)
	for _, tt := range []struct {
		text string
		typ  pii.Type
	}{
		{"Client Daria Shapovalova просит перевыпуск", pii.CardHolder},
		{"Оплата картой Apple Pay прошла", pii.CardHolder},
		{"На карте Visa Signature кешбэк выше", pii.CardHolder},
		{"Заявка от 27.03.1988 в Новосибирске рассмотрена", pii.BirthPlace},
		{"Договор заключён 27.03.2018 в Москве", pii.BirthPlace},
		{"место рождения не указано, Москва подтвердит позже", pii.BirthPlace},
		{"место рождения клиента проверено сотрудником отделения банка Москва", pii.BirthPlace},
		{"родился в Москве, Иван Петров подписал", pii.CardHolder},
		{"код подразделения 770-001", pii.PassportAuthority},
		{"подразделение банка на Тверской закрыто", pii.PassportAuthority},
	} {
		miscNone(t, miscScan(t, dicts, tt.text), tt.text, tt.typ)
	}
}

// TestMiscSpanByteOffsets проверяет, что смещения спана байтовые: кириллическая
// буква занимает два байта, и вырезка по Start:End обязана дать ровно значение.
func TestMiscSpanByteOffsets(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		name string
		text string
		span string
		typ  pii.Type
	}{
		{"гражданство", "гражданство: Российская Федерация", "Российская Федерация", pii.Citizenship},
		{"место рождения", "место рождения: г. Казань", miscPlace, pii.BirthPlace},
		{"орган выдачи", "паспорт выдан ГУ МВД России по г. Москве 20.03.2015", "ГУ МВД России по г. Москве", pii.PassportAuthority},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := lex.Tokenize(tt.text, nil)
			var cand Candidates
			miscScanner{}.Scan(doc, dicts, &cand)
			s := miscOnly(t, cand.Spans, tt.text, tt.typ)
			want := strings.Index(tt.text, tt.span)
			if int(s.Start) != want {
				t.Errorf(msgSpanStartWant, s.Start, want)
			}
			if int(s.End) != want+len(tt.span) {
				t.Errorf(msgSpanEndWant, s.End, want+len(tt.span))
			}
			// Вырезка из исходного текста документа, а не из литерала:
			// именно её получит маскирование.
			if got := doc.Text[s.Start:s.End]; got != tt.span {
				t.Errorf("вырезка %q, ожидалась %q", got, tt.span)
			}
		})
	}
}

// TestMiscWithoutGeoCities: справочник городов ведёт соседняя задача, и его
// может ещё не быть в сборке. Отсутствие справочника не должно ни ронять
// сканер, ни терять типы — топоним распознаётся и по капитализации.
func TestMiscWithoutGeoCities(t *testing.T) {
	sets := []struct {
		name  string
		dicts *dict.Set
	}{
		{"без набора вовсе", nil},
		{"пустой набор", &dict.Set{}},
		{"встроенные справочники", miscDicts(t)},
	}
	for _, s := range sets {
		t.Run(s.name, func(t *testing.T) {
			if tab := s.dicts.Table("geo_cities"); tab != nil && tab.Len() == 0 {
				t.Fatalf("справочник geo_cities загружен пустым")
			}
			const birth = "родился в Новосибирске"
			b := miscOnly(t, miscScan(t, s.dicts, birth), birth, pii.BirthPlace)
			if got := birth[b.Start:b.End]; got != "Новосибирске" {
				t.Errorf("спан места рождения %q", got)
			}
			const holder = "Держатель карты IVAN IVANOV"
			h := miscOnly(t, miscScan(t, s.dicts, holder), holder, pii.CardHolder)
			if got := holder[h.Start:h.End]; got != miscHolder {
				t.Errorf("спан держателя карты %q", got)
			}
		})
	}
}

// TestMiscDictSizes фиксирует нижнюю границу наполнения справочников: пустой
// или урезанный справочник — это молчаливый пропуск персональных данных.
func TestMiscDictSizes(t *testing.T) {
	dicts := miscDicts(t)
	tests := []struct {
		table string
		least int
	}{
		{miscCitizenshipTable, 180},
		{miscAuthorityTable, 25},
	}
	for _, tt := range tests {
		t.Run(tt.table, func(t *testing.T) {
			if n := dicts.Table(tt.table).Len(); n < tt.least {
				t.Errorf("записей в справочнике %s: %d, ожидалось не меньше %d", tt.table, n, tt.least)
			}
		})
	}
}

// TestMiscRegistered проверяет, что сканер подключается сам, без правки
// общего списка.
func TestMiscRegistered(t *testing.T) {
	for _, s := range Registered() {
		if s.Name() == "misc" {
			return
		}
	}
	t.Fatal("сканер misc не зарегистрирован")
}

// TestMiscScanNoAllocs фиксирует требование горячего пути: разбор идёт по
// токенам и срезам Norm, временных строк не собирается.
func TestMiscScanNoAllocs(t *testing.T) {
	doc := lex.Tokenize(miscBenchText, nil)
	dicts := miscDicts(t)
	var cand Candidates
	s := miscScanner{}
	s.Scan(doc, dicts, &cand)
	if len(cand.Spans) == 0 {
		t.Fatal("в тексте не найдено ни одного кандидата")
	}
	got := testing.AllocsPerRun(20, func() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	})
	if got != 0 {
		t.Errorf(msgAllocsWant, got)
	}
}

// TestMiscExtendedFormsNoAllocs — ветки T-65 (дата между маркером и значением,
// вставка после «место рождения», держатель в обычном регистре) не
// аллоцируют.
func TestMiscExtendedFormsNoAllocs(t *testing.T) {
	const text = "Паспорт выдан 14 марта 2019 г. ГУ МВД России по Республике Татарстан. " +
		"Родился 27.03.1988 в Новосибирске. Место рождения в заявлении — Шадринск. " +
		"Имя на карте Daria Shapovalova, номер 2200 7012 3456 7896. Паспорт РФ № 4618507329. " +
		"Родилась двенадцатого января тысяча девятьсот семьдесят третьего в городе Сыктывкар."
	doc := lex.Tokenize(text, nil)
	dicts := miscDicts(t)
	var cand Candidates
	s := miscScanner{}
	s.Scan(doc, dicts, &cand)
	if got := testing.AllocsPerRun(20, func() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}); got != 0 {
		t.Errorf(msgAllocsWant, got)
	}
}

// miscBenchBlock — синтетический фрагмент со всеми ветками разбора.
const miscBenchBlock = "Анкета клиента: гражданство Российская Федерация, место рождения г. Казань, " +
	"Республика Татарстан. Паспорт выдан ГУ МВД России по г. Москве 20.03.2015. " +
	"Второй заявитель — гражданин Республики Казахстан, уроженец с. Ивановка, родился в Новосибирске. " +
	"Держатель карты IVAN IVANOV, карта 2200 7001 2345 6781; CVV PIN API JSON именами не являются. " +
	"Поставки в Казахстан и доставка по России гражданством не являются.\n"

var miscBenchText = strings.Repeat(miscBenchBlock, 4096/len(miscBenchBlock)+1)

func BenchmarkScanMisc(b *testing.B) {
	if len(miscBenchText) < 4096 || len(miscBenchText) > 8192 {
		b.Fatalf(msgBenchTextSize, len(miscBenchText))
	}
	doc := lex.Tokenize(miscBenchText, nil)
	dicts := miscDicts(b)
	var cand Candidates
	s := miscScanner{}
	// Прогрев: накопитель набирает ёмкость, чтобы в измерении остался только
	// разбор. Аллокаций в Scan быть не должно.
	s.Scan(doc, dicts, &cand)
	if len(cand.Spans) == 0 {
		b.Fatal("в тексте бенчмарка не найдено ни одного кандидата")
	}
	b.SetBytes(int64(len(miscBenchText)))
	b.ReportAllocs()
	for b.Loop() {
		cand.Reset()
		s.Scan(doc, dicts, &cand)
	}
}

// TestMiscCardHolderLinearTime — строка из повторов имени держателя без
// границ предложения разбирается за линейное время (С-2 проверки качества
// кода 23.09: до правки — квадратичное).
func TestMiscCardHolderLinearTime(t *testing.T) {
	text := strings.Repeat("IVAN PETROV, ", 60000)
	dicts := miscDicts(t)
	start := time.Now()
	miscScan(t, dicts, text)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("разбор %d байт занял %s — похоже на квадратичное время", len(text), d)
	}
}
