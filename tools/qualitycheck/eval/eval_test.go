package eval

import (
	"errors"
	"strings"
	"testing"

	"qualitycheck/corpus"
)

// Синтетические типы и значения, общие для тестов пакета.
const (
	typeFullName   = "full_name"
	typePassport   = "passport_number"
	typeCVV        = "cvv"
	testName       = "Петров Пётр"
	passportSeries = "4509"
	passportNumber = "123456"
	testCVV        = "595"
)

// record собирает запись, вычисляя байтовые смещения по тексту.
func record(t *testing.T, id, kind, text string, spans []corpus.Span, traps []corpus.Trap) corpus.Record {
	t.Helper()
	for i := range spans {
		at := strings.Index(text, spans[i].Value)
		if at < 0 {
			t.Fatalf("значение спана %q не найдено", spans[i].Type)
		}
		spans[i].Start, spans[i].End = at, at+len(spans[i].Value)
	}
	for i := range traps {
		at := strings.Index(text, traps[i].Value)
		if at < 0 {
			t.Fatalf("значение ловушки %q не найдено", traps[i].Reason)
		}
		traps[i].Start, traps[i].End = at, at+len(traps[i].Value)
	}
	return corpus.Record{ID: id, Kind: kind, Text: text, Spans: spans, Traps: traps}
}

func TestEvaluateHiddenAndLeaked(t *testing.T) {
	text := "Клиент Петров Пётр, почта petrov@example.org, звони на +7 900 000-00-00."
	rec := record(t, "c-1", corpus.KindMulti, text, []corpus.Span{
		{Type: typeFullName, Value: testName},
		{Type: "email", Value: "petrov@example.org"},
		{Type: "phone", Value: "+7 900 000-00-00"},
	}, nil)

	// Почта осталась в ответе — это утечка, хотя остальные значения скрыты.
	masked := "Клиент [ФИО_1], почта petrov@example.org, звони на [ТЕЛЕФОН_1]."
	res := Evaluate(&rec, masked, text)

	hidden := map[string]bool{}
	for _, s := range res.Spans {
		hidden[s.Type] = s.Hidden
	}
	if !hidden[typeFullName] || !hidden["phone"] {
		t.Errorf("скрытые значения определены неверно: %v", hidden)
	}
	if hidden["email"] {
		t.Error("оставшаяся в ответе почта не распознана как утечка")
	}
	if !res.Restored {
		t.Error("побайтовое восстановление не засчитано")
	}
}

// Сравнение целых строк пропускает частичную утечку: ответ отличается от
// оригинала, но значение из него никуда не делось.
func TestEvaluateCatchesPartialLeak(t *testing.T) {
	text := "Карта 2200 0013 1881 8301, CVV 595."
	rec := record(t, "c-2", corpus.KindMulti, text, []corpus.Span{
		{Type: "card_number", Value: "2200 0013 1881 8301"},
		{Type: typeCVV, Value: testCVV},
	}, nil)

	masked := "Карта 2200 0013 1881 8301, CVV [CVV_1]."
	res := Evaluate(&rec, masked, text)
	if !res.Changed {
		t.Fatal("ответ отличается от оригинала, а Changed ложно")
	}
	for _, s := range res.Spans {
		if s.Type == "card_number" && s.Hidden {
			t.Error("номер карты остался в ответе, но засчитан как скрытый")
		}
	}
}

// Частичное маскирование целую строку значения из ответа убирает, поэтому
// поиск подстроки его не ловит. Ровно на этом отчёт показывал по датам
// рождения единицу, пока день уходил в модель открытым.
func TestEvaluateCatchesSurvivingFragment(t *testing.T) {
	text := "Клиент родился двенадцатого марта 1987 года."
	rec := record(t, "c-4", corpus.KindSingle, text, []corpus.Span{
		{Type: "birth_date", Value: "двенадцатого марта 1987"},
	}, nil)

	masked := "Клиент родился двенадцатого [ДАТА_РОЖДЕНИЯ_1] года."
	res := Evaluate(&rec, masked, text)
	if len(res.Spans) != 1 {
		t.Fatalf("итогов по спанам %d, ожидался один", len(res.Spans))
	}
	if res.Spans[0].Hidden {
		t.Error("день остался в ответе, но значение засчитано скрытым")
	}
	if !res.Spans[0].Partial {
		t.Error("утечка не помечена частичной")
	}
}

// Обратный контроль: значение, скрытое целиком, частичной утечкой не
// считается. Без этой проверки порог можно было бы выставить так, что
// приблизительное выравнивание объявляло бы утечкой каждое второе значение.
func TestEvaluateFullMaskingIsNotPartial(t *testing.T) {
	text := "Клиент родился двенадцатого марта 1987 года."
	rec := record(t, "c-5", corpus.KindSingle, text, []corpus.Span{
		{Type: "birth_date", Value: "двенадцатого марта 1987"},
	}, nil)

	masked := "Клиент родился [ДАТА_РОЖДЕНИЯ_1] года."
	res := Evaluate(&rec, masked, text)
	if !res.Spans[0].Hidden {
		t.Error("значение скрыто целиком, но засчитано утечкой")
	}
	if res.Spans[0].Partial {
		t.Error("значение скрыто целиком, но помечено частичной утечкой")
	}
}

// Одно и то же значение может стоять в записи дважды. Если скрыто только одно
// вхождение, скрытым обязано считаться ровно одно значение, а не оба и не ноль.
func TestEvaluateCountsDuplicateValues(t *testing.T) {
	text := "Петров Пётр в заявке; повторно Петров Пётр в анкете."
	rec := record(t, "c-3", corpus.KindMulti, text, []corpus.Span{
		{Type: typeFullName, Value: testName, Start: 0, End: len(testName)},
		{Type: typeFullName, Value: testName, Start: strings.LastIndex(text, testName), End: strings.LastIndex(text, testName) + len(testName)},
	}, nil)

	masked := "[ФИО_1] в заявке; повторно Петров Пётр в анкете."
	res := Evaluate(&rec, masked, text)

	hidden := 0
	for _, s := range res.Spans {
		if s.Hidden {
			hidden++
		}
	}
	if hidden != 1 {
		t.Fatalf("скрытых значений %d, ожидалось 1", hidden)
	}
}

func TestEvaluateTraps(t *testing.T) {
	text := "Ближайшее отделение — на улице Пушкина, клиент Пушкин Олег Петрович ждёт."
	rec := record(t, "c-4", corpus.KindNamesake, text,
		[]corpus.Span{{Type: typeFullName, Value: "Пушкин Олег Петрович"}},
		[]corpus.Trap{{Type: typeFullName, Reason: "toponym", Value: "Пушкина"}})

	// Топоним замаскирован ошибочно, однофамилец скрыт правильно.
	masked := "Ближайшее отделение — на улице [ФИО_2], клиент [ФИО_1] ждёт."
	res := Evaluate(&rec, masked, text)
	if len(res.Traps) != 1 || !res.Traps[0].Masked {
		t.Fatalf("ловушка не распознана как сработавшая: %+v", res.Traps)
	}
	if !res.Spans[0].Hidden {
		t.Error("значение однофамильца не засчитано как скрытое")
	}
}

func TestEvaluateTrapNotMasked(t *testing.T) {
	text := "Ближайшее отделение — на улице Пушкина, уточни часы."
	rec := record(t, "c-5", corpus.KindTrap, text, nil,
		[]corpus.Trap{{Type: typeFullName, Reason: "toponym", Value: "Пушкина"}})

	res := Evaluate(&rec, text, text)
	if res.Traps[0].Masked {
		t.Error("нетронутая ловушка засчитана как сработавшая")
	}
	if res.Changed {
		t.Error("ответ равен оригиналу, а Changed истинно")
	}
}

func TestEvaluateRedundancy(t *testing.T) {
	text := "Паспорт серия 4509 номер 123456 выдан отделом."
	rec := record(t, "c-6", corpus.KindSingle, text, []corpus.Span{
		{Type: typePassport, Value: passportSeries},
		{Type: typePassport, Value: passportNumber},
	}, nil)

	// Детектор накрыл маской служебные слова «серия» и «номер» — это ровно тот
	// случай избыточности, который штрафуется отдельной проверкой (A4.5).
	masked := "Паспорт [ПАСПОРТ_1] выдан отделом."
	res := Evaluate(&rec, masked, text)
	if res.ExcessBytes == 0 {
		t.Fatal("маскирование служебных слов не попало в избыточность")
	}
	if res.ExcessBytes > res.MaskedBytes {
		t.Fatalf("избыточных байтов %d больше замаскированных %d", res.ExcessBytes, res.MaskedBytes)
	}
	if res.SpanBytes != len(passportSeries)+len(passportNumber) {
		t.Errorf("байтов в спанах %d", res.SpanBytes)
	}
}

// Точные границы избыточности не дают: если маска легла ровно по значениям,
// избыточных байтов нет.
func TestEvaluateNoRedundancyOnExactBoundaries(t *testing.T) {
	text := "Паспорт серия 4509 номер 123456 выдан отделом."
	rec := record(t, "c-7", corpus.KindSingle, text, []corpus.Span{
		{Type: typePassport, Value: passportSeries},
		{Type: typePassport, Value: passportNumber},
	}, nil)

	masked := "Паспорт серия [ПАСПОРТ_1] номер [ПАСПОРТ_2] выдан отделом."
	res := Evaluate(&rec, masked, text)
	if res.ExcessBytes != 0 {
		t.Fatalf("избыточных байтов %d, ожидался 0", res.ExcessBytes)
	}
}

func TestEvaluateRestoreMismatch(t *testing.T) {
	text := "Клиент Петров Пётр."
	rec := record(t, "c-8", corpus.KindSingle, text, []corpus.Span{{Type: typeFullName, Value: testName}}, nil)
	res := Evaluate(&rec, "Клиент [ФИО_1].", "Клиент Петров Пётр")
	if res.Restored {
		t.Error("ответ без точки засчитан как побайтово восстановленный")
	}
}

func TestEvaluateFullyMasked(t *testing.T) {
	text := "Иванов Иван Иванович"
	rec := record(t, "c-9", corpus.KindSingle, text, []corpus.Span{{Type: typeFullName, Value: "Иванов Иван Иванович"}}, nil)
	res := Evaluate(&rec, "[ФИО_1]", text)
	if !res.FullyMasked {
		t.Error("текст изменён целиком, а FullyMasked ложно")
	}
	// Весь текст — одно значение, избыточным такое маскирование не считается (A4.4).
	if res.ExcessBytes != 0 {
		t.Errorf("избыточных байтов %d, ожидался 0", res.ExcessBytes)
	}
}

func TestFailedKeepsRecordIdentity(t *testing.T) {
	rec := corpus.Record{ID: "c-10", Kind: corpus.KindSingle, Text: "текст"}
	res := Failed(&rec, errors.New("сервис недоступен"))
	if res.ID != "c-10" || res.Err == "" {
		t.Fatalf("итог неудачной записи: %+v", res)
	}
}

// Короткое значение может случайно встретиться в тексте и вне разметки. Отличить
// уцелевший спан от обычного текста подсчётом вхождений нельзя, поэтому такой
// спан обязан быть помечен спорным, а не молча ухудшать или улучшать цифры.
func TestEvaluateMarksAmbiguousValues(t *testing.T) {
	text := "В форме оплаты поле CVV заполнено как 595, сумма 595 рублей."
	rec := record(t, "c-11", corpus.KindSingle, text, []corpus.Span{{Type: typeCVV, Value: testCVV}}, nil)

	masked := "В форме оплаты поле CVV заполнено как [CVV_1], сумма 595 рублей."
	res := Evaluate(&rec, masked, text)
	if !res.Spans[0].Ambiguous {
		t.Fatal("значение встречается вне разметки, но спан не помечен спорным")
	}
	if res.Ambiguous != 1 {
		t.Errorf("спорных спанов %d, ожидался 1", res.Ambiguous)
	}
	// Трактовка в худшую сторону: оставшееся вхождение засчитано как утечка.
	if res.Spans[0].Hidden {
		t.Error("спорный спан засчитан скрытым, ожидалась трактовка в худшую сторону")
	}
}

func TestEvaluateUnambiguousValueIsNotMarked(t *testing.T) {
	text := "В форме оплаты поле CVV заполнено как 595, проверь тикет."
	rec := record(t, "c-12", corpus.KindSingle, text, []corpus.Span{{Type: typeCVV, Value: testCVV}}, nil)
	res := Evaluate(&rec, "В форме оплаты поле CVV заполнено как [CVV_1], проверь тикет.", text)
	if res.Spans[0].Ambiguous || res.Ambiguous != 0 {
		t.Fatal("однозначное значение помечено спорным")
	}
	if !res.Spans[0].Hidden {
		t.Error("значение скрыто, но не засчитано")
	}
}
