package eval

import (
	"math"
	"testing"

	"qualitycheck/corpus"
)

// Идентификаторы записей в тестах сводки.
const (
	recordID1 = "c-1"
	recordID2 = "c-2"
)

func nearly(got, want float64) bool { return math.Abs(got-want) < 1e-9 }

// typeStatOf возвращает статистику типа или нулевую, если типа в сводке нет.
func typeStatOf(m Metrics, name string) TypeStat {
	for _, ts := range m.Types {
		if ts.Type == name {
			return ts
		}
	}
	return TypeStat{}
}

func TestAggregateTypeMetrics(t *testing.T) {
	results := []RecordResult{
		{
			ID: recordID1, Kind: corpus.KindSingle, Restored: true,
			Spans: []SpanOutcome{
				{RecordID: recordID1, Type: typeFullName, Hidden: true},
				{RecordID: recordID1, Type: typeFullName, Hidden: false, Start: 10, End: 20},
				{RecordID: recordID1, Type: "phone", Hidden: true},
			},
			Traps: []TrapOutcome{
				{RecordID: recordID1, Type: typeFullName, Reason: "toponym", Masked: true},
				{RecordID: recordID1, Type: typeFullName, Reason: "public_figure", Masked: false},
			},
		},
	}

	m := Aggregate(results)

	fullName := typeStatOf(m, typeFullName)
	// TP = 1 скрытое значение, FN = 1 пропуск, FP = 1 сработавшая ловушка.
	if fullName.Hidden != 1 || fullName.Leaked != 1 || fullName.TrapsMasked != 1 {
		t.Fatalf("статистика full_name: %+v", fullName)
	}
	if !nearly(fullName.Precision, 0.5) || !nearly(fullName.Recall, 0.5) || !nearly(fullName.F1, 0.5) {
		t.Errorf("precision %.4f, recall %.4f, F1 %.4f — ожидались 0.5", fullName.Precision, fullName.Recall, fullName.F1)
	}

	// У типа без ловушек источника ложных срабатываний нет, precision равна 1
	// по построению — отчёт обязан показывать это вместе с числом ловушек.
	phone := typeStatOf(m, "phone")
	if phone.Traps != 0 || !nearly(phone.Precision, 1) {
		t.Errorf("статистика phone: %+v", phone)
	}

	if m.Totals.Leaked != 1 || len(m.Leaks) != 1 {
		t.Errorf("утечек %d, в списке %d", m.Totals.Leaked, len(m.Leaks))
	}
	if m.Totals.TrapsMasked != 1 || len(m.FalsePositives) != 1 {
		t.Errorf("ложных срабатываний %d, в списке %d", m.Totals.TrapsMasked, len(m.FalsePositives))
	}
}

func TestAggregateRedundancyAndRestore(t *testing.T) {
	results := []RecordResult{
		{ID: recordID1, Kind: corpus.KindSingle, TextBytes: 100, SpanBytes: 20, MaskedBytes: 30, ExcessBytes: 10, Restored: true, Changed: true},
		{ID: recordID2, Kind: corpus.KindClean, TextBytes: 50, SpanBytes: 0, MaskedBytes: 5, ExcessBytes: 5, Restored: false, Changed: true},
	}
	m := Aggregate(results)

	if m.Redundancy.OutsideBytes != 130 {
		t.Errorf("байтов вне спанов %d, ожидалось 130", m.Redundancy.OutsideBytes)
	}
	if !nearly(m.Redundancy.ExcessOfMasked, 15.0/35.0) {
		t.Errorf("доля избыточного среди замаскированного %.4f", m.Redundancy.ExcessOfMasked)
	}
	if !nearly(m.Redundancy.ExcessOfOutside, 15.0/130.0) {
		t.Errorf("доля текста вне спанов под маской %.4f", m.Redundancy.ExcessOfOutside)
	}
	if m.Redundancy.CleanTotal != 1 || m.Redundancy.CleanChanged != 1 {
		t.Errorf("чистые записи: %d изменено из %d", m.Redundancy.CleanChanged, m.Redundancy.CleanTotal)
	}
	if m.Restore.Failed != 1 || !nearly(m.Restore.Rate, 0.5) {
		t.Errorf("восстановление: сбоев %d, доля %.4f", m.Restore.Failed, m.Restore.Rate)
	}
}

func TestAggregateCountsRunErrors(t *testing.T) {
	results := []RecordResult{
		{ID: recordID1, Kind: corpus.KindSingle, Restored: true},
		{ID: recordID2, Kind: corpus.KindSingle, Err: "прямой шаг: сервис недоступен"},
	}
	m := Aggregate(results)
	if m.Totals.Records != 2 || m.Totals.Evaluated != 1 || m.Totals.Errors != 1 {
		t.Fatalf("итоги: %+v", m.Totals)
	}
	// Запись с ошибкой не попадает в знаменатель восстановления: иначе
	// недоступность сервиса выглядела бы как ошибка демаскирования.
	if m.Restore.Records != 1 {
		t.Errorf("записей в статистике восстановления %d, ожидалась 1", m.Restore.Records)
	}
}

// Значения персональных данных вычищаются из метрик до печати, а не
// скрываются форматированием: в JSON их тоже быть не должно.
func TestRedactRemovesValues(t *testing.T) {
	m := Metrics{
		Leaks:          []Leak{{RecordID: recordID1, Type: typeFullName, Value: testName}},
		FalsePositives: []FalsePositive{{RecordID: recordID2, Reason: "toponym", Value: "Пушкина"}},
	}
	m.Redact()
	if m.Leaks[0].Value != "" || m.FalsePositives[0].Value != "" {
		t.Fatal("значения остались в метриках после Redact")
	}
	if m.Leaks[0].RecordID == "" || m.Leaks[0].Type == "" {
		t.Error("Redact вычистил не только значения")
	}
}

func TestRatioAndF1EdgeCases(t *testing.T) {
	if got := ratio(1, 0); got != 0 {
		t.Errorf("доля при пустом знаменателе %v, ожидался 0", got)
	}
	if got := f1(0, 0); got != 0 {
		t.Errorf("F1 при нулевых precision и recall %v, ожидался 0", got)
	}
	if got := f1(1, 1); !nearly(got, 1) {
		t.Errorf("F1 при единичных precision и recall %v", got)
	}
}

// Верхняя граница recall получается, если считать спорные утечки скрытыми:
// без неё читатель отчёта не может оценить ширину неопределённости.
func TestAggregateRecallUpperBound(t *testing.T) {
	results := []RecordResult{{
		ID: recordID1, Kind: corpus.KindLong, Restored: true,
		Spans: []SpanOutcome{
			{RecordID: recordID1, Type: typeCVV, Hidden: true},
			{RecordID: recordID1, Type: typeCVV, Hidden: false, Ambiguous: true},
			{RecordID: recordID1, Type: typeCVV, Hidden: false},
		},
	}}
	m := Aggregate(results)
	ts := m.Types[0]
	if ts.Leaked != 2 || ts.LeakedAmbiguous != 1 {
		t.Fatalf("статистика типа: %+v", ts)
	}
	if !nearly(ts.Recall, 1.0/3.0) || !nearly(ts.RecallUpper, 2.0/3.0) {
		t.Fatalf("recall %.4f, верхняя граница %.4f", ts.Recall, ts.RecallUpper)
	}
	if !nearly(m.Totals.HideRate, 1.0/3.0) || !nearly(m.Totals.HideRateUpper, 2.0/3.0) {
		t.Fatalf("доля сокрытия %.4f, верхняя граница %.4f", m.Totals.HideRate, m.Totals.HideRateUpper)
	}
	if m.Kinds[0].LeakedAmbiguous != 1 {
		t.Errorf("спорных утечек по виду записей %d", m.Kinds[0].LeakedAmbiguous)
	}
}
