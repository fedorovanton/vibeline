package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"qualitycheck/corpus"
	"qualitycheck/eval"
	"qualitycheck/probe"
)

// Синтетические значения, общие для тестов пакета.
const (
	typeFullName  = "full_name"
	renderFailFmt = "Render: %v"
	kindSingle    = "single"
	reasonToponym = "toponym"
	toponymValue  = "Пушкина"
)

// secret — значение, которое ни при каких условиях не должно оказаться в
// отчёте без -verbose.
const secret = "Петров Пётр Петрович"

func sampleReport() *Report {
	return &Report{
		Tool:    "qualitycheck",
		Version: Version,
		Run: Run{
			RunID: "qc-test", StartedAt: time.Unix(0, 0).UTC(), FinishedAt: time.Unix(1, 0).UTC(),
			DurationSec: 1, Concurrency: 4, TimeoutSec: 10,
		},
		Corpus: Corpus{
			Path: "corpus.jsonl", SHA256: strings.Repeat("a", 64), Bytes: 1024,
			Seed: 20260922, Count: 1200, Long: true,
			Summary: corpus.Summary{Records: 2, Spans: 2, Traps: 1, Kinds: map[string]int{kindSingle: 2}},
		},
		Service: probe.Service{URL: "http://localhost:8080", Version: "dev", Scanners: []string{"name"}},
		Method:  Method(),
		Metrics: eval.Metrics{
			Totals: eval.Totals{Records: 2, Evaluated: 2, Spans: 2, Hidden: 1, Leaked: 1, HideRate: 0.5, Traps: 1, TrapsMasked: 1},
			Types:  []eval.TypeStat{{Type: typeFullName, Spans: 2, Hidden: 1, Leaked: 1, Traps: 1, TrapsMasked: 1, Precision: 0.5, Recall: 0.5, F1: 0.5}},
			Kinds:  []eval.KindStat{{Kind: kindSingle, Records: 2, Spans: 2, Hidden: 1, Leaked: 1}},
			Reasons: []eval.ReasonStat{
				{Reason: reasonToponym, Traps: 1, Masked: 1, Rate: 1},
			},
			Redundancy: eval.Redundancy{TextBytes: 200, SpanBytes: 40, OutsideBytes: 160, MaskedBytes: 50, ExcessBytes: 10, ExcessOfMasked: 0.2, ExcessOfOutside: 0.0625},
			Restore:    eval.Restore{Records: 2, Restored: 2},
			Leaks:      []eval.Leak{{RecordID: "c-1", Kind: kindSingle, Type: typeFullName, Start: 7, End: 47, Value: secret}},
			FalsePositives: []eval.FalsePositive{
				{RecordID: "c-2", Type: typeFullName, Reason: reasonToponym, Start: 3, End: 10, Value: toponymValue},
			},
			Errors: []eval.RunError{{RecordID: "c-3", Error: "прямой шаг: сервис недоступен"}},
		},
	}
}

// Главный инвариант отчёта: без -verbose в нём нет ни одного значения
// персональных данных — только типы, идентификаторы записей и позиции.
func TestRenderHasNoValuesWithoutVerbose(t *testing.T) {
	rep := sampleReport()
	rep.Metrics.Redact()

	var b bytes.Buffer
	if err := rep.Render(&b, false); err != nil {
		t.Fatalf(renderFailFmt, err)
	}
	out := b.String()
	if strings.Contains(out, secret) || strings.Contains(out, toponymValue) {
		t.Fatal("в отчёте без -verbose оказались значения персональных данных")
	}
	for _, want := range []string{"c-1", typeFullName, "[7;47)", reasonToponym} {
		if !strings.Contains(out, want) {
			t.Errorf("в отчёте нет %q", want)
		}
	}
}

func TestWriteJSONHasNoValuesAfterRedact(t *testing.T) {
	rep := sampleReport()
	rep.Metrics.Redact()

	var b bytes.Buffer
	if err := rep.WriteJSON(&b); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if strings.Contains(b.String(), secret) || strings.Contains(b.String(), toponymValue) {
		t.Fatal("в JSON после Redact остались значения персональных данных")
	}
	if !strings.Contains(b.String(), `"sha256"`) {
		t.Error("в JSON нет отпечатка корпуса")
	}
}

// С -verbose значения печатаются — иначе разбирать пропуски невозможно.
func TestRenderShowsValuesWithVerbose(t *testing.T) {
	var b bytes.Buffer
	if err := sampleReport().Render(&b, true); err != nil {
		t.Fatalf(renderFailFmt, err)
	}
	if !strings.Contains(b.String(), secret) {
		t.Fatal("с -verbose значение не напечатано")
	}
}

// Прогоны сравнимы только вместе с происхождением корпуса и версией правил.
func TestRenderCarriesProvenanceAndMethod(t *testing.T) {
	var b bytes.Buffer
	if err := sampleReport().Render(&b, false); err != nil {
		t.Fatalf(renderFailFmt, err)
	}
	out := b.String()
	for _, want := range []string{
		strings.Repeat("a", 64), // отпечаток корпуса
		"-seed 20260922",
		"-count 1200",
		"методика",
		"Сокрытие",
		"RESULT",
		"dev", // версия сервиса
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в отчёте нет %q", want)
		}
	}
}

func TestRenderShowsAllRequiredMetrics(t *testing.T) {
	var b bytes.Buffer
	if err := sampleReport().Render(&b, false); err != nil {
		t.Fatalf(renderFailFmt, err)
	}
	out := b.String()
	for _, want := range []string{"precision", "recall", "F1", "Избыточное маскирование", "Ловушки", "ошибок восстановления"} {
		if !strings.Contains(out, want) {
			t.Errorf("в отчёте нет раздела или столбца %q", want)
		}
	}
}

func TestSortStringsDoesNotMutateInput(t *testing.T) {
	in := []string{"b", "a"}
	out := SortStrings(in)
	if in[0] != "b" {
		t.Error("SortStrings изменил исходный срез")
	}
	if out[0] != "a" {
		t.Error("SortStrings не отсортировал копию")
	}
}
