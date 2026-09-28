package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Пометка недостоверного прогона и операция в тестах отчёта.
const (
	tagInvalid = "НЕДОСТОВЕРНО"
	testOpMask = "mask"
)

func sampleReport(t *testing.T) *report {
	t.Helper()
	f := newFakeGateway()
	srv := httptest.NewServer(f)
	defer srv.Close()

	o := options{
		url:      srv.URL + processPath,
		conns:    4,
		duration: 600 * time.Millisecond,
		ramp:     100 * time.Millisecond,
		timeout:  5 * time.Second,
		mode:     modeMixed,
		seed:     1,
		quiet:    true,
	}
	c, err := buildCorpus("", modeMixed, 1)
	if err != nil {
		t.Fatal(err)
	}
	res := runClosedLoop(context.Background(), runConfig{
		URL: o.url, Conns: o.conns, Duration: o.duration, Ramp: o.ramp,
		Timeout: o.timeout, Mode: o.mode, Seed: o.seed,
	}, c, nil)
	return buildReport(context.Background(), reportInput{opts: o, corpus: c, res: res, pidNote: "цель не локальная"})
}

// TestReportStatesClosedLoopCeiling — AC-4. Соотношение «соединения /
// латентность = RPS» и объяснение предела обязаны быть напечатаны: без них
// цифру RPS прочитают как ёмкость сервиса.
func TestReportStatesClosedLoopCeiling(t *testing.T) {
	var buf bytes.Buffer
	sampleReport(t).writeText(&buf)
	out := buf.String()

	for _, want := range []string{
		"ПРЕДЕЛ ЗАКРЫТОГО КОНТУРА",
		"соединения / средняя латентность",
		"ограничивает конкурентность клиента, а не ёмкость сервиса",
		"фактический goodput",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("в отчёте нет фрагмента %q", want)
		}
	}
}

// TestReportStatesConditions — AC-6. Без условий измерения цифры несравнимы.
func TestReportStatesConditions(t *testing.T) {
	var buf bytes.Buffer
	sampleReport(t).writeText(&buf)
	out := buf.String()

	for _, want := range []string{
		"УСЛОВИЯ ИЗМЕРЕНИЯ",
		"Версия Go (клиент)",
		"Ядер CPU",
		"Оперативная память",
		"Соединений",
		"Длительность",
		"СОСТАВ НАГРУЗКИ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("в отчёте нет условия измерения %q", want)
		}
	}
}

// TestReportSplitsPercentilesByOperation — AC-3.
func TestReportSplitsPercentilesByOperation(t *testing.T) {
	rep := sampleReport(t)
	var ops []string
	for _, s := range rep.Client {
		ops = append(ops, s.Op)
	}
	want := []string{testOpMask, "unmask", "итого"}
	if len(ops) != len(want) {
		t.Fatalf("операций в отчёте %v, ожидалось %v", ops, want)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("операции в отчёте %v, ожидалось %v", ops, want)
		}
	}
	var buf bytes.Buffer
	rep.writeText(&buf)
	for _, want := range []string{"сред.мс", "p50 мс", "p95 мс", "p99 мс", "макс мс"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("в отчёте нет колонки %q", want)
		}
	}
}

// TestReportMarksUnmeasuredGC — непрогнанное измерение не выдаётся за успешное.
func TestReportMarksUnmeasuredGC(t *testing.T) {
	var buf bytes.Buffer
	sampleReport(t).writeText(&buf)
	if !strings.Contains(buf.String(), "NOT_MEASURED") {
		t.Fatal("отсутствующие данные по куче и сборкам мусора не помечены NOT_MEASURED")
	}
}

func TestReportTargetsAreDerivedFromConns(t *testing.T) {
	rep := sampleReport(t)
	if len(rep.ClosedLoop.Targets) != 3 {
		t.Fatalf("целевых уровней %d, ожидалось 3", len(rep.ClosedLoop.Targets))
	}
	for _, tg := range rep.ClosedLoop.Targets {
		want := float64(rep.ClosedLoop.Conns) / float64(tg.RPS) * 1000
		if tg.RequiredMeanM != want {
			t.Fatalf("для %d RPS требуется %.3f мс, посчитано %.3f", tg.RPS, want, tg.RequiredMeanM)
		}
	}
}

func TestReportCeilingMatchesFormula(t *testing.T) {
	rep := sampleReport(t)
	cl := rep.ClosedLoop
	if cl.MeanMS <= 0 {
		t.Fatal("средняя латентность не измерена")
	}
	want := float64(cl.Conns) / (cl.MeanMS / 1000)
	if diff := want - cl.CeilingRPS; diff > 1e-6 || diff < -1e-6 {
		t.Fatalf("потолок %f не равен conns/латентность %f", cl.CeilingRPS, want)
	}
	if cl.GoodputRPS > cl.CeilingRPS*1.05 {
		t.Fatalf("goodput %f выше потолка закрытого контура %f", cl.GoodputRPS, cl.CeilingRPS)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := sampleReport(t).writeJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("JSON-отчёт не разбирается: %v", err)
	}
	for _, key := range []string{"conditions", "client_latency", "closed_loop", "resources"} {
		if _, ok := back[key]; !ok {
			t.Fatalf("в JSON-отчёте нет раздела %q", key)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		512:             "512 Б",
		2048:            "2.0 КиБ",
		3 * 1024 * 1024: "3.0 МиБ",
		5 * 1 << 30:     "5.0 ГиБ",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Fatalf("humanBytes(%d) = %q, ожидалось %q", in, got, want)
		}
	}
}

func TestMetricsURLDerivedFromProcess(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:8080/process":      "http://127.0.0.1:8080/metrics",
		"https://gw.example.com/process?x=1": "https://gw.example.com/metrics",
	}
	for in, want := range cases {
		if got := metricsURL(in); got != want {
			t.Fatalf("metricsURL(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

func TestClientPlacementNotesSharedHost(t *testing.T) {
	if got := clientPlacement("http://127.0.0.1:8080/process"); !strings.Contains(got, "делят ядра") {
		t.Fatalf("совмещение клиента и сервиса не отмечено: %q", got)
	}
	if got := clientPlacement("http://gw.example.com:8080/process"); strings.Contains(got, "делят ядра") {
		t.Fatalf("удалённая цель помечена как совмещённая: %q", got)
	}
}

// TestCheckValidityRejectsFailedRun закрепляет главное свойство инструмента
// измерения: прогон, в котором ничего не измерилось, не выдаёт себя за
// измерение.
//
// Дефект был настоящий и найден соседней сессией: команда из README била в
// корень вместо /process, сервис отвечал 405 на каждый запрос, а инструмент
// печатал «goodput 0 запр/с (RESULT)», «среднее 0,000 мс (RESULT)» и
// завершался с кодом 0. Опасность тут не в нулях, а в пометке RESULT рядом с
// ними: латентность набирается только по успешным ответам, поэтому чем
// больше отказов, тем ближе среднее к нулю — то есть тем лучше выглядит
// провальный прогон.
func TestCheckValidityRejectsFailedRun(t *testing.T) {
	cases := []struct {
		name      string
		stats     []latencyStats
		wantValid bool
		wantTag   string
	}{
		{
			name:      "ни одного ответа",
			stats:     []latencyStats{{Op: testOpMask}},
			wantValid: false,
			wantTag:   tagInvalid,
		},
		{
			name:      "все ответы 405",
			stats:     []latencyStats{{Op: testOpMask, Failed: 29612}},
			wantValid: false,
			wantTag:   tagInvalid,
		},
		{
			name:      "только транспортные отказы",
			stats:     []latencyStats{{Op: testOpMask, Errors: 512}},
			wantValid: false,
			wantTag:   tagInvalid,
		},
		{
			name:      "успешных меньше порога",
			stats:     []latencyStats{{Op: testOpMask, Count: 900, Failed: 100}},
			wantValid: false,
			wantTag:   tagInvalid,
		},
		{
			name:      "здоровый прогон",
			stats:     []latencyStats{{Op: testOpMask, Count: 10000, Failed: 3}},
			wantValid: true,
			wantTag:   "RESULT",
		},
		{
			// 429 отказом не считается: это штатное поведение сервиса под
			// нагрузкой, оно учитывается отдельной колонкой отчёта.
			name:      "отказы по перегрузке достоверности не отменяют",
			stats:     []latencyStats{{Op: testOpMask, Count: 5000, Throttled429: 4000}},
			wantValid: true,
			wantTag:   "RESULT",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &report{Client: tc.stats}
			r.checkValidity()

			if r.Valid != tc.wantValid {
				t.Errorf("Valid = %v, ожидалось %v (причина: %q)", r.Valid, tc.wantValid, r.InvalidWhy)
			}
			if got := r.tag(); got != tc.wantTag {
				t.Errorf("tag() = %q, ожидалось %q", got, tc.wantTag)
			}
			if !tc.wantValid && r.InvalidWhy == "" {
				t.Error("недостоверный прогон обязан назвать причину")
			}
		})
	}
}

// TestInvalidRunTextHasNoResultTag проверяет, что у недостоверного прогона в
// тексте отчёта не остаётся ни одной пометки RESULT: именно по ней величины
// переносятся в отчёт о производительности.
func TestInvalidRunTextHasNoResultTag(t *testing.T) {
	r := &report{
		Task:   "T-16",
		Client: []latencyStats{{Op: testOpMask, Failed: 100}},
	}
	r.checkValidity()

	var buf bytes.Buffer
	r.writeText(&buf)
	out := buf.String()

	if strings.Contains(out, "(RESULT)") {
		t.Error("в отчёте недостоверного прогона осталась пометка RESULT")
	}
	if !strings.Contains(out, "ПРОГОН НЕДОСТОВЕРЕН") {
		t.Error("отчёт не предупреждает о недостоверности прогона")
	}
}
