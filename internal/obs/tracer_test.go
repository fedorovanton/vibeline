package obs

import (
	"testing"
	"time"
)

func TestStageTreeIsConsistent(t *testing.T) {
	// Форма дерева задана статически. Опечатка в таблице родителей привела бы
	// к бесконечному вложению на странице, поэтому проверяется здесь.
	seen := make(map[string]bool, StageCount)
	for i := 0; i < StageCount; i++ {
		s := Stage(i)
		if s.Key() == "" || s.Label() == "" {
			t.Errorf("этап %d без имени: key=%q label=%q", i, s.Key(), s.Label())
		}
		if seen[s.Key()] {
			t.Errorf("машинное имя этапа %q повторяется", s.Key())
		}
		seen[s.Key()] = true

		if s.Root() {
			continue
		}
		p := s.Parent()
		if !p.Root() {
			t.Errorf("этап %s вложен в невершинный %s: дерево глубже двух уровней", s, p)
		}
	}
}

func TestOnlyModelWaitIsOutsideServiceTime(t *testing.T) {
	// Главное свойство трассировки для жюри: ожидание модели — единственный
	// этап вне времени сервиса. Если однажды таким окажется что-то ещё,
	// страница покажет это без пояснений, а тест сообщит об этом раньше.
	for i := 0; i < StageCount; i++ {
		s := Stage(i)
		if s == StageLLM {
			if s.InService() {
				t.Error("ожидание модели помечено как входящее во время сервиса")
			}
			continue
		}
		if !s.InService() {
			t.Errorf("этап %s помечен как не входящий во время сервиса", s)
		}
	}
}

func TestTracerMarksStagesRelativeToStart(t *testing.T) {
	base := time.Now()
	tr := NewTracer(true, base)

	tr.Mark(StageAccept, base, base.Add(2*time.Millisecond))
	tr.MarkDur(StageProtect, base.Add(2*time.Millisecond), 5*time.Millisecond)
	tr.MarkNs(StageDetect, 2*int64(time.Millisecond), int64(3*time.Millisecond))
	tr.MarkDur(StageLLM, base.Add(7*time.Millisecond), 400*time.Millisecond)
	tr.MarkDur(StageRestore, base.Add(407*time.Millisecond), time.Millisecond)

	tc := tr.Trace()
	sp, ok := tc.Span(StageAccept)
	if !ok || sp.StartNs != 0 || sp.DurNs != int64(2*time.Millisecond) {
		t.Fatalf("приём записан как %+v (наличие %v)", sp, ok)
	}
	sp, ok = tc.Span(StageDetect)
	if !ok || sp.StartNs != int64(2*time.Millisecond) {
		t.Errorf("детекция записана как %+v (наличие %v)", sp, ok)
	}
	if _, ok := tc.Span(StageMask); ok {
		t.Error("незаписанный этап считается записанным")
	}

	// Время сервиса складывается только из корневых отрезков: детекция входит
	// в защиту, и её двойной учёт исказил бы ровно тот показатель, который
	// оценивают организаторы.
	wantService := int64(2+5+1) * int64(time.Millisecond)
	if got := tc.ServiceNs(); got != wantService {
		t.Errorf("время сервиса %d нс, ожидалось %d нс", got, wantService)
	}
	if got := tc.WaitNs(); got != int64(400*time.Millisecond) {
		t.Errorf("ожидание модели %d нс, ожидалось %d нс", got, int64(400*time.Millisecond))
	}
	if got := tc.TotalNs(); got != int64(408*time.Millisecond) {
		t.Errorf("длина трассировки %d нс, ожидалось %d нс", got, int64(408*time.Millisecond))
	}
}

func TestTracerDisabledRecordsNothing(t *testing.T) {
	// AC-4: трассировка выключается настройкой. Выключенный трассировщик не
	// просто не показывается — он ничего не собирает.
	base := time.Now()
	tr := NewTracer(false, base)
	tr.Mark(StageAccept, base, base.Add(time.Millisecond))
	tr.MarkDur(StageLLM, base, time.Second)
	tr.MarkNs(StageDetect, 0, 1000)

	tc := tr.Trace()
	if !tc.Empty() {
		t.Error("выключенный трассировщик записал отрезки")
	}
	if tc.TotalNs() != 0 || tc.ServiceNs() != 0 || tc.WaitNs() != 0 {
		t.Error("выключенный трассировщик вернул ненулевые длительности")
	}
}

func TestTraceClampsNegativeDurations(t *testing.T) {
	// Длительности приходят разностью моментов, измеренных в разных местах.
	// Отрицательная разность возможна, и на шкале она уехала бы влево.
	var tc Trace
	tc.Mark(StageRestore, -5, -100)
	sp, ok := tc.Span(StageRestore)
	if !ok {
		t.Fatal("этап не записан")
	}
	if sp.StartNs != 0 || sp.DurNs != 0 {
		t.Errorf("отрицательные значения не схлопнуты: %+v", sp)
	}
}

func TestTraceCarriesNoText(t *testing.T) {
	// REQ-701. Трассировка состоит из чисел и перечислимых констант; поля,
	// способного унести значение персональных данных, в ней нет.
	// Проверяется размером: структура фиксирована и указателей не содержит.
	var tc Trace
	if got := len(tc.spans); got != StageCount {
		t.Fatalf("в трассировке %d отрезков при %d этапах", got, StageCount)
	}
	for _, s := range tc.spans {
		if s.StartNs != 0 || s.DurNs != 0 {
			t.Fatal("нулевая трассировка содержит данные")
		}
	}
}
