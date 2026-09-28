package obs

import (
	"strconv"
	"strings"
	"testing"
)

// Счётчики рантайма добавлены ради отчёта о производительности: без них
// размер кучи и затраты на сборку мусора приходилось доставать разбором
// журнала процесса, то есть на практике не доставали вовсе.
func TestRuntimeMetricsExposed(t *testing.T) {
	var b strings.Builder
	NewMetrics().WriteProm(&b)
	out := b.String()

	want := []string{
		"aigw_go_heap_bytes",
		"aigw_go_memory_bytes",
		"aigw_go_gc_goal_bytes",
		"aigw_go_gc_cycles_total",
		"aigw_go_gc_cpu_fraction",
		"aigw_go_goroutines",
		"aigw_go_heap_objects_allocated_total",
		"aigw_go_heap_objects_freed_total",
	}
	for _, name := range want {
		if !strings.Contains(out, "# TYPE "+name+" ") {
			t.Errorf("метрика %s не объявлена", name)
		}
		if !strings.Contains(out, "\n"+name+" ") && !strings.HasPrefix(out, name+" ") {
			t.Errorf("метрика %s объявлена, но значения нет", name)
		}
	}
}

// Значения обязаны быть разбираемыми числами: экспозиция, которую не примет
// сборщик метрик, ничем не лучше её отсутствия.
func TestRuntimeMetricsAreNumbers(t *testing.T) {
	var b strings.Builder
	NewMetrics().WriteProm(&b)
	for _, line := range strings.Split(b.String(), "\n") {
		if !strings.HasPrefix(line, "aigw_go_") {
			continue
		}
		name, value, ok := strings.Cut(line, " ")
		if !ok {
			t.Errorf("строка %q без значения", line)
			continue
		}
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			t.Errorf("метрика %s: значение %q не число (%v)", name, value, err)
		}
	}
}

// Живые значения должны быть осмысленными: куча не бывает нулевой, горутин
// хотя бы одна. Проверка ловит ошибку в порядке чтения счётчиков — имена в
// runtime/metrics читаются по позициям, и перестановка не видна компилятору.
func TestRuntimeMetricsPlausible(t *testing.T) {
	s := readRuntime()
	if s.heapBytes == 0 {
		t.Error("куча нулевая")
	}
	if s.totalBytes < s.heapBytes {
		t.Errorf("вся память %d меньше кучи %d", s.totalBytes, s.heapBytes)
	}
	if s.goroutines == 0 {
		t.Error("горутин ноль")
	}
	if s.gcCPUFrac < 0 || s.gcCPUFrac > 1 {
		t.Errorf("доля процессорного времени на сборку %v вне [0;1]", s.gcCPUFrac)
	}
	if s.mallocTotal < s.freeTotal {
		t.Errorf("освобождено объектов %d больше, чем выделено %d", s.freeTotal, s.mallocTotal)
	}
}
