package obs

import (
	"runtime/metrics"
	"strings"
	"sync"
)

// Счётчики рантайма Go в экспозиции Prometheus.
//
// Без них отчёт о производительности не мог назвать ни размер кучи, ни
// затраты на сборку мусора, ни запас до предела памяти: единственным путём
// оставался GODEBUG=gctrace=1, то есть разбор журнала процесса снаружи
// (PERFORMANCE.md §7.2). Метрика, которую нельзя снять штатно, на практике не
// снимается вовсе.
//
// Читается пакет runtime/metrics, а не runtime.ReadMemStats: последний
// останавливает мир на время снятия, и вызывать его на каждый запрос к
// /metrics нельзя. Выборка runtime/metrics обходится без остановки.
//
// Значения ПД сюда попасть не могут по построению: это счётчики рантайма, а
// не данные запроса.

// runtimeSample — одно снятие счётчиков рантайма.
type runtimeSample struct {
	heapBytes   uint64  // объекты кучи, живые и ещё не собранные
	totalBytes  uint64  // вся память, взятая у операционной системы
	goalBytes   uint64  // цель, к которой сборщик ведёт размер кучи
	gcCycles    uint64  // завершённых циклов сборки
	gcCPUFrac   float64 // доля процессорного времени, ушедшая на сборку
	goroutines  uint64
	mallocTotal uint64 // всего выделений объектов за жизнь процесса
	freeTotal   uint64
}

// runtimeNames — имена счётчиков в том порядке, в котором они читаются.
// Порядок фиксирован: runtime/metrics заполняет срез по позициям.
var runtimeNames = [...]string{
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/total:bytes",
	"/gc/heap/goal:bytes",
	"/gc/cycles/total:gc-cycles",
	"/cpu/classes/gc/total:cpu-seconds",
	"/cpu/classes/total:cpu-seconds",
	"/sched/goroutines:goroutines",
	"/gc/heap/allocs:objects",
	"/gc/heap/frees:objects",
}

// runtimeSamples переиспользуется между снятиями: /metrics опрашивают часто, и
// выделять срез описаний на каждый запрос незачем. Доступ под мьютексом —
// runtime/metrics.Read пишет в переданный срез.
var (
	runtimeMu      sync.Mutex
	runtimeSamples []metrics.Sample
)

func readRuntime() runtimeSample {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()

	if runtimeSamples == nil {
		runtimeSamples = make([]metrics.Sample, len(runtimeNames))
		for i, name := range runtimeNames {
			runtimeSamples[i].Name = name
		}
	}
	metrics.Read(runtimeSamples)

	var s runtimeSample
	var gcCPU, totalCPU float64
	for i := range runtimeSamples {
		v := runtimeSamples[i].Value
		switch v.Kind() {
		case metrics.KindUint64:
			u := v.Uint64()
			switch i {
			case 0:
				s.heapBytes = u
			case 1:
				s.totalBytes = u
			case 2:
				s.goalBytes = u
			case 3:
				s.gcCycles = u
			case 6:
				s.goroutines = u
			case 7:
				s.mallocTotal = u
			case 8:
				s.freeTotal = u
			}
		case metrics.KindFloat64:
			switch i {
			case 4:
				gcCPU = v.Float64()
			case 5:
				totalCPU = v.Float64()
			}
		}
	}
	// Доля, а не абсолютные секунды: абсолютные зависят от числа ядер и от
	// времени жизни процесса, и сравнивать их между прогонами нельзя.
	if totalCPU > 0 {
		s.gcCPUFrac = gcCPU / totalCPU
	}
	return s
}

// writeRuntimeProm дописывает счётчики рантайма в экспозицию.
func writeRuntimeProm(b *strings.Builder) {
	s := readRuntime()
	writeScalars(b, []promScalar{
		{"aigw_go_heap_bytes", promGauge, "Объём живых объектов кучи", fmtUint(s.heapBytes)},
		{"aigw_go_memory_bytes", promGauge, "Вся память процесса, взятая у операционной системы", fmtUint(s.totalBytes)},
		{"aigw_go_gc_goal_bytes", promGauge, "Цель размера кучи для следующей сборки", fmtUint(s.goalBytes)},
		{"aigw_go_gc_cycles_total", promCounter, "Завершённых циклов сборки мусора", fmtUint(s.gcCycles)},
		{"aigw_go_gc_cpu_fraction", promGauge, "Доля процессорного времени, ушедшая на сборку мусора", fmtFloat(s.gcCPUFrac)},
		{"aigw_go_goroutines", promGauge, "Число горутин", fmtUint(s.goroutines)},
		{"aigw_go_heap_objects_allocated_total", promCounter, "Выделено объектов кучи за жизнь процесса", fmtUint(s.mallocTotal)},
		{"aigw_go_heap_objects_freed_total", promCounter, "Освобождено объектов кучи за жизнь процесса", fmtUint(s.freeTotal)},
	})
}
