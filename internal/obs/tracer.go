package obs

import "time"

// Трассировка этапов обработки — собственная, в памяти, без внешних
// зависимостей. OpenTelemetry отклонён владельцем: он тянет зависимости и
// второй контейнер в поставку, а на стенде нужно показать восемь отрезков
// одного запроса, а не построить распределённую систему наблюдения.
//
// Главное свойство: трассировка не содержит ни одного значения персональных
// данных. В отрезке лежат только имя этапа, смещение от старта запроса и
// длительность — числа и константы, из которых восстановить текст невозможно
// (REQ-701).

// Stage — этап обработки запроса.
//
// Набор этапов перечислим и фиксирован: это позволяет держать трассировку
// массивом фиксированного размера и класть её прямо в запись истории, не
// аллоцируя ничего на запрос.
type Stage uint8

// Этапы обработки. Порядок значений — порядок выполнения; менять нельзя, он
// используется как индекс массива.
const (
	// StageAccept — приём и разбор запроса: чтение тела, проверка схемы,
	// выбор потребителя.
	StageAccept Stage = iota
	// StageProtect — защита запроса целиком. Родитель для четырёх этапов ниже.
	StageProtect
	// StageDetect — токенизация и сканеры.
	StageDetect
	// StagePolicy — применение политики потребителя к найденным спанам.
	StagePolicy
	// StageMask — применение замен.
	StageMask
	// StageStore — запись соответствия в хранилище.
	StageStore
	// StageLLM — ожидание модели. Единственный этап вне времени сервиса.
	StageLLM
	// StageRestore — восстановление плейсхолдеров и повторное сканирование
	// ответа модели.
	StageRestore
	// StageRespond — сериализация и запись ответа клиенту.
	StageRespond

	stageCount
)

// StageCount — число этапов трассировки.
const StageCount = int(stageCount)

// stageMeta — описание этапа для страницы и тестов.
type stageMeta struct {
	key    string
	label  string
	parent Stage
	// root отмечает этап верхнего уровня: у него нет родителя.
	root bool
	// service сообщает, входит ли этап во время сервиса.
	service bool
}

// stages — дерево отрезков. Родительские связи заданы статически: форма дерева
// одинакова для всех запросов, поэтому хранить её в каждой трассировке
// незачем.
var stages = [stageCount]stageMeta{
	StageAccept:  {"accept", "Приём и разбор", 0, true, true},
	StageProtect: {"protect", "Защита запроса", 0, true, true},
	StageDetect:  {"detect", "Детекция", StageProtect, false, true},
	StagePolicy:  {"policy", "Применение политики", StageProtect, false, true},
	StageMask:    {"mask", "Маскирование", StageProtect, false, true},
	StageStore:   {"store", "Запись соответствия", StageProtect, false, true},
	// Ожидание модели измеряется, но во время сервиса не входит: организаторы
	// оценивают наше время, и чужая задержка в него попадать не должна.
	// Страница обязана показывать это отдельной дорожкой, без пояснений.
	StageLLM:     {"llm", "Ожидание модели", 0, true, false},
	StageRestore: {"restore", "Восстановление ответа", 0, true, true},
	StageRespond: {"respond", "Запись ответа", 0, true, true},
}

// Key возвращает машинное имя этапа — для JSON и тестов.
func (s Stage) Key() string { return stages[s.clamp()].key }

// Label возвращает человекочитаемое имя этапа для стенда.
func (s Stage) Label() string { return stages[s.clamp()].label }

// Root сообщает, что этап верхнего уровня и родителя не имеет.
func (s Stage) Root() bool { return stages[s.clamp()].root }

// Parent возвращает родительский этап. Осмысленно только если Root ложно.
func (s Stage) Parent() Stage { return stages[s.clamp()].parent }

// InService сообщает, входит ли этап во время сервиса.
//
// Ложь возвращает только StageLLM: ожидание модели измеряется отдельно и
// вычитается из времени ответа сервиса везде — в метриках, в истории и на
// трассировке.
func (s Stage) InService() bool { return stages[s.clamp()].service }

// String реализует fmt.Stringer через машинное имя.
func (s Stage) String() string { return s.Key() }

func (s Stage) clamp() Stage {
	if int(s) >= StageCount {
		return StageAccept
	}
	return s
}

// Span — один отрезок трассировки.
//
// Смещение отсчитывается от старта запроса, а не от эпохи: разность двух
// моментов не зависит от перевода часов, и на странице отрезки укладываются
// на шкалу без дополнительных вычислений.
type Span struct {
	// StartNs — начало отрезка относительно старта запроса, наносекунды.
	StartNs int64
	// DurNs — длительность отрезка, наносекунды.
	DurNs int64
}

// Trace — трассировка одного запроса.
//
// Структура фиксированного размера без указателей: копирование трассировки в
// кольцевой буфер не аллоцирует. Признак заполненности этапа хранится битовой
// маской — нулевая длительность законна и от «этапа не было» отличима.
type Trace struct {
	set   uint16
	spans [stageCount]Span
}

// Has сообщает, записан ли этап.
func (t *Trace) Has(s Stage) bool { return t.set&(1<<s.clamp()) != 0 }

// Span возвращает отрезок этапа и признак его наличия.
func (t *Trace) Span(s Stage) (Span, bool) {
	c := s.clamp()
	return t.spans[c], t.Has(c)
}

// Empty сообщает, что не записан ни один этап.
func (t *Trace) Empty() bool { return t.set == 0 }

// Mark записывает отрезок этапа.
//
// Повторная запись того же этапа перезаписывает отрезок: этап встречается в
// запросе один раз, и накопление здесь скрыло бы ошибку вызывающего кода.
func (t *Trace) Mark(s Stage, startNs, durNs int64) {
	c := s.clamp()
	if durNs < 0 {
		// Отрицательная длительность означает рассинхронизацию измерений.
		// Показывать её на шкале нельзя: отрезок уехал бы влево и исказил
		// всю картину. Схлопываем в ноль, отрезок при этом остаётся видимым.
		durNs = 0
	}
	if startNs < 0 {
		startNs = 0
	}
	t.spans[c] = Span{StartNs: startNs, DurNs: durNs}
	t.set |= 1 << c
}

// ServiceNs возвращает время сервиса: сумма корневых отрезков без ожидания
// модели.
//
// Считается по корневым этапам, а не по всем: иначе детекция и маскирование
// вошли бы в сумму дважды — сами по себе и внутри родительской защиты.
func (t *Trace) ServiceNs() int64 {
	var sum int64
	for s := Stage(0); s < stageCount; s++ {
		if !t.Has(s) || !s.Root() || !s.InService() {
			continue
		}
		sum += t.spans[s].DurNs
	}
	return sum
}

// WaitNs возвращает время вне сервиса: ожидание модели.
func (t *Trace) WaitNs() int64 {
	var sum int64
	for s := Stage(0); s < stageCount; s++ {
		if t.Has(s) && s.Root() && !s.InService() {
			sum += t.spans[s].DurNs
		}
	}
	return sum
}

// TotalNs возвращает длину всей трассировки: от нуля до правого края самого
// правого отрезка.
func (t *Trace) TotalNs() int64 {
	var end int64
	for s := Stage(0); s < stageCount; s++ {
		if !t.Has(s) {
			continue
		}
		if e := t.spans[s].StartNs + t.spans[s].DurNs; e > end {
			end = e
		}
	}
	return end
}

// Tracer собирает трассировку одного запроса.
//
// Значение живёт на стеке обработчика и между горутинами не разделяется,
// поэтому синхронизации не требует и ничего не аллоцирует. Выключенный
// трассировщик не пишет ничего: остаётся только проверка флага.
type Tracer struct {
	base time.Time
	on   bool
	t    Trace
}

// NewTracer создаёт трассировщик с началом отсчёта в base.
//
// Начало отсчёта задаётся явно, а не берётся текущим временем: обработчик уже
// засёк момент старта для метрик, и второй вызов time.Now() сдвинул бы всю
// шкалу относительно измеренной длительности запроса.
func NewTracer(on bool, base time.Time) Tracer {
	return Tracer{base: base, on: on}
}

// On сообщает, включена ли трассировка.
func (tr *Tracer) On() bool { return tr.on }

// Base возвращает момент начала отсчёта.
func (tr *Tracer) Base() time.Time { return tr.base }

// Mark записывает этап по абсолютным моментам начала и конца.
func (tr *Tracer) Mark(s Stage, start, end time.Time) {
	if !tr.on {
		return
	}
	tr.t.Mark(s, start.Sub(tr.base).Nanoseconds(), end.Sub(start).Nanoseconds())
}

// MarkDur записывает этап по моменту начала и длительности.
func (tr *Tracer) MarkDur(s Stage, start time.Time, d time.Duration) {
	if !tr.on {
		return
	}
	tr.t.Mark(s, start.Sub(tr.base).Nanoseconds(), d.Nanoseconds())
}

// MarkNs записывает этап смещением и длительностью в наносекундах.
//
// Нужен там, где длительность измерена глубже по стеку и вернулась числом:
// ядро обработки возвращает длительности этапов, а раскладку на шкале делает
// транспорт.
func (tr *Tracer) MarkNs(s Stage, startNs, durNs int64) {
	if !tr.on {
		return
	}
	tr.t.Mark(s, startNs, durNs)
}

// Trace возвращает собранную трассировку.
func (tr *Tracer) Trace() Trace { return tr.t }
