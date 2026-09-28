package obs

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"ai-gateway/internal/pii"
)

// Кольцевые буферы наблюдаемости: история запросов и поток журнала для
// демонстрационного стенда.
//
// Инвариант приватности сильнее наглядности. Ни в историю, ни в журнал на
// странице, ни в трассировку не попадает ни одно значение персональных данных
// (REQ-701). Хранятся только идентификатор запроса, потребитель, операция,
// имена типов ПД, счётчики по типам, длительности и исход — ровно перечень
// REQ-700. Значения — никогда.
//
// Инвариант держится не соглашением, а построением:
//
//   - запись истории состоит из чисел, перечислимых констант и битовых масок
//     типов; поля для текста в ней просто нет;
//   - журнал принимает атрибуты по белому списку имён, и каждое разрешённое
//     имя несёт значение, происходящее из реестра типов, конфигурации или
//     самого сервиса — ничего, полученного из тела запроса, туда не приходит.

// DefaultHistorySize — вместимость кольцевого буфера истории.
//
// Размер задан константой, а не настройкой: поля в схеме конфигурации для него
// пока нет, а выходить за список owns задачи нельзя. Двести записей выбраны
// как верх того, что имеет смысл на демонстрации: таблицу глубже трёх экранов
// на проекторе никто не листает, а памяти это стоит около 200 × 400 Б ≈ 80 КиБ
// — величина, которой можно пренебречь рядом с гигабайтом хранилища
// соответствий. Неограниченного роста нет по построению: буфер кольцевой и
// выделяется один раз при старте.
const DefaultHistorySize = 200

// DefaultJournalSize — вместимость кольцевого буфера журнала.
//
// Больше истории в два с половиной раза: на один запрос приходится несколько
// записей журнала (приём, предупреждения, итог), и при равных размерах поток
// вытеснял бы сам себя быстрее, чем история.
const DefaultJournalSize = 500

// maxFieldBytes — предел длины строкового поля, попадающего в буферы.
//
// Идентификатор запроса клиент может прислать заголовком X-Request-Id, то есть
// это единственное строковое поле, на которое он влияет. Транспорт его
// нормализует, но предел стоит и здесь: буферы долгоживущие, и ограничение их
// содержимого не должно зависеть от того, что кто-то выше по стеку ничего не
// забыл.
const maxFieldBytes = 64

// envBuffers — переменная окружения, выключающая буферы целиком.
//
// Отдельного поля в конфигурации нет: internal/config/schema.go не входит в
// список owns задачи T-23. Переменная окружения — тот же способ настройки,
// которым уже задаются ключи доступа, и она не требует правки чужого файла.
// Предложение для схемы описано в «Журнале» задачи: секция observability с
// полями enabled, history_size, journal_size.
const envBuffers = "AIGW_OBS_BUFFERS"

// Record — одна запись истории запросов.
//
// Структура фиксированного размера: массивы счётчиков, битовые маски типов,
// перечислимые метки и трассировка. Единственные указатели — заголовки строк,
// и все они ссылаются на уже существующие значения (идентификатор запроса,
// идентификаторы потребителей из снимка конфигурации), поэтому запись в буфер
// не выделяет память.
type Record struct {
	// Seq — порядковый номер записи. Ноль означает незанятую ячейку буфера.
	Seq uint64
	// At — момент завершения запроса.
	At time.Time
	// RequestID — идентификатор запроса, он же ключ трассировки.
	RequestID string
	// Caller — потребитель, чьим ключом выполнен запрос. Пусто для контракта
	// без ключа: именно это поле определяет видимость записи.
	Caller string
	// Consumer — потребитель, чья политика применена. На стенде он может
	// отличаться от Caller: прогон показывают под разными политиками.
	Consumer string
	Endpoint Endpoint
	Op       Op
	Outcome  Outcome
	// Degraded отмечает срабатывание безопасного отката.
	Degraded bool
	// Detected и Masked — множества типов ПД, битовые маски.
	Detected pii.Set
	Masked   pii.Set
	// DetectedCounts и MaskedCounts — счётчики по типам.
	DetectedCounts [pii.Count]uint16
	MaskedCounts   [pii.Count]uint16
	// BytesIn и BytesOut — объём обработанного текста.
	BytesIn  int32
	BytesOut int32
	// Service — время сервиса без ожидания модели.
	Service time.Duration
	// LLM — ожидание модели. Во время сервиса не входит.
	LLM time.Duration
	// Trace — отрезки этапов обработки.
	Trace Trace
}

// LogEntry — одна запись потока журнала для страницы.
//
// Набор полей закрыт: расширять его можно только новым полем в этой структуре,
// а не произвольным атрибутом журнала. Это и есть гарантия того, что в поток
// не попадёт текст запроса.
type LogEntry struct {
	Seq     uint64
	At      time.Time
	Level   slog.Level
	Message string
	// RequestID пуст у служебных записей, сделанных до того, как стал известен
	// потребитель.
	RequestID string
	// Owner — потребитель, чьим ключом выполнен запрос; по нему и только по
	// нему работает изоляция. Пусто у служебных записей и у контракта без
	// ключа. Отдельное от Consumer поле нужно потому, что на стенде политика
	// применяется по выбору жюри: запись о прогоне под чужой политикой
	// принадлежит предъявителю ключа, а не владельцу этой политики.
	Owner string
	// Consumer — потребитель, чья политика применена. Показывается на
	// странице; на видимость записи не влияет.
	Consumer string
	Endpoint string
	Op       string
	// Outcome — исход запроса либо статус цепочки продуктового контура.
	Outcome  string
	Detected pii.Set
	Masked   pii.Set
	// MaskedCount и RestoredCount — число замен и восстановлений.
	MaskedCount   int32
	RestoredCount int32
	BytesIn       int32
	DurationMS    int32
	LLMMS         int32
}

// Recorder — кольцевые буферы истории и журнала.
//
// Оба буфера выделяются один раз при создании и не растут. Запись защищена
// мьютексом: критическая секция — копирование структуры фиксированного размера,
// то есть десятки наносекунд. Свободная от блокировок схема (seqlock) здесь
// отвергнута сознательно: в Go она означает несинхронизированное чтение полей,
// которое детектор гонок обязан считать дефектом, а `go test -race` в проверке
// задачи обязателен.
type Recorder struct {
	histMu  sync.Mutex
	hist    []Record
	histSeq uint64

	jrnMu  sync.Mutex
	jrn    []LogEntry
	jrnSeq uint64
}

// NewRecorder создаёт буферы заданной вместимости.
//
// Неположительный размер отключает соответствующий буфер: отключение —
// штатный режим, а не ошибка настройки.
func NewRecorder(historySize, journalSize int) *Recorder {
	r := &Recorder{}
	if historySize > 0 {
		r.hist = make([]Record, historySize)
	}
	if journalSize > 0 {
		r.jrn = make([]LogEntry, journalSize)
	}
	return r
}

// NewRecorderFromEnv собирает буферы по переменной окружения AIGW_OBS_BUFFERS.
//
// Значения off, 0, false, no выключают историю, журнал и трассировку целиком;
// любое другое значение и отсутствие переменной оставляют размеры по
// умолчанию. Возвращается nil, а не пустой буфер: выключенный накопитель не
// должен стоить обработчику ничего, кроме проверки указателя на nil.
func NewRecorderFromEnv() *Recorder {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envBuffers))) {
	case "off", "0", "false", "no":
		return nil
	}
	return NewRecorder(DefaultHistorySize, DefaultJournalSize)
}

// Enabled сообщает, ведётся ли история. Метод безопасен для nil-накопителя.
func (r *Recorder) Enabled() bool { return r != nil && len(r.hist) > 0 }

// HistoryCap возвращает вместимость буфера истории.
func (r *Recorder) HistoryCap() int {
	if r == nil {
		return 0
	}
	return len(r.hist)
}

// JournalCap возвращает вместимость буфера журнала.
func (r *Recorder) JournalCap() int {
	if r == nil {
		return 0
	}
	return len(r.jrn)
}

// Record кладёт запись в кольцевой буфер истории.
//
// Аргумент передаётся указателем и наружу не сохраняется: анализ убегания
// оставляет запись вызывающего кода на стеке, поэтому обращение к буферу не
// выделяет памяти. Бенчмарк BenchmarkRecorderRecord с -benchmem это
// подтверждает.
func (r *Recorder) Record(rec *Record) {
	if r == nil || len(r.hist) == 0 || rec == nil {
		return
	}
	// Строковые поля подрезаются до входа в долгоживущий буфер: длина
	// идентификатора запроса не должна определять расход памяти буфера.
	rec.RequestID = clip(rec.RequestID)

	r.histMu.Lock()
	r.histSeq++
	seq := r.histSeq
	slot := &r.hist[(seq-1)%uint64(len(r.hist))]
	*slot = *rec
	slot.Seq = seq
	r.histMu.Unlock()
}

// visible решает, показывать ли запись потребителю caller.
//
// Правило одно на историю и журнал: запись, выполненная по ключу, видна только
// владельцу ключа; запись без ключа — служебная и видна всем допущенным.
//
// Полная изоляция здесь не потребовала ни нового права в политике, ни правки
// internal/policy: достаточно сравнения идентификаторов, поэтому выбран строгий
// вариант, а не послабление. Записи контракта POST /process видны всем
// сознательно: этот контур по требованию организаторов работает без
// аутентификации, обслуживается одним общим потребителем и ничьей
// собственностью не является — скрывать его телеметрию не от кого. Записи
// продуктовых контуров /v1/* и стенда чужому ключу не видны ни при каких
// параметрах запроса (REQ-404).
func visible(owner, caller string) bool { return owner == "" || owner == caller }

// History возвращает записи истории, доступные потребителю caller, от новых к
// старым.
//
// Возвращается копия: буфер продолжает переписываться, пока читатель
// сериализует ответ.
func (r *Recorder) History(caller string, limit int) []Record {
	if r == nil || len(r.hist) == 0 || limit <= 0 {
		return nil
	}
	out := make([]Record, 0, min(limit, len(r.hist)))

	r.histMu.Lock()
	defer r.histMu.Unlock()
	n := uint64(len(r.hist))
	for seq := r.histSeq; seq > 0 && len(out) < limit; seq-- {
		slot := &r.hist[(seq-1)%n]
		if slot.Seq != seq {
			// Ячейка уже переписана более новой записью: всё, что старше,
			// потеряно, и продолжать обход незачем.
			break
		}
		if !visible(slot.Caller, caller) {
			continue
		}
		out = append(out, *slot)
	}
	return out
}

// Find возвращает запись по идентификатору запроса, если она доступна
// потребителю caller.
//
// Недоступная чужая запись неотличима от несуществующей: иначе перебор
// идентификаторов раскрывал бы факт обращения другого потребителя.
func (r *Recorder) Find(caller, requestID string) (Record, bool) {
	if r == nil || len(r.hist) == 0 || requestID == "" {
		return Record{}, false
	}
	r.histMu.Lock()
	defer r.histMu.Unlock()
	n := uint64(len(r.hist))
	for seq := r.histSeq; seq > 0; seq-- {
		slot := &r.hist[(seq-1)%n]
		if slot.Seq != seq {
			break
		}
		if slot.RequestID == requestID && visible(slot.Caller, caller) {
			return *slot, true
		}
	}
	return Record{}, false
}

// journal кладёт запись в кольцевой буфер журнала.
func (r *Recorder) journal(e *LogEntry) {
	if r == nil || len(r.jrn) == 0 {
		return
	}
	r.jrnMu.Lock()
	r.jrnSeq++
	seq := r.jrnSeq
	slot := &r.jrn[(seq-1)%uint64(len(r.jrn))]
	*slot = *e
	slot.Seq = seq
	r.jrnMu.Unlock()
}

// Journal возвращает записи журнала, доступные потребителю caller, от старых к
// новым, начиная со следующей после after.
//
// Порядок прямой, а не обратный: страница дописывает поток снизу, и разворот
// пришлось бы делать в браузере. Параметр after делает опрос разностным —
// повторно передаётся только то, чего страница ещё не видела.
func (r *Recorder) Journal(caller string, after uint64, limit int) []LogEntry {
	if r == nil || len(r.jrn) == 0 || limit <= 0 {
		return nil
	}
	out := make([]LogEntry, 0, min(limit, len(r.jrn)))

	r.jrnMu.Lock()
	defer r.jrnMu.Unlock()
	n := uint64(len(r.jrn))

	// Самая старая уцелевшая запись: всё, что старше, уже переписано.
	oldest := uint64(1)
	if r.jrnSeq > n {
		oldest = r.jrnSeq - n + 1
	}
	from := after + 1
	if from < oldest {
		from = oldest
	}
	for seq := from; seq <= r.jrnSeq && len(out) < limit; seq++ {
		slot := &r.jrn[(seq-1)%n]
		if slot.Seq != seq {
			continue
		}
		if !visible(slot.Owner, caller) {
			continue
		}
		e := *slot
		if e.Owner == "" && e.Consumer == "" {
			// Запись без владельца и без потребителя сделана до того, как
			// аутентификация прошла: отказ по перегрузке, паника, обращение к
			// странице. Она могла относиться к обращению другого потребителя,
			// поэтому идентификатор запроса из неё убирается — сама запись
			// остаётся, потому что описывает состояние сервиса, а не чьи-то
			// данные.
			//
			// Записи контракта POST /process владельца не имеют, но потребителя
			// называют: этот контур по требованию организаторов работает без
			// аутентификации, и его телеметрия публична по построению — скрывать
			// её не от кого. Идентификатор в них сохраняется, иначе поток
			// журнала невозможно было бы сопоставить с таблицей истории.
			e.RequestID = ""
		}
		out = append(out, e)
	}
	return out
}

// JournalSeq возвращает номер последней записи журнала.
func (r *Recorder) JournalSeq() uint64 {
	if r == nil || len(r.jrn) == 0 {
		return 0
	}
	r.jrnMu.Lock()
	defer r.jrnMu.Unlock()
	return r.jrnSeq
}

// clip подрезает строку до предела длины буфера, не разрывая руну.
func clip(s string) string {
	if len(s) <= maxFieldBytes {
		return s
	}
	i := maxFieldBytes
	for i > 0 && s[i]&0xC0 == 0x80 {
		i--
	}
	return s[:i]
}

// journalFields — разобранные атрибуты одной записи журнала.
type journalFields struct {
	requestID string
	owner     string
	consumer  string
	endpoint  string
	op        string
	outcome   string
	detected  pii.Set
	masked    pii.Set
	maskedN   int32
	restoredN int32
	bytesIn   int32
	durationM int32
	llmMS     int32
}

// apply разбирает один атрибут журнала по белому списку имён.
//
// Имя вне списка не приводит ни к какому эффекту: значение не читается и в
// буфер не попадает. Список закрыт сознательно — чёрный список пришлось бы
// пополнять при каждом новом поле журнала, и первая же забытая строка стала бы
// утечкой. Каждое разрешённое имя несёт значение из реестра типов, из
// конфигурации или измеренное самим сервисом; ни одно не приходит из тела
// запроса.
func (f *journalFields) apply(a slog.Attr) {
	v := a.Value.Resolve()
	switch a.Key {
	case "request_id":
		f.requestID = clip(v.String())
	case "owner":
		f.owner = clip(v.String())
	case "consumer":
		f.consumer = clip(v.String())
	case "endpoint":
		f.endpoint = clip(v.String())
	case "op":
		f.op = clip(v.String())
	case "outcome", "chain_status":
		f.outcome = clip(v.String())
	case "detected_types":
		f.detected = typeSet(v)
	case "masked_types":
		f.masked = typeSet(v)
	case "masked_count":
		f.maskedN = int32(v.Int64())
	case "restored_count":
		f.restoredN = int32(v.Int64())
	case "bytes_in":
		f.bytesIn = int32(v.Int64())
	case "duration_ms":
		f.durationM = int32(v.Int64())
	case "llm_ms":
		f.llmMS = int32(v.Int64())
	}
}

// typeSet переводит перечень машинных ключей типов ПД в битовую маску.
//
// Имена типов приходят из реестра internal/pii, а не из запроса: неизвестный
// ключ отбрасывается, и произвольная строка в буфер не попадает даже в виде
// имени.
func typeSet(v slog.Value) pii.Set {
	keys, ok := v.Any().([]string)
	if !ok {
		return 0
	}
	var out pii.Set
	for _, k := range keys {
		if t, ok := pii.ByKey(k); ok {
			out = out.Add(t)
		}
	}
	return out
}

// journalHandler зеркалит записи журнала в кольцевой буфер и передаёт их
// дальше без изменений.
//
// Обработчик стоит поверх настроенного в конфигурации: stdout продолжает
// получать ровно то же самое, а страница получает разобранную копию. Формат и
// уровень журнала остаются делом NewLogger.
type journalHandler struct {
	next slog.Handler
	rec  *Recorder
	// fields — атрибуты, накопленные вызовами With.
	fields journalFields
	// grouped отмечает, что открыта группа: внутри группы имена атрибутов
	// принадлежат её пространству, и белый список верхнего уровня к ним
	// неприменим. Такие атрибуты в буфер не попадают.
	grouped bool
}

// NewJournalHandler оборачивает обработчик журнала зеркалом в буфер.
//
// Возвращается исходный обработчик, если буфер выключен: лишнего звена в
// цепочке журналирования при выключенном стенде быть не должно.
func NewJournalHandler(next slog.Handler, rec *Recorder) slog.Handler {
	if rec == nil || len(rec.jrn) == 0 {
		return next
	}
	return &journalHandler{next: next, rec: rec}
}

func (h *journalHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *journalHandler) Handle(ctx context.Context, r slog.Record) error {
	f := h.fields
	if !h.grouped {
		r.Attrs(func(a slog.Attr) bool {
			f.apply(a)
			return true
		})
	}
	e := LogEntry{
		At:            r.Time,
		Level:         r.Level,
		Message:       r.Message,
		RequestID:     f.requestID,
		Owner:         f.owner,
		Consumer:      f.consumer,
		Endpoint:      f.endpoint,
		Op:            f.op,
		Outcome:       f.outcome,
		Detected:      f.detected,
		Masked:        f.masked,
		MaskedCount:   f.maskedN,
		RestoredCount: f.restoredN,
		BytesIn:       f.bytesIn,
		DurationMS:    f.durationM,
		LLMMS:         f.llmMS,
	}
	h.rec.journal(&e)
	return h.next.Handle(ctx, r)
}

func (h *journalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.next = h.next.WithAttrs(attrs)
	if !h.grouped {
		for _, a := range attrs {
			c.fields.apply(a)
		}
	}
	return &c
}

func (h *journalHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.next = h.next.WithGroup(name)
	c.grouped = true
	return &c
}
