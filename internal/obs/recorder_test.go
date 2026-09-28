package obs

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/pii"
)

// sample собирает запись истории, похожую на настоящую: заполнены все поля,
// которые обработчики действительно заполняют.
func sample(i int, caller string) Record {
	rec := Record{
		At:        time.Now(),
		RequestID: "r" + strconv.Itoa(i),
		Caller:    caller,
		Consumer:  caller,
		Endpoint:  EndpointChat,
		Op:        OpProxy,
		Outcome:   OutcomeOK,
		Detected:  pii.NewSet(pii.FullName, pii.Phone),
		Masked:    pii.NewSet(pii.FullName),
		BytesIn:   512,
		BytesOut:  256,
		Service:   3 * time.Millisecond,
		LLM:       400 * time.Millisecond,
	}
	rec.DetectedCounts[pii.FullName] = 1
	rec.DetectedCounts[pii.Phone] = 2
	rec.MaskedCounts[pii.FullName] = 1
	rec.Trace.Mark(StageAccept, 0, int64(time.Millisecond))
	rec.Trace.Mark(StageProtect, int64(time.Millisecond), int64(2*time.Millisecond))
	rec.Trace.Mark(StageLLM, int64(3*time.Millisecond), int64(400*time.Millisecond))
	return rec
}

func TestHistoryIsBoundedAndDropsOldest(t *testing.T) {
	// AC-1: история ограничена размером, неограниченного роста нет.
	const size = 8
	r := NewRecorder(size, size)
	for i := 1; i <= size*5; i++ {
		rec := sample(i, "")
		r.Record(&rec)
	}

	got := r.History(callerDemo, 1000)
	if len(got) != size {
		t.Fatalf("в буфере %d записей при вместимости %d", len(got), size)
	}
	// Возвращаются новые, а не первые попавшие: вытесняется самое старое.
	if got[0].RequestID != "r40" {
		t.Errorf("первой отдана запись %q, ожидалась r40", got[0].RequestID)
	}
	if got[size-1].RequestID != "r33" {
		t.Errorf("последней отдана запись %q, ожидалась r33", got[size-1].RequestID)
	}
	// Вытесненная запись недоступна и по идентификатору.
	if _, ok := r.Find(callerDemo, "r1"); ok {
		t.Error("вытесненная запись всё ещё находится по идентификатору")
	}
}

func TestHistoryLimitIsRespected(t *testing.T) {
	r := NewRecorder(50, 50)
	for i := 1; i <= 50; i++ {
		rec := sample(i, "")
		r.Record(&rec)
	}
	if got := r.History(callerDemo, 5); len(got) != 5 {
		t.Errorf("запрошено 5 записей, отдано %d", len(got))
	}
	if got := r.History(callerDemo, 0); got != nil {
		t.Errorf("нулевой предел вернул %d записей", len(got))
	}
}

func TestHistoryIsolatesConsumers(t *testing.T) {
	// REQ-404 и AC-9. Запись, выполненная по ключу, видна только владельцу
	// ключа. Записи без ключа служебные: контракт POST /process работает без
	// аутентификации и ничьей собственностью не является.
	r := NewRecorder(20, 20)
	for _, caller := range []string{callerCRM, callerDemo, ""} {
		rec := sample(1, caller)
		rec.RequestID = "req-" + caller
		r.Record(&rec)
	}

	demo := r.History(callerDemo, 20)
	if len(demo) != 2 {
		t.Fatalf("потребителю demo видно %d записей, ожидалось 2", len(demo))
	}
	for _, rec := range demo {
		if rec.Caller == callerCRM {
			t.Errorf("потребителю demo видна запись crm: %q", rec.RequestID)
		}
	}
	if _, ok := r.Find(callerDemo, reqCRM); ok {
		t.Error("чужая запись найдена по идентификатору: изоляция нарушена")
	}
	if _, ok := r.Find(callerCRM, reqCRM); !ok {
		t.Error("владелец не нашёл собственную запись")
	}
	if _, ok := r.Find(callerDemo, "req-"); !ok {
		t.Error("служебная запись недоступна допущенному потребителю")
	}
}

func TestRecorderDisabledIsSafe(t *testing.T) {
	// AC-4: буфер выключается настройкой. Выключенный накопитель безопасен и
	// ничего не хранит; обработчикам не приходится проверять его отдельно.
	var r *Recorder
	rec := sample(1, callerDemo)
	r.Record(&rec)
	if r.Enabled() || r.HistoryCap() != 0 || r.JournalCap() != 0 {
		t.Error("nil-накопитель считает себя включённым")
	}
	if got := r.History(callerDemo, 10); got != nil {
		t.Error("nil-накопитель вернул историю")
	}
	if _, ok := r.Find(callerDemo, "r1"); ok {
		t.Error("nil-накопитель нашёл запись")
	}
	if got := r.Journal(callerDemo, 0, 10); got != nil {
		t.Error("nil-накопитель вернул журнал")
	}
	if r.JournalSeq() != 0 {
		t.Error("nil-накопитель вернул номер записи")
	}

	off := NewRecorder(0, 0)
	off.Record(&rec)
	if off.Enabled() {
		t.Error("буфер нулевого размера считает себя включённым")
	}
	if got := off.History(callerDemo, 10); len(got) != 0 {
		t.Error("буфер нулевого размера вернул историю")
	}
}

func TestRecorderFromEnvHonoursSwitch(t *testing.T) {
	t.Setenv(envBuffers, "off")
	if r := NewRecorderFromEnv(); r != nil {
		t.Error("значение off не выключило буферы")
	}
	t.Setenv(envBuffers, "")
	r := NewRecorderFromEnv()
	if r == nil || r.HistoryCap() != DefaultHistorySize || r.JournalCap() != DefaultJournalSize {
		t.Errorf("по умолчанию собран буфер %d/%d", r.HistoryCap(), r.JournalCap())
	}
}

func TestRecorderIsSafeUnderConcurrency(t *testing.T) {
	// Горячий путь обслуживает до 200 соединений одновременно; запись в буфер
	// обязана переживать это без гонок и без потери структуры.
	r := NewRecorder(64, 64)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				rec := sample(g*1000+i, "")
				r.Record(&rec)
			}
		}(g)
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = r.History(callerDemo, 20)
				_ = r.Journal(callerDemo, 0, 20)
			}
		}()
	}
	wg.Wait()

	got := r.History(callerDemo, 1000)
	if len(got) != 64 {
		t.Fatalf("после конкурентной записи в буфере %d записей вместо 64", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Seq <= got[i].Seq {
			t.Fatalf("порядок записей нарушен: %d после %d", got[i].Seq, got[i-1].Seq)
		}
	}
}

func TestRecordClipsRequestID(t *testing.T) {
	// Идентификатор запроса клиент присылает заголовком. Длина долгоживущего
	// буфера не должна от него зависеть.
	r := NewRecorder(4, 4)
	rec := sample(1, "")
	rec.RequestID = strings.Repeat("ф", 200)
	r.Record(&rec)

	got := r.History(callerDemo, 1)
	if len(got) != 1 {
		t.Fatal("запись не попала в буфер")
	}
	if len(got[0].RequestID) > maxFieldBytes {
		t.Errorf("идентификатор длиной %d байт не подрезан", len(got[0].RequestID))
	}
	if !utf8Valid(got[0].RequestID) {
		t.Error("подрезка разорвала руну")
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// newJournalLogger собирает журнал, зеркалящий записи в буфер.
func newJournalLogger(r *Recorder) *slog.Logger {
	base := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(NewJournalHandler(base, r))
}

func TestJournalCapturesOnlyAllowedAttributes(t *testing.T) {
	// REQ-701. Белый список имён — единственная причина, по которой в поток
	// журнала на странице не может попасть текст запроса. Проверяется и то,
	// что разрешённое доехало, и то, что постороннее отброшено.
	r := NewRecorder(10, 10)
	log := newJournalLogger(r).With(keyRequestID, "r7", keyOwner, callerDemo, keyEndpoint, endpointProcessName)
	log.Info(msgHandled,
		keyConsumer, callerDemo,
		"op", opMaskName,
		keyOutcome, "ok",
		keyDetectedTypes, []string{typeFullName, "phone"},
		keyMaskedTypes, []string{typeFullName},
		keyMaskedCount, 3,
		keyDurationMS, 12,
		// Посторонние атрибуты: они существуют в настоящем журнале и в буфер
		// попадать не должны.
		"payload", "Иванов Иван Иванович, карта 4111 1111 1111 1111",
		"payload_id", fioIvanov,
		"panic", fioIvanov,
		keyError, fioIvanov,
		"path", "/Иванов Иван Иванович",
	)

	rows := r.Journal(callerDemo, 0, 10)
	if len(rows) != 1 {
		t.Fatalf("в журнале %d записей, ожидалась одна", len(rows))
	}
	e := rows[0]
	if e.RequestID != "r7" || e.Endpoint != endpointProcessName || e.Consumer != callerDemo || e.Op != opMaskName {
		t.Errorf("разрешённые атрибуты потеряны: %+v", e)
	}
	if e.Outcome != "ok" || e.MaskedCount != 3 || e.DurationMS != 12 {
		t.Errorf("числовые и перечислимые атрибуты потеряны: %+v", e)
	}
	if !e.Detected.Has(pii.FullName) || !e.Detected.Has(pii.Phone) {
		t.Errorf("типы ПД не разобраны: %v", e.Detected.Keys())
	}
	if !e.Masked.Has(pii.FullName) || e.Masked.Has(pii.Phone) {
		t.Errorf("замаскированные типы разобраны неверно: %v", e.Masked.Keys())
	}
	if strings.Contains(e.Message, "Иванов") {
		t.Error("значение попало в текст сообщения")
	}
}

func TestJournalDropsUnknownTypeKeys(t *testing.T) {
	// Имена типов берутся из реестра internal/pii: произвольная строка не
	// попадает в буфер даже в виде имени типа.
	r := NewRecorder(4, 4)
	newJournalLogger(r).Info("проверка", keyConsumer, callerDemo,
		keyDetectedTypes, []string{typeFullName, fioIvanov})

	rows := r.Journal(callerDemo, 0, 4)
	if len(rows) != 1 {
		t.Fatalf("в журнале %d записей", len(rows))
	}
	if got := rows[0].Detected.Keys(); len(got) != 1 || got[0] != typeFullName {
		t.Errorf("неизвестный ключ типа принят: %v", got)
	}
}

func TestJournalIsolatesConsumers(t *testing.T) {
	// AC-9: поток журнала не должен стать способом увидеть чужие запросы.
	r := NewRecorder(10, 10)
	log := newJournalLogger(r)
	log.Info("запрос crm", keyRequestID, reqCRM, keyOwner, callerCRM, keyConsumer, callerCRM)
	log.Info("запрос demo", keyRequestID, "req-demo", keyOwner, callerDemo, keyConsumer, callerDemo)
	// Прогон стенда под чужой политикой: владелец — предъявитель ключа.
	log.Info("стенд: прогон выполнен", keyRequestID, "req-demo-crm", keyOwner, callerDemo, keyConsumer, callerCRM)
	// Запись контракта без ключа: владельца нет, потребитель назван.
	log.Info(msgHandled, keyRequestID, "req-bench", keyConsumer, callerBenchmark)
	// Запись до аутентификации: не известно ни владельца, ни потребителя.
	log.Warn("запрос отклонён по пределу одновременной обработки", keyRequestID, "req-anon")

	rows := r.Journal(callerDemo, 0, 10)
	if len(rows) != 4 {
		t.Fatalf("потребителю demo видно %d записей, ожидалось 4", len(rows))
	}
	for _, e := range rows {
		if e.Owner == callerCRM || strings.Contains(e.Message, "запрос crm") {
			t.Errorf("потребителю demo видна запись crm: %+v", e)
		}
		if e.Owner == "" && e.Consumer == "" && e.RequestID != "" {
			t.Errorf("запись без владельца отдана с идентификатором чужого запроса: %q", e.RequestID)
		}
		if e.Consumer == callerBenchmark && e.RequestID != "req-bench" {
			t.Error("у записи контракта без ключа отобран идентификатор: поток не сопоставить с историей")
		}
	}

	// Владелец политики не видит чужого прогона под ней.
	for _, e := range r.Journal(callerCRM, 0, 10) {
		if e.RequestID == "req-demo-crm" {
			t.Error("прогон стенда под политикой crm показан владельцу этой политики")
		}
	}
}

func TestJournalPollIsIncremental(t *testing.T) {
	// Опрос страницы разностный: повторно передаётся только новое.
	r := NewRecorder(10, 20)
	log := newJournalLogger(r)
	for i := 0; i < 5; i++ {
		log.Info("первая волна", keyConsumer, callerDemo)
	}
	first := r.Journal(callerDemo, 0, 20)
	if len(first) != 5 {
		t.Fatalf("первая выборка вернула %d записей", len(first))
	}
	after := first[len(first)-1].Seq

	if got := r.Journal(callerDemo, after, 20); len(got) != 0 {
		t.Errorf("повторный опрос вернул %d записей вместо нуля", len(got))
	}
	log.Info("вторая волна", keyConsumer, callerDemo)
	got := r.Journal(callerDemo, after, 20)
	if len(got) != 1 || got[0].Message != "вторая волна" {
		t.Errorf("разностный опрос вернул %d записей: %+v", len(got), got)
	}
	// Порядок прямой: страница дописывает поток снизу.
	for i := 1; i < len(first); i++ {
		if first[i-1].Seq >= first[i].Seq {
			t.Fatal("записи журнала отданы не по возрастанию номера")
		}
	}
}

func TestJournalIsBounded(t *testing.T) {
	r := NewRecorder(4, 6)
	log := newJournalLogger(r)
	for i := 0; i < 100; i++ {
		log.Info("запись "+strconv.Itoa(i), keyConsumer, callerDemo)
	}
	got := r.Journal(callerDemo, 0, 1000)
	if len(got) != 6 {
		t.Fatalf("в журнале %d записей при вместимости 6", len(got))
	}
	if got[len(got)-1].Message != "запись 99" {
		t.Errorf("последняя запись — %q", got[len(got)-1].Message)
	}
	if r.JournalSeq() != 100 {
		t.Errorf("номер последней записи %d, ожидался 100", r.JournalSeq())
	}
}

func TestJournalHandlerPassesThrough(t *testing.T) {
	// Зеркало не подменяет журнал: stdout продолжает получать то же самое.
	var out strings.Builder
	r := NewRecorder(4, 4)
	base := slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.New(NewJournalHandler(base, r)).Info("сообщение", keyConsumer, callerDemo)

	if !strings.Contains(out.String(), "сообщение") {
		t.Errorf("запись не дошла до настоящего журнала: %q", out.String())
	}
	if len(r.Journal(callerDemo, 0, 4)) != 1 {
		t.Error("запись не попала в буфер")
	}
}

func TestJournalHandlerIgnoresGroupedAttributes(t *testing.T) {
	// Внутри группы имена принадлежат её пространству, и белый список верхнего
	// уровня к ним неприменим. Такие атрибуты в буфер не попадают.
	r := NewRecorder(4, 4)
	log := newJournalLogger(r).With(keyOwner, callerDemo, keyConsumer, callerDemo)
	log.WithGroup("req").Info("в группе", keyOwner, callerCRM, keyConsumer, callerCRM, keyRequestID, "чужой")

	rows := r.Journal(callerDemo, 0, 4)
	if len(rows) != 1 {
		t.Fatalf("в журнале %d записей", len(rows))
	}
	if rows[0].Owner != callerDemo || rows[0].Consumer != callerDemo || rows[0].RequestID != "" {
		t.Errorf("атрибуты группы попали в буфер: %+v", rows[0])
	}
}

func TestJournalHandlerSkippedWhenBuffersOff(t *testing.T) {
	base := slog.NewTextHandler(io.Discard, nil)
	if got := NewJournalHandler(base, nil); got != base {
		t.Error("при выключенном буфере в цепочку журналирования добавлено лишнее звено")
	}
	if got := NewJournalHandler(base, NewRecorder(4, 0)); got != base {
		t.Error("при нулевом журнале в цепочку добавлено лишнее звено")
	}
}

func TestJournalHandlerRespectsLevel(t *testing.T) {
	r := NewRecorder(4, 4)
	base := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewJournalHandler(base, r)
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("зеркало включает уровень, отключённый настройкой журнала")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("зеркало отключает уровень, включённый настройкой журнала")
	}
}

// ── Бенчмарки ───────────────────────────────────────────────────────────────
//
// Сервис держит 20 000 запросов в секунду при среднем ответе 9,5 мс. Вопрос
// один: сколько стоит запись в кольцевой буфер относительно этого бюджета.
// «До» — выключенный буфер (обработчик вызывает тот же метод и выходит по
// проверке указателя), «после» — включённый. Разница и есть цена.

func BenchmarkRecorderDisabled(b *testing.B) {
	var r *Recorder
	rec := sample(1, callerDemo)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Record(&rec)
	}
}

func BenchmarkRecorderRecord(b *testing.B) {
	r := NewRecorder(DefaultHistorySize, DefaultJournalSize)
	rec := sample(1, callerDemo)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Record(&rec)
	}
}

// BenchmarkRecorderRecordParallel — тот же замер под конкуренцией: боевой
// профиль — до 200 одновременных соединений, и мьютекс буфера обязан оставаться
// дешевле полезной работы запроса.
func BenchmarkRecorderRecordParallel(b *testing.B) {
	r := NewRecorder(DefaultHistorySize, DefaultJournalSize)
	b.SetParallelism(200)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rec := sample(1, callerDemo)
		for pb.Next() {
			r.Record(&rec)
		}
	})
}

func BenchmarkRecorderDisabledParallel(b *testing.B) {
	var r *Recorder
	b.SetParallelism(200)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rec := sample(1, callerDemo)
		for pb.Next() {
			r.Record(&rec)
		}
	})
}

// BenchmarkRecordJournalOff и BenchmarkRecordJournalOn — цена зеркала журнала
// на фоне самого журналирования: сравнивается одна и та же запись slog с
// зеркалом и без него.
func BenchmarkRecordJournalOff(b *testing.B) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil)).With(keyRequestID, "r1")
	benchLog(b, log)
}

func BenchmarkRecordJournalOn(b *testing.B) {
	r := NewRecorder(DefaultHistorySize, DefaultJournalSize)
	base := slog.NewJSONHandler(io.Discard, nil)
	log := slog.New(NewJournalHandler(base, r)).With(keyRequestID, "r1")
	benchLog(b, log)
}

func benchLog(b *testing.B, log *slog.Logger) {
	b.Helper()
	types := []string{typeFullName, "phone"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Info(msgHandled,
			keyConsumer, callerDemo, "op", opMaskName, keyOutcome, "ok",
			keyDetectedTypes, types, keyMaskedTypes, types,
			keyMaskedCount, 3, keyDurationMS, 9)
	}
}
