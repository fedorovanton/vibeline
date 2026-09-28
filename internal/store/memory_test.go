package store

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// Фикстуры тестов: идентификатор записи и синтетическая маска.
const (
	testID1         = "id-1"
	placeholderFIO1 = "[ФИО_1]"
)

func newTestStore(t *testing.T, opts Options) *Memory {
	t.Helper()
	m := NewMemory(opts)
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestPutGetRoundTrip(t *testing.T) {
	m := newTestStore(t, Options{TTL: time.Hour})
	rec := Record{Original: "исходный текст", Masked: placeholderFIO1, Consumer: "benchmark"}

	if err := m.Put(testID1, rec); err != nil {
		t.Fatalf("Put вернул ошибку: %v", err)
	}
	got, ok := m.Get(testID1)
	if !ok {
		t.Fatal("запись не найдена сразу после сохранения")
	}
	if got.Original != rec.Original || got.Masked != rec.Masked {
		t.Fatalf("запись искажена: получено %+v, ожидалось %+v", got, rec)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt не проставлен")
	}
}

func TestGetMissing(t *testing.T) {
	m := newTestStore(t, Options{TTL: time.Hour})
	if _, ok := m.Get("нет такого"); ok {
		t.Error("получена запись по неизвестному идентификатору")
	}
}

func TestExpiredRecordIsInvisible(t *testing.T) {
	now := time.Now()
	clock := now
	m := newTestStore(t, Options{TTL: time.Minute, Now: func() time.Time { return clock }})

	if err := m.Put(testID1, Record{Original: "a", Masked: "b"}); err != nil {
		t.Fatalf("Put вернул ошибку: %v", err)
	}
	clock = now.Add(time.Minute + time.Second)

	if _, ok := m.Get(testID1); ok {
		t.Error("истёкшая запись видна через Get")
	}
}

func TestPutReplacesExisting(t *testing.T) {
	m := newTestStore(t, Options{TTL: time.Hour})
	_ = m.Put(testID1, Record{Original: "первый", Masked: "м1"})
	_ = m.Put(testID1, Record{Original: "второй", Masked: "м2"})

	got, ok := m.Get(testID1)
	if !ok {
		t.Fatal("запись пропала после замены")
	}
	if got.Original != "второй" {
		t.Fatalf("осталась старая запись: %q", got.Original)
	}
	if st := m.Stats(); st.Entries != 1 {
		t.Fatalf("замена породила лишнюю запись: Entries=%d", st.Entries)
	}
}

func TestEvictionByEntryLimit(t *testing.T) {
	// Лимит делится между сегментами, поэтому проверяется не точное число
	// вытеснений, а то, что рост ограничен и вытеснение происходит.
	const perShard = 2
	m := newTestStore(t, Options{TTL: time.Hour, MaxEntries: perShard * shardCount})

	const n = shardCount * perShard * 8
	for i := 0; i < n; i++ {
		if err := m.Put("id-"+strconv.Itoa(i), Record{Original: "o", Masked: "m"}); err != nil {
			t.Fatalf("Put %d вернул ошибку: %v", i, err)
		}
	}
	st := m.Stats()
	if st.Entries > perShard*shardCount {
		t.Fatalf("число записей превысило лимит: %d > %d", st.Entries, perShard*shardCount)
	}
	if st.Evicted == 0 {
		t.Error("вытеснение не зафиксировано, хотя лимит исчерпан")
	}
}

func TestOversizedRecordRejected(t *testing.T) {
	m := newTestStore(t, Options{TTL: time.Hour, MaxBytes: shardCount * 200})
	big := make([]byte, 4096)
	err := m.Put(testID1, Record{Original: string(big), Masked: "м"})
	if err != ErrFull {
		t.Fatalf("ожидалась ErrFull, получено: %v", err)
	}
}

func TestSweepRemovesExpired(t *testing.T) {
	now := time.Now()
	clock := now
	m := newTestStore(t, Options{
		TTL:           time.Minute,
		SweepInterval: time.Hour, // очистку запускаем вручную
		Now:           func() time.Time { return clock },
	})
	for i := 0; i < 100; i++ {
		_ = m.Put("id-"+strconv.Itoa(i), Record{Original: "o", Masked: "m"})
	}
	clock = now.Add(2 * time.Minute)
	m.sweep()

	st := m.Stats()
	if st.Entries != 0 {
		t.Fatalf("после очистки осталось %d записей", st.Entries)
	}
	if st.Expired != 100 {
		t.Fatalf("учтено %d истёкших записей вместо 100", st.Expired)
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := newTestStore(t, Options{TTL: time.Hour})
	const workers, perWorker = 16, 200

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := "w" + strconv.Itoa(w) + "-" + strconv.Itoa(i)
				if err := m.Put(id, Record{Original: id, Masked: "м"}); err != nil {
					t.Errorf("Put %s: %v", id, err)
					return
				}
				got, ok := m.Get(id)
				if !ok || got.Original != id {
					t.Errorf("запись %s потеряна или искажена", id)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if st := m.Stats(); st.Entries != workers*perWorker {
		t.Fatalf("сохранено %d записей вместо %d", st.Entries, workers*perWorker)
	}
}

// TestMemoryRewriteDoesNotGrowOrder — перезапись одного ключа не копит
// устаревшие ссылки в очереди вытеснения (С-13 проверки качества кода 23.09).
func TestMemoryRewriteDoesNotGrowOrder(t *testing.T) {
	m := NewMemory(Options{MaxEntries: 1 << 20})
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("закрытие хранилища: %v", err)
		}
	})
	for i := 0; i < 100_000; i++ {
		if err := m.Put("same-id", Record{Original: "синтетика", Masked: placeholderFIO1}); err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for i := range m.shards {
		total += len(m.shards[i].order)
	}
	if total > 200 {
		t.Fatalf("очередь вытеснения выросла до %d ссылок при одной живой записи", total)
	}
	if rec, ok := m.Get("same-id"); !ok || rec.Masked != placeholderFIO1 {
		t.Fatal("запись потеряна после сжатия очереди")
	}
}
