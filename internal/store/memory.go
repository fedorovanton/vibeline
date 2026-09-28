package store

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

// shardCount — число независимых сегментов хранилища.
//
// Сегментирование снимает конкуренцию за один мьютекс: при 200 одновременных
// коннектах шансы попасть в один сегмент малы. Значение — степень двойки,
// чтобы выбор сегмента сводился к битовой маске.
const shardCount = 64

// Options — настройки хранилища в памяти.
type Options struct {
	// TTL — время жизни записи с момента создания.
	TTL time.Duration
	// MaxEntries ограничивает общее число записей. Ноль — без ограничения.
	MaxEntries int
	// MaxBytes ограничивает общий объём записей. Ноль — без ограничения.
	MaxBytes int64
	// SweepInterval задаёт период фоновой очистки истёкших записей.
	SweepInterval time.Duration
	// Now позволяет подменить источник времени в тестах.
	Now func() time.Time
}

func (o *Options) withDefaults() {
	if o.TTL <= 0 {
		o.TTL = 30 * time.Minute
	}
	if o.SweepInterval <= 0 {
		o.SweepInterval = time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

type entry struct {
	rec     Record
	expires int64 // unix nano
	seq     uint64
	size    int64
}

type orderRef struct {
	id  string
	seq uint64
}

type shard struct {
	mu      sync.RWMutex
	m       map[string]*entry
	order   []orderRef // порядок вставки, для вытеснения самых старых
	bytes   int64
	seq     uint64
	maxN    int
	maxB    int64
	evicted uint64
	expired uint64
}

// Memory — хранилище соответствий в памяти процесса.
//
// Ограничения задаются числом записей и суммарным объёмом; при исчерпании
// вытесняются самые старые записи. Неограниченный рост исключён: пятиминутный
// прогон с уникальными идентификаторами не должен исчерпать память хоста.
type Memory struct {
	shards [shardCount]shard
	opts   Options
	seed   maphash.Seed

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
	entries   atomic.Int64
}

// NewMemory создаёт хранилище и запускает фоновую очистку истёкших записей.
func NewMemory(opts Options) *Memory {
	opts.withDefaults()
	m := &Memory{opts: opts, seed: maphash.MakeSeed(), done: make(chan struct{})}

	perShardN := 0
	if opts.MaxEntries > 0 {
		perShardN = opts.MaxEntries / shardCount
		if perShardN < 1 {
			perShardN = 1
		}
	}
	var perShardB int64
	if opts.MaxBytes > 0 {
		perShardB = opts.MaxBytes / shardCount
		if perShardB < 1 {
			perShardB = 1
		}
	}
	for i := range m.shards {
		m.shards[i].m = make(map[string]*entry, 1024)
		m.shards[i].maxN = perShardN
		m.shards[i].maxB = perShardB
	}

	m.wg.Add(1)
	go m.sweepLoop()
	return m
}

func (m *Memory) shardFor(id string) *shard {
	h := maphash.String(m.seed, id)
	return &m.shards[h&(shardCount-1)]
}

// Get возвращает запись по идентификатору.
func (m *Memory) Get(id string) (Record, bool) {
	s := m.shardFor(id)
	now := m.opts.Now().UnixNano()

	s.mu.RLock()
	e, ok := s.m[id]
	if !ok || e.expires <= now {
		s.mu.RUnlock()
		return Record{}, false
	}
	rec := e.rec
	s.mu.RUnlock()
	return rec, true
}

// Put сохраняет запись, вытесняя при необходимости самые старые.
func (m *Memory) Put(id string, rec Record) error {
	now := m.opts.Now()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	size := rec.Size(id)
	s := m.shardFor(id)

	if s.maxB > 0 && size > s.maxB {
		return ErrFull // одна запись не помещается в бюджет сегмента
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if old, ok := s.m[id]; ok {
		s.bytes -= old.size
		delete(s.m, id)
		m.entries.Add(-1)
	}
	if evicted := s.evictLocked(size, now.UnixNano()); evicted > 0 {
		m.entries.Add(int64(-evicted))
	}

	s.seq++
	s.m[id] = &entry{rec: rec, expires: now.Add(m.opts.TTL).UnixNano(), seq: s.seq, size: size}
	s.order = append(s.order, orderRef{id: id, seq: s.seq})
	s.maybeCompactOrderLocked()
	s.bytes += size
	m.entries.Add(1)
	return nil
}

// maybeCompactOrderLocked сжимает очередь вытеснения, когда устаревших
// ссылок в ней становится больше живых записей.
//
// Перезапись того же ключа оставляет в очереди старую ссылку, а убирает её
// только вытеснение при упоре в предел или фоновая очистка истёкших. Сто
// тысяч перезаписей одного ключа давали одну запись и очередь из ста тысяч
// ссылок (С-13 проверки качества кода 23.09). Сжатие при двукратном перевесе
// стоит амортизированно O(1) на запись.
func (s *shard) maybeCompactOrderLocked() {
	if len(s.order) > 2*len(s.m)+64 {
		s.compactOrderLocked()
	}
}

// evictLocked освобождает место под запись размером size и возвращает число
// удалённых записей. Вызывается под удерживаемой блокировкой сегмента.
//
// Счётчик записей хранилища ведётся вызывающим кодом: сегмент не знает про
// общий счётчик, а расхождение между ними приводит к тому, что лимит
// перестаёт соблюдаться.
func (s *shard) evictLocked(size int64, now int64) int {
	removed := 0
	for len(s.order) > 0 {
		overN := s.maxN > 0 && len(s.m)+1 > s.maxN
		overB := s.maxB > 0 && s.bytes+size > s.maxB
		if !overN && !overB {
			return removed
		}
		ref := s.order[0]
		s.order = s.order[1:]
		e, ok := s.m[ref.id]
		if !ok || e.seq != ref.seq {
			continue // устаревшая ссылка: запись уже заменена или удалена
		}
		s.bytes -= e.size
		delete(s.m, ref.id)
		removed++
		if e.expires <= now {
			s.expired++
		} else {
			s.evicted++
		}
	}
	return removed
}

// Stats возвращает текущее состояние хранилища.
func (m *Memory) Stats() Stats {
	var st Stats
	st.Entries = int(m.entries.Load())
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.RLock()
		st.Bytes += s.bytes
		st.Evicted += s.evicted
		st.Expired += s.expired
		s.mu.RUnlock()
	}
	return st
}

// Close останавливает фоновую очистку и дожидается её завершения.
func (m *Memory) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)
		m.wg.Wait()
	})
	return nil
}

// sweepLoop — единственная фоновая горутина хранилища. Владелец — Memory,
// условие выхода — закрытие канала done в Close.
func (m *Memory) sweepLoop() {
	defer m.wg.Done()
	t := time.NewTicker(m.opts.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.sweep()
		}
	}
}

func (m *Memory) sweep() {
	now := m.opts.Now().UnixNano()
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		removed := 0
		for id, e := range s.m {
			if e.expires <= now {
				s.bytes -= e.size
				delete(s.m, id)
				s.expired++
				removed++
			}
		}
		if removed > 0 {
			s.compactOrderLocked()
		}
		s.mu.Unlock()
		if removed > 0 {
			m.entries.Add(int64(-removed))
		}
	}
}

// compactOrderLocked выбрасывает из очереди ссылки на уже удалённые записи,
// чтобы очередь не росла неограниченно при долгом прогоне.
func (s *shard) compactOrderLocked() {
	kept := s.order[:0]
	for _, ref := range s.order {
		if e, ok := s.m[ref.id]; ok && e.seq == ref.seq {
			kept = append(kept, ref)
		}
	}
	s.order = kept
}
