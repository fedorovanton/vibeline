package eval

import (
	"sort"

	"qualitycheck/corpus"
)

// TypeStat — метрики по одному типу персональных данных.
//
// Precision и recall считаются по факту сокрытия значения, а не по совпадению
// границ спана: соглашение корпуса о границах может не совпадать с разметкой
// детектора, и сверка границ занизила бы цифры, не имея отношения к качеству
// защиты.
//
//	TP — размеченное значение исчезло из ответа;
//	FN — размеченное значение осталось в ответе (пропуск);
//	FP — ловушка этого типа исчезла из ответа (ложное срабатывание).
//
// У типов, для которых корпус не содержит ловушек, источника FP нет: precision
// у них равна единице по построению и качество отнесения не измеряет. Поле
// Traps показано в отчёте именно поэтому.
type TypeStat struct {
	Type   string `json:"type"`
	Spans  int    `json:"spans"`
	Hidden int    `json:"hidden"`
	Leaked int    `json:"leaked"`
	// LeakedAmbiguous — утечки, значение которых встречается в тексте и вне
	// разметки. Верхняя граница recall получается, если считать их скрытыми.
	LeakedAmbiguous int `json:"leaked_ambiguous"`
	// LeakedPartial — утечки, где значение замаскировано не целиком. Их стоит
	// смотреть первыми: это дефект границ правила, а не пропуск типа.
	LeakedPartial int     `json:"leaked_partial"`
	Traps         int     `json:"traps"`
	TrapsMasked   int     `json:"traps_masked"`
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	RecallUpper   float64 `json:"recall_upper"`
	F1            float64 `json:"f1"`
}

// KindStat — метрики по виду записей. Вид namesake выделен намеренно: там
// фамилия публичной персоны принадлежит клиенту, значение обязано быть скрыто,
// и пропуск стоит дороже всего.
type KindStat struct {
	Kind            string `json:"kind"`
	Records         int    `json:"records"`
	Spans           int    `json:"spans"`
	Hidden          int    `json:"hidden"`
	Leaked          int    `json:"leaked"`
	LeakedAmbiguous int    `json:"leaked_ambiguous"`
	Traps           int    `json:"traps"`
	TrapsMasked     int    `json:"traps_masked"`
	Changed         int    `json:"changed_records"`
	RestoreErrors   int    `json:"restore_errors"`
}

// ReasonStat — ложные срабатывания по причинам ловушек.
type ReasonStat struct {
	Reason string  `json:"reason"`
	Traps  int     `json:"traps"`
	Masked int     `json:"masked"`
	Rate   float64 `json:"rate"`
}

// Redundancy — избыточное маскирование в байтах.
type Redundancy struct {
	TextBytes    int `json:"text_bytes"`
	SpanBytes    int `json:"span_bytes"`
	OutsideBytes int `json:"outside_span_bytes"`
	MaskedBytes  int `json:"masked_bytes"`
	ExcessBytes  int `json:"excess_bytes"`
	// ExcessOfMasked — доля избыточного среди всего замаскированного.
	ExcessOfMasked float64 `json:"excess_of_masked"`
	// ExcessOfOutside — доля текста вне спанов, который оказался замаскирован.
	ExcessOfOutside float64 `json:"excess_of_outside"`
	// FullyMasked — записи, изменённые целиком. Избыточным это считается
	// только когда текст не состоит из одного значения (A4.4).
	FullyMasked int `json:"fully_masked_records"`
	// CleanChanged — записи без ПД и без ловушек, которые всё-таки изменены.
	CleanChanged int `json:"clean_records_changed"`
	CleanTotal   int `json:"clean_records_total"`
}

// Restore — побайтовое восстановление на обратном шаге.
type Restore struct {
	Records  int     `json:"records"`
	Restored int     `json:"restored"`
	Failed   int     `json:"failed"`
	Rate     float64 `json:"error_rate"`
}

// Totals — сводные числа прогона.
type Totals struct {
	Records         int     `json:"records"`
	Evaluated       int     `json:"evaluated"`
	Errors          int     `json:"errors"`
	Spans           int     `json:"spans"`
	Hidden          int     `json:"hidden"`
	Leaked          int     `json:"leaked"`
	LeakedAmbiguous int     `json:"leaked_ambiguous"`
	LeakedPartial   int     `json:"leaked_partial"`
	HideRate        float64 `json:"hide_rate"`
	HideRateUpper   float64 `json:"hide_rate_upper"`
	Traps           int     `json:"traps"`
	TrapsMasked     int     `json:"traps_masked"`
	TrapRate        float64 `json:"trap_false_positive_rate"`
	Precision       float64 `json:"precision"`
	Recall          float64 `json:"recall"`
	F1              float64 `json:"f1"`
	Ambiguous       int     `json:"ambiguous_spans"`
}

// Leak — пропущенное значение. Значение не печатается без -verbose: в отчёте
// остаются только тип, идентификатор записи и позиция.
type Leak struct {
	RecordID  string `json:"record_id"`
	Kind      string `json:"kind"`
	Type      string `json:"type"`
	Start     int    `json:"start"`
	End       int    `json:"end"`
	Ambiguous bool   `json:"ambiguous"`
	// Partial — значение замаскировано не целиком: часть его уцелела в ответе.
	Partial bool   `json:"partial,omitempty"`
	Value   string `json:"value,omitempty"`
}

// FalsePositive — ошибочно замаскированная ловушка.
type FalsePositive struct {
	RecordID string `json:"record_id"`
	Type     string `json:"type"`
	Reason   string `json:"reason"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Value    string `json:"value,omitempty"`
}

// RunError — запись, прогон которой не состоялся.
type RunError struct {
	RecordID string `json:"record_id"`
	Error    string `json:"error"`
}

// Metrics — всё измеренное за прогон.
type Metrics struct {
	Totals         Totals          `json:"totals"`
	Types          []TypeStat      `json:"types"`
	Kinds          []KindStat      `json:"kinds"`
	Reasons        []ReasonStat    `json:"trap_reasons"`
	Redundancy     Redundancy      `json:"redundancy"`
	Restore        Restore         `json:"restore"`
	Leaks          []Leak          `json:"leaks"`
	FalsePositives []FalsePositive `json:"false_positives"`
	Errors         []RunError      `json:"run_errors"`
}

// Aggregate сводит итоги записей в метрики отчёта.
func Aggregate(results []RecordResult) Metrics {
	a := aggregator{
		types:   map[string]*TypeStat{},
		kinds:   map[string]*KindStat{},
		reasons: map[string]*ReasonStat{},
	}
	for i := range results {
		a.addRecord(&results[i])
	}
	return a.finalize()
}

// aggregator — промежуточное состояние Aggregate: сводные метрики и счётчики
// по типам, видам и причинам ловушек, которые в отчёт попадают отсортированными.
type aggregator struct {
	m       Metrics
	types   map[string]*TypeStat
	kinds   map[string]*KindStat
	reasons map[string]*ReasonStat
}

// getOrCreate возвращает запись по ключу, заводя её при первом обращении.
func getOrCreate[V any](m map[string]*V, key string, create func() *V) *V {
	v := m[key]
	if v == nil {
		v = create()
		m[key] = v
	}
	return v
}

func (a *aggregator) addRecord(r *RecordResult) {
	m := &a.m
	m.Totals.Records++
	if r.Err != "" {
		m.Totals.Errors++
		m.Errors = append(m.Errors, RunError{RecordID: r.ID, Error: r.Err})
		return
	}
	m.Totals.Evaluated++
	m.Totals.Ambiguous += r.Ambiguous

	k := getOrCreate(a.kinds, r.Kind, func() *KindStat { return &KindStat{Kind: r.Kind} })
	k.Records++
	if r.Changed {
		k.Changed++
	}
	if !r.Restored {
		k.RestoreErrors++
	}

	m.Restore.Records++
	if r.Restored {
		m.Restore.Restored++
	} else {
		m.Restore.Failed++
	}

	a.addRedundancy(r)
	for i := range r.Spans {
		a.addSpan(k, &r.Spans[i])
	}
	for i := range r.Traps {
		a.addTrap(k, &r.Traps[i])
	}
}

func (a *aggregator) addRedundancy(r *RecordResult) {
	rd := &a.m.Redundancy
	rd.TextBytes += r.TextBytes
	rd.SpanBytes += r.SpanBytes
	rd.MaskedBytes += r.MaskedBytes
	rd.ExcessBytes += r.ExcessBytes
	if r.FullyMasked && r.SpanBytes < r.TextBytes {
		rd.FullyMasked++
	}
	if r.Kind == corpus.KindClean {
		rd.CleanTotal++
		if r.Changed {
			rd.CleanChanged++
		}
	}
}

func (a *aggregator) typeStat(name string) *TypeStat {
	return getOrCreate(a.types, name, func() *TypeStat { return &TypeStat{Type: name} })
}

func (a *aggregator) addSpan(k *KindStat, s *SpanOutcome) {
	m := &a.m
	t := a.typeStat(s.Type)
	t.Spans++
	k.Spans++
	m.Totals.Spans++
	if s.Hidden {
		t.Hidden++
		k.Hidden++
		m.Totals.Hidden++
		return
	}
	t.Leaked++
	k.Leaked++
	m.Totals.Leaked++
	if s.Ambiguous {
		t.LeakedAmbiguous++
		k.LeakedAmbiguous++
		m.Totals.LeakedAmbiguous++
	}
	if s.Partial {
		t.LeakedPartial++
		m.Totals.LeakedPartial++
	}
	m.Leaks = append(m.Leaks, Leak{
		RecordID: s.RecordID, Kind: s.Kind, Type: s.Type,
		Start: s.Start, End: s.End, Ambiguous: s.Ambiguous,
		Partial: s.Partial, Value: s.Value,
	})
}

func (a *aggregator) addTrap(k *KindStat, tr *TrapOutcome) {
	m := &a.m
	t := a.typeStat(tr.Type)
	rs := getOrCreate(a.reasons, tr.Reason, func() *ReasonStat { return &ReasonStat{Reason: tr.Reason} })
	t.Traps++
	rs.Traps++
	k.Traps++
	m.Totals.Traps++
	if !tr.Masked {
		return
	}
	t.TrapsMasked++
	rs.Masked++
	k.TrapsMasked++
	m.Totals.TrapsMasked++
	m.FalsePositives = append(m.FalsePositives, FalsePositive{
		RecordID: tr.RecordID, Type: tr.Type, Reason: tr.Reason,
		Start: tr.Start, End: tr.End, Value: tr.Value,
	})
}

// finalize считает доли и раскладывает накопленное в детерминированном порядке.
func (a *aggregator) finalize() Metrics {
	m := a.m
	for _, name := range corpus.SortedKeys(a.types) {
		t := a.types[name]
		t.Precision = ratio(t.Hidden, t.Hidden+t.TrapsMasked)
		t.Recall = ratio(t.Hidden, t.Spans)
		t.RecallUpper = ratio(t.Hidden+t.LeakedAmbiguous, t.Spans)
		t.F1 = f1(t.Precision, t.Recall)
		m.Types = append(m.Types, *t)
	}
	for _, name := range corpus.SortedKeys(a.kinds) {
		m.Kinds = append(m.Kinds, *a.kinds[name])
	}
	for _, name := range corpus.SortedKeys(a.reasons) {
		r := a.reasons[name]
		r.Rate = ratio(r.Masked, r.Traps)
		m.Reasons = append(m.Reasons, *r)
	}

	m.Totals.HideRate = ratio(m.Totals.Hidden, m.Totals.Spans)
	m.Totals.HideRateUpper = ratio(m.Totals.Hidden+m.Totals.LeakedAmbiguous, m.Totals.Spans)
	m.Totals.TrapRate = ratio(m.Totals.TrapsMasked, m.Totals.Traps)
	m.Totals.Precision = ratio(m.Totals.Hidden, m.Totals.Hidden+m.Totals.TrapsMasked)
	m.Totals.Recall = ratio(m.Totals.Hidden, m.Totals.Spans)
	m.Totals.F1 = f1(m.Totals.Precision, m.Totals.Recall)

	m.Redundancy.OutsideBytes = m.Redundancy.TextBytes - m.Redundancy.SpanBytes
	m.Redundancy.ExcessOfMasked = ratio(m.Redundancy.ExcessBytes, m.Redundancy.MaskedBytes)
	m.Redundancy.ExcessOfOutside = ratio(m.Redundancy.ExcessBytes, m.Redundancy.OutsideBytes)
	m.Restore.Rate = ratio(m.Restore.Failed, m.Restore.Records)

	sortByPosition(m.Leaks, func(l Leak) (string, int) { return l.RecordID, l.Start })
	sortByPosition(m.FalsePositives, func(f FalsePositive) (string, int) { return f.RecordID, f.Start })
	sort.Slice(m.Errors, func(i, j int) bool { return m.Errors[i].RecordID < m.Errors[j].RecordID })
	return m
}

// Redact вычищает значения персональных данных. Вызывается всегда, кроме
// явного -verbose: отчёт не должен содержать ни одного значения.
func (m *Metrics) Redact() {
	for i := range m.Leaks {
		m.Leaks[i].Value = ""
	}
	for i := range m.FalsePositives {
		m.FalsePositives[i].Value = ""
	}
}

// sortByPosition упорядочивает находки по записи, затем по началу в тексте.
func sortByPosition[T any](v []T, key func(T) (string, int)) {
	sort.Slice(v, func(i, j int) bool {
		ri, si := key(v[i])
		rj, sj := key(v[j])
		if ri != rj {
			return ri < rj
		}
		return si < sj
	})
}

// ratio возвращает долю; пустой знаменатель даёт ноль, а не NaN, иначе доля
// не сериализуется в JSON.
func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func f1(precision, recall float64) float64 {
	if precision+recall == 0 {
		return 0
	}
	return 2 * precision * recall / (precision + recall)
}
