package corpus

import (
	"fmt"
	"math/rand/v2"
)

// Значения по умолчанию для командной строки.
const (
	DefaultCount = 1200
	DefaultSeed  = 20260922
)

// MinPerType — нижняя граница покрытия: каждый из 17 обязательных типов должен
// встречаться минимум в стольких записях, иначе оценка по типу статистически
// пуста.
const MinPerType = 60

// Options — параметры генерации.
type Options struct {
	Count int    // базовое число записей, без длинных
	Seed  uint64 // зерно: один seed даёт побайтово одинаковый корпус
	Long  bool   // добавлять ли длинные записи
	// Bare добавляет голые значения (KindBare) в самый конец корпуса. Поток
	// ГПСЧ у них свой, поэтому остальной корпус от флага не меняется: корпус
	// без флага — побайтовый префикс корпуса с флагом.
	Bare bool
}

// Generate строит корпус. Результат полностью определяется Options: ГПСЧ
// создаётся из seed, обходов map в генерации нет, порядок записей задан
// перемешиванием того же ГПСЧ. Без этого метрики разных прогонов несравнимы.
func Generate(opt Options) []Record {
	if opt.Count <= 0 {
		opt.Count = DefaultCount
	}
	// Второй поток PCG выводится из seed: два разных seed дают два разных
	// состояния, один и тот же seed — всегда одно и то же.
	g := &gen{r: rand.New(rand.NewPCG(opt.Seed, opt.Seed^0x9E3779B97F4A7C15))}

	nTrap := share(opt.Count, 12, len(trapTemplates))
	nClean := share(opt.Count, 8, len(cleanTexts))
	nNamesake := share(opt.Count, 3, len(namesakes))
	nMulti := share(opt.Count, 18, len(multis))
	nSingle := opt.Count - nTrap - nClean - nNamesake - nMulti
	if nSingle < len(RequiredTypes) {
		nSingle = len(RequiredTypes)
	}

	recs := make([]Record, 0, opt.Count+len(LongSizes))
	// Типы перебираются по кругу, шаблоны внутри типа — тоже: так каждый
	// шаблон и каждая вариация написания попадают в корпус, а не «в среднем».
	for i := 0; i < nSingle; i++ {
		recs = append(recs, g.single(RequiredTypes[i%len(RequiredTypes)], i/len(RequiredTypes)))
	}
	for i := 0; i < nMulti; i++ {
		recs = append(recs, g.build(KindMulti, multis[i%len(multis)].make))
	}
	for i := 0; i < nTrap; i++ {
		recs = append(recs, g.build(KindTrap, trapTemplates[i%len(trapTemplates)].make))
	}
	for i := 0; i < nClean; i++ {
		recs = append(recs, g.clean(i%len(cleanTexts)))
	}
	for i := 0; i < nNamesake; i++ {
		recs = append(recs, g.build(KindNamesake, namesakes[i%len(namesakes)]))
	}

	recs = topUp(g, recs)

	g.r.Shuffle(len(recs), func(i, j int) { recs[i], recs[j] = recs[j], recs[i] })

	// Длинные записи идут в конец: потребителю корпуса удобнее встретить
	// мегабайтный текст после коротких, а не в середине.
	if opt.Long {
		for _, size := range LongSizes {
			recs = append(recs, g.longRecord(size))
		}
	}
	// Голые значения идут за длинными, а не перед ними: так у всех прежних
	// записей остаются и содержимое, и идентификаторы.
	if opt.Bare {
		recs = append(recs, bareRecords(opt.Seed)...)
	}

	for i := range recs {
		recs[i].ID = fmt.Sprintf("c-%04d", i+1)
	}
	return recs
}

// share возвращает долю от count, но не меньше floor: при малом -count иначе
// пропали бы целые виды записей (например, часть видов ловушек).
func share(count, percent, floor int) int {
	return max(count*percent/100, floor)
}

func (g *gen) build(kind string, compose func(g *gen) []piece) Record {
	var b builder
	b.add(compose(g)...)
	return b.record(kind)
}

func (g *gen) clean(i int) Record {
	var b builder
	b.add(lit(cleanTexts[i]))
	return b.record(KindClean)
}

func (g *gen) single(typ string, round int) Record {
	ts := singles[typ]
	return g.build(KindSingle, ts[round%len(ts)].make)
}

// topUp добавляет записи для типов, не добравших MinPerType: доли по видам
// записей случайны, и без добора редкий тип может не собрать статистики.
func topUp(g *gen, recs []Record) []Record {
	counts := map[string]int{}
	for i := range recs {
		for _, t := range recordTypes(&recs[i]) {
			counts[t]++
		}
	}
	for _, typ := range RequiredTypes {
		// Граница на число попыток защищает от бесконечного цикла, если
		// шаблон типа перестанет порождать спан своего типа.
		for round := 0; counts[typ] < MinPerType && round < 10*MinPerType; round++ {
			rec := g.single(typ, round)
			for _, t := range recordTypes(&rec) {
				counts[t]++
			}
			recs = append(recs, rec)
		}
	}
	return recs
}

// recordTypes возвращает типы ПД записи без повторов, в порядке появления.
func recordTypes(r *Record) []string {
	out := make([]string, 0, len(r.Spans))
	for _, s := range r.Spans {
		seen := false
		for _, t := range out {
			if t == s.Type {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, s.Type)
		}
	}
	return out
}

// ---------- Сводка ----------

// TypeStat — покрытие одного типа ПД.
type TypeStat struct {
	Type    string
	Records int
	Spans   int
}

// ReasonStat — сколько ловушек каждого вида.
type ReasonStat struct {
	Reason string
	Traps  int
}

// KindStat — сколько записей каждого вида.
type KindStat struct {
	Kind    string
	Records int
}

// Summary — сводка по корпусу для отчёта и для проверки критериев приёмки.
type Summary struct {
	Records int
	Tokens  int
	Kinds   []KindStat
	Types   []TypeStat
	Reasons []ReasonStat
}

var kindOrder = []string{KindSingle, KindMulti, KindTrap, KindClean, KindNamesake, KindLong, KindBare}

// Summarize считает сводку. Порядок строк фиксирован списками RequiredTypes,
// TrapReasons и kindOrder: обход map дал бы разный вывод при каждом запуске.
func Summarize(recs []Record) Summary {
	s := Summary{Records: len(recs)}
	byKind := map[string]int{}
	recsByType := map[string]int{}
	spansByType := map[string]int{}
	byReason := map[string]int{}

	for i := range recs {
		r := &recs[i]
		byKind[r.Kind]++
		s.Tokens += countTokens(r.Text)
		for _, t := range recordTypes(r) {
			recsByType[t]++
		}
		for _, sp := range r.Spans {
			spansByType[sp.Type]++
		}
		for _, tr := range r.Traps {
			byReason[tr.Reason]++
		}
	}
	for _, k := range kindOrder {
		s.Kinds = append(s.Kinds, KindStat{Kind: k, Records: byKind[k]})
	}
	for _, t := range RequiredTypes {
		s.Types = append(s.Types, TypeStat{Type: t, Records: recsByType[t], Spans: spansByType[t]})
	}
	for _, r := range TrapReasons {
		s.Reasons = append(s.Reasons, ReasonStat{Reason: r, Traps: byReason[r]})
	}
	return s
}
