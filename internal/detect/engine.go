package detect

import (
	"context"
	"maps"
	"slices"
	"sort"
	"sync"
	"sync/atomic"

	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/lex"
)

// Engine — движок детекции: запускает сканеры и разрешает их результаты.
//
// Движок неизменяем после создания и безопасен для конкурентного использования.
// Изменяемое состояние запроса живёт в Candidates и Result, которые передаются
// вызывающим кодом и берутся из пула.
type Engine struct {
	scanners []Scanner
	dicts    *dict.Set
}

// New собирает движок из справочников и набора сканеров.
func New(dicts *dict.Set, scanners ...Scanner) *Engine {
	return &Engine{scanners: scanners, dicts: dicts}
}

// Scanners возвращает имена подключённых сканеров — для диагностики и README.
func (e *Engine) Scanners() []string {
	out := make([]string, len(e.scanners))
	for i, s := range e.scanners {
		out[i] = s.Name()
	}
	return out
}

// cancelStride — через сколько шагов цикла движок проверяет отмену.
//
// Степень двойки, чтобы проверка шага была маской, а не делением. Шаг
// выбран так, чтобы проверка не была заметна в горячем пути — на тексте в
// четыре килобайта до неё не доходит ни разу, — и при этом квадратичный цикл
// на тысячах кандидатов не уходил за предел обработки без единой проверки.
const cancelStride = 1 << 10

// Detect находит персональные данные в размеченном тексте.
//
// Возвращается res, заполненный непересекающимися спанами в порядке появления
// в тексте. Аргументы cand и res переиспользуются вызывающим кодом; их
// содержимое перезаписывается.
//
// Если в тексте больше значений к маскированию, чем разрешает
// opts.MaxSpans, res.LimitExceeded выставляется в true, а res.Spans содержит
// только первые по силе спаны в пределах предела. Такой результат неполон:
// выпускать по нему текст нельзя — остаток значений остался бы открытым.
func (e *Engine) Detect(ctx context.Context, doc *lex.Doc, opts Options, cand *Candidates, res *Result) (*Result, error) {
	cand.Reset()
	res.Reset()

	// Отмена проверяется между сканерами и внутри циклов движка, которые
	// растут быстрее числа кандидатов (вето по спанам, вставка в отбор).
	// Без проверки объявленный предел обработки был бы фикцией: запрос с
	// десятками тысяч кандидатов досчитывал бы отбор после истечения
	// бюджета.
	for _, sc := range e.scanners {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sc.Scan(doc, e.dicts, cand)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	spans := cand.Spans
	if err := applyVetos(ctx, spans, cand.Vetos); err != nil {
		return nil, err
	}
	// Подъём по кластеру — то, чем balanced отличается от strict: порог
	// допуска у обоих профилей один (Strong), и слабый кандидат внутри
	// кластера доходит до отбора только под balanced. Под paranoid подъём
	// не нужен — там допускается любой кандидат. Решение T-25.
	if opts.Profile == Balanced {
		promoteByCluster(doc, spans, cand)
	}
	// Голое значение — payload целиком из одного значения ПД (T-63, A4.4).
	// Под strict шаг не выполняется: этот профиль маскирует только то, что
	// сканер нашёл достоверным сам. Под paranoid слабые кандидаты допускаются
	// и так, но классификатор формы нужен и там: у «314» кандидата нет вовсе,
	// а у «9264071835» он другого типа.
	//
	// Шаг идёт после подъёма по кластеру, а не до него: значение, опознанное
	// по форме строки, не должно становиться якорем. Иначе слабый кандидат на
	// тех же байтах поднимался бы кластером до той же силы и выигрывал
	// перекрытие порядком типа: «9264071835» опознан телефоном, а маской
	// становился паспорт. Кандидат дописывается, поэтому срез перечитывается.
	if opts.Profile != Strict {
		promoteBare(doc, e.dicts, cand)
		spans = cand.Spans
	}
	kept, exceeded, err := selectSpans(ctx, spans, opts, cand)
	if err != nil {
		return nil, err
	}
	res.LimitExceeded = exceeded

	res.Spans = append(res.Spans, kept...)
	for _, s := range res.Spans {
		res.Found = res.Found.Add(s.Type)
		if res.Counts[s.Type] < ^uint16(0) {
			res.Counts[s.Type]++
		}
	}
	return res, nil
}

// applyVetos опускает до Denied каждый спан, накрытый подходящим запретом.
// Запрет действует при любом пересечении: контр-правило описывает участок
// текста, который не является персональными данными.
//
// Цикл — произведение числа спанов на число запретов, поэтому отмена
// проверяется по счётчику сравнений, а не по спанам: иначе один спан при
// сотне тысяч запретов проходил бы без единой проверки.
func applyVetos(ctx context.Context, spans []Span, vetos []Veto) error {
	if len(vetos) == 0 {
		return nil
	}
	steps := 0
	for i := range spans {
		s := &spans[i]
		for _, v := range vetos {
			if steps++; steps&(cancelStride-1) == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if !engineVetoCovers(v, s) {
				continue
			}
			s.Conf = Denied
			s.Rule = v.Rule
			break
		}
	}
	return nil
}

// engineVetoCovers сообщает, что запрет v снимает спан s: участки
// пересекаются, и запрет либо на все типы, либо на тип спана.
func engineVetoCovers(v Veto, s *Span) bool {
	if s.Start >= v.End || s.End <= v.Start {
		return false
	}
	return v.Types.Empty() || v.Types.Has(s.Type)
}

// promoteByCluster повышает слабых кандидатов до Strong, если в том же
// предложении есть достоверное значение другого типа.
//
// Основание: реквизиты в пределах одного предложения относятся к одной
// сущности. Три цифры сами по себе ничего не значат, но три цифры рядом с
// номером карты, прошедшим проверку Луна, — это CVV. Этот же механизм
// закрывает требование ТЗ §6 «маскировать при наличии нескольких
// однозначно идентифицированных типов».
func promoteByCluster(doc *lex.Doc, spans []Span, cand *Candidates) {
	if len(spans) < 2 {
		return
	}
	cand.sentences = sentenceStarts(doc, cand.sentences)
	bounds := cand.sentences

	// Идентификаторы предложений плотные — от нуля до числа предложений,
	// поэтому якоря держатся в срезе по индексу, а не в карте: карта на
	// запрос это и аллокация, и хеширование там, где хватает индексации.
	anchors := cand.anchors[:0]
	for range bounds {
		anchors = append(anchors, 0)
	}
	cand.anchors = anchors

	found := false
	for _, s := range spans {
		if s.Conf < Strong {
			continue
		}
		id := sentenceOf(bounds, s.Start)
		anchors[id] = anchors[id].Add(s.Type)
		found = true
	}
	if !found {
		return
	}
	for i := range spans {
		s := &spans[i]
		if s.Conf != Weak {
			continue
		}
		if anchors[sentenceOf(bounds, s.Start)].Remove(s.Type).Empty() {
			continue
		}
		s.Conf = Strong
		s.Rule = clusterRules.of(s.Rule)
	}
}

// clusterSuffix — пометка подъёма по кластеру в имени правила.
const clusterSuffix = "+cluster"

// ruleSuffix — кеш имён правил с пометкой подъёма: «+cluster», «+bare».
//
// Без кеша «+cluster» давал почти пятую часть всех аллокаций запроса: по
// одной на каждого поднятого кандидата, а поднимаются они пачками.
//
// Копирование при записи, а не sync.Map: имена правил образуют закрытый
// набор, поэтому запись случается несколько раз за жизнь процесса, а чтение —
// в горячем пути. Чтение здесь это атомарная загрузка указателя и поиск в
// карте по строковому ключу, и ни то, ни другое не аллоцирует; sync.Map
// потребовал бы упаковать ключ в интерфейс, то есть вернул бы аллокацию, ради
// устранения которой всё и делается.
type ruleSuffix struct {
	suffix string
	rules  atomic.Pointer[map[string]string]
	mu     sync.Mutex
}

var (
	clusterRules = &ruleSuffix{suffix: clusterSuffix}
	bareRules    = &ruleSuffix{suffix: bareSuffix}
)

// of возвращает имя правила rule с пометкой подъёма.
func (r *ruleSuffix) of(rule string) string {
	if m := r.rules.Load(); m != nil {
		if v, ok := (*m)[rule]; ok {
			return v
		}
	}
	joined := rule + r.suffix

	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]string, 16)
	if old := r.rules.Load(); old != nil {
		maps.Copy(next, *old)
	}
	next[rule] = joined
	r.rules.Store(&next)
	return joined
}

// sentenceStarts возвращает смещения начал предложений в порядке возрастания.
// Первый элемент всегда 0.
//
// Буфер передаётся вызывающим и переиспользуется: собственный срез рос
// последовательными удвоениями и на тексте в четыре килобайта давал больше
// половины всех аллокаций запроса.
func sentenceStarts(doc *lex.Doc, buf []int32) []int32 {
	starts := append(buf[:0], 0)
	for i := range doc.Tokens {
		if !doc.IsSentenceBreak(i) {
			continue
		}
		if i+1 < len(doc.Tokens) {
			starts = append(starts, doc.Tokens[i+1].Start)
		}
	}
	return starts
}

// sentenceOf возвращает индекс предложения, содержащего смещение off.
func sentenceOf(starts []int32, off int32) int {
	i := sort.Search(len(starts), func(i int) bool { return starts[i] > off })
	return i - 1
}

// selectSpans отбирает спаны по профилю, разрешает перекрытия и применяет
// список типов потребителя.
//
// Кандидаты рассматриваются в порядке убывания силы, и каждый принимается,
// если не пересекается с уже принятыми. Порядок полный и детерминированный,
// поэтому результат воспроизводим при любом порядке работы сканеров.
//
// Перекрытия разрешаются на полном наборе кандидатов, и только к победителям
// отбора применяется список типов потребителя. Обратный порядок делал бы
// разметку текста зависимой от настройки: отключённый тип освобождал бы
// занятые им байты, и на них всплывал бы более слабый кандидат другого типа,
// проигравший перекрытие при полном наборе типов. Настройка потребителя
// решает, маскируется ли фрагмент, а не чем он считается.
//
// Второе значение сообщает, что предел MaxSpans превышен: после исчерпания
// бюджета нашёлся кандидат, который не пересекается с принятыми и подлежит
// маскированию у этого потребителя. Отобранные спаны при этом те же, что и
// без флага, — флаг не меняет разметку, а только запрещает её выпуск.
func selectSpans(ctx context.Context, spans []Span, opts Options, cand *Candidates) ([]Span, bool, error) {
	filtered := selectAdmitted(spans, opts)
	slices.SortStableFunc(filtered, selectOrder)

	kept, masked, exceeded, err := selectResolve(ctx, filtered, opts, cand)
	if err != nil {
		return nil, false, err
	}
	if masked == len(kept) {
		// Полный набор типов: вычёркивать нечего. Это случай потребителя
		// benchmark, под которым идёт автоматическая проверка.
		return kept, exceeded, nil
	}
	return selectWanted(kept, opts), exceeded, nil
}

// selectAdmitted оставляет на месте в spans кандидатов, допущенных профилем.
//
// Запись идёт по индексу, а не через append: результат не длиннее входа, и
// append здесь только заставлял бы компилятор считать, что срез уходит в кучу.
func selectAdmitted(spans []Span, opts Options) []Span {
	n := 0
	for _, s := range spans {
		if !admits(s, opts) {
			continue
		}
		spans[n] = s
		n++
	}
	return spans[:n]
}

// selectOrder — порядок отбора: сильнейший кандидат первым, см. stronger.
func selectOrder(a, b Span) int {
	switch {
	case stronger(a, b):
		return -1
	case stronger(b, a):
		return 1
	}
	return 0
}

// selectResolve разрешает перекрытия упорядоченных кандидатов filtered и
// возвращает принятые спаны в порядке начала, число подлежащих маскированию
// среди них и признак превышения MaxSpans.
func selectResolve(ctx context.Context, filtered []Span, opts Options, cand *Candidates) ([]Span, int, bool, error) {
	// Предел MaxSpans считается по заменам: победитель, не входящий в список
	// типов потребителя, до маскирования не доходит и бюджет не расходует.
	// Байты он при этом удерживает — иначе вернулась бы та же зависимость
	// разметки от настройки потребителя.
	//
	// Исчерпанный предел не обрывает цикл молча. До T-52 здесь стоял break,
	// и значения сверх предела оставались в тексте открытыми при ответе 200:
	// 20 050 телефонов давали 20 000 масок и 50 открытых номеров. Теперь
	// после исчерпания бюджета цикл ищет первого кандидата, который занял бы
	// замену, и по нему сообщает о превышении. Принятые спаны при этом не
	// меняются: после предела ничего не вставляется, как и при break.
	limit := opts.MaxSpans
	kept := cand.kept[:0]
	masked := 0
	exceeded := false
	for i, s := range filtered {
		// Вставка сдвигает хвост принятых, и на десятках тысяч кандидатов
		// цикл квадратичен — отмена проверяется и здесь.
		if err := selectCancelled(ctx, i); err != nil {
			cand.kept = kept
			return nil, 0, false, err
		}
		if overlapsAny(kept, s) {
			continue
		}
		if limit > 0 && masked >= limit {
			if wanted(s, opts) {
				exceeded = true
				break
			}
			// Победитель вне списка типов бюджет не расходует, но после
			// предела и не вставляется — как было при break.
			continue
		}
		insertSorted(&kept, s)
		if wanted(s, opts) {
			masked++
		}
	}
	// Ёмкость возвращается в накопитель на обоих путях выхода, иначе буфер
	// не переиспользуется и вся экономия пропадает на первом же запросе.
	cand.kept = kept
	return kept, masked, exceeded, nil
}

// selectCancelled проверяет отмену на каждом cancelStride-м кандидате i.
func selectCancelled(ctx context.Context, i int) error {
	if i&(cancelStride-1) != cancelStride-1 {
		return nil
	}
	return ctx.Err()
}

// selectWanted оставляет на месте в kept победителей, подлежащих
// маскированию у потребителя. Запись по индексу — как в selectAdmitted.
func selectWanted(kept []Span, opts Options) []Span {
	n := 0
	for _, s := range kept {
		if wanted(s, opts) {
			kept[n] = s
			n++
		}
	}
	return kept[:n]
}

// admits решает, участвует ли кандидат в отборе, по профилю.
//
// Список типов потребителя здесь не применяется: он решает судьбу уже
// отобранных победителей, см. selectSpans. Профиль же — про уровень
// уверенности кандидата, а не про политику, и остаётся частью отбора.
//
// Порог у strict и balanced совпадает намеренно: различие профилей в том,
// поднимается ли слабый кандидат по кластеру до отбора, см. Detect.
func admits(s Span, opts Options) bool {
	if s.Conf == Denied {
		return false
	}
	switch opts.Profile {
	case Strict:
		return s.Conf >= Strong
	case Paranoid:
		return true
	default:
		return s.Conf >= Strong
	}
}

// wanted сообщает, подлежит ли победитель отбора маскированию у этого
// потребителя. Пустое множество типов означает все типы.
func wanted(s Span, opts Options) bool {
	return opts.Types.Empty() || opts.Types.Has(s.Type)
}

// stronger задаёт полный порядок предпочтения при перекрытии: сначала уровень
// уверенности, затем длина значения, затем порядок объявления типа, затем
// позиция. Последние два критерия нужны только ради воспроизводимости.
func stronger(a, b Span) bool {
	if a.Conf != b.Conf {
		return a.Conf > b.Conf
	}
	if a.Len() != b.Len() {
		return a.Len() > b.Len()
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	return a.Start < b.Start
}

// overlapsAny сообщает, пересекается ли s с каким-либо из отсортированных
// по началу спанов kept.
func overlapsAny(kept []Span, s Span) bool {
	i := sort.Search(len(kept), func(i int) bool { return kept[i].End > s.Start })
	return i < len(kept) && kept[i].Start < s.End
}

// insertSorted вставляет s в kept, сохраняя порядок по началу спана.
func insertSorted(kept *[]Span, s Span) {
	k := *kept
	i := sort.Search(len(k), func(i int) bool { return k[i].Start >= s.Start })
	k = append(k, Span{})
	copy(k[i+1:], k[i:])
	k[i] = s
	*kept = k
}
