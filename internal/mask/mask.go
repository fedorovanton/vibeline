// Package mask — преобразование найденных спанов в защищённый текст.
//
// Маскирование выполняется только после того, как детекция разметила текст,
// а политика решила, что именно маскировать. Исходный текст не изменяется:
// результат собирается в отдельный буфер.
//
// Маскирование — чистая детерминированная функция от текста, спанов и выбора
// стратегии. Отсюда следует идемпотентность прямого шага /process и
// безвредность параллельных повторов с одним payload_id: любые две попытки
// дают побайтово одинаковый результат.
package mask

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/detect"
	"ai-gateway/internal/pii"
)

// Strategy — способ замены значения.
type Strategy interface {
	// Name возвращает имя стратегии, как оно задаётся в конфигурации.
	Name() string
	// Mask возвращает замену для значения orig типа t. Номер seq различает
	// разные значения одного типа в пределах запроса; одинаковые значения
	// получают одинаковый номер и, следовательно, одинаковую замену.
	Mask(orig string, t pii.Type, seq int) string
}

// Applied — выполненная замена. Используется демо-стендом и восстановлением
// плейсхолдеров в ответе модели.
type Applied struct {
	Start       int32
	End         int32
	Type        pii.Type
	Seq         int
	Replacement string
}

// Applier собирает защищённый текст. Переиспользуется между запросами через
// пул; Reset сохраняет ёмкость буферов.
type Applier struct {
	out  []byte
	list []Applied
	num  Numbering

	// Буферы CoverRepeats: множество отобранных значений, первый спан
	// каждого значения, найденные повторы и итоговый список спанов.
	vals   Values
	src    []detect.Span
	extra  []detect.Span
	merged []detect.Span
}

type seqKey struct {
	t pii.Type
	v string
}

// Numbering — нумерация значений: какой номер получает значение каждого типа.
//
// Обычно нумерация живёт внутри одного вызова Apply. Запрос к модели состоит
// из нескольких сообщений, и номера в нём обязаны быть сквозными: разные
// люди в разных сообщениях — «[ФИО_1]» и «[ФИО_2]», один человек — один номер
// во всех сообщениях. Для этого вызывающий код держит одну Numbering на весь
// запрос и передаёт её в ApplyNumbered.
//
// Нулевое значение готово к работе.
type Numbering struct {
	seq  map[seqKey]int
	next [pii.Count]int
	// Reserved, если задан, сообщает, что замена уже буквально присутствует
	// во входе. Такой номер не выдаётся: иначе выданная маска совпала бы с
	// текстом, написанным пользователем, и при восстановлении ответа модели
	// буквальный «[ФИО_1]» превратился бы в значение. Вызывается только на
	// первом вхождении значения, повторные берут прежний номер.
	//
	// Заданный Reserved включает и второе правило: замена, уже выданная
	// другому значению, тоже не выдаётся повторно. Synthetic при совпадении
	// замены с исходным значением сдвигается на соседнюю позицию и может
	// попасть на замену соседа; для восстановления ответа модели это два
	// человека под одной маской, и ни один не восстанавливается.
	Reserved func(repl string) bool
	issued   map[string]struct{}
}

// reservedSkipMax ограничивает число пропущенных номеров на одно значение:
// вход, набитый буквальными плейсхолдерами, не должен превращать нумерацию
// в перебор.
const reservedSkipMax = 64

// Reset очищает нумерацию, сохраняя ёмкость. Reserved не трогается.
func (n *Numbering) Reset() {
	n.next = [pii.Count]int{}
	clear(n.issued)
	if n.seq == nil {
		n.seq = make(map[seqKey]int, 16)
		return
	}
	clear(n.seq)
}

// assign возвращает номер и замену значения orig типа t.
//
// Повторное вхождение того же значения получает прежний номер: замаскированный
// текст остаётся связным, и модель может рассуждать о «[ФИО_1] и [ФИО_2]» как
// о разных людях.
func (n *Numbering) assign(t pii.Type, orig string, st Strategy) (int, string) {
	if n.seq == nil {
		n.seq = make(map[seqKey]int, 16)
	}
	key := seqKey{t: t, v: orig}
	if seq, ok := n.seq[key]; ok {
		return seq, st.Mask(orig, t, seq)
	}
	n.next[t]++
	seq := n.next[t]
	repl := st.Mask(orig, t, seq)
	if n.Reserved != nil {
		if n.issued == nil {
			n.issued = make(map[string]struct{}, 16)
		}
		for i := 0; i < reservedSkipMax && n.taken(repl); i++ {
			cand := st.Mask(orig, t, seq+1)
			if cand == repl {
				// Замена не зависит от номера (token, asterisks): перебор
				// ничего не даст. Совпадение с буквальным текстом разбирает
				// восстановление — такая маска не восстанавливается.
				break
			}
			seq++
			repl = cand
		}
		n.next[t] = seq
		n.issued[repl] = struct{}{}
	}
	n.seq[key] = seq
	return seq, repl
}

// taken сообщает, что замену выдавать нельзя: она буквально есть во входе
// или уже выдана другому значению.
func (n *Numbering) taken(repl string) bool {
	if _, ok := n.issued[repl]; ok {
		return true
	}
	return n.Reserved(repl)
}

// Reset очищает состояние, сохраняя ёмкость.
func (a *Applier) Reset() {
	a.out = a.out[:0]
	a.list = a.list[:0]
	a.num.Reset()
}

// Apply заменяет спаны в text и возвращает результат вместе со списком замен.
// Нумерация значений начинается заново.
//
// Спаны обязаны быть отсортированы по началу и не пересекаться — движок
// детекции гарантирует оба свойства. pick выбирает стратегию по типу.
//
// Возвращаемая строка и слайс замен принадлежат Applier и действительны до
// следующего Reset.
func (a *Applier) Apply(text string, spans []detect.Span, pick func(pii.Type) Strategy) (string, []Applied) {
	a.Reset()
	return a.apply(text, spans, pick, &a.num)
}

// ApplyNumbered — то же, что Apply, но номера берутся из num и продолжают
// его: так нумеруются несколько текстов одного запроса.
func (a *Applier) ApplyNumbered(text string, spans []detect.Span, pick func(pii.Type) Strategy, num *Numbering) (string, []Applied) {
	a.out = a.out[:0]
	a.list = a.list[:0]
	return a.apply(text, spans, pick, num)
}

func (a *Applier) apply(text string, spans []detect.Span, pick func(pii.Type) Strategy, num *Numbering) (string, []Applied) {
	if len(spans) == 0 {
		return text, nil
	}
	// Ёмкость под результат набирается заранее: замены редко бывают длиннее
	// оригинала, и восьмушка запаса покрывает разницу.
	//
	// Прежняя запись `append(a.out, make([]byte, 0, len(text))...)` выглядела
	// как то же самое, но делала обратное: оптимизация компилятора, ради
	// которой такую форму и пишут, отключается, когда у make задана ёмкость.
	// Получалось честное выделение len(text) байт, дописывание из него нуля
	// элементов и немедленный выброс буфера в мусор — на каждый запрос, а на
	// тексте в сто тысяч токенов это почти полмегабайта впустую.
	if cap(a.out) < len(text) {
		a.out = make([]byte, 0, len(text)+len(text)/8)
	}

	prev := int32(0)
	for _, s := range spans {
		// Защита от рассогласования: пропускаем битый спан — перекрытие с
		// предыдущим, выход за текст, пустой или перевёрнутый.
		if s.Start < prev || s.End > int32(len(text)) || s.End <= s.Start {
			continue
		}
		a.out = append(a.out, text[prev:s.Start]...)

		orig := text[s.Start:s.End]
		seq, repl := num.assign(s.Type, orig, pick(s.Type))

		a.list = append(a.list, Applied{
			Start: s.Start, End: s.End, Type: s.Type, Seq: seq, Replacement: repl,
		})
		a.out = append(a.out, repl...)
		prev = s.End
	}
	a.out = append(a.out, text[prev:]...)
	return string(a.out), a.list
}

// RuleRepeat — правило спана, который добавил CoverRepeats: повтор значения,
// отобранного к маскированию в другом месте того же текста.
const RuleRepeat = "repeat"

// CoverRepeats дополняет отобранные спаны остальными точными вхождениями тех
// же значений, стоящими по границам токенов (С-4, T-56).
//
// Детекция опирается на контекст, и повтор уже найденного значения без
// маркера рядом — «дата рождения 01.02.1990. Договор от 01.02.1990» — она
// может не опознать. Такой повтор — утечка ровно того значения, которое
// политика велела скрыть: на /process он уходил открытым, а на продуктовом
// контуре проверка полноты отклоняла весь запрос. Повтор получает тип и
// уверенность первого спана с тем же значением, а по нумерации — тот же
// номер и ту же замену: нумерация различает значения, а не места.
//
// Вхождение внутри другого числа или слова повтором не считается: CVV «123»
// в сумме «1230» и имя внутри другого слова — другие данные. Граница токена —
// как у лексера: цифра, продолженная цифрой, и буква, продолженная буквой,
// — один токен, всё остальное — граница. Вхождение, задевающее уже
// отобранный спан, не добавляется: оно и так скрыто.
//
// Спаны на входе отсортированы по началу и не пересекаются, как их отдаёт
// движок; результат обладает теми же свойствами. Если повторов нет,
// возвращается исходный слайс — поведение на тексте без повторов побайтово
// прежнее. Иначе результат принадлежит Applier и действителен до следующего
// вызова CoverRepeats.
//
// Все значения ищутся за один проход по тексту (Values), поэтому цена не
// зависит от числа спанов.
func (a *Applier) CoverRepeats(text string, spans []detect.Span) []detect.Span {
	if len(spans) == 0 {
		return spans
	}
	a.vals.Reset()
	a.src = a.src[:0]
	for _, s := range spans {
		if s.Start < 0 || s.End > int32(len(text)) || s.End <= s.Start {
			continue
		}
		if id := a.vals.Add(text[s.Start:s.End]); int(id) == len(a.src) {
			a.src = append(a.src, s)
		}
	}
	return a.cover(text, spans, &a.vals, a.src)
}

// CoverValues — то же, что CoverRepeats, но значения берутся не из спанов
// этого текста, а из заданного множества: vals — значения, src[id] — спан,
// тип и уверенность которого получает вхождение значения id. Так запрос к
// модели закрывает в каждом сообщении значения, найденные в любом другом
// сообщении того же запроса.
//
// Результат — как у CoverRepeats: исходный слайс, если добавлять нечего,
// иначе слайс Applier до следующего вызова CoverRepeats или CoverValues.
func (a *Applier) CoverValues(text string, spans []detect.Span, vals *Values, src []detect.Span) []detect.Span {
	if vals.Len() == 0 {
		return spans
	}
	return a.cover(text, spans, vals, src)
}

func (a *Applier) cover(text string, spans []detect.Span, vals *Values, src []detect.Span) []detect.Span {
	extra := a.extra[:0]
	vals.Each(text, func(id int32, start, end int) bool {
		if overlapsSpan(spans, start, end) || !tokenBounded(text, start, end) {
			return true
		}
		s := src[id]
		extra = append(extra, detect.Span{
			Start: int32(start), End: int32(end), Type: s.Type, Conf: s.Conf, Rule: RuleRepeat,
		})
		return true
	})
	a.extra = extra
	if len(extra) == 0 {
		return spans
	}

	// Автомат сообщает вхождения по возрастанию конца; слияние идёт по
	// началу, а из пересекающихся повторов остаётся раньше начавшийся и при
	// равном начале — более длинный.
	slices.SortFunc(extra, func(x, y detect.Span) int {
		if x.Start != y.Start {
			return cmp.Compare(x.Start, y.Start)
		}
		return cmp.Compare(y.End, x.End)
	})
	out := a.merged[:0]
	i, last := 0, int32(0)
	for _, e := range extra {
		if e.Start < last {
			continue
		}
		for i < len(spans) && spans[i].Start < e.Start {
			out = append(out, spans[i])
			i++
		}
		out = append(out, e)
		last = e.End
	}
	out = append(out, spans[i:]...)
	a.merged = out
	return out
}

// overlapsSpan сообщает, задевает ли участок [start, end) один из спанов.
// Спаны отсортированы и не пересекаются, поэтому их концы тоже возрастают, и
// достаточно двоичного поиска первого спана, кончающегося правее start.
func overlapsSpan(spans []detect.Span, start, end int) bool {
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if int(spans[mid].End) > start {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo < len(spans) && int(spans[lo].Start) < end
}

// tokenBounded сообщает, что участок [start, end) не продолжает соседний
// токен ни слева, ни справа.
func tokenBounded(text string, start, end int) bool {
	if start > 0 {
		prev, _ := utf8.DecodeLastRuneInString(text[:start])
		first, _ := utf8.DecodeRuneInString(text[start:end])
		if sameToken(prev, first) {
			return false
		}
	}
	if end < len(text) {
		last, _ := utf8.DecodeLastRuneInString(text[start:end])
		next, _ := utf8.DecodeRuneInString(text[end:])
		if sameToken(last, next) {
			return false
		}
	}
	return true
}

// sameToken сообщает, что руны a и b, стоящие вплотную, лексер отнёс бы к
// одному токену: обе — ASCII-цифры или обе — буквы. Комбинируемый знак
// продолжает слово, как в лексере.
func sameToken(a, b rune) bool {
	ca := tokenClass(a)
	return ca != 0 && ca == tokenClass(b)
}

func tokenClass(r rune) uint8 {
	switch {
	case r >= '0' && r <= '9':
		return 1
	case r < utf8.RuneSelf:
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return 2
		}
		return 0
	case unicode.IsLetter(r) || unicode.Is(unicode.M, r):
		return 2
	}
	return 0
}

// Values — множество строк, все вхождения которых ищутся за один проход по
// тексту: автомат Ахо — Корасик над байтами, без регулярных выражений.
//
// Поиск каждого значения отдельной подстрокой стоит O(значения × длина
// текста): на 637 КБ и 15 000 значениях — четыре секунды (С-5, T-56).
// Автомат проходит текст один раз, и цена почти не зависит от числа значений.
//
// Нулевое значение готово к работе. Reset сохраняет ёмкость буферов, поэтому
// автомат переиспользуется между запросами вместе с Applier из пула.
type Values struct {
	nodes []valueNode
	// root — переходы из корня плотной таблицей: из корня автомат выходит на
	// каждом байте текста, не начинающем ни одного значения, и поиск по
	// списку потомков здесь стоил бы дороже всего остального.
	root  [256]int32
	queue []int32
	count int32
	built bool
}

// valueNode — узел бора. Потомки узла — односвязный список через next.
type valueNode struct {
	child int32 // первый потомок; 0 — потомков нет (корень ничьим потомком не бывает)
	next  int32 // следующий потомок того же родителя
	fail  int32 // узел самого длинного собственного суффикса пути, есть в боре
	out   int32 // ближайший по суффиксным ссылкам конец значения; 0 — такого нет
	depth int32 // длина пути от корня в байтах
	id    int32 // номер значения, которое здесь кончается; -1 — не кончается
	b     byte
}

// Reset очищает множество, сохраняя ёмкость.
func (v *Values) Reset() {
	v.nodes = append(v.nodes[:0], valueNode{id: -1})
	v.root = [256]int32{}
	v.count = 0
	v.built = false
}

// Len возвращает число различных значений.
func (v *Values) Len() int { return int(v.count) }

// Add добавляет значение и возвращает его номер. Номера выдаются подряд с
// нуля; повторное добавление той же строки возвращает прежний номер. Пустая
// строка не добавляется: результат -1.
func (v *Values) Add(s string) int32 {
	if s == "" {
		return -1
	}
	if len(v.nodes) == 0 {
		v.Reset()
	}
	v.built = false
	n := int32(0)
	for i := 0; i < len(s); i++ {
		n = v.childOrNew(n, s[i])
	}
	if v.nodes[n].id < 0 {
		v.nodes[n].id = v.count
		v.count++
	}
	return v.nodes[n].id
}

func (v *Values) childOrNew(n int32, b byte) int32 {
	if n == 0 {
		if c := v.root[b]; c != 0 {
			return c
		}
	} else {
		for c := v.nodes[n].child; c != 0; c = v.nodes[c].next {
			if v.nodes[c].b == b {
				return c
			}
		}
	}
	c := int32(len(v.nodes))
	v.nodes = append(v.nodes, valueNode{depth: v.nodes[n].depth + 1, id: -1, b: b})
	if n == 0 {
		v.root[b] = c
	} else {
		v.nodes[c].next = v.nodes[n].child
		v.nodes[n].child = c
	}
	return c
}

// step — переход автомата из n по байту b с откатом по суффиксным ссылкам.
func (v *Values) step(n int32, b byte) int32 {
	for n != 0 {
		for c := v.nodes[n].child; c != 0; c = v.nodes[c].next {
			if v.nodes[c].b == b {
				return c
			}
		}
		n = v.nodes[n].fail
	}
	return v.root[b]
}

// build достраивает суффиксные ссылки обходом бора в ширину.
func (v *Values) build() {
	q := v.queue[:0]
	for b := range 256 {
		if c := v.root[b]; c != 0 {
			v.nodes[c].fail, v.nodes[c].out = 0, 0
			q = append(q, c)
		}
	}
	for h := 0; h < len(q); h++ {
		u := q[h]
		for c := v.nodes[u].child; c != 0; c = v.nodes[c].next {
			// Суффикс пути c на байт короче пути u плюс байт c: глубина
			// результата не больше глубины u, и c сам себе ссылкой не станет.
			f := v.step(v.nodes[u].fail, v.nodes[c].b)
			v.nodes[c].fail = f
			if v.nodes[f].id >= 0 {
				v.nodes[c].out = f
			} else {
				v.nodes[c].out = v.nodes[f].out
			}
			q = append(q, c)
		}
	}
	v.queue = q[:0]
	v.built = true
}

// Each вызывает fn для каждого вхождения каждого значения в text: номер
// значения и границы вхождения в байтах. Пересекающиеся вхождения
// сообщаются все. Порядок — по возрастанию конца, при равном конце — от
// длинного значения к короткому. fn, вернувшая false, прекращает обход.
func (v *Values) Each(text string, fn func(id int32, start, end int) bool) {
	if v.count == 0 {
		return
	}
	if !v.built {
		v.build()
	}
	nodes, root := v.nodes, &v.root
	n := int32(0)
	for i := 0; i < len(text); i++ {
		b := text[i]
		if n == 0 {
			// Из корня — по таблице; байт, не начинающий ни одного значения,
			// оставляет автомат в корне без обращения к узлам.
			if n = root[b]; n == 0 {
				continue
			}
		} else if n = stepFrom(nodes, root, n, b); n == 0 {
			continue
		}
		if !emitMatches(nodes, n, i, fn) {
			return
		}
	}
}

// stepFrom — шаг автомата из узла n, отличного от корня, по байту b: переход
// по ребёнку с байтом b, иначе откат по суффиксной ссылке. Из корня переход
// берётся по таблице root.
func stepFrom(nodes []valueNode, root *[256]int32, n int32, b byte) int32 {
	for {
		c := nodes[n].child
		for c != 0 && nodes[c].b != b {
			c = nodes[c].next
		}
		if c != 0 {
			return c
		}
		if n = nodes[n].fail; n == 0 {
			return root[b]
		}
	}
}

// emitMatches сообщает fn все значения, оканчивающиеся байтом i в узле n:
// сам узел, если он конец значения, и цепочку выходных ссылок. Ложь — fn
// прекратила обход.
func emitMatches(nodes []valueNode, n int32, i int, fn func(id int32, start, end int) bool) bool {
	m := n
	if nodes[m].id < 0 {
		m = nodes[m].out
	}
	for m != 0 {
		nd := &nodes[m]
		if !fn(nd.id, i+1-int(nd.depth), i+1) {
			return false
		}
		m = nd.out
	}
	return true
}

// Placeholder — стратегия по умолчанию: типизированный плейсхолдер [ФИО_1].
//
// Значение скрывается целиком, что даёт максимум по метрике сокрытия, при этом
// тип остаётся виден модели и смысл запроса сохраняется. Разные значения не
// схлопываются в одинаковую маску, в отличие от замены звёздочками.
type Placeholder struct{}

// Name возвращает имя стратегии.
func (Placeholder) Name() string { return "placeholder" }

// Mask возвращает плейсхолдер вида [ТИП_N].
func (Placeholder) Mask(_ string, t pii.Type, seq int) string {
	if int(t) < pii.Count && seq >= 1 && seq <= placeholderMaxSeq {
		return placeholderTable[t][seq]
	}
	return buildPlaceholder(t, seq)
}

// placeholderMaxSeq — до какого номера плейсхолдеры собраны заранее.
//
// Плейсхолдер собирается на каждую замену, а замен в тексте сотни: на
// четырёхкилобайтном фрагменте сборка через strings.Builder давала больше ста
// аллокаций — больше, чем всё остальное маскирование вместе взятое. Номера
// идут подряд от единицы, поэтому таблица закрывает подавляющее большинство
// случаев, а редкий хвост собирается прежним способом.
const placeholderMaxSeq = 64

var placeholderTable [pii.Count][placeholderMaxSeq + 1]string

func init() {
	for t := range pii.Count {
		for seq := 1; seq <= placeholderMaxSeq; seq++ {
			placeholderTable[t][seq] = buildPlaceholder(pii.Type(t), seq)
		}
	}
}

func buildPlaceholder(t pii.Type, seq int) string {
	var b strings.Builder
	base := t.Placeholder()
	b.Grow(len(base) + 6)
	b.WriteByte('[')
	b.WriteString(base)
	b.WriteByte('_')
	b.WriteString(strconv.Itoa(seq))
	b.WriteByte(']')
	return b.String()
}

// Asterisks — замена звёздочками по числу символов значения.
//
// Разделители внутри значения сохраняются: организаторы оставили это на
// усмотрение команды, а читаемая структура помогает человеку на демо понять,
// что именно было скрыто.
type Asterisks struct{}

// Name возвращает имя стратегии.
func (Asterisks) Name() string { return "asterisks" }

// Mask заменяет буквы и цифры на «*», сохраняя разделители.
func (Asterisks) Mask(orig string, _ pii.Type, _ int) string {
	var b strings.Builder
	b.Grow(len(orig))
	for _, r := range orig {
		switch r {
		case ' ', '-', '.', '/', '(', ')', '+':
			b.WriteRune(r)
		default:
			b.WriteByte('*')
		}
	}
	return b.String()
}

// registry — стратегии, доступные в конфигурации по имени.
var registry = map[string]Strategy{
	"placeholder": Placeholder{},
	"asterisks":   Asterisks{},
}

// Register добавляет стратегию в реестр. Вызывается из init-функций пакета;
// после старта сервиса реестр только читается.
func Register(s Strategy) { registry[s.Name()] = s }

// ByName возвращает стратегию по имени из конфигурации.
func ByName(name string) (Strategy, bool) {
	s, ok := registry[name]
	return s, ok
}

// Names возвращает имена зарегистрированных стратегий в порядке возрастания.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
