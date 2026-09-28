package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
)

// bytesPerToken — та же оценка, что использует сервис в метриках
// aigw_tokens_in_total: 4 байта на токен. Единая оценка нужна, чтобы состав
// нагрузки в отчёте инструмента и счётчики сервиса говорили об одном и том же.
const bytesPerToken = 4

// Классы размера. Разделение нужно и для состава смешанного режима, и для
// отчёта: «средняя латентность» без состава нагрузки не воспроизводима.
const (
	classShort  = iota // < 512 токенов — типовой запрос к ассистенту
	classMedium        // < 8 192 токенов
	classLarge         // < 50 000 токенов
	classHuge          // >= 50 000 токенов — предельный вход по ТЗ
	classCount
)

var className = [classCount]string{"short", "medium", "large", "huge"}

// hugeTokens — целевой размер элемента в режиме длинных текстов.
const hugeTokens = 100_000

type item struct {
	id   string
	text string
}

// corpus хранит элементы, разложенные по классам размера, и веса выбора класса.
// Элементы переиспользуются: корпус read-only, строки неизменяемы, поэтому
// одновременное чтение из всех воркеров безопасно без блокировок.
type corpus struct {
	source  string
	classes [classCount][]item
	cum     [classCount]float64 // накопленные веса выбора класса
	total   float64
}

func (c *corpus) size() int {
	n := 0
	for _, cl := range c.classes {
		n += len(cl)
	}
	return n
}

// pick выбирает элемент: сначала класс по весу, затем элемент внутри класса.
func (c *corpus) pick(rnd *rand.Rand) item {
	x := rnd.Float64() * c.total
	for i := 0; i < classCount; i++ {
		if len(c.classes[i]) == 0 {
			continue
		}
		if x < c.cum[i] {
			return c.classes[i][rnd.IntN(len(c.classes[i]))]
		}
	}
	// Запасной путь на случай погрешности float: берём последний непустой класс.
	for i := classCount - 1; i >= 0; i-- {
		if len(c.classes[i]) > 0 {
			return c.classes[i][rnd.IntN(len(c.classes[i]))]
		}
	}
	return item{id: "empty", text: ""}
}

// setWeights задаёт веса классов. Вес пустого класса перераспределяется на
// ближайший непустой: иначе прогон встал бы на выборе несуществующего элемента.
func (c *corpus) setWeights(w [classCount]float64) {
	eff := w
	for i := 0; i < classCount; i++ {
		if len(c.classes[i]) != 0 || eff[i] == 0 {
			continue
		}
		moved := eff[i]
		eff[i] = 0
		if dst := c.nearestNonEmpty(i); dst >= 0 {
			eff[dst] += moved
		}
	}
	var acc float64
	for i := 0; i < classCount; i++ {
		acc += eff[i]
		c.cum[i] = acc
	}
	c.total = acc
}

// nearestNonEmpty возвращает ближайший к i непустой класс, при равном
// расстоянии — меньший; -1, если непустых классов нет.
func (c *corpus) nearestNonEmpty(i int) int {
	for d := 1; d < classCount; d++ {
		if i-d >= 0 && len(c.classes[i-d]) > 0 {
			return i - d
		}
		if i+d < classCount && len(c.classes[i+d]) > 0 {
			return i + d
		}
	}
	return -1
}

// composition описывает состав нагрузки для отчёта.
type compositionEntry struct {
	Class      string  `json:"class"`
	Items      int     `json:"items"`
	Weight     float64 `json:"weight"`
	MinTokens  int     `json:"min_tokens"`
	MedTokens  int     `json:"median_tokens"`
	MaxTokens  int     `json:"max_tokens"`
	TotalBytes int     `json:"total_bytes"`
}

func (c *corpus) composition() []compositionEntry {
	out := make([]compositionEntry, 0, classCount)
	prev := 0.0
	for i := 0; i < classCount; i++ {
		if len(c.classes[i]) == 0 {
			prev = c.cum[i]
			continue
		}
		sizes := make([]int, 0, len(c.classes[i]))
		total := 0
		for _, it := range c.classes[i] {
			sizes = append(sizes, len(it.text))
			total += len(it.text)
		}
		sort.Ints(sizes)
		w := 0.0
		if c.total > 0 {
			w = (c.cum[i] - prev) / c.total
		}
		prev = c.cum[i]
		out = append(out, compositionEntry{
			Class:      className[i],
			Items:      len(sizes),
			Weight:     w,
			MinTokens:  sizes[0] / bytesPerToken,
			MedTokens:  sizes[len(sizes)/2] / bytesPerToken,
			MaxTokens:  sizes[len(sizes)-1] / bytesPerToken,
			TotalBytes: total,
		})
	}
	return out
}

func classOf(text string) int {
	tok := len(text) / bytesPerToken
	switch {
	case tok < 512:
		return classShort
	case tok < 8192:
		return classMedium
	case tok < 50_000:
		return classLarge
	default:
		return classHuge
	}
}

func (c *corpus) add(it item) {
	cl := classOf(it.text)
	c.classes[cl] = append(c.classes[cl], it)
}

// loadCorpus читает корпус T-14 в формате JSON Lines. Отсутствие файла не
// является ошибкой: корпус — чужая задача, и прогон не должен от неё зависеть.
// Вторым значением возвращается пояснение для отчёта.
func loadCorpus(path string) (*corpus, string, error) {
	if path == "" {
		return nil, "флаг -corpus не задан", nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Sprintf("файл %s отсутствует", path), nil
		}
		return nil, "", err
	}
	// Файл открыт только на чтение: ошибка закрытия данных не теряет.
	defer func() { _ = f.Close() }()

	c := &corpus{source: "JSONL " + path}
	dec := json.NewDecoder(f)
	line := 0
	for {
		var rec struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		}
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return nil, "", fmt.Errorf("%s, запись %d: %w", path, line+1, err)
		}
		line++
		if rec.Text == "" {
			continue
		}
		if rec.ID == "" {
			rec.ID = fmt.Sprintf("line-%d", line)
		}
		c.add(item{id: rec.ID, text: rec.Text})
	}
	if c.size() == 0 {
		return nil, fmt.Sprintf("файл %s не содержит пригодных записей", path), nil
	}
	return c, "", nil
}

// buildCorpus собирает корпус для режима: берёт файл, если он есть, и
// достраивает встроенным набором то, чего в нём нет.
func buildCorpus(path, mode string, seed int64) (*corpus, error) {
	c, why, err := loadCorpus(path)
	if err != nil {
		return nil, err
	}
	note := ""
	if c == nil {
		c = builtinCorpus(seed)
		note = "встроенный набор (" + why + ")"
		c.source = note
	}

	switch mode {
	case modeLong:
		// Режим длинных текстов требует элементов на 100 000 токенов. Если в
		// корпусе их нет, достраиваем: проверка предельного входа не должна
		// отменяться из-за состава чужого файла.
		if len(c.classes[classHuge]) == 0 {
			for i := 0; i < 3; i++ {
				c.classes[classHuge] = append(c.classes[classHuge], item{
					id:   fmt.Sprintf("builtin-huge-%d", i),
					text: buildLongText(hugeTokens, seed+int64(i)),
				})
			}
			c.source += " + встроенные тексты на 100 000 токенов"
		}
		c.setWeights([classCount]float64{0, 0, 0, 1})
	default:
		// Смешанный состав: «размеры текстов различные» (07-clarifications §7.2,
		// A6.4). Перекос в короткие отражает типовой запрос к ассистенту.
		c.setWeights([classCount]float64{0.70, 0.25, 0.05, 0})
	}
	return c, nil
}

// --- Встроенный набор -------------------------------------------------------
//
// Все значения синтетические: реальные персональные данные в репозиторий не
// попадают ни в каком виде (AGENTS.md §7). Номера карт — из тестового
// диапазона 4000 00.., паспорта и телефоны — вымышленные.

var builtinShort = []string{
	"Найди клиента Волошина Петра Игнатьевича, паспорт 4509 123456, и покажи его адрес.",
	"Клиент просит перевыпустить карту 4000 1234 5678 9010, срок 05/29, звонить на +7 916 000-11-22.",
	"Оформи заявку на кредит: ИНН 771234567890, дата рождения 14.03.1987, почта pjotr.voloshin@example.org.",
	"Подскажи, доставлен ли заказ по адресу г. Тверь, ул. Озёрная, д. 12, кв. 47, получатель Серебрякова Анна Львовна.",
	"Проверь СНИЛС 112-233-445 95 и полис ОМС 7712345678901234 у клиента Гнездилова Марка Олеговича.",
	"Сравни два тарифа мобильной связи и объясни, какой выгоднее при 20 ГБ трафика в месяц.",
	"Водительское удостоверение 77 12 345678 выдано 02 сентября 2019 года, владелец Кайсарова Дина Ринатовна.",
	"Клиент звонил в отделение банка на улице Пушкина, говорил про поэта Пушкина и просил счёт 40817810099910004312.",
	"Сформируй выписку по договору №ДГ-2291/17 за период с 01.01.2025 по 31.03.2025.",
	"Запиши: контактное лицо Ушаков Тимур Аркадьевич, телефон 8 (495) 987-65-43, email t.ushakov@example.net.",
}

var builtinFillers = []string{
	"Клиент уточняет условия обслуживания и просит подробный расчёт по каждому месяцу.",
	"Оператор зафиксировал обращение и передал его в профильное подразделение.",
	"В обращении упомянуты сроки рассмотрения и порядок уведомления заявителя.",
	"Дополнительно требуется сверить реквизиты и подтвердить согласие на обработку.",
	"История обращений показывает три похожих запроса за последний квартал.",
}

// builtinCorpus собирает набор на случай отсутствия корпуса T-14:
// короткие запросы, средние диалоги и крупные тексты.
func builtinCorpus(seed int64) *corpus {
	c := &corpus{}
	for i, t := range builtinShort {
		c.add(item{id: fmt.Sprintf("builtin-short-%02d", i), text: t})
	}
	for i := 0; i < 4; i++ {
		c.add(item{id: fmt.Sprintf("builtin-medium-%d", i), text: buildLongText(1500, seed+int64(100+i))})
	}
	for i := 0; i < 2; i++ {
		c.add(item{id: fmt.Sprintf("builtin-large-%d", i), text: buildLongText(20_000, seed+int64(200+i))})
	}
	return c
}

// buildLongText собирает текст примерно на targetTokens токенов (4 байта на
// токен). Значения ПД внутри различаются от абзаца к абзацу: однородный
// повтор одной строки измерял бы кеш, а не работу сканеров.
func buildLongText(targetTokens int, seed int64) string {
	rnd := rand.New(rand.NewPCG(uint64(seed), 0x9e3779b97f4a7c15))
	target := targetTokens * bytesPerToken
	var b strings.Builder
	b.Grow(target + 256)
	b.WriteString("Обращение в поддержку. Ниже переписка по обслуживанию клиентов.\n")
	n := 0
	for b.Len() < target {
		n++
		fmt.Fprintf(&b, "Пункт %d. %s ", n, builtinFillers[rnd.IntN(len(builtinFillers))])
		switch n % 5 {
		case 0:
			fmt.Fprintf(&b, "Клиент %s, паспорт %02d%02d %06d, телефон +7 9%02d %03d-%02d-%02d.\n",
				synthName(rnd), rnd.IntN(90)+10, rnd.IntN(90)+10, rnd.IntN(1000000),
				rnd.IntN(100), rnd.IntN(1000), rnd.IntN(100), rnd.IntN(100))
		case 1:
			fmt.Fprintf(&b, "Карта 4000 %04d %04d %04d, срок %02d/%02d, счёт 408178%014d.\n",
				rnd.IntN(10000), rnd.IntN(10000), rnd.IntN(10000),
				rnd.IntN(12)+1, rnd.IntN(10)+26, rnd.Int64N(1e14))
		case 2:
			fmt.Fprintf(&b, "Адрес доставки: г. Тверь, ул. Озёрная, д. %d, кв. %d, получатель %s.\n",
				rnd.IntN(90)+1, rnd.IntN(300)+1, synthName(rnd))
		case 3:
			fmt.Fprintf(&b, "ИНН %012d, дата рождения %02d.%02d.19%02d, почта user%04d@example.org.\n",
				rnd.Int64N(1e12), rnd.IntN(28)+1, rnd.IntN(12)+1, rnd.IntN(60)+40, rnd.IntN(10000))
		default:
			fmt.Fprintf(&b, "Договор №ДГ-%04d/%02d рассмотрен, персональные данные в пункте не упоминаются.\n",
				rnd.IntN(10000), rnd.IntN(30))
		}
	}
	return b.String()
}

var synthFirst = []string{"Пётр", "Анна", "Марк", "Дина", "Тимур", "Ольга", "Егор", "Лев", "Зоя", "Игнат"}
var synthLast = []string{"Волошин", "Серебрякова", "Гнездилов", "Кайсарова", "Ушаков", "Пряхина", "Дорофеев", "Юрганова"}
var synthMid = []string{"Игнатьевич", "Львовна", "Олегович", "Ринатовна", "Аркадьевич", "Тимофеевна"}

func synthName(rnd *rand.Rand) string {
	return synthLast[rnd.IntN(len(synthLast))] + " " +
		synthFirst[rnd.IntN(len(synthFirst))] + " " +
		synthMid[rnd.IntN(len(synthMid))]
}
