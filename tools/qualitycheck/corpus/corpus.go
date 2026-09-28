// Package corpus читает размеченный корпус, порождённый tools/corpusgen.
//
// Структуры описаны здесь заново, а не импортированы из corpusgen: это
// отдельный модуль, и связывать их означало бы тянуть replace-директиву ради
// четырёх типов. Контракт полей зафиксирован в tools/corpusgen/README.md;
// расхождение формата ловится Validate, а не проявляется в метриках.
package corpus

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

// Виды записей корпуса. Метрики по ловушкам и «чистым» записям считаются
// отдельно от записей с персональными данными, поэтому вид нужен отчёту.
const (
	KindSingle   = "single"
	KindMulti    = "multi"
	KindTrap     = "trap"
	KindClean    = "clean"
	KindNamesake = "namesake"
	KindLong     = "long"
)

// Span — размеченное значение, которое обязано быть скрыто.
// Смещения байтовые и полуинтервальные: Text[Start:End] == Value.
type Span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Len — длина значения в байтах.
func (s Span) Len() int { return s.End - s.Start }

// Trap — фрагмент, похожий на персональные данные, но ими не являющийся.
// Type — тип, за который фрагмент можно ошибочно принять, Reason — почему это
// не персональные данные.
type Trap struct {
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Type   string `json:"type"`
	Reason string `json:"reason"`
	Value  string `json:"value"`
}

// Record — одна запись корпуса, одна строка JSON Lines.
type Record struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Text  string `json:"text"`
	Spans []Span `json:"spans"`
	Traps []Trap `json:"traps"`
}

// Corpus — прочитанный корпус вместе с отпечатком файла.
//
// Отпечаток обязателен: без него прогоны несравнимы между собой, а сравнение
// метрик разных корпусов бессмысленно (docs/spec/ACCEPTANCE.md §4).
type Corpus struct {
	Path    string
	SHA256  string
	Bytes   int64
	Records []Record
}

// Load читает корпус и проверяет разметку. Ошибка сообщает идентификатор
// записи и смещения, но не значения: отчёт и диагностика инструмента не
// раскрывают персональные данные.
func Load(path string) (*Corpus, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("открытие корпуса: %w", err)
	}
	// Файл открыт только на чтение: ошибка закрытия данных не теряет.
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("размер корпуса: %w", err)
	}

	h := sha256.New()
	// TeeReader считает хеш ровно тех байтов, которые разобрал декодер:
	// отпечаток относится к прочитанному файлу, а не к файлу на диске «вообще».
	dec := json.NewDecoder(io.TeeReader(bufio.NewReaderSize(f, 1<<20), h))

	recs := make([]Record, 0, 1024)
	for {
		var r Record
		err := dec.Decode(&r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("разбор записи %d: %w", len(recs)+1, err)
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("корпус %s пуст", path)
	}

	c := &Corpus{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: st.Size(), Records: recs}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate сверяет смещения со значениями. Если Text[Start:End] не равно Value,
// метрика избыточности считается по неверным границам и молча врёт, поэтому
// расхождение — отказ, а не предупреждение.
func (c *Corpus) Validate() error {
	for i := range c.Records {
		r := &c.Records[i]
		if r.ID == "" {
			return fmt.Errorf("запись %d: пустой идентификатор", i+1)
		}
		for j, s := range r.Spans {
			if err := checkFragment(r.Text, s.Start, s.End, s.Value); err != nil {
				return fmt.Errorf("запись %s, спан %d (%s): %w", r.ID, j, s.Type, err)
			}
		}
		for j, t := range r.Traps {
			if err := checkFragment(r.Text, t.Start, t.End, t.Value); err != nil {
				return fmt.Errorf("запись %s, ловушка %d (%s): %w", r.ID, j, t.Reason, err)
			}
		}
	}
	return nil
}

// checkFragment сверяет полуинтервал [start, end) текста со значением.
func checkFragment(text string, start, end int, value string) error {
	if err := checkOffsets(text, start, end, len(value)); err != nil {
		return err
	}
	if text[start:end] != value {
		return fmt.Errorf("текст на [%d;%d) не равен значению", start, end)
	}
	return nil
}

func checkOffsets(text string, start, end, valueLen int) error {
	switch {
	case start < 0 || end < start:
		return fmt.Errorf("некорректный полуинтервал [%d;%d)", start, end)
	case end > len(text):
		return fmt.Errorf("конец %d за пределами текста длиной %d", end, len(text))
	case end-start != valueLen:
		return fmt.Errorf("длина полуинтервала %d не равна длине значения %d", end-start, valueLen)
	}
	return nil
}

// Summary — сводка корпуса для шапки отчёта.
type Summary struct {
	Records int            `json:"records"`
	Bytes   int            `json:"text_bytes"`
	Spans   int            `json:"spans"`
	Traps   int            `json:"traps"`
	Kinds   map[string]int `json:"kinds"`
	Types   map[string]int `json:"span_types"`
}

// Summarize считает состав корпуса: он попадает в отчёт, чтобы по одному
// документу было видно, на чём получены цифры.
func (c *Corpus) Summarize() Summary {
	s := Summary{Kinds: map[string]int{}, Types: map[string]int{}}
	for i := range c.Records {
		r := &c.Records[i]
		s.Records++
		s.Bytes += len(r.Text)
		s.Spans += len(r.Spans)
		s.Traps += len(r.Traps)
		s.Kinds[r.Kind]++
		for _, sp := range r.Spans {
			s.Types[sp.Type]++
		}
	}
	return s
}

// SortedKeys возвращает ключи в детерминированном порядке: отчёт должен быть
// побайтово воспроизводимым, иначе прогоны неудобно сравнивать диффом.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
