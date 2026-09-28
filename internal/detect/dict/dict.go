// Package dict — встроенные справочники детекции.
//
// Справочники встраиваются в бинарник через go:embed: сервис работает без сети
// и без внешних файлов, а содержимое версионируется вместе с кодом. Расширение
// справочника — добавление строки в текстовый файл, правка ядра не требуется
// (ТЗ §3.2.1: возможность расширения списка идентифицируемых ПД).
//
// Формат файла: UTF-8, одна запись на строку. Пустые строки и строки,
// начинающиеся с «#», игнорируются. Необязательный второй столбец через
// табуляцию задаёт метку записи — сканер трактует её по своему усмотрению
// (например, род имени или тип населённого пункта).
package dict

import (
	"bufio"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"unicode"
)

//go:embed data
var files embed.FS

// Table — неизменяемый справочник: нормализованная запись → метка.
//
// Таблица строится один раз при старте и далее только читается, поэтому
// безопасна для конкурентного доступа без синхронизации.
type Table struct {
	name    string
	entries map[string]string
}

// Name возвращает имя справочника (имя файла без расширения).
func (t *Table) Name() string { return t.name }

// Len возвращает число записей.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.entries)
}

// Has сообщает, есть ли нормализованное слово в справочнике.
// Отсутствующая таблица ведёт себя как пустая: сканер продолжает работу.
func (t *Table) Has(word string) bool {
	if t == nil {
		return false
	}
	_, ok := t.entries[word]
	return ok
}

// Get возвращает метку записи. Второе значение — признак наличия записи.
func (t *Table) Get(word string) (string, bool) {
	if t == nil {
		return "", false
	}
	v, ok := t.entries[word]
	return v, ok
}

// Set — собранный набор справочников.
type Set struct {
	tables map[string]*Table
}

// Table возвращает справочник по имени. Для отсутствующего имени возвращается
// nil: методы Table корректно работают на nil-приёмнике, поэтому сканер,
// справочник которого ещё не добавлен, не падает, а просто ничего не находит.
func (s *Set) Table(name string) *Table {
	if s == nil {
		return nil
	}
	return s.tables[name]
}

// Names возвращает имена загруженных справочников.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.tables))
	for n := range s.tables {
		out = append(out, n)
	}
	return out
}

// Load собирает набор справочников из встроенных файлов data/*.txt.
func Load() (*Set, error) {
	set := &Set{tables: make(map[string]*Table)}
	entries, err := fs.ReadDir(files, "data")
	if err != nil {
		return nil, fmt.Errorf("чтение каталога справочников: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".txt")
		t, err := loadFile("data/"+e.Name(), name)
		if err != nil {
			return nil, err
		}
		set.tables[name] = t
	}
	return set, nil
}

func loadFile(path, name string) (*Table, error) {
	f, err := files.Open(path)
	if err != nil {
		return nil, fmt.Errorf("открытие справочника %s: %w", name, err)
	}
	// Файл встроенной ФС открыт только на чтение: ошибка закрытия ничего не
	// теряет и на результат разбора не влияет.
	defer func() { _ = f.Close() }()

	t := &Table{name: name, entries: make(map[string]string, 256)}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, label, _ := strings.Cut(text, "\t")
		key = Normalize(strings.TrimSpace(key))
		if key == "" {
			return nil, fmt.Errorf("справочник %s, строка %d: пустой ключ", name, line)
		}
		t.entries[key] = strings.TrimSpace(label)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("разбор справочника %s: %w", name, err)
	}
	return t, nil
}

// Normalize приводит запись справочника к той же форме, в которой лексер
// хранит нормализованные токены: нижний регистр и «ё» → «е».
func Normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case 'ё', 'Ё':
			r = 'е'
		default:
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}
