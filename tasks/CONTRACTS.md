# Контракты пакетов для задач детекции

Справочник API, зафиксированного волной 0. Эти интерфейсы менять нельзя —
на них опираются параллельно работающие задачи. Нужна правка контракта —
это блокер для оркестратора, а не самостоятельное решение.

## Как подключается сканер

Файл сканера самодостаточен: он регистрирует себя сам, общий список
редактировать не нужно.

```go
func init() { detect.Register(digitsScanner{}) }

type digitsScanner struct{}

func (digitsScanner) Name() string { return "digits" }

func (digitsScanner) Scan(doc *lex.Doc, dicts *dict.Set, out *detect.Candidates) {
    // ...
}
```

`Scan` обязан быть чистой функцией от `doc` и `dicts`: без состояния между
вызовами, безопасен для конкурентного использования, исходный текст не меняет.

## internal/lex

```go
type Kind uint8   // KindWord | KindDigits | KindPunct
type Flags uint8  // FlagFirstUpper | FlagAllUpper | FlagCyrillic | FlagLatin
func (f Flags) Has(m Flags) bool

type Token struct {
    Start, End int32  // смещения в БАЙТАХ в Doc.Text и Doc.Norm
    Kind  Kind
    Flags Flags
}
func (t Token) Len() int

type Doc struct {
    Text   string  // исходный текст, неизменный
    Norm   string  // нормализованная копия, ПОБАЙТОВО выровнена с Text
    Tokens []Token // пробелы токенами не становятся
}

func (d *Doc) Raw(i int) string        // исходный текст токена i
func (d *Doc) NormOf(i int) string     // нормализованный текст токена i
func (d *Doc) Span(i, j int) string    // исходный текст от токена i до j включительно
func (d *Doc) Gap(i int) string        // текст между токенами i и i+1
func (d *Doc) Adjacent(i int) bool     // между i и i+1 нет ни одного символа
func (d *Doc) SentenceBounds(i int) (lo, hi int)
func (d *Doc) IsSentenceBreak(i int) bool
```

Ключевые свойства:

- `Doc.Norm` — нижний регистр и «ё» → «е», смещения те же, что в `Doc.Text`.
  Сравнивать со словарями надо через `NormOf`, а не через `strings.ToLower`.
- Пробелы токенами не становятся. Расстояние между токенами — через `Gap` или
  `Adjacent`, а не по индексам.
- `Start`/`End` — **байты**, не руны. Смешивать нельзя.

## internal/detect

```go
type Confidence uint8 // Denied | Weak | Strong | Certain

type Span struct {
    Start, End int32
    Type pii.Type
    Conf Confidence
    Rule string   // имя сработавшего правила, для отладки и отчётов
}

type Candidates struct { ... }
func (c *Candidates) Add(start, end int, t pii.Type, conf Confidence, rule string)
func (c *Candidates) Deny(start, end int, types pii.Set, rule string)
```

Уровни уверенности — не вероятность, а перечисление сработавших условий:

| Уровень | Когда ставить |
|---|---|
| `Certain` | форма плюс контрольная сумма или самодостаточная грамматика (Луна для карты, контрольная сумма ИНН, `local@domain.tld`) |
| `Strong` | форма плюс явный маркер типа рядом («паспорт», «выдан», «cvv», «дата рождения») |
| `Weak` | совпала только форма. Движок сам поднимет до `Strong`, если в том же предложении есть достоверное значение другого типа |
| `Denied` | ставится не сканером, а через `Deny`: контр-правило |

Движок сам разрешает перекрытия, поднимает слабых кандидатов по кластеру и
применяет профиль. Сканеру этого делать не надо — он только сообщает находки.
Перекрывающиеся кандидаты разных типов регистрировать можно и нужно: движок
выберет сильнейший.

## internal/detect/dict

```go
func (s *Set) Table(name string) *Table  // nil для отсутствующего справочника
func (t *Table) Has(word string) bool    // корректно работает на nil
func (t *Table) Get(word string) (label string, ok bool)
func dict.Normalize(s string) string
```

Справочник — файл `internal/detect/dict/data/<имя>.txt`, встраивается
автоматически. Формат: одна запись на строку, `#` — комментарий,
необязательный второй столбец через табуляцию — метка записи.
Ключи нормализуются при загрузке, в файле можно писать как удобно.

## internal/pii

```go
type Type uint8  // FullName, BirthDate, ..., CardHolder, SNILS, ...
func (t Type) Key() string          // "full_name"
func (t Type) Label() string        // "ФИО"
func (t Type) Placeholder() string  // "ФИО"

type Set uint32
func NewSet(types ...Type) Set
func (s Set) Add(t Type) Set
func (s Set) Has(t Type) bool
```

## Границы спана

Спан держится **точно по значению**. Служебные слова в него не входят:

| Текст | Правильный спан | Неправильный |
|---|---|---|
| `паспорт серия 4509 номер 123456` | `4509 номер 123456`, либо два спана `4509` и `123456` | `серия 4509 номер 123456` |
| `ул. Ленина, д. 5` | `Ленина, д. 5` как часть адреса | `ул. Ленина, д. 5` |
| `родился 12.05.1990 года` | `12.05.1990` | `12.05.1990 года` |

Избыточное маскирование штрафуется отдельной проверкой. Пропуск штрафуется
сильнее лишней маски, поэтому при равенстве аргументов выбирается маскирование —
но захват служебных слов равенством не является.

## Требования к коду

- `regexp` в горячем пути запрещён. Работа идёт по токенам `lex.Doc`.
- Аллокации в `Scan` держать около нуля: никаких `strings.ToLower`,
  `fmt.Sprintf`, сборки временных строк и срезов на каждый токен.
- UTF-8: `Start`/`End` — байты. Кириллическая буква занимает два байта.
- Тесты — только на синтетических данных. Реальные ПД в репозиторий не попадают.
