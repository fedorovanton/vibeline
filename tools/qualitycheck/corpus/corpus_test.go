package corpus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Синтетические значения, общие для тестов пакета.
const (
	typePhone    = "phone"
	loadFailFmt  = "Load: %v"
	testName     = "Петров Пётр"
	testRecordID = "c-1"
)

// writeCorpus раскладывает строки JSON Lines во временный файл.
func writeCorpus(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corpus.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("подготовка корпуса: %v", err)
	}
	return path
}

// marshal собирает строку корпуса из записи, считая смещения по тексту:
// хардкодить байтовые смещения кириллицы в тесте — верный способ проверить
// опечатку вместо кода.
func marshal(t *testing.T, id, kind, text string, spans []Span, traps []Trap) string {
	t.Helper()
	for i := range spans {
		at := strings.Index(text, spans[i].Value)
		if at < 0 {
			t.Fatalf("значение спана не найдено в тексте записи %s", id)
		}
		spans[i].Start, spans[i].End = at, at+len(spans[i].Value)
	}
	for i := range traps {
		at := strings.Index(text, traps[i].Value)
		if at < 0 {
			t.Fatalf("значение ловушки не найдено в тексте записи %s", id)
		}
		traps[i].Start, traps[i].End = at, at+len(traps[i].Value)
	}
	if spans == nil {
		spans = []Span{}
	}
	if traps == nil {
		traps = []Trap{}
	}
	b, err := json.Marshal(Record{ID: id, Kind: kind, Text: text, Spans: spans, Traps: traps})
	if err != nil {
		t.Fatalf("сборка записи: %v", err)
	}
	return string(b)
}

func TestLoadReadsRecordsAndFingerprint(t *testing.T) {
	path := writeCorpus(t,
		marshal(t, "c-0001", KindSingle, "Клиент Петров Пётр, телефон +7 900 000-00-00.",
			[]Span{{Type: "full_name", Value: testName}, {Type: typePhone, Value: "+7 900 000-00-00"}}, nil),
		marshal(t, "c-0002", KindClean, "Как долго идёт перевод между банками?", nil, nil),
	)

	c, err := Load(path)
	if err != nil {
		t.Fatalf(loadFailFmt, err)
	}
	if len(c.Records) != 2 {
		t.Fatalf("записей %d, ожидалось 2", len(c.Records))
	}
	// sha256 пустой строки не бывает, а длина отпечатка фиксирована.
	if len(c.SHA256) != 64 {
		t.Errorf("отпечаток %q не похож на sha256", c.SHA256)
	}
	if c.Bytes <= 0 {
		t.Errorf("размер корпуса %d", c.Bytes)
	}

	s := c.Summarize()
	if s.Records != 2 || s.Spans != 2 {
		t.Errorf("сводка: записей %d, спанов %d", s.Records, s.Spans)
	}
	if s.Kinds[KindClean] != 1 {
		t.Errorf("чистых записей %d, ожидалась 1", s.Kinds[KindClean])
	}
	if s.Types[typePhone] != 1 {
		t.Errorf("спанов phone %d, ожидался 1", s.Types[typePhone])
	}
}

// Смещения байтовые: у кириллицы номер символа и байтовое смещение расходятся,
// и проверка обязана ловить именно это.
func TestCyrillicOffsetsAreBytes(t *testing.T) {
	text := "Клиент Петров Пётр."
	at := strings.Index(text, testName)
	if at != 13 {
		t.Fatalf("байтовое смещение %d, ожидалось 13", at)
	}
	path := writeCorpus(t, marshal(t, testRecordID, KindSingle, text, []Span{{Type: "full_name", Value: testName}}, nil))
	c, err := Load(path)
	if err != nil {
		t.Fatalf(loadFailFmt, err)
	}
	s := c.Records[0].Spans[0]
	if c.Records[0].Text[s.Start:s.End] != s.Value {
		t.Errorf("текст на [%d;%d) не равен значению спана", s.Start, s.End)
	}
	if s.Len() != len(s.Value) {
		t.Errorf("длина спана %d, длина значения %d", s.Len(), len(s.Value))
	}
}

func TestLoadRejectsBrokenOffsets(t *testing.T) {
	cases := map[string]string{
		"смещение мимо значения": `{"id":"c-1","kind":"single","text":"Клиент Петров.","spans":[{"start":0,"end":12,"type":"full_name","value":"Петров"}],"traps":[]}`,
		"конец за текстом":       `{"id":"c-1","kind":"single","text":"Клиент.","spans":[{"start":0,"end":99,"type":"full_name","value":"Петров"}],"traps":[]}`,
		"пустой идентификатор":   `{"id":"","kind":"clean","text":"Текст.","spans":[],"traps":[]}`,
		"ловушка мимо значения":  `{"id":"c-1","kind":"trap","text":"Улица Пушкина.","spans":[],"traps":[{"start":0,"end":14,"type":"full_name","reason":"toponym","value":"Пушкина"}]}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeCorpus(t, line)); err == nil {
				t.Fatal("ожидалась ошибка разметки, получен успех")
			}
		})
	}
}

func TestLoadRejectsEmptyCorpus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("пустой корпус принят, ожидалась ошибка")
	}
}

// Отпечаток обязан меняться вместе с содержимым: на нём держится сравнимость
// прогонов.
func TestFingerprintFollowsContent(t *testing.T) {
	a, err := Load(writeCorpus(t, marshal(t, testRecordID, KindClean, "Первый текст.", nil, nil)))
	if err != nil {
		t.Fatalf(loadFailFmt, err)
	}
	b, err := Load(writeCorpus(t, marshal(t, testRecordID, KindClean, "Второй текст.", nil, nil)))
	if err != nil {
		t.Fatalf(loadFailFmt, err)
	}
	if a.SHA256 == b.SHA256 {
		t.Error("разные корпуса дали одинаковый отпечаток")
	}
}

func TestSortedKeysIsDeterministic(t *testing.T) {
	m := map[string]int{typePhone: 1, "address": 2, "email": 3}
	got := SortedKeys(m)
	want := []string{"address", "email", typePhone}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("порядок ключей %v, ожидался %v", got, want)
		}
	}
}
