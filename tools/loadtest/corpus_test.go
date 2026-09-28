package main

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Поле текста записи корпуса JSON Lines.
const fieldText = "text"

// TestBuildCorpusWithoutFile — ключевое свойство: корпус T-14 может ещё не
// существовать, и прогон обязан работать без него.
func TestBuildCorpusWithoutFile(t *testing.T) {
	c, err := buildCorpus(filepath.Join(t.TempDir(), "нет-такого.jsonl"), modeMixed, 7)
	if err != nil {
		t.Fatalf("отсутствие файла корпуса стало ошибкой: %v", err)
	}
	if c.size() == 0 {
		t.Fatal("встроенный набор пуст")
	}
	if !strings.Contains(c.source, "встроенный") {
		t.Fatalf("источник не помечен как встроенный: %q", c.source)
	}
	rnd := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 200; i++ {
		if c.pick(rnd).text == "" {
			t.Fatal("выбран пустой элемент")
		}
	}
}

func TestBuildCorpusEmptyFlag(t *testing.T) {
	c, err := buildCorpus("", modeMixed, 1)
	if err != nil {
		t.Fatalf("пустой -corpus стал ошибкой: %v", err)
	}
	if c.size() == 0 {
		t.Fatal("встроенный набор пуст")
	}
}

func writeCorpus(t *testing.T, recs []map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corpus.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Ошибка закрытия означает недописанный корпус — тест обязан о ней узнать.
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	enc := json.NewEncoder(f)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestLoadCorpusJSONL(t *testing.T) {
	// Длинная запись проверяет, что чтение не упирается в размер строки:
	// в корпусе T-14 есть тексты на 100 000 токенов.
	long := strings.Repeat("длинный текст обращения. ", 30000)
	path := writeCorpus(t, []map[string]any{
		{"id": "c-0001", fieldText: "короткий запрос клиента", "spans": []any{}},
		{"id": "c-0002", fieldText: long},
		{fieldText: "запись без идентификатора"},
		{"id": "c-0004", fieldText: ""},
	})
	c, why, err := loadCorpus(path)
	if err != nil {
		t.Fatalf("загрузка корпуса: %v (%s)", err, why)
	}
	if c == nil {
		t.Fatalf("корпус не загружен: %s", why)
	}
	if got := c.size(); got != 3 {
		t.Fatalf("загружено %d записей, ожидалось 3 (пустой текст пропускается)", got)
	}
	if len(c.classes[classHuge]) != 1 {
		t.Fatalf("длинная запись не попала в класс huge: %v", c.classes[classHuge])
	}
}

func TestLoadCorpusBrokenJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.jsonl")
	if err := os.WriteFile(path, []byte("{\"id\":\"a\",\"text\":\"ок\"}\n{сломано}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCorpus(path); err == nil {
		t.Fatal("битый корпус принят без ошибки: молча испорченная нагрузка хуже отказа")
	}
}

// TestLongModeHasHugeItems — AC-7: режим длинных текстов обязан дать вход на
// 100 000 токенов даже тогда, когда в файле корпуса таких записей нет.
func TestLongModeHasHugeItems(t *testing.T) {
	path := writeCorpus(t, []map[string]any{{"id": "c-1", fieldText: "короткая запись"}})
	c, err := buildCorpus(path, modeLong, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.classes[classHuge]) == 0 {
		t.Fatal("в режиме long нет элементов на 100 000 токенов")
	}
	rnd := rand.New(rand.NewPCG(5, 6))
	for i := 0; i < 50; i++ {
		it := c.pick(rnd)
		if tok := len(it.text) / bytesPerToken; tok < 50_000 {
			t.Fatalf("в режиме long выбран элемент на %d токенов", tok)
		}
	}
}

func TestBuildLongTextSize(t *testing.T) {
	for _, target := range []int{1500, 20_000, hugeTokens} {
		txt := buildLongText(target, 11)
		tok := len(txt) / bytesPerToken
		if tok < target {
			t.Fatalf("текст на %d токенов получился короче: %d", target, tok)
		}
		// Перебор допускается в пределах одного абзаца, а не кратно.
		if tok > target+400 {
			t.Fatalf("текст на %d токенов получился длиннее допустимого: %d", target, tok)
		}
	}
}

func TestBuildLongTextIsDeterministic(t *testing.T) {
	a := buildLongText(3000, 42)
	b := buildLongText(3000, 42)
	if a != b {
		t.Fatal("один seed дал разный текст: прогоны стали бы несравнимы")
	}
	if c := buildLongText(3000, 43); a == c {
		t.Fatal("разные seed дали одинаковый текст")
	}
}

// TestSetWeightsRedistributes: вес пустого класса не должен оставаться
// «висящим», иначе часть выборов пришлась бы в пустоту.
func TestSetWeightsRedistributes(t *testing.T) {
	c := &corpus{}
	c.add(item{id: "s", text: "короткий текст"})
	c.setWeights([classCount]float64{0.5, 0.3, 0.2, 0})
	if c.total <= 0 {
		t.Fatal("суммарный вес не положителен")
	}
	rnd := rand.New(rand.NewPCG(9, 9))
	for i := 0; i < 100; i++ {
		if c.pick(rnd).id != "s" {
			t.Fatal("выбран несуществующий элемент")
		}
	}
}

func TestCompositionReportsClasses(t *testing.T) {
	c, err := buildCorpus("", modeMixed, 1)
	if err != nil {
		t.Fatal(err)
	}
	comp := c.composition()
	if len(comp) == 0 {
		t.Fatal("состав нагрузки пуст — условия измерения были бы неполны")
	}
	var sum float64
	for _, e := range comp {
		if e.Items == 0 {
			t.Fatalf("класс %s попал в отчёт без элементов", e.Class)
		}
		sum += e.Weight
	}
	if sum < 0.99 || sum > 1.01 {
		t.Fatalf("сумма долей состава = %f, ожидалась единица", sum)
	}
}
