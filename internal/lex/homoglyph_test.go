package lex

import (
	"strings"
	"testing"
)

// TestHomoglyphFold — раунд 5 жюри (T-80, класс 6): латинская буква-двойник
// внутри кириллического слова сводится к кириллице только для поиска. Текст,
// Norm и границы токена не меняются, NormOf отдаёт кириллическую форму.
func TestHomoglyphFold(t *testing.T) {
	for _, tc := range []struct {
		text, norm string
		extra      int
	}{
		{"Мaзур", "мазур", 1},        // латинская a
		{"Смирнoв", "смирнов", 1},    // латинская o
		{"Mазур", "мазур", 1},        // латинская M в начале слова
		{"МAЗУР", "мазур", 1},        // капсом
		{"Пeтрoва", "петрова", 2},    // две латинские буквы
		{"Кузнeцoв", "кузнецов", 2},  // e и o
		{"Хoмякoва", "хомякова", 2},  // o дважды
		{"ОРЁЛ", "орел", 0},          // без латиницы: не сводится
		{"TOPOTA", "topota", 0},      // одна латиница: не сводится
		{"ivanоv", "ivanоv", 0},      // кириллическая о в латинском слове
		{"Мaзуr", "мaзуr", 0},        // r двойника не имеет
		{"Кaфé", "кaфé", 0},          // латинская буква вне ASCII
		{"Сa", "сa", 0},              // кириллицы не больше латиницы
		{"Мa\u200bзур", "мaзур", 0},  // невидимый символ: слово не сводится
		{"Нинa Павловна", "нина", 1}, // первое слово
	} {
		d := Tokenize(tc.text, nil)
		tok := d.Tokens[0]
		if got := d.NormOf(0); got != tc.norm {
			t.Errorf("%q: NormOf = %q, ожидалось %q", tc.text, got, tc.norm)
		}
		if got := tok.FoldExtra(); got != tc.extra {
			t.Errorf("%q: FoldExtra = %d, ожидалось %d", tc.text, got, tc.extra)
		}
		if tc.extra > 0 && !tok.Flags.Has(FlagFolded|FlagCyrillic) {
			t.Errorf("%q: признаки %b, ожидались FlagFolded и FlagCyrillic", tc.text, tok.Flags)
		}
		if len(d.Norm) != len(d.Text) {
			t.Errorf("%q: выравнивание Norm нарушено", tc.text)
		}
	}
}

// TestHomoglyphFoldKeepsOffsets проверяет, что сведение не сдвигает токены и
// что каждое сведённое слово текста отдаёт свою форму.
func TestHomoglyphFoldKeepsOffsets(t *testing.T) {
	text := "Клиент Мaзур Олег, телефон; Смирнoв И. Пeтрова"
	d := Tokenize(text, nil)
	want := map[string]string{"Мaзур": "мазур", "Смирнoв": "смирнов", "Пeтрова": "петрова"}
	found := 0
	for i := range d.Tokens {
		raw := d.Raw(i)
		if w, ok := want[raw]; ok {
			found++
			if got := d.NormOf(i); got != w {
				t.Errorf("%q: NormOf = %q, ожидалось %q", raw, got, w)
			}
		}
	}
	if found != len(want) {
		t.Fatalf("найдено %d сведённых слов из %d", found, len(want))
	}
	// Повторная разметка в тот же Doc не тащит сведённые формы прошлого
	// текста.
	d = Tokenize("Мaзур", d)
	if got := d.NormOf(0); got != "мазур" {
		t.Errorf("повторная разметка: NormOf = %q", got)
	}
	d = Tokenize("Мазур", d)
	if d.Tokens[0].Flags.Has(FlagFolded) {
		t.Error("слово без латиницы помечено FlagFolded")
	}
}

// TestHomoglyphFoldAllocations — сведение в переиспользуемом Doc не
// аллоцирует: буфер набирает ёмкость на первом тексте.
func TestHomoglyphFoldAllocations(t *testing.T) {
	text := "Клиент Мaзур Олег, Смирнoв Иван, Пeтрова Анна"
	d := Tokenize(text, nil)
	got := testing.AllocsPerRun(20, func() { d = Tokenize(text, d) })
	if got != 0 {
		t.Errorf("аллокаций на разметку: %.0f, требуется 0", got)
	}
}

// TestHomoglyphFoldLimits — пределы упаковки Token.Hidden: слово с восемью
// латинскими буквами и слова сверх maxFolds не сводятся и остаются как есть.
func TestHomoglyphFoldLimits(t *testing.T) {
	// Восемь латинских двойников при девяти кириллических буквах.
	d := Tokenize("aaaaaaaaжжжжжжжжж", nil)
	if d.Tokens[0].Flags.Has(FlagFolded) {
		t.Error("слово с восемью латинскими буквами сведено")
	}
	text := strings.Repeat("Мaзур ", maxFolds+2)
	d = Tokenize(text, d)
	for _, i := range []int{0, maxFolds - 1} {
		if got := d.NormOf(i); got != "мазур" {
			t.Fatalf("токен %d: NormOf = %q", i, got)
		}
	}
	if d.Tokens[maxFolds].Flags.Has(FlagFolded) {
		t.Error("слово сверх maxFolds сведено")
	}
}
