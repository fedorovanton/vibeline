// Команда corpusgen порождает независимый размеченный корпус для оценки
// качества детекции персональных данных.
//
// Корпус не должен порождаться теми же грамматиками и справочниками, которыми
// работает детектор: иначе измерение проверяет совпадение кода с самим собой,
// а не качество (docs/spec/ACCEPTANCE.md §4). Поэтому инструмент вынесен в
// отдельный модуль и не импортирует ai-gateway.
//
//	go run . -out corpus.jsonl -count 1200 -seed 20260922
//	go run . -out corpus-bare.jsonl -bare   # плюс голые значения (T-63)
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"corpusgen/corpus"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "corpusgen:", err)
		os.Exit(1)
	}
}

func run() error {
	out := flag.String("out", "corpus.jsonl", "файл вывода в формате JSON Lines; «-» — стандартный вывод")
	count := flag.Int("count", corpus.DefaultCount, "базовое число записей без длинных")
	seed := flag.Uint64("seed", corpus.DefaultSeed, "зерно генератора: один seed даёт побайтово одинаковый корпус")
	long := flag.Bool("long", true, "добавить длинные записи на 50 000 и 100 000 токенов")
	bare := flag.Bool("bare", false, "добавить голые значения: запись целиком из одного значения ПД")
	quiet := flag.Bool("quiet", false, "не печатать сводку в поток ошибок")
	flag.Parse()

	if *count <= 0 {
		return fmt.Errorf("-count должен быть положительным, получено %d", *count)
	}

	recs := corpus.Generate(corpus.Options{Count: *count, Seed: *seed, Long: *long, Bare: *bare})

	if *out == "-" {
		w := bufio.NewWriterSize(os.Stdout, 1<<20)
		if err := corpus.Write(w, recs); err != nil {
			return err
		}
		if err := w.Flush(); err != nil {
			return err
		}
	} else if err := writeFile(*out, recs); err != nil {
		return err
	}

	if !*quiet {
		printSummary(os.Stderr, corpus.Summarize(recs), *seed)
	}
	return nil
}

func writeFile(path string, recs []corpus.Record) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("создание %s: %w", path, err)
	}
	// Ошибка закрытия важна: она означает недописанный корпус.
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	w := bufio.NewWriterSize(f, 1<<20)
	if err := corpus.Write(w, recs); err != nil {
		return err
	}
	return w.Flush()
}

func printSummary(f *os.File, s corpus.Summary, seed uint64) {
	var b strings.Builder
	fmt.Fprintf(&b, "seed: %d\nзаписей: %d, токенов: %d\n", seed, s.Records, s.Tokens)
	b.WriteString("виды записей:\n")
	for _, k := range s.Kinds {
		fmt.Fprintf(&b, "  %-9s %5d\n", k.Kind, k.Records)
	}
	fmt.Fprintf(&b, "типы ПД (минимум по задаче — %d записей на тип):\n", corpus.MinPerType)
	for _, t := range s.Types {
		mark := " "
		if t.Records < corpus.MinPerType {
			mark = "!"
		}
		fmt.Fprintf(&b, " %s %-20s записей %5d, спанов %5d\n", mark, t.Type, t.Records, t.Spans)
	}
	b.WriteString("ловушки:\n")
	for _, r := range s.Reasons {
		fmt.Fprintf(&b, "  %-16s %5d\n", r.Reason, r.Traps)
	}
	// Сводка — справка в поток ошибок; корпус к этому моменту уже записан,
	// и отказ печати сводки на него не влияет.
	_, _ = f.WriteString(b.String())
}
