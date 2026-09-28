// Команда qualitycheck измеряет качество детекции и маскирования на
// независимом корпусе из tools/corpusgen и печатает отчёт.
//
// Инструмент вынесен в отдельный модуль и не импортирует ai-gateway: измерение,
// использующее внутренности детектора, проверяет совпадение кода с самим собой,
// а не качество (docs/spec/ACCEPTANCE.md §4). Сервис виден инструменту только
// через HTTP-контракт POST /process.
//
//	go run . -url http://localhost:8080 -corpus corpus.jsonl
//	go run . -corpus corpus.jsonl -json report.json
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"qualitycheck/corpus"
	"qualitycheck/eval"
	"qualitycheck/probe"
	"qualitycheck/report"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "qualitycheck:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("qualitycheck", flag.ExitOnError)
	url := fs.String("url", "http://localhost:8080", "адрес сервиса с контрактом POST /process")
	path := fs.String("corpus", "corpus.jsonl", "файл корпуса в формате JSON Lines из tools/corpusgen")
	jsonOut := fs.String("json", "", "файл машинного отчёта JSON; «-» — стандартный вывод вместо таблицы")
	verbose := fs.Bool("verbose", false, "печатать значения персональных данных в отчёте; по умолчанию их нет ни в таблице, ни в JSON")
	timeout := fs.Duration("timeout", 10*time.Second, "предел на один запрос, как в официальной проверке")
	concurrency := fs.Int("concurrency", 16, "число одновременно проверяемых записей")
	seed := fs.Uint64("seed", 20260922, "seed, которым порождён корпус: попадает в отчёт для сравнимости прогонов")
	count := fs.Int("count", 1200, "параметр -count генератора корпуса: попадает в отчёт")
	long := fs.Bool("long", true, "были ли в корпусе длинные записи: попадает в отчёт")
	limit := fs.Int("limit", 0, "прогнать только первые N записей; 0 — весь корпус")
	fs.Usage = func() { usage(fs) }
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *concurrency < 1 {
		return fmt.Errorf("-concurrency должен быть положительным, получено %d", *concurrency)
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout должен быть положительным, получено %s", *timeout)
	}

	corp, err := corpus.Load(*path)
	if err != nil {
		return err
	}
	recs := corp.Records
	if *limit > 0 && *limit < len(recs) {
		recs = recs[:*limit]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := probe.New(*url, *timeout)
	service, err := client.Describe(ctx)
	if err != nil {
		// Версия правил не получена — прогон это не останавливает, но отчёт
		// обязан показать пробел, а не сделать вид, что версия известна.
		fmt.Fprintf(os.Stderr, "qualitycheck: версия сервиса не получена: %v\n", err)
	}

	runID := "qc-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	runner := &Runner{Client: client, RunID: runID, Concurrency: *concurrency, Progress: os.Stderr}

	started := time.Now()
	results := runner.Run(ctx, recs)
	finished := time.Now()

	metrics := eval.Aggregate(results)
	if !*verbose {
		metrics.Redact()
	}

	rep := &report.Report{
		Tool:    "qualitycheck",
		Version: report.Version,
		Run: report.Run{
			RunID:       runID,
			StartedAt:   started,
			FinishedAt:  finished,
			DurationSec: finished.Sub(started).Seconds(),
			Concurrency: *concurrency,
			TimeoutSec:  timeout.Seconds(),
			Verbose:     *verbose,
		},
		Corpus: report.Corpus{
			Path:    corp.Path,
			SHA256:  corp.SHA256,
			Bytes:   corp.Bytes,
			Seed:    *seed,
			Count:   *count,
			Long:    *long,
			Summary: corp.Summarize(),
		},
		Service: service,
		Method:  report.Method(),
		Metrics: metrics,
	}

	if *jsonOut == "-" {
		return rep.WriteJSON(os.Stdout)
	}
	if err := rep.Render(os.Stdout, *verbose); err != nil {
		return err
	}
	if *jsonOut != "" {
		return writeJSONFile(*jsonOut, rep)
	}
	return nil
}

func writeJSONFile(path string, rep *report.Report) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("создание %s: %w", path, err)
	}
	// Ошибка закрытия важна: она означает недописанный отчёт.
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return rep.WriteJSON(f)
}

// usageText — описание инструмента перед списком флагов.
const usageText = `qualitycheck — измерение качества маскирования на независимом корпусе.

Инструмент шлёт каждую запись корпуса на POST /process, затем возвращает
полученную маску с тем же payload_id и проверяет сокрытие значений,
побайтовое восстановление, избыточное маскирование и ложные срабатывания
на ловушках.

Приватность. По умолчанию отчёт не содержит ни одного значения персональных
данных: только типы, идентификаторы записей и позиции. Флаг -verbose включает
печать самих значений — и в таблицу, и в JSON; включать его следует, только
когда вывод никуда не сохраняется.

Флаги:
`

func usage(fs *flag.FlagSet) {
	// Справка печатается в поток ошибок; об отказе записи туда сообщить некуда.
	_, _ = io.WriteString(fs.Output(), usageText)
	fs.PrintDefaults()
}
