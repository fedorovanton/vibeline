package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"qualitycheck/corpus"
	"qualitycheck/eval"
	"qualitycheck/probe"
)

// Runner прогоняет корпус через контракт POST /process.
//
// На каждую запись приходится ровно два обращения: прямой шаг и обратный с
// полученной маской и тем же payload_id. Внутри записи они строго
// последовательны — обратный шаг без прямого не имеет смысла; параллелизм
// только между записями.
type Runner struct {
	Client      *probe.Client
	RunID       string
	Concurrency int
	Progress    io.Writer
}

// Run возвращает итоги в том же порядке, в каком записи лежат в корпусе:
// отчёт должен быть воспроизводимым и сравнимым диффом между прогонами.
func (r *Runner) Run(ctx context.Context, recs []corpus.Record) []eval.RecordResult {
	results := make([]eval.RecordResult, len(recs))
	jobs := make(chan int)

	workers := r.Concurrency
	if workers < 1 {
		workers = 1
	}

	var done atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = r.one(ctx, &recs[i])
				r.report(int(done.Add(1)), len(recs))
			}
		}()
	}

	for i := range recs {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			markCancelled(results, recs, ctx.Err())
			return results
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

// one выполняет оба шага автомата для одной записи.
func (r *Runner) one(ctx context.Context, rec *corpus.Record) eval.RecordResult {
	id := r.RunID + "-" + rec.ID

	masked, err := r.Client.Process(ctx, id, rec.Text)
	if err != nil {
		return eval.Failed(rec, fmt.Errorf("прямой шаг: %w", err))
	}
	restored, err := r.Client.Process(ctx, id, masked)
	if err != nil {
		return eval.Failed(rec, fmt.Errorf("обратный шаг: %w", err))
	}
	return eval.Evaluate(rec, masked, restored)
}

// report печатает ход прогона в поток ошибок: на большом корпусе молчание
// неотличимо от зависшего запроса.
func (r *Runner) report(done, total int) {
	if r.Progress == nil || (done%100 != 0 && done != total) {
		return
	}
	// Ход прогона — диагностика, а не результат: отказ её записи прогон не
	// останавливает и на отчёт не влияет.
	_, _ = fmt.Fprintf(r.Progress, "\rпрогон: %d/%d", done, total)
	if done == total {
		_, _ = fmt.Fprintln(r.Progress)
	}
}

// markCancelled помечает записи, до которых прогон не дошёл. Пустой итог без
// пометки выглядел бы как запись без персональных данных и завысил бы метрики.
func markCancelled(results []eval.RecordResult, recs []corpus.Record, err error) {
	for i := range results {
		if results[i].ID == "" {
			results[i] = eval.Failed(&recs[i], err)
		}
	}
}
