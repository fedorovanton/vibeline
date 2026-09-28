package main

import (
	"math"
	"testing"
)

// TestBucketIndexIsContiguous проверяет, что нумерация корзин не имеет разрывов
// и не переставляет значения: перцентили считаются обходом по возрастанию
// номера, и любой разрыв дал бы неверный ответ.
func TestBucketIndexIsContiguous(t *testing.T) {
	prev := bucketIndex(0)
	if prev != 0 {
		t.Fatalf("bucketIndex(0) = %d, ожидалось 0", prev)
	}
	for v := uint64(1); v < 1<<22; v = v + 1 + v/64 {
		idx := bucketIndex(v)
		if idx < prev {
			t.Fatalf("bucketIndex(%d) = %d меньше предыдущего %d", v, idx, prev)
		}
		if idx >= bucketCount {
			t.Fatalf("bucketIndex(%d) = %d вне диапазона %d", v, idx, bucketCount)
		}
		prev = idx
	}
}

// TestBucketValueWithinBucket проверяет, что представитель корзины лежит в
// пределах допустимой относительной погрешности от исходного значения.
func TestBucketValueWithinBucket(t *testing.T) {
	const maxRelErr = 1.0 / subBucketCount
	for v := uint64(1); v < 1<<24; v = v + 1 + v/37 {
		got := bucketValue(bucketIndex(v))
		if v < subBucketCount {
			if got != v {
				t.Fatalf("малое значение %d восстановлено как %d", v, got)
			}
			continue
		}
		rel := math.Abs(float64(got)-float64(v)) / float64(v)
		if rel > maxRelErr {
			t.Fatalf("значение %d восстановлено как %d, погрешность %.4f > %.4f", v, got, rel, maxRelErr)
		}
	}
}

func TestHistogramMeanAndExtremes(t *testing.T) {
	var h histogram
	for i := 1; i <= 1000; i++ {
		h.record(uint64(i))
	}
	if h.count != 1000 {
		t.Fatalf("count = %d, ожидалось 1000", h.count)
	}
	if h.min != 1 || h.max != 1000 {
		t.Fatalf("min/max = %d/%d, ожидалось 1/1000", h.min, h.max)
	}
	// Среднее считается по точной сумме и погрешности разбивки не имеет.
	if want := 500.5; math.Abs(h.mean()-want) > 1e-9 {
		t.Fatalf("mean = %f, ожидалось %f", h.mean(), want)
	}
}

func TestHistogramQuantiles(t *testing.T) {
	var h histogram
	for i := 1; i <= 100000; i++ {
		h.record(uint64(i))
	}
	cases := []struct {
		q    float64
		want float64
	}{{0.5, 50000}, {0.95, 95000}, {0.99, 99000}}
	for _, c := range cases {
		got := float64(h.quantile(c.q))
		rel := math.Abs(got-c.want) / c.want
		if rel > 0.02 {
			t.Fatalf("quantile(%.2f) = %.0f, ожидалось ~%.0f (отклонение %.3f)", c.q, got, c.want, rel)
		}
	}
	if got := h.quantile(1.0); got != h.max {
		t.Fatalf("quantile(1.0) = %d, ожидался максимум %d", got, h.max)
	}
}

func TestHistogramQuantileEmpty(t *testing.T) {
	var h histogram
	if got := h.quantile(0.99); got != 0 {
		t.Fatalf("пустая гистограмма вернула %d", got)
	}
	if h.mean() != 0 {
		t.Fatalf("пустая гистограмма вернула среднее %f", h.mean())
	}
}

func TestHistogramMerge(t *testing.T) {
	var a, b, want histogram
	for i := 1; i <= 500; i++ {
		a.record(uint64(i))
		want.record(uint64(i))
	}
	for i := 501; i <= 1500; i++ {
		b.record(uint64(i))
		want.record(uint64(i))
	}
	a.merge(&b)
	if a.count != want.count || a.sum != want.sum || a.min != want.min || a.max != want.max {
		t.Fatalf("после слияния count/sum/min/max = %d/%d/%d/%d, ожидалось %d/%d/%d/%d",
			a.count, a.sum, a.min, a.max, want.count, want.sum, want.min, want.max)
	}
	if a.quantile(0.95) != want.quantile(0.95) {
		t.Fatalf("p95 после слияния %d, ожидалось %d", a.quantile(0.95), want.quantile(0.95))
	}
}

// TestHistogramClampsHugeValue проверяет, что значение выше диапазона не
// выходит за границы массива: таймаут в 10 секунд и разрыв соединения дают
// большие величины, и паника в этом месте оборвала бы прогон.
func TestHistogramClampsHugeValue(t *testing.T) {
	var h histogram
	h.record(math.MaxUint64)
	h.record(1)
	if h.count != 2 {
		t.Fatalf("count = %d, ожидалось 2", h.count)
	}
	if h.quantile(0.99) == 0 {
		t.Fatal("перцентиль по переполненной корзине равен нулю")
	}
}
