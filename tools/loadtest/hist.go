package main

import (
	"math"
	"math/bits"
)

// Разбивка гистограммы: логарифмически-линейная схема HdrHistogram.
// Значения хранятся в микросекундах.
const (
	subBucketBits  = 7
	subBucketCount = 1 << subBucketBits // 128 подкорзин на двоичный порядок
	magnitudeCount = 26                 // до 2^32 мкс — заведомо выше клиентского таймаута
	bucketCount    = magnitudeCount * subBucketCount
)

// histogram накапливает латентности без хранения отдельных замеров.
//
// Почему не срез всех значений: при 200 соединениях и субмиллисекундном ответе
// прогон даёт десятки миллионов замеров, полный срез — гигабайты памяти в
// клиенте, и клиент сам становится узким местом. Логарифмически-линейная
// гистограмма занимает ~26 КБ и даёт перцентили с относительной погрешностью
// 1/128 ≈ 0,8 %. Сумма, минимум и максимум хранятся точно, поэтому среднее и
// максимум погрешности разбивки не имеют.
type histogram struct {
	counts [bucketCount]uint64
	count  uint64
	sum    uint64 // микросекунды
	min    uint64
	max    uint64
}

// bucketIndex возвращает номер корзины для значения в микросекундах.
func bucketIndex(v uint64) int {
	if v < subBucketCount {
		return int(v)
	}
	msb := bits.Len64(v) - 1
	shift := uint(msb - subBucketBits)
	idx := (int(shift)+1)*subBucketCount + int(v>>shift) - subBucketCount
	if idx >= bucketCount {
		return bucketCount - 1
	}
	return idx
}

// bucketValue возвращает представителя корзины — её середину.
func bucketValue(idx int) uint64 {
	if idx < subBucketCount {
		return uint64(idx)
	}
	shift := uint(idx/subBucketCount - 1)
	sub := uint64(idx%subBucketCount + subBucketCount)
	return (sub << shift) + (uint64(1)<<shift)/2
}

func (h *histogram) record(d uint64) {
	h.counts[bucketIndex(d)]++
	h.count++
	h.sum += d
	if h.count == 1 || d < h.min {
		h.min = d
	}
	if d > h.max {
		h.max = d
	}
}

func (h *histogram) merge(o *histogram) {
	if o.count == 0 {
		return
	}
	for i := range o.counts {
		h.counts[i] += o.counts[i]
	}
	if h.count == 0 || o.min < h.min {
		h.min = o.min
	}
	if o.max > h.max {
		h.max = o.max
	}
	h.count += o.count
	h.sum += o.sum
}

// mean — точное среднее в микросекундах, считается по сумме, а не по корзинам.
func (h *histogram) mean() float64 {
	if h.count == 0 {
		return 0
	}
	return float64(h.sum) / float64(h.count)
}

// quantile возвращает значение перцентиля в микросекундах.
func (h *histogram) quantile(q float64) uint64 {
	if h.count == 0 {
		return 0
	}
	target := uint64(math.Ceil(q * float64(h.count)))
	if target == 0 {
		target = 1
	}
	if target > h.count {
		target = h.count
	}
	var cum uint64
	for i := range h.counts {
		cum += h.counts[i]
		if cum >= target {
			v := bucketValue(i)
			// Границы поджимаются к точным min/max: середина корзины может
			// выйти за фактический диапазон замеров.
			if v < h.min {
				return h.min
			}
			if v > h.max {
				return h.max
			}
			return v
		}
	}
	return h.max
}
