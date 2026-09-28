package pii

import (
	"math/bits"
	"sort"
	"strings"
)

// Set — множество типов ПД в виде битовой маски.
//
// Ширины uint32 хватает на Count типов; проверка размера выполняется тестом,
// чтобы добавление типа сверх разрядности не прошло молча.
type Set uint32

// NewSet собирает множество из перечисленных типов.
func NewSet(types ...Type) Set {
	var s Set
	for _, t := range types {
		s = s.Add(t)
	}
	return s
}

// FullSet — множество из всех зарегистрированных типов, кроме Unknown.
func FullSet() Set { return NewSet(All()...) }

// Add возвращает копию множества с добавленным типом.
func (s Set) Add(t Type) Set { return s | (1 << t) }

// Remove возвращает копию множества без указанного типа.
func (s Set) Remove(t Type) Set { return s &^ (1 << t) }

// Union возвращает объединение множеств.
//
// Нужно там, где типы накапливаются по нескольким проходам: например,
// в продуктовом прокси ответ модели сканируется заново, и найденное в нём
// добавляется к найденному в запросе.
func (s Set) Union(other Set) Set { return s | other }

// Intersect возвращает пересечение множеств.
func (s Set) Intersect(other Set) Set { return s & other }

// Contains сообщает, что все типы other входят в s.
func (s Set) Contains(other Set) bool { return s&other == other }

// Has сообщает, входит ли тип в множество.
func (s Set) Has(t Type) bool { return s&(1<<t) != 0 }

// Empty сообщает, пусто ли множество.
func (s Set) Empty() bool { return s == 0 }

// Len возвращает число типов в множестве.
func (s Set) Len() int { return bits.OnesCount32(uint32(s)) }

// Types возвращает типы множества в порядке объявления.
func (s Set) Types() []Type {
	out := make([]Type, 0, s.Len())
	for t := Type(1); int(t) < Count; t++ {
		if s.Has(t) {
			out = append(out, t)
		}
	}
	return out
}

// Keys возвращает отсортированные машинные ключи типов множества.
// Используется в логах: порядок стабилен между запусками.
func (s Set) Keys() []string {
	ts := s.Types()
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Key()
	}
	sort.Strings(out)
	return out
}

// String печатает множество как список ключей через запятую.
func (s Set) String() string { return strings.Join(s.Keys(), ",") }
