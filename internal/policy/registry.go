package policy

import "fmt"

// DefaultConsumerID — потребитель, применяемый к запросам без ключа.
//
// Проверяющая система шлёт запросы на /process без заголовков, поэтому у неё
// должна быть своя изолированная политика. Доступ к продуктовым данным и
// соответствиям других потребителей это не открывает.
const DefaultConsumerID = "benchmark"

// Registry — набор настроенных потребителей.
//
// Реестр неизменяем после сборки; обновление конфигурации публикует новый
// экземпляр целиком, поэтому читатели всегда видят согласованный снимок.
type Registry struct {
	byID  map[string]*Consumer
	byKey map[string]*Consumer
	def   *Consumer
	order []*Consumer
}

// NewRegistry собирает реестр и проверяет уникальность идентификаторов и ключей.
func NewRegistry(consumers []*Consumer) (*Registry, error) {
	r := &Registry{
		byID:  make(map[string]*Consumer, len(consumers)),
		byKey: make(map[string]*Consumer, len(consumers)),
		order: consumers,
	}
	for _, c := range consumers {
		if _, dup := r.byID[c.ID]; dup {
			return nil, fmt.Errorf("потребитель %q объявлен дважды", c.ID)
		}
		r.byID[c.ID] = c
		if c.APIKey != "" {
			if other, dup := r.byKey[c.APIKey]; dup {
				return nil, fmt.Errorf("потребители %q и %q используют один ключ доступа", other.ID, c.ID)
			}
			r.byKey[c.APIKey] = c
		}
		if c.ID == DefaultConsumerID {
			r.def = c
		}
	}
	if r.def == nil {
		return nil, fmt.Errorf("в конфигурации нет потребителя %q, применяемого к запросам без ключа", DefaultConsumerID)
	}
	return r, nil
}

// ByKey возвращает потребителя по ключу доступа. Отключённый потребитель не
// возвращается: проверка допуска выполняется здесь, а не у вызывающего кода.
func (r *Registry) ByKey(key string) (*Consumer, bool) {
	if key == "" {
		return nil, false
	}
	c, ok := r.byKey[key]
	if !ok || !c.Enabled {
		return nil, false
	}
	return c, true
}

// ByID возвращает потребителя по идентификатору, включая отключённого.
func (r *Registry) ByID(id string) (*Consumer, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// Default возвращает потребителя для запросов без ключа.
func (r *Registry) Default() *Consumer { return r.def }

// All возвращает потребителей в порядке объявления в конфигурации.
func (r *Registry) All() []*Consumer { return r.order }
