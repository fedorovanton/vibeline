// Package config — схема, разбор и публикация конфигурации сервиса.
//
// Конфигурация публикуется целиком как неизменяемый снимок: читатели никогда
// не видят наполовину применённые настройки. Невалидное обновление
// отклоняется, и сервис продолжает работать на последнем корректном снимке.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration — длительность, читаемая из YAML в формате «30m», «1s», «500ms».
type Duration time.Duration

// UnmarshalYAML разбирает длительность из строки или числа секунд.
//
// Числовая ветка идёт первой намеренно: yaml.v3 успешно разбирает
// нетипизированный скаляр 1800 в строку, поэтому строковая ветка забрала бы
// значение себе и упала на ParseDuration, не дойдя до числовой. Порядок тот
// же, что в Bytes.UnmarshalYAML.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var n int64
	if err := unmarshal(&n); err == nil {
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return fmt.Errorf("длительность должна быть строкой вида \"30m\" или числом секунд")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("некорректная длительность %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Duration возвращает значение как time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String печатает длительность в человекочитаемом виде.
func (d Duration) String() string { return time.Duration(d).String() }

// Bytes — размер в байтах, читаемый из YAML как число или строка с суффиксом
// KiB, MiB, GiB, KB, MB, GB.
type Bytes int64

// UnmarshalYAML разбирает размер из числа или строки с суффиксом.
func (b *Bytes) UnmarshalYAML(unmarshal func(any) error) error {
	var n int64
	if err := unmarshal(&n); err == nil {
		*b = Bytes(n)
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return fmt.Errorf("размер должен быть числом байт или строкой вида \"8MiB\"")
	}
	v, err := parseBytes(s)
	if err != nil {
		return err
	}
	*b = Bytes(v)
	return nil
}

// Int64 возвращает размер в байтах.
func (b Bytes) Int64() int64 { return int64(b) }

var byteUnits = []struct {
	suffix string
	mult   int64
}{
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
	{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"B", 1},
}

func parseBytes(s string) (int64, error) {
	up := strings.ToUpper(strings.TrimSpace(s))
	for _, u := range byteUnits {
		if !strings.HasSuffix(up, u.suffix) {
			continue
		}
		num := strings.TrimSpace(strings.TrimSuffix(up, u.suffix))
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, fmt.Errorf("некорректный размер %q: %w", s, err)
		}
		return int64(v * float64(u.mult)), nil
	}
	v, err := strconv.ParseInt(up, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("некорректный размер %q", s)
	}
	return v, nil
}
