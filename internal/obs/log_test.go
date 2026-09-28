package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerAcceptsDocumentedLevels(t *testing.T) {
	// Уровень приходит из конфигурации, то есть от человека: регистр и
	// синоним warning допустимы, пустое значение означает уровень по
	// умолчанию.
	cases := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"DEBUG":    slog.LevelDebug,
		levelInfo:  slog.LevelInfo,
		"":         slog.LevelInfo,
		"Warn":     slog.LevelWarn,
		"warning":  slog.LevelWarn,
		levelError: slog.LevelError,
	}
	for level, want := range cases {
		var buf bytes.Buffer
		l, err := NewLogger(&buf, level, formatJSON)
		if err != nil {
			t.Errorf("уровень %q отвергнут: %v", level, err)
			continue
		}
		if !l.Enabled(context.Background(), want) {
			t.Errorf("уровень %q не пропускает записи уровня %v", level, want)
		}
		if want > slog.LevelDebug && l.Enabled(context.Background(), want-4) {
			t.Errorf("уровень %q пропускает записи ниже себя", level)
		}
	}
}

func TestNewLoggerAcceptsDocumentedFormats(t *testing.T) {
	for _, format := range []string{formatJSON, "JSON", formatText, "Text", ""} {
		var buf bytes.Buffer
		if _, err := NewLogger(&buf, levelInfo, format); err != nil {
			t.Errorf("формат %q отвергнут: %v", format, err)
		}
	}
}

func TestNewLoggerRejectsUnknownLevel(t *testing.T) {
	// Опечатка в конфигурации обязана останавливать запуск с внятным
	// текстом, а не молча включать уровень по умолчанию.
	l, err := NewLogger(&bytes.Buffer{}, "verbose", formatJSON)
	if err == nil {
		t.Fatal("неизвестный уровень принят без ошибки")
	}
	if l != nil {
		t.Error("при ошибке возвращён журнал")
	}
	msg := err.Error()
	if !strings.Contains(msg, "logging.level") {
		t.Errorf("текст ошибки не называет параметр: %q", msg)
	}
	if !strings.Contains(msg, "verbose") {
		t.Errorf("текст ошибки не называет отвергнутое значение: %q", msg)
	}
}

func TestNewLoggerRejectsUnknownFormat(t *testing.T) {
	l, err := NewLogger(&bytes.Buffer{}, levelInfo, "yaml")
	if err == nil {
		t.Fatal("неизвестный формат принят без ошибки")
	}
	if l != nil {
		t.Error("при ошибке возвращён журнал")
	}
	msg := err.Error()
	if !strings.Contains(msg, "logging.format") {
		t.Errorf("текст ошибки не называет параметр: %q", msg)
	}
	// Перечень допустимых значений в тексте ошибки экономит чтение кода.
	if !strings.Contains(msg, formatJSON) || !strings.Contains(msg, formatText) {
		t.Errorf("текст ошибки не перечисляет допустимые форматы: %q", msg)
	}
}

func TestJSONRecordIsValidJSON(t *testing.T) {
	// Формат json выбран, чтобы записи разбирала машина. Проверяется именно
	// разбор, а не наличие подстрок.
	var buf bytes.Buffer
	l, err := NewLogger(&buf, levelInfo, formatJSON)
	if err != nil {
		t.Fatalf(fmtLoggerFail, err)
	}
	l.Info(msgHandled, keyRequestID, "r42", keyDetectedTypes, []string{"phone", "email"}, keyMaskedCount, 2)

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("запись не является JSON: %v (%q)", err, buf.String())
	}
	for _, key := range []string{"time", keyLevel, keyMsg, keyRequestID, keyMaskedCount} {
		if _, ok := rec[key]; !ok {
			t.Errorf("в записи нет поля %q: %v", key, rec)
		}
	}
	if rec[keyMsg] != msgHandled {
		t.Errorf("поле msg = %v", rec[keyMsg])
	}
	if rec[keyLevel] != "INFO" {
		t.Errorf("поле level = %v", rec[keyLevel])
	}
}

func TestTextRecordCarriesAttributes(t *testing.T) {
	var buf bytes.Buffer
	l, err := NewLogger(&buf, levelInfo, formatText)
	if err != nil {
		t.Fatalf(fmtLoggerFail, err)
	}
	l.Warn("хранилище исчерпано", "payload_id", "p-7")

	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "payload_id=p-7") {
		t.Errorf("текстовая запись не содержит ожидаемых полей: %q", out)
	}
}

func TestLevelFiltersLowerRecords(t *testing.T) {
	var buf bytes.Buffer
	l, err := NewLogger(&buf, levelError, formatJSON)
	if err != nil {
		t.Fatalf(fmtLoggerFail, err)
	}
	l.Debug("подробности")
	l.Info("ход обработки")
	if buf.Len() != 0 {
		t.Errorf("журнал уровня error записал более низкий уровень: %q", buf.String())
	}
	l.Error("отказ")
	if buf.Len() == 0 {
		t.Error("журнал уровня error не записал запись своего уровня")
	}
}

func TestJSONHandlerKeepsUTF8Readable(t *testing.T) {
	// От этого зависит тест утечек: поиск ведётся по подстроке в накопленном
	// журнале. Если бы обработчик экранировал кириллицу в \uXXXX, поиск по
	// исходному значению ничего не нашёл бы и проверка стала бы пустой.
	var buf bytes.Buffer
	l, err := NewLogger(&buf, levelInfo, formatJSON)
	if err != nil {
		t.Fatalf(fmtLoggerFail, err)
	}
	const value = "Строка с кириллицей"
	l.Info("проверка", "value", value)
	if !strings.Contains(buf.String(), value) {
		t.Errorf("значение записано в неразборчивом виде: %q", buf.String())
	}
}

func TestLoggerFromEmptyContextIsUsable(t *testing.T) {
	// Журнал из контекста берут обработчики на всех путях, включая аварийные.
	// Возврат nil означал бы панику в обработчике паники.
	var buf bytes.Buffer
	fallback, err := NewLogger(&buf, "debug", formatJSON)
	if err != nil {
		t.Fatalf(fmtLoggerFail, err)
	}
	prev := slog.Default()
	slog.SetDefault(fallback)
	t.Cleanup(func() { slog.SetDefault(prev) })

	l := LoggerFrom(context.Background())
	if l == nil {
		t.Fatal("LoggerFrom вернул nil на контексте без журнала")
	}
	l.Info("запись без контекста")
	if buf.Len() == 0 {
		t.Error("журнал по умолчанию ничего не записал")
	}
}

func TestWithLoggerRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	l, err := NewLogger(&buf, levelInfo, formatJSON)
	if err != nil {
		t.Fatalf(fmtLoggerFail, err)
	}
	ctx := WithLogger(context.Background(), l)
	if got := LoggerFrom(ctx); got != l {
		t.Error("из контекста вернулся не тот журнал, который был положен")
	}

	// Значение под чужим ключом не должно подменять журнал.
	type otherKey struct{}
	foreign := context.WithValue(context.Background(), otherKey{}, l)
	if LoggerFrom(foreign) == l {
		t.Error("журнал найден по чужому ключу контекста")
	}
}
