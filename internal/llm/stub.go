package llm

import (
	"context"
	"strings"
)

// Stub — детерминированная модель без сети (режим llm.mode: stub).
//
// Нужна по двум причинам. Первая: демо не должно зависеть от доступности сети
// и корпоративного сертификата на чужой машине. Вторая: тесты конвейера защиты
// обязаны обходиться без внешних вызовов.
//
// Ответ цитирует полученные плейсхолдеры — так на демо видно, что модель
// получила именно маску, а не исходные значения.
type Stub struct {
	// Model — идентификатор, который заглушка называет в ответе.
	Model string
}

// ModeStub — значение llm.mode, при котором сервис работает с заглушкой
// вместо сетевого клиента модели.
const ModeStub = "stub"

// stubID — идентификатор ответа заглушки. Фиксирован: ответ обязан быть
// детерминированным, иначе его нельзя сравнить в тесте.
const stubID = "chatcmpl-stub"

// Chat возвращает детерминированный ответ, не обращаясь к сети.
func (s Stub) Chat(ctx context.Context, req Request) (*Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var in int
	for _, m := range req.Messages {
		in += len(m.Content)
	}

	content := stubContent(req.Messages)
	model := req.Model
	if model == "" {
		model = s.Model
	}

	return &Response{
		ID:      stubID,
		Object:  "chat.completion",
		Created: 0, // фиксированное значение: ответ должен быть воспроизводим
		Model:   model,
		Choices: []Choice{{
			Index:        0,
			Message:      Message{Role: "assistant", Content: content},
			FinishReason: "stop",
		}},
		Usage: Usage{
			PromptTokens:     in / stubBytesPerToken,
			CompletionTokens: len(content) / stubBytesPerToken,
			TotalTokens:      (in + len(content)) / stubBytesPerToken,
		},
	}, nil
}

// stubBytesPerToken — грубая оценка «байт на токен» для счётчиков заглушки.
// Совпадает с определением метрики сервиса и не выдаётся за токенизатор модели.
const stubBytesPerToken = 4

func stubContent(msgs []Message) string {
	var found []string
	seen := make(map[string]struct{})
	for _, m := range msgs {
		for _, p := range placeholders(m.Content) {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			found = append(found, p)
		}
	}

	var b strings.Builder
	// Заглушка повторяет метки, которые получила, и сервис восстанавливает их
	// в ответе для потребителя с правом восстановления. Поэтому текст не
	// утверждает «модель получила только маски»: после восстановления на
	// месте меток стоят значения, и фраза читалась бы наоборот. И не
	// утверждает, что исходных значений не было: заглушка видит только метки
	// и не знает, что детекция пропустила (бизнес-жюри 23.09, раунд 2).
	b.WriteString("Режим stub: обращения к модели не было. ")
	if len(found) == 0 {
		b.WriteString("Меток в полученном тексте нет. Что именно ушло бы в модель — в блоке «что фактически ушло в модель».")
		return b.String()
	}
	b.WriteString("Заглушка повторяет полученные метки: ")
	b.WriteString(strings.Join(found, ", "))
	b.WriteString(". Если здесь видны значения, их восстановил сервис для потребителя с правом восстановления; что ушло наружу — в блоке «что фактически ушло в модель».")
	return b.String()
}

// placeholders выделяет типизированные плейсхолдеры вида [ФИО_1] в порядке
// появления.
//
// Разбор ручной, без regexp: пакет входит в путь запроса, а формат маски
// известен и прост — скобки, заглавные буквы, подчёркивание и номер.
func placeholders(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '[' {
			continue
		}
		end := strings.IndexByte(s[i:], ']')
		if end < 0 {
			break
		}
		end += i
		if body := s[i+1 : end]; isPlaceholderBody(body) {
			out = append(out, s[i:end+1])
		}
		i = end
	}
	return out
}

// isPlaceholderBody проверяет содержимое скобок: основа типа, подчёркивание и
// номер. Строчные буквы и пробелы отвергаются — так обычный текст в скобках
// не принимается за маску.
func isPlaceholderBody(b string) bool {
	under := strings.LastIndexByte(b, '_')
	if under <= 0 || under == len(b)-1 {
		return false
	}
	for i := 0; i < under; i++ {
		switch c := b[i]; {
		case c == '_', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c >= 0x80: // байты кириллицы в UTF-8
		default:
			return false
		}
	}
	for i := under + 1; i < len(b); i++ {
		if b[i] < '0' || b[i] > '9' {
			return false
		}
	}
	return true
}
