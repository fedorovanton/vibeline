package gateway

// Общие фикстуры и хелперы тестов пакета. Все значения — синтетические:
// реальные персональные данные в репозиторий не попадают.

import (
	"context"
	"errors"
	"testing"

	"ai-gateway/internal/llm"
	"ai-gateway/internal/policy"
)

// Стратегии, роли и потребители.
const (
	strategyPlaceholder = "placeholder"
	strategyAsterisks   = "asterisks"
	strategyToken       = "token"

	roleUser      = "user"
	roleAssistant = "assistant"

	consumerCRM   = "crm"
	consumerOther = "other"
	testModelName = "test-model"
	testAPIKey    = "sk-test-0000000000000000"
)

// Идентификаторы корреляции.
const (
	testID1  = "id-1"
	sharedID = "shared-id"
	oldID    = "id-old"
	limitID  = "limit-1"
)

// Синтетические значения ПД и тексты с ними.
const (
	surnameIvanov     = "Иванов"
	stubWordIvanov    = "иванов"
	fioIvanov         = "Иванов Иван Иванович"
	fioPetrov         = "Петров Пётр Петрович"
	clientIvanov      = "Клиент Иванов Иван Иванович"
	clientPetrov      = "Клиент Петров Пётр Петрович"
	clientIvanovShort = "Клиент Иванов"
	clientIvanovEmail = "Клиент Иванов Иван Иванович, почта ivanov@example.test"
	emailIvanov       = "ivanov@example.test"
	placeholderFIO1   = "[ФИО_1]"
	tokenPrefix       = "{{pii:"
	cvvValue          = "123"
	pinValue          = "1234"
	replyAnswer       = "ответ"
	// badByte — байт, недопустимый в UTF-8.
	badByte = "\xff"
)

// Форматы сообщений о провале, повторяющиеся в нескольких тестах.
const (
	fmtStoreFull   = "ожидалась store.ErrFull, получено %v"
	fmtRestoredAs  = "восстановлено %q вместо %q"
	fmtSentToModel = "в модель ушло %q"
	fmtReply       = "ответ: %q"
	fmtBackward    = "обратный шаг: %v"
	fmtFailClosed  = "получена ошибка %v, ожидалась ErrFailClosed"
)

// userChat собирает запрос к модели из сообщений пользователя.
func userChat(msgs ...string) llm.Request {
	var req llm.Request
	for _, m := range msgs {
		req.Messages = append(req.Messages, llm.Message{Role: roleUser, Content: m})
	}
	return req
}

// userRequest — запрос прокси с областью id из сообщений пользователя.
func userRequest(id string, msgs ...string) ProxyRequest {
	return ProxyRequest{ID: id, Chat: userChat(msgs...)}
}

// mustProxy проксирует запрос и валит тест при любой ошибке.
func mustProxy(t *testing.T, svc *Service, model llm.Chatter, req ProxyRequest, c *policy.Consumer) ProxyResult {
	t.Helper()
	res, err := svc.Proxy(context.Background(), model, req, c)
	if err != nil {
		t.Fatalf("проксирование: %v", err)
	}
	return res
}

// replyOf — содержимое первого варианта ответа.
func replyOf(res ProxyResult) string {
	return res.Response.Choices[0].Message.Content
}

// mustForward выполняет прямой шаг /process и валит тест при ошибке.
func mustForward(t *testing.T, svc *Service, id, payload string, c *policy.Consumer) ProcessResult {
	t.Helper()
	res, err := svc.Process(context.Background(), id, payload, c)
	if err != nil {
		t.Fatalf("прямой шаг: %v", err)
	}
	return res
}

// mustBackward выполняет обратный шаг /process и валит тест при ошибке.
func mustBackward(t *testing.T, svc *Service, id, masked string, c *policy.Consumer) ProcessResult {
	t.Helper()
	res, err := svc.Process(context.Background(), id, masked, c)
	if err != nil {
		t.Fatalf(fmtBackward, err)
	}
	return res
}

// mustConsumer собирает потребителя и валит тест при ошибке конфигурации.
func mustConsumer(t *testing.T, base policy.Consumer, strategy string) *policy.Consumer {
	t.Helper()
	c, err := policy.NewConsumer(base, strategy, nil, nil)
	if err != nil {
		t.Fatalf("сборка потребителя: %v", err)
	}
	return c
}

// assertNoModelCalls — тест-перехватчик: фальшивая модель не получила ни
// одного запроса.
func assertNoModelCalls(t *testing.T, m *recordingModel) {
	t.Helper()
	if n := m.calls(); n != 0 {
		t.Fatalf("фальшивая модель получила %d запросов вместо нуля", n)
	}
}

// assertUpstream — ошибка относится к отказу модели.
func assertUpstream(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("получена ошибка %v, ожидалась ErrUpstream", err)
	}
}
