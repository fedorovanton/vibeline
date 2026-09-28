# Контракт вызова ИИ-модели AlfaGen (Enterprise Vibe Coding)

Документ описывает контракт вызова корпоративной ИИ-модели AlfaGen, которую
решение использует для генерации текста/кода.

> ✅ **Статус контракта: подтверждён живым запросом (OpenAI-совместимый).**
> Контракт проверен реальным запросом через `check.sh` и curl:
> - `GET /v1/models` → `200`, возвращает модель `deepseek-ai/DeepSeek-V4-Flash-0731`.
> - `POST /v1/chat/completions` (ключ **без** `Bearer`) → `200`, OpenAI-совместимый
>   ответ с `choices[].message.content` и `usage`.
> - Заголовок `Authorization` с префиксом `Bearer` → `HTTP 400` (префикс не нужен).
> - Потоковый режим (`stream: true`) → SSE с `data:` чанками и завершающим `data: [DONE]`.

---

## 1. Общие сведения

| Параметр | Значение |
|----------|----------|
| Базовый URL | `https://alfagen.alfabank.ru/continue-dev/` |
| Альтернативный URL | `https://alfagen.alfabank.ru/continue-dev/v1` |
| Модель | `deepseek-ai/DeepSeek-V4-Flash-0731` |
| Протокол | OpenAI-совместимый (REST + JSON) |
| Порт | 443 (HTTPS) |
| Провайдер | AlfaGen (Альфа-Банк), раздел «Enterprise Vibe Coding» |

Ключ доступа выдаётся на портале `https://alfagen.alfabank.ru/` (раздел
«Enterprise Vibe Coding»).

---

## 2. Авторизация

Авторизация выполняется через HTTP-заголовок `Authorization`.

> ⚠️ **Важно:** в поле `apiKey` **НЕ добавляется** префикс `Bearer` — передаётся
> только сам ключ. Это указано в официальной инструкции подключения
> (`docs/context/06-environment.md`).

```
Authorization: <API_KEY>
```

Пример:

```
Authorization: sk-alfagen-xxxxxxxxxxxxxxxx
```

> 🔒 Никогда не храните ключ в коде или в git. Основной способ — файл `.env`
> в корне репозитория (игнорируется git, см. `.gitignore`): пользователь кладёт
> ключ в `.env`, и решение работает на любом ПК. Альтернатива — переменная
> окружения `ALFAGEN_API_KEY`. Пример — в `.env.example`.

---

## 3. Эндпоинты

### 3.1. Список моделей

```
GET {base}/v1/models
```

Пример:

```
GET https://alfagen.alfabank.ru/continue-dev/v1/models
```

Ожидаемый ответ (OpenAI-совместимый):

```json
{
  "object": "list",
  "data": [
    {
      "id": "deepseek-ai/DeepSeek-V4-Flash-0731",
      "object": "model",
      "created": 0,
      "owned_by": "alfagen"
    }
  ]
}
```

### 3.2. Чат-завершение (chat completion)

```
POST {base}/v1/chat/completions
```

Пример:

```
POST https://alfagen.alfabank.ru/continue-dev/v1/chat/completions
```

---

## 4. Схема запроса `POST /v1/chat/completions`

### 4.1. Заголовки

| Заголовок | Значение |
|-----------|----------|
| `Authorization` | `<API_KEY>` (без `Bearer`) |
| `Content-Type` | `application/json` |

### 4.2. Тело запроса

```json
{
  "model": "deepseek-ai/DeepSeek-V4-Flash-0731",
  "messages": [
    { "role": "system", "content": "Ты — ассистент." },
    { "role": "user", "content": "Привет!" }
  ],
  "temperature": 0.7,
  "max_tokens": 1024,
  "top_p": 1,
  "stream": false
}
```

### 4.3. Поля запроса

| Поле | Тип | Обязательное | Описание |
|------|-----|--------------|----------|
| `model` | string | да | Идентификатор модели, напр. `deepseek-ai/DeepSeek-V4-Flash-0731` |
| `messages` | array | да | Массив сообщений диалога |
| `messages[].role` | string | да | `system` \| `user` \| `assistant` |
| `messages[].content` | string | да | Текст сообщения |
| `temperature` | number | нет | Креативность (0–2), дефолт ~0.7 |
| `top_p` | number | нет | Ядерная выборка (0–1), дефолт ~1 |
| `max_tokens` | integer | нет | Максимум токенов в ответе |
| `stream` | boolean | **да** | Потоковая передача (SSE). ❗ Проверено 22.09.2026: без этого поля сервер отвечает HTTP 400, хотя в исходном описании оно числилось необязательным. Отправлять всегда, включая `false` |

> Поля `temperature`, `top_p`, `max_tokens`, `stream` — стандартные для
> OpenAI-совместимых API. Точный набор поддерживаемых параметров уточняется
> реальным запросом.

---

## 5. Схема ответа

### 5.1. Непотоковый ответ (`stream: false`)

```json
{
  "id": "chatcmpl-xxxxxxxx",
  "object": "chat.completion",
  "created": 1727000000,
  "model": "deepseek-ai/DeepSeek-V4-Flash-0731",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Привет! Чем могу помочь?"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 12,
    "completion_tokens": 8,
    "total_tokens": 20
  }
}
```

### 5.2. Потоковый ответ (`stream: true`, SSE)

Ответ передаётся как поток `text/event-stream`. Каждое событие — строка
`data: {json}`. Последнее событие — `data: [DONE]`.

```
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}

data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Привет"},"finish_reason":null}]}

data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

---

## 6. Обработка ошибок

При ошибке API возвращает HTTP-статус и JSON-тело (OpenAI-совместимый формат):

```json
{
  "error": {
    "message": "Описание ошибки",
    "type": "invalid_request_error",
    "code": "invalid_api_key"
  }
}
```

| HTTP-статус | Значение | Типичная причина |
|-------------|----------|------------------|
| `200` | Успех | — |
| `400` | Некорректный запрос | Невалидный JSON, отсутствует `model`/`messages` |
| `401` | Не авторизован | Отсутствует/неверный `Authorization` |
| `403` | Доступ запрещён | Ключ не имеет прав на модель |
| `404` | Не найдено | Неверный путь или модель |
| `429` | Слишком много запросов | Превышен rate limit |
| `500` | Внутренняя ошибка | Ошибка на стороне сервера |
| `503` | Сервис недоступен | Временная недоступность |

> ✅ Проверено живым запросом: без ключа эндпоинты возвращают `HTTP 401` с пустым
> JSON-телом (`content-length: 0`). С ключом без префикса `Bearer` — `200`.
> С префиксом `Bearer` — `HTTP 400`.

---

## 7. Лимиты

Из конфигурации OpenCode (`docs/context/06-environment.md`):

| Лимит | Значение |
|-------|----------|
| Контекст (context) | 1 000 000 токенов |
| Выход (output) | 30 000 токенов |

Точные лимиты запросов в минуту (RPM) и токенов в минуту (TPM) уточняются у
поддержки хакатона.

---

## 8. Примеры вызова

### 8.1. curl

```bash
curl -sS https://alfagen.alfabank.ru/continue-dev/v1/chat/completions \
  -H "Authorization: ${ALFAGEN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-ai/DeepSeek-V4-Flash-0731",
    "messages": [
      { "role": "system", "content": "Ты — ассистент." },
      { "role": "user", "content": "Привет!" }
    ],
    "temperature": 0.7,
    "max_tokens": 1024,
    "stream": false
  }'
```

### 8.2. Go (стандартная библиотека `net/http`)

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// ChatRequest — тело запроса к /v1/chat/completions.
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatResponse — тело ответа (непотокового).
type ChatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int `json:"index"`
		Message      Message `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func main() {
	apiKey := os.Getenv("ALFAGEN_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "ошибка: переменная ALFAGEN_API_KEY не задана")
		os.Exit(1)
	}

	baseURL := os.Getenv("ALFAGEN_BASE_URL")
	if baseURL == "" {
		baseURL = "https://alfagen.alfabank.ru/continue-dev/v1"
	}
	model := os.Getenv("ALFAGEN_MODEL")
	if model == "" {
		model = "deepseek-ai/DeepSeek-V4-Flash-0731"
	}

	reqBody := ChatRequest{
		Model: model,
		Messages: []Message{
			{Role: "system", Content: "Ты — ассистент."},
			{Role: "user", Content: "Привет!"},
		},
		Temperature: 0.7,
		MaxTokens:   1024,
		Stream:      false,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка сериализации:", err)
		os.Exit(1)
	}

	url := baseURL + "/chat/completions"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка создания запроса:", err)
		os.Exit(1)
	}
	// ВАЖНО: без префикса "Bearer" — только сам ключ.
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка сети:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка чтения ответа:", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "HTTP %d: %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка разбора ответа:", err)
		os.Exit(1)
	}

	if len(chatResp.Choices) > 0 {
		fmt.Println(chatResp.Choices[0].Message.Content)
	}
}
```

### 8.3. Go (популярный клиент — `github.com/sashabaranov/go-openai`)

```go
package main

import (
	"context"
	"fmt"
	"os"

	openai "github.com/sashabaranov/go-openai"
)

func main() {
	apiKey := os.Getenv("ALFAGEN_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "ошибка: переменная ALFAGEN_API_KEY не задана")
		os.Exit(1)
	}

	baseURL := os.Getenv("ALFAGEN_BASE_URL")
	if baseURL == "" {
		baseURL = "https://alfagen.alfabank.ru/continue-dev/v1"
	}
	model := os.Getenv("ALFAGEN_MODEL")
	if model == "" {
		model = "deepseek-ai/DeepSeek-V4-Flash-0731"
	}

	// ВАЖНО: клиент сам добавит "Bearer " к ключу. Если AlfaGen требует
	// ключ без префикса, используйте стандартную библиотеку net/http
	// (см. пример 8.2) или настройте кастомный транспорт.
	client := openai.NewClientWithConfig(openai.ClientConfig{
		BaseURL: baseURL,
		APIType: openai.APITypeOpenAI,
		// AuthToken: apiKey, // при необходимости
	})

	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "Ты — ассистент."},
			{Role: openai.ChatMessageRoleUser, Content: "Привет!"},
		},
		Temperature: 0.7,
		MaxTokens:   1024,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка вызова:", err)
		os.Exit(1)
	}

	if len(resp.Choices) > 0 {
		fmt.Println(resp.Choices[0].Message.Content)
	}
}
```

> ⚠️ Клиент `go-openai` по умолчанию добавляет префикс `Bearer`. Поскольку
> AlfaGen требует ключ **без** префикса, для продакшена предпочтителен пример
> на стандартной библиотеке `net/http` (8.2), где заголовок задаётся вручную.

---

## 9. Проверка работоспособности

Используйте скрипт [`check.sh`](./check.sh):

```bash
export ALFAGEN_API_KEY="ваш_ключ"
bash specs/api-alfagen/check.sh
```

Скрипт выполняет тестовый chat-completion запрос и выводит ответ модели.
Подробности — в самом скрипте и в [`README.md`](./README.md).

---

## 10. Чек-лист перед использованием

- [ ] Установлен корневой сертификат «Russian Trusted Root CA» (см. `docs/context/06-environment.md`).
- [ ] Ключ получен на портале AlfaGen (раздел «Enterprise Vibe Coding»).
- [ ] Ключ хранится в `ALFAGEN_API_KEY` (не в коде, не в git).
- [ ] Заголовок `Authorization` содержит ключ **без** префикса `Bearer`.
- [x] Контракт проверен реальным запросом через `check.sh` (подтверждён).