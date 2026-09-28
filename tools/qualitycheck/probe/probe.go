// Package probe — клиент контракта POST /process.
//
// Клиент намеренно минимален и не знает ни про стратегии маскирования, ни про
// формат плейсхолдеров: эталонной маски не существует (07-clarifications.md
// §7.1), и любое знание о внутреннем формате превратило бы измерение качества
// в сверку кода с самим собой.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxRetries — сколько раз повторять запрос, получивший 429.
// Проверяющая система ведёт себя так же: 429 ошибкой не считается, но ответ
// нужно всё-таки получить, иначе запись выпадет из выборки (07-clarifications §7.2).
const maxRetries = 3

// defaultRetryAfter — пауза, если сервис не прислал разборчивый Retry-After.
const defaultRetryAfter = time.Second

// minRetryAfter — пауза, когда сервис попросил повторить немедленно.
// Совсем без паузы повтор превратился бы в busy-loop по перегруженному сервису.
const minRetryAfter = 50 * time.Millisecond

// Client — HTTP-клиент сервиса.
type Client struct {
	baseURL string
	hc      *http.Client
}

// New создаёт клиента. timeout — предел на один запрос; по умолчанию 10 с,
// как в официальной проверке.
func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		hc: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        512,
				MaxIdleConnsPerHost: 512,
				MaxConnsPerHost:     0,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

type processRequest struct {
	Payload   string `json:"payload"`
	PayloadID string `json:"payload_id"`
}

type processResponse struct {
	Result string `json:"result"`
}

// Process выполняет один шаг автомата: прямой при первом обращении с этим
// payloadID, обратный — при повторном с выданной маской.
//
// Тело запроса в текст ошибки не попадает: в нём персональные данные.
func (c *Client) Process(ctx context.Context, payloadID, payload string) (string, error) {
	body, err := json.Marshal(processRequest{Payload: payload, PayloadID: payloadID})
	if err != nil {
		return "", fmt.Errorf("payload_id %s: сборка запроса: %w", payloadID, err)
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		res, retryAfter, err := c.once(ctx, payloadID, body)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if retryAfter <= 0 {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(retryAfter):
		}
	}
	return "", fmt.Errorf("payload_id %s: исчерпаны повторы после 429: %w", payloadID, lastErr)
}

// once делает один запрос. Ненулевая пауза во втором возвращаемом значении
// означает «повторить»; ноль — окончательный отказ.
func (c *Client) once(ctx context.Context, payloadID string, body []byte) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/process", bytes.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("payload_id %s: сборка запроса: %w", payloadID, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("payload_id %s: запрос не выполнен: %w", payloadID, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", retryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("payload_id %s: сервис ответил 429", payloadID)
	}
	if resp.StatusCode != http.StatusOK {
		// Тело ответа на ошибку не пересказываем: сервис не обязан быть
		// свободным от данных запроса, а отчёт обязан.
		return "", 0, fmt.Errorf("payload_id %s: код ответа %d", payloadID, resp.StatusCode)
	}

	var out processResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("payload_id %s: разбор ответа: %w", payloadID, err)
	}
	return out.Result, 0, nil
}

func retryAfter(h string) time.Duration {
	if h == "" {
		return defaultRetryAfter
	}
	sec, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || sec < 0 {
		return defaultRetryAfter
	}
	if sec == 0 {
		return minRetryAfter
	}
	return time.Duration(sec) * time.Second
}

// Service — сведения о сервисе для шапки отчёта: без версии правил прогоны
// несравнимы так же, как без версии корпуса.
type Service struct {
	URL          string   `json:"url"`
	Version      string   `json:"version"`
	ConfigLoaded string   `json:"config_loaded_at"`
	Consumers    []string `json:"consumers"`
	Scanners     []string `json:"scanners"`
}

type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type readyResponse struct {
	ConfigLoaded string   `json:"config_loaded_at"`
	Consumers    []string `json:"consumers"`
	Scanners     []string `json:"scanners"`
}

// Describe читает /healthz и /readyz. Отказ не останавливает прогон: отчёт
// просто зафиксирует, что версия правил не получена.
func (c *Client) Describe(ctx context.Context) (Service, error) {
	s := Service{URL: c.baseURL}
	var h healthResponse
	if err := c.getJSON(ctx, "/healthz", &h); err != nil {
		return s, err
	}
	s.Version = h.Version

	var r readyResponse
	if err := c.getJSON(ctx, "/readyz", &r); err != nil {
		return s, err
	}
	s.ConfigLoaded, s.Consumers, s.Scanners = r.ConfigLoaded, r.Consumers, r.Scanners
	return s, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("%s: сборка запроса: %w", path, err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s: запрос не выполнен: %w", path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: код ответа %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s: разбор ответа: %w", path, err)
	}
	return nil
}
