// Package llm — клиент OpenAI-совместимой модели AlfaGen.
//
// Пакет ничего не знает о персональных данных: он получает уже защищённый
// текст и отправляет его наружу. Решение о том, что текст можно выпускать,
// принимается выше — в gateway.Proxy, где перечислены предусловия выпуска.
//
// Ни ключ доступа, ни тело запроса не попадают в текст ошибок: сообщения
// описывают класс проблемы и код ответа, но не содержимое.
package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Message — одно сообщение диалога.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Request — тело запроса POST /v1/chat/completions.
//
// Поля temperature и top_p — указатели: ноль является допустимым значением и
// должен отличаться от «параметр не задан».
type Request struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature *float64  `json:"temperature,omitempty"`
	TopP        *float64  `json:"top_p,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	// Stream сериализуется всегда, без omitempty. Контракт помечает поле
	// необязательным, но AlfaGen отвечает HTTP 400 на запрос без него —
	// проверено побитовым перебором полей 22.09.2026. Со значением false
	// omitempty выбросил бы поле и сломал каждый вызов.
	Stream bool `json:"stream"`
}

// Choice — один вариант ответа модели.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason,omitempty"`
}

// Usage — счётчики токенов, как их вернула модель.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Response — непотоковый ответ модели.
type Response struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Chatter — downstream-модель.
//
// Интерфейс позволяет подменить реальный вызов детерминированной заглушкой и
// проверить конвейер защиты без сети.
type Chatter interface {
	Chat(ctx context.Context, req Request) (*Response, error)
}

// ErrNoAPIKey возвращается, когда ключ доступа к модели не задан.
var ErrNoAPIKey = errors.New("llm: ключ доступа к модели не задан")

// FailureClass — класс отказа обращения к модели.
//
// Перечень закрытый и потому пригоден и для журнала, и для метки метрики:
// значения не зависят ни от текста ошибки библиотеки, ни от содержимого
// запроса, и их кардинальность ограничена.
type FailureClass string

const (
	// ClassStatus — сервер ответил, но кодом, отличным от 200. Конкретный код
	// лежит в Failure.Status.
	ClassStatus FailureClass = "http_status"
	// ClassTimeout — ответа не дождались: истёк дедлайн вызова.
	ClassTimeout FailureClass = "timeout"
	// ClassTLS — не прошла проверка сертификата или рукопожатие TLS. Именно
	// этот класс отличает «в образе нет корневых сертификатов» от «неверный
	// ключ доступа»: 22.09.2026 их пришлось различать вручную около часа.
	ClassTLS FailureClass = "tls"
	// ClassDNS — имя хоста модели не разрешилось.
	ClassDNS FailureClass = "dns"
	// ClassConnect — соединение не установлено: отказ, сброс, нет маршрута.
	ClassConnect FailureClass = "connect"
	// ClassNetwork — прочий сетевой отказ, не попавший в классы выше.
	ClassNetwork FailureClass = "network"
	// ClassCanceled — вызов прерван вызывающей стороной.
	ClassCanceled FailureClass = "canceled"
	// ClassResponse — ответ получен, но непригоден: не прочитан, не разобран
	// или не содержит ни одного варианта.
	ClassResponse FailureClass = "bad_response"
	// ClassRequest — запрос не удалось собрать: до сети дело не дошло.
	ClassRequest FailureClass = "bad_request"
	// ClassUnknown — источник отказа неизвестен: ошибку вернул не этот клиент.
	ClassUnknown FailureClass = "unknown"
)

// Failure — причина отказа обращения к модели.
//
// Значение пригодно для журнала целиком: в нём есть класс отказа, код ответа
// и краткое описание, но нет ни ключа доступа, ни тела запроса, ни тела
// ответа. Тело ответа не читается в причину сознательно: модель может
// отразить в нём фрагмент запроса, а вместе с ним персональные данные.
//
// Err заполняется только для отказов транспорта и отмены контекста — их текст
// приходит из сетевого стека, где тела ответа ещё нет. Ошибки разбора ответа
// в Err не попадают: сообщение json умеет цитировать разбираемые байты.
type Failure struct {
	// Class — класс отказа.
	Class FailureClass
	// Status — код ответа модели. Ноль означает, что ответа не было.
	Status int
	// Reason — краткое описание причины для журнала и стенда.
	Reason string
	// Err — исходная ошибка транспорта, если она безопасна для показа.
	Err error
}

// Error собирает сообщение: описание, класс и код ответа.
func (f *Failure) Error() string {
	var b strings.Builder
	b.Grow(96)
	b.WriteString("llm: ")
	b.WriteString(f.Reason)
	b.WriteString(" (класс ")
	b.WriteString(string(f.Class))
	if f.Status > 0 {
		b.WriteString(", код ответа ")
		b.WriteString(strconv.Itoa(f.Status))
	}
	b.WriteByte(')')
	if f.Status == 0 && f.Err != nil {
		b.WriteString(": ")
		b.WriteString(f.Err.Error())
	}
	return b.String()
}

// Unwrap открывает исходную ошибку для errors.Is и errors.As: вызывающий код
// должен уметь отличить отмену контекста от сетевого отказа.
func (f *Failure) Unwrap() error { return f.Err }

// Classify извлекает причину отказа из ошибки вызова модели.
//
// Функция никогда не оставляет класс пустым: ошибка чужой реализации Chatter
// получает класс unknown, и запись журнала остаётся заполненной при любом
// источнике отказа. Нулевое значение возвращается только для nil.
func Classify(err error) Failure {
	if err == nil {
		return Failure{}
	}
	var f *Failure
	if errors.As(err, &f) && f != nil {
		return *f
	}
	if class, reason, ok := classifyContext(err); ok {
		return Failure{Class: class, Reason: reason, Err: err}
	}
	if class, reason, ok := classifyTransport(err); ok {
		return Failure{Class: class, Reason: reason, Err: err}
	}
	// Текст чужой ошибки в причину не переносится: он мог быть собран из
	// содержимого запроса или ответа.
	return Failure{Class: ClassUnknown, Reason: "модель не ответила"}
}

// classifyContext отделяет отмену вызывающей стороной от исчерпанного дедлайна.
func classifyContext(err error) (FailureClass, string, bool) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ClassTimeout, "истекло время ожидания ответа модели", true
	case errors.Is(err, context.Canceled):
		return ClassCanceled, "вызов модели прерван вызывающей стороной", true
	default:
		return "", "", false
	}
}

// classifyTransport определяет класс сетевого отказа.
//
// Порядок проверок значим. Отказ проверки сертификата приходит завёрнутым в
// ошибку рукопожатия, а часть сетевых ошибок одновременно являются net.Error
// с признаком таймаута — поэтому конкретные классы проверяются раньше общих.
func classifyTransport(err error) (FailureClass, string, bool) {
	var (
		certErr *tls.CertificateVerificationError
		recErr  tls.RecordHeaderError
		alert   tls.AlertError
		authErr x509.UnknownAuthorityError
		hostErr x509.HostnameError
		invErr  x509.CertificateInvalidError
		dnsErr  *net.DNSError
		netErr  net.Error
		opErr   *net.OpError
	)
	switch {
	case errors.As(err, &certErr), errors.As(err, &authErr),
		errors.As(err, &hostErr), errors.As(err, &invErr):
		return ClassTLS, "отказ проверки сертификата модели", true
	case errors.As(err, &recErr), errors.As(err, &alert):
		return ClassTLS, "отказ рукопожатия TLS с моделью", true
	case errors.As(err, &dnsErr):
		if dnsErr.IsTimeout {
			return ClassDNS, "разрешение имени хоста модели не завершилось", true
		}
		return ClassDNS, "имя хоста модели не разрешилось", true
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EPIPE):
		return ClassConnect, "соединение с моделью не установлено", true
	case errors.As(err, &netErr) && netErr.Timeout():
		return ClassTimeout, "истекло время ожидания ответа модели", true
	case errors.As(err, &opErr):
		if opErr.Op == "dial" {
			return ClassConnect, "соединение с моделью не установлено", true
		}
		return ClassNetwork, "сетевой отказ при обращении к модели", true
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return ClassNetwork, "модель разорвала соединение до ответа", true
	default:
		return "", "", false
	}
}

// transportFailure собирает причину для ошибки, пришедшей из транспорта.
//
// В отличие от Classify, здесь известно, что ошибка сетевая, поэтому
// нераспознанный случай получает класс network, а не unknown.
func transportFailure(err error) *Failure {
	class, reason, ok := classifyTransport(err)
	if !ok {
		class, reason = ClassNetwork, "сетевой отказ при обращении к модели"
	}
	return &Failure{Class: class, Reason: reason, Err: err}
}

// statusReason называет причину отказа по коду ответа.
//
// Описание не пересказывает тело ответа: оно выводится только из кода. Самые
// частые на разборе случаи названы отдельно — иначе «модель ответила отказом»
// одинаково звучит и для просроченного ключа, и для превышенной квоты.
func statusReason(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "модель отклонила запрос"
	case http.StatusUnauthorized:
		return "модель не приняла ключ доступа"
	case http.StatusForbidden:
		return "модель отказала в доступе"
	case http.StatusNotFound:
		return "адрес модели не найден"
	case http.StatusRequestTimeout:
		return "модель прервала запрос по таймауту"
	case http.StatusRequestEntityTooLarge:
		return "модель отклонила запрос по размеру"
	case http.StatusTooManyRequests:
		return "модель ограничила частоту обращений"
	}
	if code >= 500 {
		return "модель ответила ошибкой"
	}
	return "модель ответила отказом"
}

// Options — настройки клиента.
type Options struct {
	// BaseURL — базовый адрес вида https://host/continue-dev/v1.
	BaseURL string
	// Model — идентификатор модели по умолчанию.
	Model string
	// APIKey — ключ доступа. Читается из переменной окружения вызывающим
	// кодом и никогда не попадает ни в конфигурацию, ни в логи.
	APIKey string
	// Timeout — предельное время всего вызова, включая повторы.
	Timeout time.Duration
	// MaxAttempts — бюджет попыток, включая первую.
	MaxAttempts int
	// BaseBackoff — задержка перед второй попыткой; далее удваивается.
	BaseBackoff time.Duration
	// MaxBackoff ограничивает рост задержки.
	MaxBackoff time.Duration
	// Transport подменяет транспорт. Предназначено для тестов.
	Transport http.RoundTripper
}

// Значения по умолчанию для настроек, не заданных явно.
const (
	defaultTimeout     = 60 * time.Second
	defaultMaxAttempts = 3
	defaultBaseBackoff = 200 * time.Millisecond
	defaultMaxBackoff  = 2 * time.Second
	// maxResponseBytes ограничивает объём читаемого ответа: модель за
	// границей доверия, и её ответ не должен уметь исчерпать память.
	maxResponseBytes = 8 << 20
	// maxDrainBytes — сколько байт тела дочитывается перед закрытием, чтобы
	// соединение вернулось в пул. Содержимое при этом не используется.
	maxDrainBytes = 32 << 10
)

// Client — клиент чат-завершений AlfaGen.
//
// Экземпляр переиспользуется между запросами: транспорт держит пул соединений
// и keep-alive, поэтому на каждый запрос не выполняется новое рукопожатие TLS.
// Значение безопасно для конкурентного использования.
type Client struct {
	endpoint string
	model    string
	apiKey   string
	timeout  time.Duration
	attempts int
	backoff  time.Duration
	maxWait  time.Duration
	http     *http.Client
}

// New собирает клиента и проверяет настройки.
func New(o Options) (*Client, error) {
	if o.BaseURL == "" {
		return nil, errors.New("llm: не задан базовый адрес модели")
	}
	u, err := url.Parse(o.BaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("llm: некорректный базовый адрес модели %q", o.BaseURL)
	}
	if o.APIKey == "" {
		return nil, ErrNoAPIKey
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = defaultMaxAttempts
	}
	if o.BaseBackoff <= 0 {
		o.BaseBackoff = defaultBaseBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = defaultMaxBackoff
	}

	tr := o.Transport
	if tr == nil {
		tr = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	}

	return &Client{
		endpoint: strings.TrimSuffix(o.BaseURL, "/") + "/chat/completions",
		model:    o.Model,
		apiKey:   o.APIKey,
		timeout:  o.Timeout,
		attempts: o.MaxAttempts,
		backoff:  o.BaseBackoff,
		maxWait:  o.MaxBackoff,
		// Таймаут задаётся контекстом, а не http.Client.Timeout: бюджет
		// должен покрывать все попытки целиком, а не каждую по отдельности.
		http: &http.Client{Transport: tr},
	}, nil
}

// Endpoint возвращает адрес, на который уходят запросы. Ключа в нём нет.
func (c *Client) Endpoint() string { return c.endpoint }

// Chat выполняет чат-завершение.
//
// Контекст пробрасывается в транспорт: отмена вызывающей стороной немедленно
// прекращает работу и повторы. Поверх контекста ставится собственный дедлайн
// из настроек — он ограничивает весь вызов, включая повторы.
func (c *Client) Chat(ctx context.Context, req Request) (*Response, error) {
	// Модель задаёт конфигурация, а не клиент: стандартные OpenAI-клиенты
	// всегда передают своё имя модели («gpt-4o»), AlfaGen отвечает на чужое
	// имя 422, и прокси отдавал 502 «модель недоступна» (замечено при
	// проверке публичного адреса 23.09). Потребитель выбирает не модель, а
	// политику защиты.
	req.Model = c.model
	// Потоковый режим клиентом не поддерживается: ответ демаскируется целиком,
	// а поток пришлось бы буферизовать до конца, теряя смысл потока.
	req.Stream = false

	body, err := json.Marshal(req)
	if err != nil {
		// Текст ошибки json может содержать значения полей, поэтому наружу
		// отдаётся только класс проблемы.
		return nil, &Failure{Class: ClassRequest, Reason: "запрос к модели не сериализован"}
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var last error
	for attempt := 1; ; attempt++ {
		resp, hint, err := c.do(ctx, body)
		if err == nil {
			return resp, nil
		}
		last = err
		if !hint.allowed || attempt >= c.attempts {
			break
		}
		// Повтор допустим только для идемпотентного исхода: сетевой сбой или
		// временный отказ сервера. Ждём с экспоненциальной задержкой и не
		// выходим за общий дедлайн вызова.
		if err := sleepCtx(ctx, c.delay(attempt, hint.after)); err != nil {
			break
		}
	}
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(ctxErr, context.DeadlineExceeded) {
		// Класс отказа — таймаут, даже если последняя попытка сорвалась иначе:
		// решающим оказался исчерпанный бюджет вызова. Причина последней
		// попытки остаётся доступной через errors.As — кроме случая, когда она
		// сама была таймаутом: повторять её текст в сообщении незачем.
		f := &Failure{
			Class:  ClassTimeout,
			Reason: fmt.Sprintf("модель не ответила за %s", c.timeout),
			Err:    last,
		}
		if Classify(last).Class == ClassTimeout {
			f.Err = context.DeadlineExceeded
		}
		return nil, f
	}
	return nil, last
}

// hint — решение о повторе после неудачной попытки.
type hint struct {
	// allowed — повтор имеет смысл: сбой временный и операция идемпотентна.
	allowed bool
	// after — пауза, запрошенная сервером через Retry-After. Ноль означает,
	// что сервер её не назвал и решает собственная оценка клиента.
	after time.Duration
}

var (
	retryNo  = hint{}
	retryYes = hint{allowed: true}
)

// Заголовки исходящего запроса к модели.
const (
	headerAuthorization = "Authorization"
	mimeJSON            = "application/json"
)

// do выполняет одну попытку. Второе возвращаемое значение сообщает, имеет ли
// смысл повтор: сетевой сбой и коды 429, 502, 503, 504 — временные, коды
// 400, 401, 403 повтор не исправит.
func (c *Client) do(ctx context.Context, body []byte) (*Response, hint, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, retryNo, &Failure{Class: ClassRequest, Reason: "запрос к модели не собран"}
	}
	// Ключ передаётся без префикса Bearer: с префиксом AlfaGen отвечает 400.
	// Это подтверждено живым запросом и зафиксировано в контракте.
	httpReq.Header.Set(headerAuthorization, c.apiKey)
	httpReq.Header.Set("Content-Type", mimeJSON)
	httpReq.Header.Set("Accept", mimeJSON)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			// Отмена или исчерпанный дедлайн: повторять нечего.
			class, reason, _ := classifyContext(ctx.Err())
			return nil, retryNo, &Failure{Class: class, Reason: reason, Err: ctx.Err()}
		}
		// Класс сетевого отказа определяется здесь и дальше не теряется:
		// таймаут, отказ проверки сертификата, отказ разрешения имени и отказ
		// соединения в журнале различимы.
		return nil, retryYes, transportFailure(unwrapURLError(err))
	}
	// Ошибка закрытия тела для вызывающего ничего не меняет: ответ уже
	// прочитан или отвергнут.
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Тело ошибки не читается в сообщение: модель могла отразить в нём
		// фрагмент запроса. Дочитываем ограниченный объём, чтобы соединение
		// вернулось в пул, и сообщаем только код.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
		h := hint{allowed: retryableStatus(resp.StatusCode)}
		if h.allowed {
			if d, ok := retryAfter(resp.Header); ok {
				h.after = d
			}
		}
		return nil, h, &Failure{
			Class:  ClassStatus,
			Status: resp.StatusCode,
			Reason: statusReason(resp.StatusCode),
		}
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, retryYes, &Failure{
			Class:  ClassResponse,
			Status: resp.StatusCode,
			Reason: "ответ модели не прочитан целиком",
		}
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		// Разбор не удался — повтор не поможет, формат ответа не изменится.
		// Ошибка json не оборачивается: её текст цитирует разбираемые байты,
		// то есть тело ответа модели.
		return nil, retryNo, &Failure{
			Class:  ClassResponse,
			Status: resp.StatusCode,
			Reason: "ответ модели не является корректным JSON",
		}
	}
	if len(out.Choices) == 0 {
		return nil, retryNo, &Failure{
			Class:  ClassResponse,
			Status: resp.StatusCode,
			Reason: "ответ модели не содержит ни одного варианта",
		}
	}
	return &out, retryNo, nil
}

// retryableStatus сообщает, имеет ли смысл повтор при данном коде ответа.
//
// Список закрытый: 400, 401 и 403 означают, что повтор даст тот же результат,
// а лишние попытки только удлинят ответ клиенту.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// delay вычисляет паузу перед следующей попыткой.
//
// Если сервер прислал Retry-After, он важнее собственной оценки: игнорировать
// явное указание rate-limiter'а означает получить следующий отказ. Джиттер не
// добавляется: клиент один, эффект стада ему не грозит, а детерминированная
// задержка делает поведение воспроизводимым в тестах.
func (c *Client) delay(attempt int, after time.Duration) time.Duration {
	d := c.backoff << (attempt - 1)
	if d > c.maxWait || d <= 0 {
		d = c.maxWait
	}
	if after > d {
		d = after
	}
	return d
}

// sleepCtx ждёт d, прекращая ожидание по отмене контекста.
//
// Если до дедлайна осталось меньше d, ждать бессмысленно: попытка всё равно
// не успеет, и вызывающий код получит отказ раньше.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= d {
		return context.DeadlineExceeded
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// unwrapURLError убирает из сообщения обёртку *url.Error с полным адресом.
//
// Адрес сам по себе секретом не является, но в сообщения об ошибках попадает
// только то, что туда попасть обязано: класс сбоя.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// retryAfter разбирает заголовок Retry-After в секундах.
//
// Формат с датой не поддерживается сознательно: AlfaGen отдаёт секунды, а
// разбор даты добавил бы зависимость от часов сервера.
func retryAfter(h http.Header) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}
