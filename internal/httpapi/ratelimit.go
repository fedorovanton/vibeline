package httpapi

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/obs"
)

// modelLimiter — лимит частоты обращений к модели по ключу потребителя
// (P4-8 раунда 4 жюри).
//
// Демонстрационные ключи опубликованы в README, и без лимита любой держатель
// ключа расходовал бы квоту AlfaGen команды и рисковал блокировкой ключа на
// время демонстрации. Лимит стоит только на маршрутах, которые вызывают
// модель: /v1/chat/completions и /api/v1/analyze. Контракт /process и явный
// API маскирования им не затронуты — ни проверкой, ни блокировкой.
//
// Алгоритм — token bucket: корзина ёмкостью burst восполняется со скоростью
// rps. Корзин две ступени (Б5-11 раунда 5 жюри):
//
//   - корзина клиента — пара «потребитель, адрес клиента» с лимитом из
//     конфигурации. Опубликованный ключ держат многие, и при одной корзине на
//     ключ посторонний выбирал бы её целиком и держал стенд на 429 во время
//     защиты;
//   - общая корзина потребителя — тот же лимит, умноженный на
//     modelAggregateFactor. Она ограничивает суммарный расход квоты AlfaGen по
//     ключу, сколько бы адресов его ни предъявляли.
//
// Запрос проходит, только если в обеих корзинах есть место; списывается из
// обеих сразу. Адрес — хост из RemoteAddr: перед сервисом нет доверенного
// прокси, и X-Forwarded-For подделывается клиентом. Число корзин клиентов
// ограничено modelClientBuckets: сверх него забываются корзины, которые уже
// восполнились до ёмкости, — их состояние неотличимо от новой корзины. Адрес
// клиента в журнал и метрики не попадает.
type modelLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

// modelAggregateFactor — во сколько раз общая корзина потребителя больше
// корзины одного клиента.
const modelAggregateFactor = 8

// modelClientBuckets — предел числа корзин клиентов в памяти.
const modelClientBuckets = 4096

// bucket — состояние одной корзины.
type bucket struct {
	tokens float64
	last   time.Time
}

func newModelLimiter() *modelLimiter {
	return &modelLimiter{buckets: make(map[string]*bucket, 8), now: time.Now}
}

// refill восполняет корзину на момент now и урезает остаток до ёмкости.
func (b *bucket) refill(now time.Time, rate config.RateLimit) {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * rate.RPS
	}
	b.last = now
	if limit := float64(rate.Burst); b.tokens > limit {
		b.tokens = limit
	}
}

// wait — пауза до появления в корзине следующего запроса.
func (b *bucket) wait(rate config.RateLimit) time.Duration {
	return time.Duration((1 - b.tokens) / rate.RPS * float64(time.Second))
}

// get возвращает корзину по ключу, заводя полную при первом обращении.
func (l *modelLimiter) get(key string, now time.Time, rate config.RateLimit) *bucket {
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(rate.Burst), last: now}
		l.buckets[key] = b
	}
	b.refill(now, rate)
	return b
}

// allow забирает по одному запросу из корзины клиента и из общей корзины
// потребителя.
//
// При отказе возвращает паузу до появления следующего запроса. Параметры
// лимита передаются при каждом вызове, а не запоминаются: после перезагрузки
// конфигурации по SIGHUP действует новый лимит, а накопленный остаток
// урезается до новой ёмкости.
func (l *modelLimiter) allow(consumerID, client string, rate config.RateLimit) (bool, time.Duration) {
	now := l.now()
	total := config.RateLimit{RPS: rate.RPS * modelAggregateFactor, Burst: rate.Burst * modelAggregateFactor}

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.buckets) > modelClientBuckets {
		l.sweep(now, rate)
	}
	own := l.get(consumerID+"\x00"+client, now, rate)
	all := l.get(consumerID, now, total)
	if own.tokens < 1 {
		return false, own.wait(rate)
	}
	if all.tokens < 1 {
		return false, all.wait(total)
	}
	own.tokens--
	all.tokens--
	return true, 0
}

// sweep забывает корзины клиентов, восполнившиеся до ёмкости.
func (l *modelLimiter) sweep(now time.Time, rate config.RateLimit) {
	full := time.Duration(float64(rate.Burst) / rate.RPS * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) >= full {
			delete(l.buckets, k)
		}
	}
}

// clientHost — адрес клиента для корзины лимита: хост из RemoteAddr.
func clientHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// retryAfterFor переводит паузу в значение заголовка Retry-After: целые
// секунды, округление вверх, не меньше одной.
func retryAfterFor(wait time.Duration) int {
	return max(1, int(math.Ceil(wait.Seconds())))
}

// allowModel проверяет лимит частоты обращений к модели для предъявителя
// ключа и при отказе сам отвечает 429 с Retry-After.
//
// Возвращает ложь, если запрос отклонён: вызывающий обработчик завершает
// работу, не читая тела. Проверка идёт сразу после аутентификации, до разбора
// тела и до детекции: отклонённый запрос не стоит сервису ничего, кроме
// строки журнала.
func (s *Server) allowModel(w http.ResponseWriter, r *http.Request, log *slog.Logger, snap *config.Snapshot,
	consumerID string, e obs.Endpoint, started time.Time) bool {

	rate, on := snap.ModelRate(consumerID)
	if !on {
		return true
	}
	ok, wait := s.limiter.allow(consumerID, clientHost(r), rate)
	if ok {
		return true
	}
	retry := retryAfterFor(wait)
	// Ключ в журнал не идёт: потребитель назван идентификатором из
	// конфигурации, этого достаточно, чтобы понять, чью квоту выбрали.
	log.Warn("запрос отклонён по лимиту частоты обращений к модели",
		logKeyConsumer, consumerID,
		"rps", rate.RPS, "burst", rate.Burst, "retry_after_s", retry,
		logKeyOutcome, obs.OutcomeRateLimited.String())
	s.deps.Metrics.Request(e, obs.OpProxy, obs.OutcomeRateLimited, time.Since(started).Seconds())
	s.deps.Metrics.ConsumerRequest(consumerID, e, obs.OutcomeRateLimited)
	setRetryAfter(w, retry)
	writeError(w, http.StatusTooManyRequests,
		"превышен лимит частоты обращений к модели, повторите запрос позже")
	return false
}
