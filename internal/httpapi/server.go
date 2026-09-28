// Package httpapi — HTTP-транспорт сервиса.
//
// Транспорт разбирает запрос, выбирает потребителя, вызывает ядро обработки и
// переводит его исходы в коды ответа. Логика детекции и маскирования здесь
// отсутствует: её можно проверять без поднятия сети.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/obs"
)

// Deps — зависимости HTTP-слоя.
type Deps struct {
	Config  *config.Holder
	Gateway *gateway.Service
	Metrics *obs.Metrics
	Logger  *slog.Logger
	// Recorder — кольцевые буферы истории и журнала для стенда. Пустое
	// значение означает «собрать по умолчанию»: точка сборки сервиса
	// (cmd/ai-gateway) о наблюдаемости стенда знать не обязана. Явно заданный
	// nil здесь не отличим от незаданного, и это сознательно: выключение
	// выполняется переменной окружения, которую читает NewRecorderFromEnv, а
	// не подстановкой nil из вызывающего кода.
	Recorder *obs.Recorder
	// Version — версия сборки, отдаётся в /healthz.
	Version string
	// StartedAt — момент запуска, отдаётся в /healthz.
	StartedAt time.Time
}

// Server — HTTP-сервер сервиса.
type Server struct {
	deps Deps
	http *http.Server
	sem  chan struct{}
	// limiter — лимит частоты обращений к модели по ключу (P4-8). Состояние
	// корзин живёт в сервере, а не в снимке конфигурации: перезагрузка по
	// SIGHUP меняет параметры лимита, но не обнуляет израсходованную квоту.
	limiter *modelLimiter
}

// NewServer собирает сервер и маршруты по текущему снимку конфигурации.
func NewServer(deps Deps) *Server {
	snap := deps.Config.Current()

	if deps.Recorder == nil {
		deps.Recorder = obs.NewRecorderFromEnv()
	}
	// Поток журнала на странице — зеркало настоящего журнала, а не второй
	// источник правды. Обработчик оборачивается здесь, а не в точке сборки
	// сервиса: так зеркало получают все обращения к s.deps.Logger, включая
	// ErrorLog самого http.Server, и ни один обработчик не может случайно
	// писать мимо буфера. Формат и уровень при этом остаются за NewLogger.
	if deps.Recorder.JournalCap() > 0 {
		deps.Logger = slog.New(obs.NewJournalHandler(deps.Logger.Handler(), deps.Recorder))
	}

	s := &Server{
		deps:    deps,
		sem:     make(chan struct{}, snap.Server.MaxConcurrent),
		limiter: newModelLimiter(),
	}

	mux := http.NewServeMux()
	mux.Handle(routePOST+pathProcess, s.wrap(http.HandlerFunc(s.handleProcess)))
	mux.Handle(routeGET+pathHealth, http.HandlerFunc(s.handleHealth))
	mux.Handle(routeGET+pathReady, http.HandlerFunc(s.handleReady))
	mux.Handle(routeGET+pathMetrics, http.HandlerFunc(s.handleMetrics))
	s.registerProxyRoutes(mux)
	s.registerAPIRoutes(mux)
	s.registerUIRoutes(mux)

	s.http = &http.Server{
		Addr:              snap.Server.Addr,
		Handler:           methodGuard(mux),
		ReadHeaderTimeout: snap.Server.ReadTimeout.Duration(),
		ReadTimeout:       bodyReadTimeout(snap.Server.ReadTimeout.Duration(), snap.Server.RequestTimeout.Duration()),
		WriteTimeout:      snap.Server.WriteTimeout.Duration(),
		IdleTimeout:       snap.Server.IdleTimeout.Duration(),
		ErrorLog:          slog.NewLogLogger(deps.Logger.Handler(), slog.LevelWarn),
	}
	return s
}

// bodyReadTimeout — предел на чтение заголовков и тела вместе.
//
// read_timeout ограничивает заголовки — от медленной атаки на соединение
// этого достаточно. Тело же на публичном канале грузится дольше: текст в
// сотню тысяч токенов при полосе около 2 Мбит/с идёт больше пяти секунд, и
// тот же предел на тело отвечал 400 на корректный запрос (D-1 нагрузочного
// прогона 23.09). Тело получает бюджет request_timeout. Худший случай
// запроса тогда — чтение тела плюс обработка, до двух request_timeout; зато
// медленный канал получает 429 с Retry-After, который проверяющая система
// повторяет, а не 400, который она считает невалидным ответом.
func bodyReadTimeout(header, request time.Duration) time.Duration {
	return max(header, request)
}

// Addr возвращает адрес прослушивания.
func (s *Server) Addr() string { return s.http.Addr }

// ListenAndServe запускает сервер.
func (s *Server) ListenAndServe() error { return s.http.ListenAndServe() }

// Shutdown корректно останавливает сервер, дав текущим запросам завершиться.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }
