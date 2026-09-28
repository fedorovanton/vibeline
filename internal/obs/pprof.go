package obs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// Профилировщик на отдельном слушателе.
//
// Включается только явным флагом и только на петлевом адресе. Причина в том,
// что `/debug/pprof` отдаёт дамп кучи и стеки всех горутин: в них попадают
// рабочие буферы, а значит и обрабатываемый текст с персональными данными.
// Это прямое нарушение инвариантов приватности, если порт доступен снаружи,
// поэтому непетлевой адрес не предупреждение, а отказ запускаться.
//
// Слушатель отдельный, а не маршрут на основном сервере: у основного сервера
// есть публичные эндпоинты без ключа (`/process`, `/metrics`, `/healthz`), и
// один неверный маршрут выставил бы профилировщик наружу вместе с ними.

// PprofServer — запущенный профилировщик.
type PprofServer struct {
	srv  *http.Server
	addr string
}

// Addr возвращает фактический адрес слушателя.
func (p *PprofServer) Addr() string { return p.addr }

// StartPprof поднимает профилировщик на addr. Пустой addr означает, что
// профилировщик не нужен: возвращается nil без ошибки.
func StartPprof(addr string, logger *slog.Logger) (*PprofServer, error) {
	if addr == "" {
		return nil, nil
	}
	if err := requireLoopback(addr); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	// Обработчики регистрируются поимённо на своём маршрутизаторе, а не через
	// DefaultServeMux, который пакет net/http/pprof заполняет в init.
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// Контекст нужен только на время открытия слушателя: сигнатура StartPprof
	// контекста не принимает, а останавливается профилировщик через Close.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("профилировщик на %s: %w", addr, err)
	}
	p := &PprofServer{
		// Таймаут записи не ставится: снятие профиля длится десятки секунд по
		// запросу профилирующего, и оборвать его по общему таймауту значит
		// не получить профиль вовсе.
		srv:  &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second},
		addr: ln.Addr().String(),
	}
	go func() {
		if err := p.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("профилировщик остановлен", "error", err)
		}
	}()
	logger.Warn("профилировщик включён",
		"addr", p.addr,
		"note", "отдаёт дамп кучи и стеки горутин; только для замеров, не для продуктивного контура")
	return p, nil
}

// Close останавливает профилировщик.
func (p *PprofServer) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	return p.srv.Shutdown(ctx)
}

// requireLoopback отвергает адрес, доступный не только с этой машины.
//
// Пустой хост («:6060») означает все интерфейсы — он запрещён наравне с
// внешним адресом: именно такая запись чаще всего и выставляет отладочный
// порт в сеть по недосмотру.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("адрес профилировщика %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("адрес профилировщика %q слушает все интерфейсы: укажите 127.0.0.1 или [::1]", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("адрес профилировщика %q: хост не является IP-адресом", addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("адрес профилировщика %q не петлевой: профилировщик отдаёт дамп кучи и наружу не выставляется", addr)
	}
	return nil
}
