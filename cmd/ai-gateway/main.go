// Команда ai-gateway — прокси-сервис защиты персональных данных между
// системой-потребителем и языковой моделью.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/detect"
	"ai-gateway/internal/detect/dict"
	"ai-gateway/internal/gateway"
	"ai-gateway/internal/httpapi"
	"ai-gateway/internal/obs"
	"ai-gateway/internal/store"
)

// version подставляется при сборке через -ldflags.
var version = "dev"

// healthcheck запрашивает URL и возвращает ошибку, если сервис не отвечает
// кодом 200.
func healthcheck(url string) error {
	const timeout = 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("проверка %s: %w", url, err)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("проверка %s: %w", url, err)
	}
	// Тело не читается: решение принимается по коду ответа, и ошибке его
	// закрытия нечего добавить к результату проверки.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("проверка %s: получен код %d", url, resp.StatusCode)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ai-gateway:", err)
		os.Exit(1)
	}
}

// keyConfig — имя флага с путём к конфигурации и ключ этого пути в журнале.
const keyConfig = "config"

// keyError — ключ журнала для текста ошибки.
const keyError = "error"

// options — параметры командной строки.
type options struct {
	configPath string
	envPath    string
	showVer    bool
	healthURL  string
	pprofAddr  string
}

func parseFlags() options {
	var (
		configPath = flag.String(keyConfig, "config.yaml", "путь к файлу конфигурации")
		envPath    = flag.String("env", ".env", "путь к файлу с переменными окружения")
		showVer    = flag.Bool("version", false, "показать версию и выйти")
		healthURL  = flag.String("healthcheck", "", "проверить доступность указанного URL и выйти")
		pprofAddr  = flag.String("pprof", "", "адрес профилировщика, только петлевой (например 127.0.0.1:6060); пусто — выключен")
	)
	flag.Parse()
	return options{
		configPath: *configPath,
		envPath:    *envPath,
		showVer:    *showVer,
		healthURL:  *healthURL,
		pprofAddr:  *pprofAddr,
	}
}

func run() error {
	opts := parseFlags()

	if opts.showVer {
		fmt.Println("ai-gateway", version)
		return nil
	}
	if opts.healthURL != "" {
		// Режим самопроверки для healthcheck контейнера: в рабочем образе нет
		// ни оболочки, ни curl, поэтому проверяет себя сам бинарник.
		return healthcheck(opts.healthURL)
	}
	return serve(opts)
}

// serve собирает сервис, запускает HTTP-сервер и обслуживает сигналы до
// остановки.
func serve(opts options) error {
	// Ключ downstream-модели берётся из .env, чтобы решение запускалось на
	// любой машине без правки кода. Файл исключён из Git.
	if err := config.LoadDotEnv(opts.envPath); err != nil {
		return err
	}

	holder, err := config.NewHolder(opts.configPath)
	if err != nil {
		return err
	}
	snap := holder.Current()

	logger, err := obs.NewLogger(os.Stdout, snap.Logging.Level, snap.Logging.Format)
	if err != nil {
		return err
	}

	dicts, err := dict.Load()
	if err != nil {
		return err
	}
	engine := detect.New(dicts, detect.Registered()...)

	st := store.NewMemory(snap.Store)
	defer func() {
		if err := st.Close(); err != nil {
			logger.Error("остановка хранилища", keyError, err)
		}
	}()

	svc := gateway.New(engine, st)
	metrics := obs.NewMetrics()

	srv := httpapi.NewServer(httpapi.Deps{
		Config:    holder,
		Gateway:   svc,
		Metrics:   metrics,
		Logger:    logger,
		Version:   version,
		StartedAt: time.Now(),
	})

	// Профилировщик поднимается до основного сервера, чтобы отказ из-за
	// непетлевого адреса остановил запуск сразу, а не после того, как сервис
	// начал принимать запросы.
	prof, err := obs.StartPprof(opts.pprofAddr, logger)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), snap.Server.ShutdownTimeout.Duration())
		defer cancel()
		if err := prof.Close(ctx); err != nil {
			logger.Error("остановка профилировщика", keyError, err)
		}
	}()

	logger.Info("сервис запускается",
		"version", version,
		"addr", srv.Addr(),
		keyConfig, holder.Path(),
		"scanners", engine.Scanners(),
		"dictionaries", dicts.Names(),
		"consumers", len(snap.Consumers.All()),
		"llm_mode", snap.LLM.Mode,
		"store_ttl", snap.Store.TTL.String(),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	return waitSignals(srv, holder, logger, snap.Server.ShutdownTimeout.Duration(), errCh)
}

// waitSignals обслуживает сигналы процесса: SIGHUP перечитывает
// конфигурацию, SIGINT и SIGTERM останавливают сервер с пределом shutdown.
// Возвращается по остановке или по ошибке сервера из errCh.
func waitSignals(srv *httpapi.Server, holder *config.Holder, logger *slog.Logger,
	shutdown time.Duration, errCh <-chan error) error {

	// SIGHUP перечитывает конфигурацию: список потребителей, типы ПД и
	// стратегии маскирования меняются без перезапуска и без правки кода.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	for {
		select {
		case err := <-errCh:
			return err
		case <-sighup:
			reload(holder, logger)
		case sig := <-stop:
			logger.Info("остановка сервиса", "signal", sig.String())
			return stopServer(srv, shutdown)
		}
	}
}

// stopServer корректно останавливает сервер, дав текущим запросам не
// больше timeout на завершение.
func stopServer(srv *httpapi.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("остановка сервера: %w", err)
	}
	return nil
}

// reload перечитывает конфигурацию по SIGHUP. Невалидное обновление
// отклоняется: сервис продолжает работать на последней корректной
// конфигурации.
func reload(holder *config.Holder, logger *slog.Logger) {
	prev := holder.Current()
	if err := holder.Reload(); err != nil {
		logger.Error("перезагрузка конфигурации отклонена", keyError, err.Error())
		return
	}
	logger.Info("конфигурация перезагружена", keyConfig, holder.Path())
	if changed := config.RestartOnly(prev, holder.Current()); len(changed) > 0 {
		logger.Warn("часть настроек применится только после перезапуска", "fields", changed)
	}
}
