package obs

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Профилировщик отдаёт дамп кучи и стеки горутин, в которых лежат рабочие
// буферы с обрабатываемым текстом. Поэтому проверка адреса — не удобство, а
// граница приватности: непетлевой адрес обязан отказывать, а не
// предупреждать.
func TestPprofRefusesNonLoopback(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"все интерфейсы", ":6060", "все интерфейсы"},
		{"внешний адрес", "0.0.0.0:6060", "не петлевой"},
		{"конкретный интерфейс", "192.168.1.10:6060", "не петлевой"},
		{"имя хоста", "example.org:6060", "не является IP-адресом"},
		{"без порта", "127.0.0.1", "адрес профилировщика"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := StartPprof(tt.addr, discardLogger())
			if err == nil {
				if p != nil {
					_ = p.Close(context.Background())
				}
				t.Fatalf("адрес %q принят, ожидался отказ", tt.addr)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ошибка %q, ожидалось упоминание %q", err, tt.want)
			}
		})
	}
}

// Пустой адрес означает «профилировщик не нужен»: это не ошибка, иначе
// сервис нельзя было бы запустить без него.
func TestPprofDisabledByDefault(t *testing.T) {
	p, err := StartPprof("", discardLogger())
	if err != nil {
		t.Fatalf("пустой адрес дал ошибку: %v", err)
	}
	if p != nil {
		t.Fatal("при пустом адресе профилировщик не должен запускаться")
	}
	// Close на nil-приёмнике обязан работать: вызывающий не проверяет.
	if err := p.Close(context.Background()); err != nil {
		t.Errorf("Close на выключенном профилировщике: %v", err)
	}
}

func TestPprofServesOnLoopback(t *testing.T) {
	p, err := StartPprof("127.0.0.1:0", discardLogger())
	if err != nil {
		t.Fatalf("запуск на петлевом адресе: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.Close(ctx); err != nil {
			t.Errorf("остановка: %v", err)
		}
	}()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+p.Addr()+"/debug/pprof/", nil)
	if err != nil {
		t.Fatalf("сборка запроса: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("запрос к профилировщику: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("закрытие тела: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код ответа %d, ожидался 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "goroutine") {
		t.Error("страница профилировщика не содержит списка профилей")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
