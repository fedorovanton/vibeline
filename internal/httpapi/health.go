package httpapi

import (
	"net/http"
	"strings"
	"time"
)

type healthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	UptimeSec int64  `json:"uptime_sec"`
}

type readyResponse struct {
	Status       string   `json:"status"`
	ConfigLoaded string   `json:"config_loaded_at"`
	Consumers    []string `json:"consumers"`
	Scanners     []string `json:"scanners"`
	StoreEntries int      `json:"store_entries"`
}

// handleHealth отвечает на проверку живости процесса.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:    "ok",
		Version:   s.deps.Version,
		UptimeSec: int64(time.Since(s.deps.StartedAt).Seconds()),
	})
}

// handleReady отвечает на проверку готовности обслуживать запросы и заодно
// показывает жюри действующую конфигурацию без раскрытия ключей.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	snap := s.deps.Config.Current()
	ids := make([]string, 0, len(snap.Consumers.All()))
	for _, c := range snap.Consumers.All() {
		state := "enabled"
		if !c.Enabled {
			state = "disabled"
		}
		ids = append(ids, c.ID+":"+state)
	}
	writeJSON(w, http.StatusOK, readyResponse{
		Status:       "ready",
		ConfigLoaded: snap.LoadedAt.Format(time.RFC3339),
		Consumers:    ids,
		Scanners:     s.deps.Gateway.Engine().Scanners(),
		StoreEntries: s.deps.Gateway.Store().Stats().Entries,
	})
}

// handleMetrics отдаёт метрики в текстовом формате Prometheus.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	st := s.deps.Gateway.Store().Stats()
	s.deps.Metrics.Store(st.Entries, st.Bytes, st.Evicted, st.Expired)

	var b strings.Builder
	b.Grow(8 << 10)
	s.deps.Metrics.WriteProm(&b)

	w.Header().Set(headerContentType, "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
