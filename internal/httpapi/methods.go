package httpapi

import "net/http"

// methodGuard отвечает JSON на обращение к известному маршруту не тем методом
// (P4-11 раунда 4 жюри).
//
// Без него GET /process забирал обработчик страницы GET / и отвечал 404, а
// PUT и DELETE получали от ServeMux 405 с телом text/plain — единственный
// ответ сервиса не в JSON. Теперь любой метод, кроме объявленного, получает
// 405 с заголовком Allow и телом {"error": …}, а неизвестный путь любым
// методом, кроме GET, — 404 в том же формате, что и GET неизвестного пути.
//
// Проверка стоит перед маршрутизатором и на верном методе стоит одного
// сравнения строк: горячий путь POST /process она не замедляет.
func methodGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allow, known := allowedMethod(r.URL.Path)
		switch {
		case r.Method == allow:
		case allow == http.MethodGet && r.Method == http.MethodHead:
			// GET-маршруты ServeMux обслуживает и для HEAD.
		case known:
			if allow == http.MethodGet {
				w.Header().Set(headerAllow, "GET, HEAD")
			} else {
				w.Header().Set(headerAllow, allow)
			}
			writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается, допустимо: "+allow)
			return
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			writeError(w, http.StatusNotFound, msgRouteNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allowedMethod возвращает метод, объявленный для маршрута. Второе значение
// ложно для пути, которого среди маршрутов нет.
//
// Таблица повторяет регистрацию в NewServer, registerProxyRoutes,
// registerAPIRoutes и registerUIRoutes; её согласованность с маршрутизатором
// проверяет TestMethodGuardMatchesRoutes.
func allowedMethod(path string) (string, bool) {
	switch path {
	case pathProcess, pathChat, pathMask, pathUnmask, pathAnalyze:
		return http.MethodPost, true
	case pathRoot, pathHealth, pathReady, pathMetrics,
		pathUIConsumers, pathUIHistory, pathUITrace, pathUIJournal:
		return http.MethodGet, true
	}
	return "", false
}
