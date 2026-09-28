package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ai-gateway/internal/config"
	"ai-gateway/internal/llm"
)

// Общие фикстуры тестов пакета. Значения синтетические: реальные
// персональные данные в репозиторий не попадают ни в каком виде.
const (
	// fixtureReply — ответ фальшивой модели, содержимое которого тесту
	// безразлично.
	fixtureReply = "ответ"
	// modeAlfaGen — режим llm.mode с сетевым клиентом модели; в тестах он
	// направлен на локальный httptest.Server.
	modeAlfaGen = "alfagen"
	// unknownKey — ключ, которого нет в конфигурации.
	unknownKey = "key-unknown"
	// placeholderName — первый плейсхолдер ФИО в маске.
	placeholderName = "[ФИО_1]"
	// typeFullName — машинный ключ типа ФИО.
	typeFullName = "full_name"
	// answerPrefix — приписка, превращающая маску в «изменённый ответ модели».
	answerPrefix = "Ответ: "
	// jsonContentType — Content-Type тела запроса в тестах.
	jsonContentType = "application/json"
	// msgCodeBody — сообщение о неожиданном коде ответа.
	msgCodeBody = "получен код %d, тело %s"
	// sourceJournal — имя источника «журнал» в проверках на утечку значений.
	sourceJournal = "журнал"
)

// newTestHolder записывает конфигурацию body во временный config.yaml и
// загружает её так же, как сервис при запуске.
func newTestHolder(t *testing.T, body string) *config.Holder {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("запись конфигурации: %v", err)
	}
	holder, err := config.NewHolder(path)
	if err != nil {
		t.Fatalf("загрузка конфигурации: %v", err)
	}
	return holder
}

// Потребители и значения тестов стенда (ui_test.go).
const (
	consumerDemoAll   = "demo-all"
	consumerDemoNames = "demo-names"

	uiName  = "Петров Пётр Петрович"
	uiPhone = "+7 905 111-22-33"
	uiEmail = "petrov@example.test"

	// uiTraceByID — путь трассировки без значения идентификатора.
	uiTraceByID = pathUITrace + "?id="
)

// assertCode прерывает тест, если код ответа rec отличается от want.
func assertCode(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	mustStatus(t, rec.Code, want, rec.Body.String())
}

// mustStatus прерывает тест, если код got отличается от want; body
// показывается в сообщении.
func mustStatus(t *testing.T, got, want int, body string) {
	t.Helper()
	if got != want {
		t.Fatalf(msgCodeBody, got, body)
	}
}

// newStubUI поднимает стенд в режиме stub с фальшивой моделью, к которой он
// обращаться не должен. Возвращает маршрутизатор стенда и модель.
func newStubUI(t *testing.T) (*http.ServeMux, *uiModel) {
	t.Helper()
	model := newUIModel(t, fixtureReply, 0)
	_, mux := newUIServer(t, llm.ModeStub, model.srv.URL, nil, nil)
	return mux, model
}

// newModelUI поднимает стенд в режиме alfagen, направленный на фальшивую
// модель с ответом reply без задержки.
func newModelUI(t *testing.T, reply string) (*Server, *http.ServeMux, *uiModel) {
	t.Helper()
	model := newUIModel(t, reply, 0)
	s, mux := newUIServer(t, modeAlfaGen, model.srv.URL, nil, nil)
	return s, mux, model
}

// mustAnalyze выполняет прогон стенда и прерывает тест, если ответ не 200.
func mustAnalyze(t *testing.T, mux *http.ServeMux, key, consumer, text string) analyzeResponse {
	t.Helper()
	code, res, body := analyze(t, mux, key, consumer, text)
	mustStatus(t, code, http.StatusOK, body)
	return res
}

// maskText маскирует text под ключом key; пустой id в запрос не передаётся.
func (a *apiServer) maskText(t *testing.T, key, text, id string) (int, maskAPIResponse, string) {
	t.Helper()
	req := map[string]string{"text": text}
	if id != "" {
		req["id"] = id
	}
	return a.mask(t, key, req)
}
