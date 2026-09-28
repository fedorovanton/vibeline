---
id: T-85
title: "Качество кода httpapi, cmd, llm, config: константы, разбиение хендлеров, тесты без повторов"
owner: agent
status: done
wave: 15
depends_on: [T-84]
owns:
  - internal/httpapi/
  - cmd/ai-gateway/
  - internal/llm/
  - internal/config/
estimate: 2h30m
---

## Что сделать

Снять замечания go:S1192 и go:S3776 без изменения поведения: константы путей,
заголовков и ключей журнала (`routes.go`), общий разбор тела и классификация
ошибок хендлеров, `run` в `main.go` по фазам, `llm.ModeStub`, затенение `max`,
S107 у `recordAPI`/`forbidden`. В тестах — пакетные хелперы и константы,
`round4_test.go` переименовать по поведению. Ожидания тестов не менять.

## Журнал

23.09, агент T-85 (коммиты 58acd0e, 1ecc33c), интеграция — оркестратор.

- `internal/httpapi/routes.go`: пути, заголовки, `no-store`, ключи журнала, хелперы
  `setRetryAfter`, `noStore`. `json.go`: общие `readBody`/`decodeJSONBody`. Перевод
  ошибки в ответ — `processFailed`, `chatFailed`, `reportAnalyze`; `diagnose` →
  `spanViewsOf`/`summaryOf`. `run` в main.go → `parseFlags`, `serve`, `waitSignals`,
  `reload`, `stopServer`. `recordAPI`/`forbidden` принимают структуры. `llm.ModeStub`.
- Тесты: `helpers_test.go` (`assertCode`, `mustStatus`, `mustAnalyze`, `newStubUI`, …);
  `round4_test.go` → `router_access_test.go`. 90 тестовых функций до и после.

RESULT (gocognit > 15 / группы повторов в файле): прод 4 → 0 / 14 → 0; тесты httpapi 8 → 0 / 52 → 0.
Проверки агента: gofmt, go vet, go test ./... (httpapi ещё `-count=3`), -race httpapi/gateway — rc=0.

Оркестратор после слияния: go vet, go test ./..., -race httpapi/gateway/store/obs — rc=0;
ответы `/process` по корпусу побайтово совпадают с эталоном; 15 проб HTTP-контракта
(405 с Allow, 400, 401, 404, маскирование и восстановление API, история, healthz, readyz)
сверены со сборкой 653f602 — коды, заголовки и тела те же, отличаются только версия,
время старта и chunked у выросшей истории. Дочищены тесты `internal/llm` (сложность 20 → 0,
4 группы повторов → 0) и `internal/config` (2 → 0), которые в зону агента не входили.
