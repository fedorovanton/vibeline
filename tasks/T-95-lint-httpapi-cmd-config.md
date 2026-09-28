---
id: T-95
title: "Линт httpapi, cmd, config: noctx, повторы по пакету, errcheck"
owner: agent
status: done
wave: 18
depends_on: [T-94]
owns:
  - internal/httpapi/
  - cmd/ai-gateway/
  - internal/config/
estimate: 1h30m
---

## Что сделать

55 замечаний: httpapi 39 (goconst 22, noctx 16, errcheck 1), config 13 (errcheck), cmd 3. Замечания `make lint` (`.golangci.yml`, T-84) в зоне — до нуля, без `//nolint`
без обоснования. Поведение не меняется: ответы `/process` по корпусу побайтово равны
эталону, тесты и ожидания прежние.

## Журнал

23.09, агент T-95 (коммит cb67199), интеграция — оркестратор. 55 → 0 без `//nolint`:
запросы в тестах с `t.Context()`, самопроверка в main — `NewRequestWithContext` + `Do`;
ошибка `st.Close()` при остановке пишется в журнал; ключи журнала и заголовки — константы
`routes.go`; `newTestHolder` вместо семи копий настройки конфига. Имена полей журнала,
коды, тела и заголовки прежние. Эталон `/process` побайтово равен; gofmt, vet, test, -race — rc=0.
