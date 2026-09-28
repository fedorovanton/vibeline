---
id: T-96
title: "Линт gateway, llm, obs, store: revive, forcetypeassert, noctx, повторы по пакету"
owner: agent
status: done
wave: 18
depends_on: [T-94]
owns:
  - internal/gateway/
  - internal/llm/
  - internal/obs/
  - internal/store/
estimate: 1h30m
---

## Что сделать

43 замечания: llm 16, obs 16, gateway 10, store 1. Замечания `make lint` (`.golangci.yml`, T-84) в зоне — до нуля, без `//nolint`
без обоснования. Поведение не меняется: ответы `/process` по корпусу побайтово равны
эталону, тесты и ожидания прежние.

## Журнал

23.09, агент T-96 (коммит b07c04b), интеграция — оркестратор. 43 → 0 без `//nolint`:
проверенное приведение из `sync.Pool` с запасным путём (`workspaceFromPool`, `newVerifier`),
`asConsumerCounters`, `ListenConfig` в pprof, закрытие тела ответа модели, константы
заголовков клиента (ключ по-прежнему без `Bearer`). Экспортируемый API прежний, allocs/op 0 → 0.
Эталон `/process` побайтово равен; gofmt, vet, test, -race — rc=0.

Итог волны 18 (T-95…T-97) на `8e5c450`: `make lint` — 0 замечаний во всех четырёх модулях
(было 335 + 98 до волны 15); `make fmt`, `vet`, `test`, `test-race` — rc=0; эталон — равен.
