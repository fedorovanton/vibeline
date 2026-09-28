---
id: T-62
title: "Повтор payload_id с новым текстом, числовой payload_id, журнал продуктовых эндпоинтов, мелочи раунда 2"
status: done
owner: "оркестратор"
wave: 11
depends_on: [T-03, T-54]
owns:
  - internal/gateway/process.go
  - internal/gateway/gateway.go
  - internal/gateway/process_test.go
  - internal/httpapi/process.go
  - internal/httpapi/process_test.go
  - internal/httpapi/proxy.go
  - internal/httpapi/api.go
  - internal/config/load.go
  - internal/config/load_test.go
  - tools/loadtest/main.go
  - tools/loadtest/runner.go
  - tools/loadtest/runner_test.go
  - web/index.html
  - README.md
  - docs/spec/SPEC.md
  - docs/spec/DECISIONS.md
estimate: 1,5h
---

## Почему задача появилась

Повторный раунд технического жюри 23.09 (`.agents/runtime/jury-tech-review/20260923-r2/REVIEW.md`),
пункты 8, 14, 15 таблицы работ и «Новый риск по демаскированию».

## Что сделано

| Находка | Правка | Подтверждение |
|---|---|---|
| Повтор `payload_id` с другим текстом: обратный шаг отдавал маску, а при совпадении масок — исходник первого текста | новый текст, не похожий на маску, заменяет соответствие; похожий на маску — не трогает (I-22, SPEC) | `TestProcessNewTextSameIDStartsNewPair`, `TestProcessSameMaskDifferentTextDoesNotLeakFirst`, `TestInvariantProcessForgedPlaceholders`; живьём: «Клиент Иванов…» и «Клиент Петров…» под одним id → обратный шаг второй пары — «Клиент Петров Пётр Петрович» |
| `payload_id` числом → 400 | принимается и строкой, и числом; `42` и `"42"` — один идентификатор | `TestProcessNumericPayloadID`; живьём `777` → обратный шаг по `"777"` |
| `types: [all, nonexistent_type]` принимался | список проверяется целиком | `TestTypesAllWithUnknownRejected` |
| Длительностей этапов нет в журнале `/v1` и `/api/v1` | `detect_us`, `policy_us`, `mask_us`, `store_us`, `restore_us` | тесты `httpapi`, `obs` |
| Зелёная галочка «главного доказательства» при пропущенных значениях | нейтральная плашка «i», красная — только если найденное ушло наружу | стенд |
| README обещал независимость от регистра без оговорок | оговорка со ссылкой на «Ограничения» | — |
| `loadtest`: повтор идентификаторов между прогонами; устаревшее «сервис не публикует счётчиков Go-рантайма» | метка прогона в `payload_id`; сообщение указывает `aigw_go_gc_cycles_total` | два прогона `make load` подряд без перезапуска — 0 расхождений из 491 278 и 490 524 |

## Журнал

- 2026-09-23 — оркестратор. `make check` — код возврата 0; `go test -race
  -count=1` по `gateway`, `httpapi`, `store` — 0; `go test ./...` в
  `tools/loadtest` — 0.
