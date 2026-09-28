---
id: T-86
title: "Качество кода gateway, obs, store, policy: разбиение Proxy и WriteProm, тесты без повторов"
owner: agent
status: done
wave: 15
depends_on: [T-84]
owns:
  - internal/gateway/
  - internal/obs/
  - internal/store/
  - internal/policy/
estimate: 2h30m
---

## Что сделать

Снять go:S1192 и go:S3776 без изменения поведения: `Proxy`, `restoreAndRescan`,
`(*scope).restore`, `coverAcrossMessages`, `labelsIn`, `looksMasked`,
`WriteProm`; хелпер вместо `"%w: %w"`, константы типов метрик Prometheus,
затенение `close`. В тестах — хелперы `mustProcess`/`mustProxy`/`userChat`,
константы фикстур, сложные тесты инвариантов — через именованные проверки.
Экспортируемый API пакетов не меняется. Ожидания тестов не менять.

## Журнал

23.09, агент T-86 (коммиты 2765dbe, 9ad5e15, c020c56), интеграция — оркестратор.

- `Proxy` разложен на `checkRelease` → `protectChat`/`maskMessages`/`verifyMessage` →
  `putProxyRecord` → `callModel` (единственный вызов `model.Chat`, строго после записи
  в Store) → `restoreChoices`; `restoreAndRescan` — тип `respMasker`; `scope.restore`,
  `coverAcrossMessages`, `labelsIn`, `scope.add`, `looksMasked` разбиты; `"%w: %w"` ×7 →
  `wrapErr`; затенение `close` убрано. `WriteProm` — таблица `promScalar` + функции рядов.
- Тесты: `gateway/helpers_test.go` (`mustProxy`, `mustForward`, `assertNoModelCalls`, …),
  `obs/helpers_test.go`; сложные тесты инвариантов — именованные проверки. Тестов в
  gateway 71 до и после, ожидания не менялись.

RESULT (gocognit > 15 / группы повторов ≥ 3 в файле): прод 9 → 0 / 4 → 0; тесты 6 → 0 / 69 → 0.
Проверки: gofmt, go vet, go test ./..., go test -race gateway/obs/store/httpapi — rc=0.
/metrics побайтово тот же (временный снимок до/после, `cmp` rc=0). После слияния:
ответы `/process` по корпусу 1204 записи побайтово совпадают с эталоном T-84.
