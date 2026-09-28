---
id: T-88
title: "Тесты detect (вне файлов T-80…T-83), lex, mask, pii: повторы и сложность"
owner: agent
status: done
wave: 15
depends_on: [T-84]
owns:
  - internal/detect/*_test.go кроме scan_name_test.go, scan_digits_test.go, scan_account_test.go, counter_test.go
  - internal/lex/*_test.go
  - internal/mask/*_test.go
  - internal/pii/*_test.go
estimate: 2h
---

## Что сделать

Константы фикстур и хелперы проверок вместо повторов строк; сложные тесты
(`TestInvariantEngineGeneratedCandidates` и др.) — через именованные функции
проверок. Продовый код и ожидания тестов не меняются. Файлы, которыми владеют
T-80…T-83, не трогаются.

## Журнал

23.09, агент T-88 (коммиты 7c1931e, 166c950, d691e36), интеграция — оркестратор.

- `TestInvariantEngineGeneratedCandidates` (62) → `assertOnlyAdmissible`,
  `assertOrderIndependent`, `assertGreedyComplete`, `assertPolicyPostFilter`,
  `newGenEngineCase`; порядок вызовов rand прежний — дайджест 3000 входов при seed 19
  совпал со старым кодом (временный тест, не закоммичен).
- `tokenizeReference` (52) → методы `referenceLexer`; сверка с `Tokenize` на затравках,
  случайных входах и полном переборе кириллицы и ASCII проходит; ineffassign исправлен.
- Ещё 12 сложных тестов — именованные `check*`; константы в `detect/messages_test.go`,
  `mask/fixtures_test.go` и по месту; SA4017 — `checksumSink`; `dict.go` — errcheck.
- 15 тестов, названных по раундам жюри, переименованы по поведению. Ссылок на старые
  имена вне `tasks/` нет.

RESULT по файлам зоны: gocognit > 15 — 14 → 0; группы повторов (≥ 5) — 44 → 0;
golangci-lint — 41 → 0. `func Test` 182 → 182, `go test -v` PASS 1695 → 1695.
Проверки агента и оркестратора после слияния: gofmt, go vet, go test ./... — rc=0;
агент — -race detect/lex/mask rc=0. Файлы T-80…T-82 не тронуты; общая константа
`msgOneSpanGot` готова для `scan_name_test.go`.
