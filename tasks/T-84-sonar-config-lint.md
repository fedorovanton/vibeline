---
id: T-84
title: Конфиг анализа Sonar, локальный линт по его правилам, .dockerignore
owner: orchestrator
status: done
wave: 15
depends_on: []
owns:
  - sonar-project.properties
  - .golangci.yml
  - .dockerignore
  - Makefile
  - tasks/INDEX.md
estimate: 40m
---

## Почему задача появилась

Предварительная автопроверка кода (SonarQube, Sonar way) 23.09: **6484 из 10000**,
372 замечания — CRITICAL 340, MAJOR 14, MINOR 18. Локальный замер показал, что
CRITICAL — это go:S3776 (Cognitive Complexity > 15, ~121 функция) и go:S1192
(литерал повторён ≥ 3 раз в файле, ~250 групп), причём ~75% — в `_test.go`:
анализатор считает тесты основным кодом. golangci-lint их не ловил, потому что
`.golangci.yml` не было и работал набор по умолчанию.

## Что сделать

1. `sonar-project.properties`: тесты — тестами, `docs/`, `tasks/`, `tools/` (dev-утилиты) — вне анализа.
2. `.golangci.yml` с аналогами правил Sonar (gocognit 15, goconst 3) и цель `make lint`.
3. `.dockerignore`: `COPY . .` не должен тянуть `.env`, `.git`, `dist/`, `reports/` в стадию сборки.

## Проверка

`make lint` запускается и печатает счёт; `make package` кладёт новые файлы в архив.

## Журнал

23.09, оркестратор.

- `sonar-project.properties`: `*_test.go` и `testdata/` — тесты; `tools/`, `docs/`,
  `tasks/`, `deploy/certs/`, артефакты — вне анализа. Ни одно правило не отключено.
- `.golangci.yml` (v2): набор `standard` + `gocognit` (15), `goconst` (5 / 3,
  `ignore-calls: false` — иначе литералы в аргументах вызовов не считаются),
  `revive` (redefines-builtin-id, unused-parameter), `forcetypeassert`, `noctx`.
- `make lint` — по корню и трём модулям `tools/*`, код возврата ненулевой при находках.
- `.dockerignore`: `.env`, `.git`, `bin`, `dist`, `reports`, корпуса.

RESULT до правок (`make lint`, 23.09 15:50 МСК): корень — 335 замечаний
(gocognit 98, goconst 149, errcheck 21, noctx 24, revive 24, staticcheck 11,
forcetypeassert 7, ineffassign 1); tools/corpusgen 27, tools/loadtest 25,
tools/qualitycheck 46. Набор по умолчанию (`--no-config`) тоже был не пуст: 17.

Эталон качества до правок (`make quality`, seed 20260922, 1204 записи):
сокрытие 0,9988, precision 1,0000, recall 0,9988, ловушек 0 из 144, ошибок
восстановления 0. Побайтовый эталон ответов `/process` по корпусу —
`reports/golden-before.jsonl`, sha256 `a8231716b2ac8a83…`, восстановление 1204 из 1204.

### Итог волны 15 (T-84…T-89), 23.09 16:25 МСК

Проверки на `787ffe3`: `make fmt`, `make vet`, `make test`, `make test-race` (все четыре
модуля) — rc=0. `make quality` — итоговый блок совпадает с эталоном до знака (сокрытие
0,9988, precision 1,0000, ловушек 0 из 144, ошибок восстановления 0). Ответы `/process`
по корпусу — 1204 из 1204 побайтово совпадают с эталоном (sha256 `a8231716b2ac8a83…`).
`make package` — проверка пройдена, 290 файлов, новые конфиги в архиве.

RESULT (правила Sonar локально; gocognit > 15 / группы литералов ≥ 3 в файле):

| | до | после |
|---|---|---|
| код сервиса | 60 / 28 | 47 / 4 |
| тесты сервиса | 39 / 249 | 10 / 54 |
| tools/ | 22 / 36 | 0 / 0 |
| `make lint`, корень | 335 | 188 |
| `make lint`, tools/* | 98 | 0 |

Остаток сознательно вне объёма (день сдачи, риск регрессии качества маскирования):

- 47 сложных функций горячего пути детекции — `internal/detect` (scan_name, bare,
  counter, scan_digits, scan_dates, scan_misc, scan_address, engine, scan_docs,
  scan_account), `lex.Tokenize`, `mask` (`synthetic.go`, `Values.Each`). Рефакторинг —
  только под побайтовый эталон `/process` и `make bench`.
- 4 группы литералов в `scan_name.go`/`counter.go` и 54 группы + 10 сложных тестов в
  `scan_name_test.go`, `counter_test.go`, `scan_digits_test.go`, `scan_account_test.go` —
  файлы T-80…T-83; делать вместе с ними (константа `msgOneSpanGot` уже заведена).
- Архитектура (ревью 23.09): `httpapi` повторяет конвейер маскирования (`diagnose`) и
  ведёт хранилище API — перенести в `gateway`; разбор формата маски — в `mask`;
  морфология и контрольные суммы продублированы между `detect` и `mask`; реестры через
  `init()`; ключи `Store` строятся в двух пакетах по-разному — при ключе у потребителя
  `benchmark` возможна коллизия `/process` ↔ прокси, нужна хотя бы валидация конфига;
  `scan_name.go` 3578 строк со словарями в коде; история раундов в комментариях.
- errcheck на `Close` файлов только для чтения и тел ответов, noctx в самопроверке и
  pprof, forcetypeassert на `sync.Pool` — идиоматичные места, правила Sonar way их не считают.
