---
id: T-54
title: Замечания жюри и проверки качества — цифры, пределы, токены, журнал
status: done
owner: "оркестратор"
wave: 9
depends_on: [T-48, T-53]
owns:
  - internal/detect/scan_digits.go
  - internal/detect/scan_digits_test.go
  - internal/detect/scan_misc.go
  - internal/detect/scan_misc_test.go
  - internal/httpapi/proxy.go
  - internal/httpapi/process.go
  - internal/config/load.go
  - internal/config/load_test.go
  - cmd/ai-gateway/main.go
  - internal/mask/token.go
  - web/index.html
  - README.md
  - .env.example
estimate: 2h
---

## Почему задача появилась

Отчёты 23.09 в `.agents/runtime/`: техническое жюри (`jury-tech-review/20260923/REVIEW.md`)
и финальная проверка качества кода (`code-quality-check/20260923/REPORT.md`).
Здесь собраны находки в файлах, не занятых задачами T-50…T-52.

## Что сделано

| Находка | Правка | Подтверждение |
|---|---|---|
| S3 (жюри): неразрывный пробел между группами цифр — карта, телефон, СНИЛС уходили открытыми | `onlySpaces` принимает U+00A0, U+202F, U+2009 | тесты в `scan_digits_test.go`; живой `/process`: `карта [КАРТА_1]`, `СНИЛС [СНИЛС_1]` |
| С-2 (качество): `miscCardNearby` квадратичен — проход предложения на каждого кандидата в держатели | запоминание по предложению (`miscCardMemo`) | `TestMiscCardHolderLinearTime` (60 000 повторов) |
| С-3: у `/v1/chat/completions` не было предела на запрос | `request_timeout + llm.timeout` на весь запрос; истечение до выпуска — fail-closed | `go test ./internal/httpapi/` |
| С-8: `max_concurrent: -1` — паника; дефолт `write_timeout` 15 с < `llm.timeout` 60 с; SIGHUP молча не применял `server.*`/`store.*`/`logging` | `validateLimits`; `write_timeout` по умолчанию = `llm.timeout + request_timeout + 5 с`; `RestartOnly` + WARN при перезагрузке | `TestLimitsValidated`, `TestRestartOnlyReportsFixedSections` |
| С-11: в заготовке стенда реальный ИНН организации и `mail.ru` | синтетический ИНН физлица и `example.com` | живой `/process` на заготовке — всё замаскировано |
| №9 (жюри): токен `token` — FNV без ключа, CVV восстанавливался перебором за миллисекунды | HMAC-SHA256 с ключом `AIGW_TOKEN_KEY` (без него — случайный на процесс) | тесты `internal/mask`; README и `.env.example` |
| №8 (жюри): длительностей этапов нет в журнале | `duration_us`, `detect_us`, `policy_us`, `mask_us`, `store_us` в строке `/process` | строка журнала ниже |

S2 (телефон на «8» без маркера) и S5 (повтор значения) закрыты раньше в T-53.

## Журнал

- 2026-09-23 — оркестратор. `make check` — код возврата 0;
  `go test -race` по `httpapi`, `store`, `mask`, `config` — 0.
  `RESULT` качества (seed 20260922, корпус `b398b99b…`, порт 8144): сокрытие
  0,9803, precision 1,0000, ловушек 0 из 144, ошибок восстановления 0 из 1204 —
  как после T-53. Строка журнала `/process`: `"duration_us":48,"detect_us":25,
  "policy_us":0,"mask_us":3,"store_us":2`.
- Не проверено: нагрузочный прогон после правок; токены `token` между
  перезапусками без `AIGW_TOKEN_KEY` различаются — это осознанно.
