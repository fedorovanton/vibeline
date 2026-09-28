---
id: T-48
title: Медленная загрузка тела не даёт 400; обрыв клиента не считается отказом защиты
status: done
owner: "оркестратор"
wave: 8
depends_on: [T-16]
owns:
  - internal/httpapi/server.go
  - internal/httpapi/json.go
  - internal/httpapi/process.go
  - internal/httpapi/api.go
  - internal/httpapi/proxy.go
  - internal/httpapi/ui.go
  - internal/httpapi/bodytimeout_test.go
  - internal/obs/metrics.go
estimate: 45m
---

## Почему задача появилась

Нагрузочный прогон 23.09 (`.agents/runtime/load-test/REPORT.md`, §9) нашёл:

- **D-1.** `server.read_timeout: 5s` шёл и в `ReadHeaderTimeout`, и в
  `ReadTimeout`, а последний в `net/http` покрывает всё тело. Тело 1,2 МБ при
  канале 200 КБ/с получало **400** за 5,1 с. Проверяющая система считает 400
  невалидным ответом, пять подряд останавливают прогон — на публичном адресе
  серия крупных текстов по узкому каналу ведёт ровно к этому.
- **O-1.** Обрыв соединения клиентом (`context.Canceled`) писался как ERROR,
  метрика `fail_closed`, ответ 500 — смешивался с настоящими отказами защиты.
- **O-2.** Нижняя корзина гистограммы — 0,5 мс, а сервис отвечает за
  десятки микросекунд: все серверные перцентили сливались в одну корзину.

## Что сделано

- Заголовки ограничены `read_timeout`, заголовки и тело вместе —
  `max(read_timeout, request_timeout)` (`bodyReadTimeout`, `server.go`).
- Истечение чтения тела на `/process`, `/api/v1/*`, `/v1/*` и стенде —
  **429 с `Retry-After`**, исход `overloaded` (`bodyReadTimedOut`,
  `writeBodyTimeout` в `json.go`).
- Новый исход метрик `client_gone`; обрыв клиента на `/process` — INFO,
  без ответа и без `fail_closed`.
- Корзины гистограммы задержки начинаются с 50 мкс.

## Критерии приёмки

- [x] AC-1 Тело, не дочитанное вовремя, даёт 429 с `Retry-After` —
      `TestBodyReadTimeoutIsRetryable` (`/process` и `/api/v1/mask`); без
      правки тест падает с «код 400».
- [x] AC-2 Тело получает бюджет `request_timeout` —
      `TestBodyReadTimeoutCoversRequestBudget`; живой прогон: тело 1,0 МБ при
      `curl --limit-rate 150k` — **200** за 10,5 с (до правки — 400 на 5 с).
- [x] AC-3 Обрыв клиента — исход `client_gone`, не `fail_closed` —
      `TestProcessClientGoneIsNotFailClosed`.
- [x] AC-4 `make check`, `go test -race ./internal/httpapi/... ./internal/store/... ./internal/obs/...` — код возврата 0.

## Журнал

- 2026-09-23 — оркестратор по отчёту нагрузочного прогона. Все проверки
  выше выполнены, коды возврата прочитаны. Поведение на обычных запросах не
  менялось: тела, дочитанные быстрее пяти секунд, идут тем же путём.
  Нагрузочный прогон после правки не повторялся — в горячем пути изменилась
  только гистограмма (три корзины впереди, цикл по массиву фиксированного
  размера).
