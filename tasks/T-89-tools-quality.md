---
id: T-89
title: "Качество кода tools/: corpusgen, qualitycheck, loadtest"
owner: agent
status: done
wave: 15
depends_on: [T-84]
owns:
  - tools/corpusgen/
  - tools/qualitycheck/
  - tools/loadtest/
estimate: 2h
---

## Что сделать

Страховка на случай, если автопроверка не учтёт `sonar-project.properties`:
сложные функции (`Aggregate` 49, `writeText` 33, `buildReport`, `memTotalBytes`,
`serverLatencies`, …), повторы строк, одинаковые `sortLeaks`/`sortFalsePositives`
(S4144), errcheck. Генерация корпуса при том же seed — побайтово та же, отчёты
qualitycheck и loadtest — те же.

## Журнал

23.09, агент T-89 (коммиты 3ef0ee3, 6d048e1, 28c3e21), интеграция — оркестратор.

- qualitycheck: `Aggregate` по фазам с generic «взять или создать»; `sortLeaks` и
  `sortFalsePositives` — одна функция; `renderFindings` по секциям, `"%.4f"` в хелпере.
- loadtest: `writeText` по секциям, шапки колонок — константы; `memTotalBytes` по
  платформам; `buildReport` принимает структуру; errcheck и noctx исправлены.
- corpusgen: одинаковые шаблоны строятся `valueTmpl`/`piecesTmpl`; литералы — константы;
  затенение `min`/`make` снято; длинные тесты — именованные проверки.

RESULT: gocognit > 15 — 22 → 0; группы повторов (≥ 5) — 36 → 0; golangci-lint —
corpusgen 27 → 0, qualitycheck 46 → 0, loadtest 25 → 0.
Поведение: корпус `-count 1200 -seed 20260922` (с `-bare` и без) — `cmp` rc=0; текстовый
и JSON-отчёты qualitycheck и loadtest на фиксированных данных — `cmp` rc=0 (временные
снимки, не закоммичены). Оркестратор после слияния: корпус из новой сборки побайтово
равен эталонному, `make quality` — итоговый блок совпадает с эталоном до знака.
