---
id: T-93
title: "Сложность сканеров цифр, дат, прочих типов и адреса"
owner: agent
status: done
wave: 17
depends_on: [T-90]
owns:
  - internal/detect/scan_digits.go
  - internal/detect/scan_dates.go
  - internal/detect/scan_misc.go
  - internal/detect/scan_address.go
estimate: 2h30m
---

## Что сделать

Шестнадцать функций сложнее 15: scan_digits.go (5), scan_dates.go (5), scan_misc.go (3), scan_address.go (3).

Поведение детекции не меняется: ответы `/process` по корпусу побайтово равны
эталону T-84 (`reports/golden/golden-before.jsonl`), `make quality` — тот же итог,
бенчмарки горячего пути без регрессии. **T-80…T-83 брать после T-91…T-94.**

## Журнал

23.09, агент T-93 (5 коммитов, последний f53a434), интеграция — оркестратор.

16 функций ≤ 15: `matchWordDate` 32 → `matchWordDateDayFirst` 4 / `…MonthFirst` 7,
`dateMarkerBefore` 29 → 14, `nextDigitPart` 23 → 13, `miscAuthorityTail` 22 → 13,
`miscSkipBirthFiller` 21 → 7 и остальные; вложенные switch — в предикаты. Две
перестановки проверок обоснованы эквивалентностью (UTF-8-длина «у»/«п»; флаг «р» на первом
значимом слове всегда false). Эталон `/process` — после каждого файла побайтово равен.
RESULT бенчмарков (поочерёдно, 8 раундов): ScanDigits +1,5%, ScanDates +1,1%, ScanMisc
−1,4%, Detect +0,7%, allocs 0 → 0; escapes 51 → 51. Варианты с регрессией 2–13% отброшены.
