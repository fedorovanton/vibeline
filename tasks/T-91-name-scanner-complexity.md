---
id: T-91
title: "Сложность сканера ФИО: Scan, nameMatch, nameFieldSlot, nameExtendLeft и др."
owner: agent
status: done
wave: 17
depends_on: [T-90]
owns:
  - internal/detect/scan_name.go
estimate: 2h30m
---

## Что сделать

Девять функций сложнее 15 в `scan_name.go`: `(nameScanner).Scan` 68, `nameFieldSlot` 64, `nameMatch` 64, `nameExtendLeft` 54, `nameFieldValue` 29, `nameBareSurname` 26, `nameLookupGiven` 23, `nameExtendRight` 16, `nameHyphenJoin` 16 (и 10 параметров, S107).

Поведение детекции не меняется: ответы `/process` по корпусу побайтово равны
эталону T-84 (`reports/golden/golden-before.jsonl`), `make quality` — тот же итог,
бенчмарки горячего пути без регрессии. **T-80…T-83 брать после T-91…T-94.**

## Журнал

23.09, агент T-91 (6 коммитов, последний 081ae05), интеграция — оркестратор.

Было → стало (gocognit): `Scan` 68 → 6 (состояние прохода `nameScan`, конструкция
`nameCons`), `nameMatch` 64 → 11 (по роли головы), `nameFieldSlot` 64 → 10 (фазы),
`nameExtendLeft` 54 → 5, `nameFieldValue` 29 → 7, `nameBareSurname` 26 → 13,
`nameLookupGiven` 23 → 2, `nameExtendRight` 16 → 9, `nameHyphenJoin` 16 → метод
`hyphenJoin` (9), 10 параметров → 1. Новые файлы `name_scan.go`, `name_match.go`,
`name_fields.go`. Эталон `/process` — после каждого из шести шагов побайтово равен.
RESULT бенчмарков (A/B-бинарники поочерёдно, 8 раундов, медианы, M1 Max): ScanName
+0,85%, Detect +0,7…1,1%, allocs 0 → 0; escapes 7 → 7.
