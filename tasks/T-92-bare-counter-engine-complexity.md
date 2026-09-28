---
id: T-92
title: "Сложность голых значений, контр-правил и движка"
owner: agent
status: done
wave: 17
depends_on: [T-90]
owns:
  - internal/detect/bare.go
  - internal/detect/counter.go
  - internal/detect/engine.go
  - internal/detect/scan_account.go
  - internal/detect/scan_docs.go
estimate: 2h30m
---

## Что сделать

Семнадцать функций сложнее 15: bare.go (7), counter.go (6), engine.go (2), scan_account.go (1), scan_docs.go (1).

Поведение детекции не меняется: ответы `/process` по корпусу побайтово равны
эталону T-84 (`reports/golden/golden-before.jsonl`), `make quality` — тот же итог,
бенчмарки горячего пути без регрессии. **T-80…T-83 брать после T-91…T-94.**

## Журнал

23.09, агент T-92 (коммиты 85f3713, fe7bcf6, 62e6964, 3899c05), интеграция — оркестратор.

17 функций ≤ 15: `counterDenyAfterOffice` 45 → 9 и `counterDenyOrgContacts` 31 → 7
(метки → state-struct окна со `step`), `bareBirthPlace` 41 → 5 и `bareFullName` 39 → 3
(общий `bareJoinerOK`), `(*counterSentence).load` 33 → 12, `selectSpans` 25 → 2,
`emitPlate` 22 → 2 и остальные. Эталон `/process` — после каждого файла побайтово равен.
RESULT бенчмарков (поочерёдно, медианы): Detect −2…+0%, ScanCounter −1%, ScanAccount
+1,6%, allocs 0 → 0; escapes 45 → 44.
