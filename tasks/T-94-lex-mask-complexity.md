---
id: T-94
title: "Сложность лексера и маскирования: Tokenize, Values.Each, синтетические ФИО"
owner: agent
status: done
wave: 17
depends_on: [T-90]
owns:
  - internal/lex/lex.go
  - internal/mask/mask.go
  - internal/mask/synthetic.go
estimate: 2h30m
---

## Что сделать

Пять функций сложнее 15: `lex.Tokenize` 63, `(*Values).Each` 30, `SyntheticNameForms` 43, `inflectName` 39, `shapeOf` 34. Самый горячий путь — только под бенчмарки до/после.

Поведение детекции не меняется: ответы `/process` по корпусу побайтово равны
эталону T-84 (`reports/golden/golden-before.jsonl`), `make quality` — тот же итог,
бенчмарки горячего пути без регрессии. **T-80…T-83 брать после T-91…T-94.**

## Журнал

23.09, агент T-94 (коммиты 4199dc3, e584c38, d4c403b), интеграция — оркестратор.

`lex.Tokenize` 63 → 14 (состояние разбора — локальный `tokenizer` в `tokenizer.go`, на стеке),
`(*Values).Each` 30 → 11 (`stepFrom`, `emitMatches` — встраиваются), `SyntheticNameForms`
43 → 8, `inflectName` 39 → 4 (таблицы окончаний `caseEnds`), `shapeOf` 34 → 2.
Эталон `/process` побайтово равен; снимок synthetic (4 372 444 строки по ФИО корпуса,
словарю имён, всем ролям/родам/падежам) до и после — `cmp` rc=0; fuzz
`FuzzTokenizeMatchesReference` 30 с — PASS до и после.
RESULT бенчмарков (поочерёдно): Tokenize −0,6%, TokenizeInvisible +0,8%, Apply −0,3%,
CoverRepeats −0,3…−0,6%, allocs без роста (SyntheticNameForms 1546 → 1514).

### Итог волны 17 (T-91…T-94), оркестратор, 23.09

На объединённом коде `ec9ff48`: `make fmt`, `vet`, `test`, `test-race` (все модули) — rc=0;
`make quality` — итоговый блок совпадает с эталоном T-84 до знака; `/process` по корпусу —
1204 из 1204 побайтово; gocognit `-over 15` по cmd, internal, web, tools — **ни одной
функции** (было 121 до волны 15); групп литералов, повторённых ≥ 3 раз в файле, — 0.
Detect целиком против 2bc5990 (A/B, 4 раунда, медианы): all_types 196,6 против 195,4 мкс
(+0,6%), crm_types +0,9%, DetectBare +1,2%, allocs 0 → 0.
