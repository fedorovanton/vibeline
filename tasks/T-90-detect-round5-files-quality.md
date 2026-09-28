---
id: T-90
title: "Качество кода в файлах T-80…T-83: повторы в scan_name.go и counter.go, тесты имён, контр-правил, цифр, счёта"
owner: orchestrator
status: done
wave: 16
depends_on: [T-88]
owns:
  - internal/detect/scan_name.go (только константы вместо повторённых литералов)
  - internal/detect/counter.go (только константы вместо повторённых литералов)
  - internal/detect/scan_name_test.go
  - internal/detect/counter_test.go
  - internal/detect/scan_digits_test.go
  - internal/detect/scan_account_test.go
estimate: 2h
---

## Почему задача появилась

Волна 15 (T-84…T-89) не трогала файлы, которыми владеют T-80…T-83, чтобы не
столкнуться с параллельной сессией. По ним остались замечания Sonar: 4 группы
повторённых литералов в `scan_name.go`/`counter.go`, 54 группы повторов и 10 сложных
тестов в `scan_name_test.go`, `counter_test.go`, `scan_digits_test.go`,
`scan_account_test.go`. На 23.09 16:35 T-80…T-83 в backlog без владельца.

## Что сделать

Константы вместо повторов, хелперы проверок, именованные функции вместо сложных тел
тестов. Логика детекции и ожидания тестов не меняются. **T-80…T-83 брать после этой
задачи** — иначе конфликт слияния в тех же файлах.

## Журнал

23.09, агенты T-90 (коммиты 76e81de — имена, adc7559 — контр-правила, цифры, счёт),
интеграция — оркестратор.

- Код сервиса: в `scan_name.go` — константы `nameWordThanks`, `nameWordHello`,
  `nameWordHi` в пяти списках (каждый список сохранил свой набор слов); в `counter.go` —
  `counterWordPhone` в трёх списках. Больше в этих файлах ничего не менялось.
- Тесты: фикстуры в `name_fixtures_test.go`, `counter_fixtures_test.go`,
  `digits_fixtures_test.go`; сложные тесты — именованные проверки
  (`TestCounterDictionaries` — одна таблица вместо шести циклов); 16 тестов
  `*Round4*` переименованы по поведению (старые имена остались только в журналах
  T-65, T-66, T-67 — это история).
- `func Test`: scan_name_test 41 → 41; counter/digits/account 29 → 29; PASS по пакету
  detect 1515 → 1515.

RESULT по всему коду (cmd, internal, web, tools): групп литералов, повторённых ≥ 3 раз
в файле, — **0** (было 313 до волны 15); тестов со сложностью > 15 — **0** (было 49).
Остаются 47 функций горячего пути детекции (`detect`, `lex`, `mask`).

Проверки после слияния: `make fmt`, `make vet`, `make test`, `make test-race` — rc=0;
`make quality` — итоговый блок совпадает с эталоном до знака; ответы `/process` по
корпусу — 1204 из 1204 побайтово равны эталону; `make lint`, корень — 170 (было 335).
