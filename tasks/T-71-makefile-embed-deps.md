---
id: T-71
title: Зависимости сборки сервиса включают встроенные через go:embed файлы
owner: "агент"
status: done
wave: 13
depends_on: []
owns:
  - Makefile
  - tasks/T-71-makefile-embed-deps.md
estimate: 20m
---

## Цель

`SRC_MAIN` в `Makefile` собирался как `find cmd internal -name '*.go'`. Правило
`$(BIN_DIR)/ai-gateway` поэтому не видело файлов, встроенных через `//go:embed`:
`web/index.html` (и `web/presentation.html` из ветки презентации), `web/web.go`,
справочники `internal/detect/dict/data/*` и `internal/mask/data/*`. После правки
только стенда, презентации или словаря `make build` отвечал «nothing to be done»,
а `make run-bg` запускал старый бинарник.

## Что сделать

- Включить в `SRC_MAIN` каталог `web` (`*.go`, `*.html`) и каталоги `data/`,
  встраиваемые целиком (`//go:embed data`).
- Больше ничего не менять.

## Критерии приёмки

- Изменение байта во встроенном HTML → `make build` пересобирает бинарник.
- Изменение файла справочника → `make build` пересобирает бинарник.
- Повторный `make build` без изменений ничего не пересобирает.
- `make check` проходит.

## Команда проверки

```bash
make build && touch web/index.html && make build   # вторая сборка обязана запустить go build
make check
```

## Журнал

- 2026-09-23 — заведена и взята агентом.
- 2026-09-23 — сделано, `status: review`.

### Что сделано

`SRC_MAIN` теперь собирается как
`find cmd internal web -type f \( -name '*.go' -o -name '*.html' -o -path '*/data/*' \) ! -name '.*'`.
Каталоги `data/` берутся по пути, а не по расширению: `//go:embed data` в
`internal/detect/dict/dict.go` встраивает любой файл каталога, кроме файлов,
начинающихся с точки. В итоге в зависимости попадают `web/web.go`,
`web/index.html`, 17 файлов `internal/detect/dict/data/*.txt` и
`internal/mask/data/synthetic_names.txt` (проверено через `make -pn build`).
Другие файлы не менялись.

### Что прошло проверку

- `make build` без изменений → `go build` не запускается, rc=0.
- Дописан маркер в `web/index.html` → `make build` запустил `go build`, маркер
  нашёлся в бинарнике (`grep -a -c` → 1); после отката и новой сборки → 0.
- Дописана строка в `internal/detect/dict/data/months.txt` → `make build`
  запустил `go build`; после отката снова пересобрал.
- Создан временный `web/presentation.html` → `make -n build` показывает
  `go build` (в этой ветке файла нет, он в ветке презентации 457e69b; временный
  файл удалён).
- `make check` → rc=0: `gofmt` без расхождений, `go vet` чисто, 18 пакетов `ok`.

### Что осталось непроверенным

- В macOS стоит GNU Make 3.81 (`/usr/bin/make`), он сравнивает mtime с точностью
  до секунды. Если правка попадает в ту же секунду, что и предыдущая сборка,
  пересборки не будет. Это ограничение самого make, а не правила: при
  проверке правки в одну секунду со сборкой пропускались, при разнесении на
  разные секунды всё пересобиралось.

- 2026-09-23 — оркестратор: независимая проверка отдельным агентом — **принято**.
  Повторная сборка без изменений ничего не делает; правка `web/index.html`,
  справочника `internal/detect/dict/data/months.txt` и
  `internal/mask/data/synthetic_names.txt` пересобирает бинарник (маркер
  находится в бинарнике, после отката — нет); `make check` — код 0; все три
  директивы `//go:embed` покрыты. Замечания низкой серьёзности: пункт журнала
  про `make -n build` ничего не доказывает (`bin/.version: FORCE` всегда
  показывает `go build` в режиме `-n`); зависимости заданы масками
  (`*.go`, `*.html`, `*/data/*`) — встроенный в `web/` `.css`/`.js` в них не
  попадёт. Статус `done`.
