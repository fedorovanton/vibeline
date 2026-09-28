---
id: T-87
title: "Качество кода стенда и презентации: JS/CSS/HTML по правилам Sonar"
owner: agent
status: done
wave: 15
depends_on: []
owns:
  - web/index.html
  - web/presentation.html
estimate: 1h30m
---

## Что сделать

MAJOR: вложенные тернарники, затенение переменных, повтор CSS-селекторов,
ARIA-роли вместо нативных тегов. MINOR: `for…of`, `substr`, `startsWith`,
`type` у кнопок, подпись поля. CRITICAL: сложные JS-функции (`lineChart`,
`renderConfig`, `parseProm`, `refreshHistory`, `refreshJournal` …), повторы
строк, вложенность колбэков глубже 4. Стенд и презентация работают как раньше.

## Журнал

23.09, агент T-87 (коммит 4cb7a5d), интеграция — оркестратор.

- index.html: 11 сложных функций разбиты на функции верхнего уровня (`lineChart` 61 →
  `chartFrame`, `drawYTicks`, `drawSeries`, …); константы `JSON_TYPE`, `ID_TRACE_BLOCK`,
  `ID_HISTORY_ROWS`, …; вложенные тернарники убраны; затенение `svc`/`dec`/`p` снято;
  `:root` и `.topmeta` слиты; `for…of`, `startsWith`, `includes`; `type="button"`,
  `aria-label`.
- presentation.html: вложенность колбэков ≤ 3; обработчик клавиш — `keyAction`/`onKey`;
  обзор — нативный `<dialog>`, `role="img"` перенесён на `<svg>`, график — `<figure>`.

Проверки: `node --check` обоих скриптов; `go build ./...`, `go test ./web/... ./internal/httpapi/...`
— rc=0; в браузере стенд (прогон, 401, вкладки, история, трассировка, журнал, дашборд)
и презентация (листание, обзор, тема, копирование) — без ошибок в консоли; скриншоты
и размеры схем совпадают с исходной версией. SonarQube не запускался — сложность JS
считалась приближённо (acorn).
