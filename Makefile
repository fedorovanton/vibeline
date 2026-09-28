# Makefile модуля безопасности персональных данных ai-gateway.
#
# Цель по умолчанию — справка. Описания целей берутся из комментариев «## …»
# справа от имени цели: отдельный список внутри справки рассинхронизировался бы
# с набором целей на первой же правке, а так расходиться нечему.
#
# Проверено на GNU Make 3.81 — той, что штатно стоит в macOS. Отсюда прямые
# ограничения: ни .ONESHELL, ни .RECIPEPREFIX, ни .SHELLFLAGS в 3.81 нет,
# поэтому каждая строка рецепта — отдельный вызов оболочки, а составные
# проверки собраны в одну строку через «\».

SHELL := /bin/bash

# ─────────────────────────────────────────────────────────────── Переменные ──
#
# Всё ниже переопределяется из окружения и из командной строки:
#
#   make run PORT=9090
#   make load CONNS=50 DURATION=60s
#   make docker-up IMAGE_TAG=hackathon
#   make deploy DEPLOY_HOST=user@1.2.3.4

GO ?= go

# Версия зашивается в бинарник из git-описания. Вне репозитория — например, в
# распакованном архиве сдачи, где каталога .git нет, — остаётся «dev», и это
# честнее пустой строки: по ней сразу видно, что сборка не из репозитория.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Порт вынесен в переменную не ради единообразия: на машине разработки 8080
# регулярно занят посторонним процессом (проверено — занят). Занятый порт даёт
# либо отказ старта, либо, что хуже, прогон проверок по чужому сервису.
# config.yaml при этом не правится: цели запуска делают копию конфигурации.
PORT ?= 8080
HOST ?= http://127.0.0.1:$(PORT)

IMAGE       ?= ai-gateway
IMAGE_TAG   ?= $(VERSION)
DEPLOY_HOST ?=
DEPLOY_DIR  ?= ~/ai-gateway

# Команда compose вынесена в переменную ради одного случая: docker-compose.yml
# задаёт container_name: ai-gateway жёстко, и второй каталог с тем же проектом
# (рабочее дерево, копия репозитория) поднять уже нельзя — Docker отвечает
# конфликтом имени. Тогда добавляется файл-надстройка, снимающий имя:
#   make docker-up COMPOSE="docker compose -f docker-compose.yml -f my-override.yml"
COMPOSE ?= docker compose
# compose читает VERSION и PORT из окружения: VERSION попадает в тег образа и в
# -ldflags сборки, PORT — в публикуемый порт хоста.
COMPOSE_ENV := VERSION=$(IMAGE_TAG) PORT=$(PORT)

# Профиль проверяющей системы: закрытый контур до 200 соединений, пять минут
# (docs/context/07-clarifications.md §7.2). Частоту запросов система не задаёт,
# поэтому «разогнать RPS» нельзя — можно только уменьшить латентность.
# Для быстрой проверки после правки: make load CONNS=50 DURATION=60s.
CONNS    ?= 200
DURATION ?= 5m
RAMP     ?= 10s
# Лестница поиска предела: удваивает число соединений с 25, пока p99 держится
# в секунде. Если инструмент скажет, что предел не достигнут, поднимите
# MAX_CONNS — иначе в отчёт уедет заниженная граница.
STEP      ?= 20s
MAX_CONNS ?= 3200

# Корпус качества. Seed и count обязаны попасть в отчёт: один seed даёт
# побайтово одинаковый корпус, без этого прогоны несравнимы.
SEED         ?= 20260922
CORPUS_COUNT ?= 1200

BIN_DIR     := bin
DIST_DIR    := dist
REPORTS_DIR := reports

# Корпуса и журналы прогонов живут в reports/ по двум причинам сразу: каталог
# исключён из .gitignore-контроля и, главное, scripts/package.sh исключает
# reports/ из архива и падает на любом файле больше 1 МБ. Корпус на 1200
# записей весит около 5 МБ — лёжа в корне, он ломал бы сборку архива сдачи.
CORPUS       := $(REPORTS_DIR)/corpus.jsonl
CORPUS_MIXED := $(REPORTS_DIR)/corpus-short.jsonl
# Файлы запуска разведены по портам: с общим PID-файлом второй
# «make run-bg PORT=…» в том же дереве отвечал «уже запущен» про чужой
# экземпляр, а «make stop PORT=…» останавливал чужой сервис. Порт по
# умолчанию сохраняет прежние имена — на них ссылается README.
ifeq ($(PORT),8080)
RUN_SUFFIX :=
else
RUN_SUFFIX := -$(PORT)
endif
RUN_CONFIG   := $(REPORTS_DIR)/config-run$(RUN_SUFFIX).yaml
RUN_LOG      := $(REPORTS_DIR)/ai-gateway$(RUN_SUFFIX).log
PIDFILE      := $(REPORTS_DIR)/ai-gateway$(RUN_SUFFIX).pid

# Инструменты в tools/ — отдельные модули Go со своими go.mod. Это и есть та
# ловушка, из-за которой проверки считались полными, не будучи таковыми:
# `go test ./...` из корня их не видит вовсе. Везде, где проверка должна быть
# полной, идёт цикл по этому списку.
MODULES := tools/corpusgen tools/loadtest tools/qualitycheck

# В сервис через //go:embed встроены не только .go: страницы web/*.html и
# каталоги data/ целиком (справочники detect/dict/data, синтетика mask/data).
# Без них в зависимостях правка стенда или словаря не пересобирала бинарник,
# и «make run-bg» молча запускал старую версию. data/ берётся по пути, а не по
# расширению: «//go:embed data» встраивает любой файл каталога, кроме
# начинающихся с точки.
SRC_MAIN       := $(shell find cmd internal web -type f \
	\( -name '*.go' -o -name '*.html' -o -path '*/data/*' \) ! -name '.*' 2>/dev/null)
SRC_CORPUSGEN  := $(shell find tools/corpusgen -name '*.go' 2>/dev/null)
SRC_LOADTEST   := $(shell find tools/loadtest -name '*.go' 2>/dev/null)
SRC_QUALITY    := $(shell find tools/qualitycheck -name '*.go' 2>/dev/null)

LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := help

##@ Справка

.PHONY: help
help: ## Показать список целей (цель по умолчанию)
	@echo "ai-gateway — модуль безопасности персональных данных, хакатон AlfaGen"
	@echo
	@echo "Использование: make <цель> [ПЕРЕМЕННАЯ=значение]"
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@ / { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
		/^[a-zA-Z0-9_-]+:.*##/ { d = $$2; sub(/^ +/, "", d); \
			printf "  \033[36m%-14s\033[0m %s\n", $$1, d }' $(MAKEFILE_LIST)
	@echo
	@echo -e "\033[1mПеременные\033[0m (значения сейчас)"
	@echo "  PORT=$(PORT)  VERSION=$(VERSION)  IMAGE_TAG=$(IMAGE_TAG)"
	@echo "  CONNS=$(CONNS)  DURATION=$(DURATION)  RAMP=$(RAMP)  STEP=$(STEP)  MAX_CONNS=$(MAX_CONNS)"
	@echo "  SEED=$(SEED)  CORPUS_COUNT=$(CORPUS_COUNT)"
	@echo "  DEPLOY_HOST=$(DEPLOY_HOST)  DEPLOY_DIR=$(DEPLOY_DIR)"

##@ Сборка

.PHONY: build build-tools build-linux
build: $(BIN_DIR)/ai-gateway ## Собрать бинарник сервиса с версией из git
build-tools: $(BIN_DIR)/corpusgen $(BIN_DIR)/loadtest $(BIN_DIR)/qualitycheck ## Собрать corpusgen, loadtest, qualitycheck

build-linux: $(BIN_DIR)/.version ## Кросс-сборка сервиса под linux/amd64 для развёртывания
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath \
		-ldflags '$(LDFLAGS)' -o $(BIN_DIR)/ai-gateway-linux-amd64 ./cmd/ai-gateway
	@echo "готово: $(BIN_DIR)/ai-gateway-linux-amd64 (версия $(VERSION))"

$(BIN_DIR)/ai-gateway: $(SRC_MAIN) go.mod go.sum $(BIN_DIR)/.version
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/ai-gateway

$(BIN_DIR)/corpusgen: $(SRC_CORPUSGEN) | $(BIN_DIR)
	cd tools/corpusgen && $(GO) build -trimpath -o ../../$@ .

$(BIN_DIR)/loadtest: $(SRC_LOADTEST) | $(BIN_DIR)
	cd tools/loadtest && $(GO) build -trimpath -o ../../$@ .

$(BIN_DIR)/qualitycheck: $(SRC_QUALITY) | $(BIN_DIR)
	cd tools/qualitycheck && $(GO) build -trimpath -o ../../$@ .

# Отметка о версии. Без неё бинарник не пересобирался бы после переезда HEAD:
# исходники те же, а -ldflags уже другие, и в собранном файле осталась бы
# версия прошлой сборки. Файл переписывается, только когда версия изменилась,
# поэтому лишних пересборок это не даёт.
$(BIN_DIR)/.version: FORCE | $(BIN_DIR)
	@echo '$(VERSION)' | cmp -s - $@ 2>/dev/null || echo '$(VERSION)' > $@

$(BIN_DIR) $(REPORTS_DIR):
	@mkdir -p $@

.PHONY: FORCE
FORCE:

##@ Проверки

.PHONY: check fmt vet test test-race bench lint
check: fmt vet test ## Полный набор проверок перед сдачей: формат, vet, тесты

fmt: ## Проверить форматирование (gofmt -l)
	@out=$$(gofmt -l . 2>/dev/null); \
	if [ -n "$$out" ]; then \
		echo "Не отформатировано:"; echo "$$out" | sed 's/^/  /'; \
		echo "Починить: gofmt -w <файлы>"; exit 1; \
	fi; \
	echo "gofmt: расхождений нет"
	@# Цикла по модулям здесь нет намеренно: gofmt обходит каталоги, а не
	@# модули Go, поэтому одного прохода из корня хватает и на tools/.
	@# Для vet, test и build это не так — см. ниже.

vet: ## go vet по всем четырём модулям, включая tools/
	$(GO) vet ./...
	@for m in $(MODULES); do \
		echo "== $$m"; \
		( cd "$$m" && $(GO) vet ./... ) || exit 1; \
	done

test: ## Тесты по всем четырём модулям, включая tools/
	$(GO) test ./...
	@for m in $(MODULES); do \
		echo "== $$m"; \
		( cd "$$m" && $(GO) test ./... ) || exit 1; \
	done

# Гонка в детекции или в конфиге проявится на закрытом контуре нагрузки, а не
# на ноутбуке, поэтому перед сдачей -race прогоняется по всему коду, а не
# только по store/httpapi/gateway, как в повседневной работе.
test-race: ## Тесты с детектором гонок по всем модулям
	$(GO) test -race ./...
	@for m in $(MODULES); do \
		echo "== $$m"; \
		( cd "$$m" && $(GO) test -race ./... ) || exit 1; \
	done

# Автопроверка заказчика — SonarQube: когнитивная сложность функции больше 15
# (go:S3776) и строка, повторённая в файле три раза и больше (go:S1192). Набор
# golangci-lint по умолчанию этого не видит, поэтому пороги — в .golangci.yml,
# а цель гоняет его по всем четырём модулям: tools/* — отдельные go.mod, и
# ./... из корня их не покрывает. Конфиг находится из подкаталогов сам —
# golangci-lint ищет .golangci.yml вверх по дереву.
lint: ## Линтеры с порогами автопроверки (сложность, повторы строк) по всем модулям
	@command -v golangci-lint >/dev/null || { echo "golangci-lint не установлен"; exit 2; }
	@rc=0; \
	for m in . $(MODULES); do \
		echo "== $$m"; \
		( cd "$$m" && golangci-lint run ./... ) || rc=1; \
	done; \
	exit $$rc

# allocs/op сравнивается с прошлым прогоном: вывод без сравнения ничего не
# доказывает. -run '^$$' отсекает обычные тесты, чтобы их время не попало в
# замер бенчмарков.
bench: ## Бенчмарки горячего пути (детекция, лексер)
	$(GO) test -bench . -benchmem -run '^$$' ./internal/...

##@ Запуск

.PHONY: run run-bg stop restart require-service require-port
run: build require-port | $(REPORTS_DIR) ## Запустить сервис в текущем терминале (PORT=…)
	@sed 's|^  addr:.*|  addr: "127.0.0.1:$(PORT)"|' config.yaml > $(RUN_CONFIG)
	@echo "ai-gateway $(VERSION) → $(HOST)  (Ctrl-C — остановка)"
	$(BIN_DIR)/ai-gateway -config $(RUN_CONFIG) -env .env

# Фоновый запуск нужен целям quality и load: им требуется отвечающий сервис, а
# держать два терминала ради этого незачем. GODEBUG=gctrace=1 включён потому,
# что сервис не публикует счётчики рантайма на /metrics, и журнал — единственный
# источник данных о куче и сборках мусора для раздела ресурсов в отчёте. Цена —
# объём: после нагрузочного прогона журнал доходит до сотни мегабайт, поэтому он
# лежит в reports/ и уносится целью clean. В цели run gctrace не включается.
run-bg: build | $(REPORTS_DIR) ## Запустить сервис в фоне (журнал и PID в reports/)
	@if [ -f $(PIDFILE) ] && kill -0 "$$(cat $(PIDFILE))" 2>/dev/null; then \
		echo "Сервис уже запущен, PID $$(cat $(PIDFILE)), $(HOST)"; exit 0; \
	fi; \
	$(MAKE) --no-print-directory require-port PORT=$(PORT) || exit 1; \
	sed 's|^  addr:.*|  addr: "127.0.0.1:$(PORT)"|' config.yaml > $(RUN_CONFIG); \
	GODEBUG=gctrace=1 $(BIN_DIR)/ai-gateway -config $(RUN_CONFIG) -env .env \
		> $(RUN_LOG) 2>&1 & \
	echo $$! > $(PIDFILE); \
	pid=$$(cat $(PIDFILE)); \
	for i in $$(seq 1 40); do \
		if ! kill -0 "$$pid" 2>/dev/null; then \
			echo "Сервис не поднялся: процесс завершился. Последние строки $(RUN_LOG):"; \
			grep -v '^gc ' $(RUN_LOG) | tail -10 | sed 's/^/  /'; \
			rm -f $(PIDFILE); exit 1; \
		fi; \
		if curl -fsS --max-time 2 "$(HOST)/readyz" 2>/dev/null | grep -q '"status":"ready"'; then \
			echo "ai-gateway $(VERSION) → $(HOST), PID $$pid, журнал $(RUN_LOG)"; exit 0; \
		fi; \
		sleep 0.5; \
	done; \
	echo "Сервис за 20 с не сообщил о готовности на $(HOST)/readyz. Журнал:"; \
	grep -v '^gc ' $(RUN_LOG) | tail -10 | sed 's/^/  /'; \
	exit 1

stop: ## Остановить сервис, запущенный через run-bg
	@if [ ! -f $(PIDFILE) ]; then \
		echo "PID-файл $(PIDFILE) не найден: останавливать нечего"; \
	elif kill -0 "$$(cat $(PIDFILE))" 2>/dev/null; then \
		kill "$$(cat $(PIDFILE))" && echo "остановлен PID $$(cat $(PIDFILE))"; \
		rm -f $(PIDFILE); \
	else \
		echo "процесс PID $$(cat $(PIDFILE)) уже не работает"; rm -f $(PIDFILE); \
	fi

# Хранилище соответствий ограничено объёмом, и на длинных текстах оно
# заполняется за один прогон. Соответствие, вытесненное между прямым и обратным
# шагом, даёт расхождения восстановления, которых на самом деле нет: измерено —
# 210 расхождений на заполненном хранилище против 0 на пустом. Отсюда эта цель:
# перед load-long и load-limit хранилище опустошается перезапуском.
restart: stop run-bg ## Перезапустить фоновый сервис с пустым хранилищем

# Внутренние цели: без ## в справке не показываются. Существуют затем, чтобы
# quality, load и demo сообщали «сервис не отвечает», а не падали внутри
# инструмента с ошибкой соединения, по которой причина не видна.
#
# Проверка идёт по GET /readyz, а не по /healthz, и это не придирка: посторонний
# процесс, занявший порт, отвечал на /healthz строкой «ok» — цель рапортовала об
# успехе, сервис при этом лежал с «bind: address already in use», а прогон ушёл
# бы по чужому сервису. Поймано на этой машине, а не придумано. Ответ /readyz с
# полем status=ready посторонним процессом уже не подделывается.
require-service:
	@curl -fsS --max-time 3 "$(HOST)/readyz" 2>/dev/null | grep -q '"status":"ready"' || { \
		echo "На $(HOST) не отвечает ai-gateway (проверка по GET /readyz)."; \
		echo "Поднимите его одной из команд:"; \
		echo "  make run-bg PORT=$(PORT)      # в фоне, журнал в $(RUN_LOG)"; \
		echo "  make docker-up PORT=$(PORT)   # в контейнере"; \
		echo "Если сервис слушает другой порт: make <цель> PORT=<порт>"; \
		exit 1; }

# Порт проверяется до запуска: чужой сервис на порту опаснее отказа старта,
# потому что сервис молча падает, а проверки уходят мимо него.
require-port:
	@if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:$(PORT) -sTCP:LISTEN -t >/dev/null 2>&1; then \
		echo "Порт $(PORT) уже занят:"; \
		lsof -nP -iTCP:$(PORT) -sTCP:LISTEN | sed 's/^/  /'; \
		echo "Запуск отменён — возьмите свободный порт: make <цель> PORT=<другой>"; \
		exit 1; \
	fi

##@ Качество и нагрузка

.PHONY: corpus corpus-mixed quality load load-long load-limit
corpus: $(CORPUS) ## Сгенерировать размеченный корпус для проверки качества
corpus-mixed: $(CORPUS_MIXED) ## Корпус без длинных записей — для смешанного нагрузочного профиля

$(CORPUS): $(BIN_DIR)/corpusgen | $(REPORTS_DIR)
	$(BIN_DIR)/corpusgen -out $@ -count $(CORPUS_COUNT) -seed $(SEED)

# -long=false здесь обязателен. corpusgen считает токены по словам, а loadtest —
# по четыре байта на токен, как метрика сервиса aigw_tokens_in_total. Запись «на
# 100 000 токенов» превращается для loadtest в текст примерно на 370 000 токенов
# и уезжает в класс huge; классы medium и large в таком корпусе пустеют, их вес
# перетекает на соседей, и 5 % запросов уходит текстами по 370 000 токенов.
# Это уже не смешанный профиль. Измерено, а не предположено.
$(CORPUS_MIXED): $(BIN_DIR)/corpusgen | $(REPORTS_DIR)
	$(BIN_DIR)/corpusgen -out $@ -count $(CORPUS_COUNT) -seed $(SEED) -long=false

quality: require-service $(BIN_DIR)/qualitycheck $(CORPUS) ## Измерить качество маскирования на независимом корпусе
	set -o pipefail; $(BIN_DIR)/qualitycheck -url $(HOST) -corpus $(CORPUS) \
		-seed $(SEED) -count $(CORPUS_COUNT) \
		-json $(REPORTS_DIR)/quality.json | tee $(REPORTS_DIR)/quality.txt

load: require-service $(BIN_DIR)/loadtest $(CORPUS_MIXED) ## Нагрузочный прогон, смешанный профиль
	set -o pipefail; $(BIN_DIR)/loadtest -url $(HOST)/process -mode mixed \
		-conns $(CONNS) -duration $(DURATION) -ramp $(RAMP) \
		-corpus $(CORPUS_MIXED) \
		-pid "$$(cat $(PIDFILE) 2>/dev/null || echo 0)" \
		-gctrace $(RUN_LOG) | tee $(REPORTS_DIR)/load-mixed.txt

# Соединений намеренно меньше профильных 200: двести параллельных текстов по
# 400 КБ — нагрузка, которой в проверке не будет, и она измеряла бы память, а не
# латентность. Смысл режима — подтвердить, что предельный вход по ТЗ (100 000
# токенов) обрабатывается и сервис остаётся работоспособен.
load-long: require-service $(BIN_DIR)/loadtest ## Прогон на текстах в 100 000 токенов
	@echo "Перед этим прогоном хранилище должно быть пустым: make restart"
	set -o pipefail; $(BIN_DIR)/loadtest -url $(HOST)/process -mode long \
		-conns 32 -duration 40s -ramp 5s \
		-pid "$$(cat $(PIDFILE) 2>/dev/null || echo 0)" \
		-gctrace $(RUN_LOG) | tee $(REPORTS_DIR)/load-long.txt

# Серверные цифры с /metrics в режиме limit охватывают все ступени сразу, а не
# отдельную: латентность для конкретного числа соединений берётся из отдельного
# прогона `make load CONNS=<число>`.
load-limit: require-service $(BIN_DIR)/loadtest ## Лестница по числу соединений — поиск предела
	set -o pipefail; $(BIN_DIR)/loadtest -url $(HOST)/process -mode limit \
		-step $(STEP) -max-conns $(MAX_CONNS) \
		-pid "$$(cat $(PIDFILE) 2>/dev/null || echo 0)" \
		-gctrace $(RUN_LOG) | tee $(REPORTS_DIR)/load-limit.txt

##@ Docker и развёртывание

.PHONY: docker-build docker-up docker-down docker-logs docker-reload deploy require-container-name
docker-build: ## Собрать образ Docker с версией из git
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(IMAGE_TAG) .

# compose монтирует ./.env внутрь контейнера. Отсутствующий файл Docker создаёт
# как каталог, и сервис молча стартует без ключа модели — поэтому пустой .env
# заводится заранее, до подъёма. Реальный ключ вписывается в него руками:
# в репозиторий и в архив сдачи .env не попадает.
docker-up: require-container-name ## Поднять сервис в контейнере (PORT=…)
	@test -f .env || { cp .env.example .env; \
		echo "Создан .env из .env.example — впишите ALFAGEN_API_KEY"; }
	$(COMPOSE_ENV) $(COMPOSE) up -d --build
	@echo "Ждём готовности $(HOST)/readyz"
	@for i in $$(seq 1 40); do \
		if curl -fsS --max-time 2 "$(HOST)/readyz" 2>/dev/null | grep -q '"status":"ready"'; then \
			echo "сервис отвечает на $(HOST)"; exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "сервис не ответил за 40 с, журнал контейнера:"; \
	$(COMPOSE_ENV) $(COMPOSE) logs --tail 30 ai-gateway; \
	exit 1

docker-down: ## Остановить контейнер и удалить его
	$(COMPOSE_ENV) $(COMPOSE) down

docker-logs: ## Показать журнал контейнера (следить: make docker-logs FOLLOW=-f)
	$(COMPOSE_ENV) $(COMPOSE) logs --tail 100 $(FOLLOW) ai-gateway

# Перезагрузка настроек без простоя: сигнал HUP заставляет сервис перечитать
# смонтированный config.yaml. Невалидный файл отклоняется, и сервис продолжает
# работать на прежних настройках — результат виден в журнале и в GET /readyz.
docker-reload: ## Перечитать config.yaml сигналом HUP без простоя
	@$(COMPOSE_ENV) $(COMPOSE) ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx ai-gateway || { \
		echo "Контейнер ai-gateway этого проекта не запущен — перезагружать нечего."; \
		echo "Поднимите его: make docker-up PORT=$(PORT)"; exit 1; }
	$(COMPOSE_ENV) $(COMPOSE) kill -s HUP ai-gateway
	@for i in $$(seq 1 20); do \
		if curl -fsS --max-time 2 "$(HOST)/readyz" 2>/dev/null | grep -q '"status":"ready"'; then \
			echo "конфигурация перечитана, простоя не было:"; \
			curl -fsS "$(HOST)/readyz"; echo; exit 0; \
		fi; \
		sleep 0.5; \
	done; \
	echo "после HUP сервис не подтвердил готовность — смотрите make docker-logs"; \
	exit 1

# Имя контейнера в docker-compose.yml задано жёстко (container_name: ai-gateway),
# поэтому две копии репозитория одновременно поднять нельзя. Без этой проверки
# Docker отвечает конфликтом имени, по которому непонятно, чей это контейнер и
# что с ним делать: подсказку даём сами.
require-container-name:
	@name=$$($(COMPOSE_ENV) $(COMPOSE) config 2>/dev/null \
		| awk '/^ *container_name:/ {print $$2; exit}'); \
	[ -n "$$name" ] || name=ai-gateway; \
	owner=$$(docker inspect "$$name" \
		--format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' 2>/dev/null || true); \
	if [ -n "$$owner" ] && [ "$$owner" != "$$(pwd)" ]; then \
		echo "Контейнер с именем $$name уже поднят из другого каталога:"; \
		echo "  $$owner"; \
		echo "docker-compose.yml задаёт container_name жёстко, поэтому две копии"; \
		echo "репозитория одновременно не поднимаются. Варианты:"; \
		echo "  1) остановить тот контейнер в его каталоге: make docker-down"; \
		echo "  2) поднять этот под другим именем через файл-надстройку:"; \
		echo "     make docker-up COMPOSE=\"docker compose -f docker-compose.yml -f <надстройка>.yml\""; \
		exit 1; \
	fi

# Задел: публичный стенд ещё не выбран, поэтому цель по умолчанию показывает
# план и ничего не делает. Ключ ALFAGEN_API_KEY на хост не копируется никогда:
# .env заполняется на хосте руками, иначе секрет уезжает по сети вместе с
# исходниками и оседает в истории оболочки.
deploy: ## Развернуть на удалённый хост: DEPLOY_HOST=user@host [CONFIRM=yes]
	@if [ -z "$(DEPLOY_HOST)" ]; then \
		echo "Переменная DEPLOY_HOST не задана — некуда развёртывать."; \
		echo; \
		echo "  make deploy DEPLOY_HOST=user@host             # показать план"; \
		echo "  make deploy DEPLOY_HOST=user@host CONFIRM=yes # выполнить"; \
		echo; \
		echo "Требования к хосту (deploy/README.md): Docker с плагином Compose"; \
		echo "и порт $(PORT), открытый наружу, — проверяющая система обращается"; \
		echo "к POST /process по публичному адресу."; \
		exit 2; \
	fi
	@echo "План развёртывания на $(DEPLOY_HOST):$(DEPLOY_DIR)"
	@echo "  1. rsync исходников без .git, .env, bin, dist, reports"
	@echo "  2. docker compose up -d --build на хосте, VERSION=$(IMAGE_TAG), PORT=$(PORT)"
	@echo "  3. проверка GET /readyz и контракта POST /process снаружи"
	@if [ "$(CONFIRM)" != "yes" ]; then \
		echo; \
		echo "Сухой прогон: ничего не выполнено. Повторите с CONFIRM=yes."; \
		echo "На хосте нужен .env с ключом ALFAGEN_API_KEY — этой целью он не копируется."; \
		exit 0; \
	fi; \
	set -e; \
	ssh "$(DEPLOY_HOST)" "mkdir -p $(DEPLOY_DIR)"; \
	rsync -az --delete \
		--exclude '.git' --exclude '.env' --exclude 'bin' \
		--exclude 'dist' --exclude 'reports' \
		./ "$(DEPLOY_HOST):$(DEPLOY_DIR)/"; \
	ssh "$(DEPLOY_HOST)" "cd $(DEPLOY_DIR) && VERSION=$(IMAGE_TAG) PORT=$(PORT) docker compose up -d --build"; \
	echo "Развёрнуто. Проверьте: curl -sS http://<адрес>:$(PORT)/readyz"

##@ Сдача и демонстрация

.PHONY: package demo
# Своя реализация упаковки здесь не нужна и вредна: package.sh не только
# собирает zip, но и проверяет его на секреты, запрещённые каталоги и файлы
# больше 1 МБ, и код возврата этой проверки — то, что решает, можно ли грузить.
package: ## Собрать архив сдачи с проверкой на секреты (scripts/package.sh)
	./scripts/package.sh

demo: require-service ## Демонстрационные сценарии через POST /process (scripts/demo.sh)
	./scripts/demo.sh $(HOST)

##@ Уборка

.PHONY: clean
# stop идёт первым: без него `rm -rf reports` унесёт PID-файл, фоновый сервис
# останется работать и займёт порт, а следующий запуск упадёт без внятной причины.
clean: stop ## Удалить собранное, архивы и временные корпуса
	rm -rf $(BIN_DIR) $(DIST_DIR) $(REPORTS_DIR)
	@echo "удалены $(BIN_DIR)/, $(DIST_DIR)/, $(REPORTS_DIR)/"
