# Развёртывание ai-gateway

## Требования

Docker с плагином Compose. Открытый наружу порт: проверяющая система должна
достучаться до `POST /process`. Допустимы HTTP и HTTPS, в том числе с
самоподписанным сертификатом — проверка идёт с отключённой проверкой
сертификата.

## Запуск

```bash
git clone <репозиторий> && cd ai-gateway
cp .env.example .env   # вписать ключ AlfaGen — тот же шаблон, что в README
docker compose up -d --build
curl -sS http://localhost:8080/healthz
```

## Проверка контракта снаружи

```bash
HOST=http://<публичный-адрес>:8080

# Прямой шаг: маскирование
curl -sS -X POST $HOST/process -H 'Content-Type: application/json' \
  -d '{"payload":"Клиент Иванов Иван Иванович, паспорт 4509 123456","payload_id":"check-1"}'

# Обратный шаг: тем же payload_id отправляется полученная маска
curl -sS -X POST $HOST/process -H 'Content-Type: application/json' \
  -d '{"payload":"<маска из первого ответа>","payload_id":"check-1"}'
```

Второй вызов обязан вернуть исходную строку побайтово.

## Перезагрузка настроек без простоя

```bash
vim config.yaml
docker compose kill -s HUP ai-gateway
```

Невалидный файл отклоняется, и сервис продолжает работать на прежних
настройках — проверить можно по журналу и по `GET /readyz`.

## Наблюдение

| Что | Где |
|---|---|
| Живость процесса | `GET /healthz` |
| Готовность, действующие потребители и сканеры | `GET /readyz` |
| Метрики Latency, RPS, TPS | `GET /metrics`, формат Prometheus |
| Журнал этапов и типов ПД | `docker compose logs -f ai-gateway` |

Значения персональных данных не попадают ни в журнал, ни в метрики, ни в
тела ответов об ошибках.

## Ресурсы

Предел памяти контейнера задаётся переменной `MEMORY_LIMIT` (по умолчанию 4 ГБ)
и должен превышать `store.max_bytes` из `config.yaml` с запасом на рабочие
буферы. При значении `store.max_bytes: 1GiB` из `config.yaml` предел в 4 ГБ
оставляет запас и на рабочие буферы, и на подъём хранилища до 2 ГиБ.

Число используемых ядер ограничивается переменной `GOMAXPROCS`; значение `0`
означает «все доступные».

## Как развёрнуто 23.09.2026

Действующий стенд — `http://94.228.167.253:8080` (VPS, Ubuntu 26.04, 2 vCPU,
3,8 ГБ). Шаги, выполненные на чистой машине:

```bash
apt-get install -y docker.io docker-compose-v2      # Docker из репозитория Ubuntu
git archive HEAD | ssh root@<хост> "mkdir -p /opt/ai-gateway && tar -x -C /opt/ai-gateway"
scp .env root@<хост>:/opt/ai-gateway/.env
ssh root@<хост> 'cd /opt/ai-gateway && chown 65532:65532 .env && chmod 600 .env \
  && VERSION=<версия> PORT=8080 MEMORY_LIMIT=3g docker compose up -d --build'
```

- `.env` принадлежит пользователю контейнера (`nonroot`, uid 65532): образ
  distroless запускается не от root, и файл с правами 600 root:root он не
  прочитал бы.
- `MEMORY_LIMIT=3g`: на машине 3,8 ГБ, а `store.max_bytes` — 1 ГиБ.
- Хост без российских корневых сертификатов, поэтому `curl` к
  `alfagen.alfabank.ru` с самого хоста падает на TLS; контейнер несёт их в
  образе (`deploy/certs/`), и обращение к модели из него работает.
- Обновление: повторить `git archive …` и `docker compose up -d --build`;
  `.env` при этом не перезаписывается.

## Мониторинг: Prometheus и Grafana

`docker compose up -d --build` поднимает вместе с сервисом ещё два контейнера:

| Сервис | Образ | Наружу | Предел памяти |
|---|---|---|---|
| `prometheus` | `prom/prometheus:v2.55.1` | не публикуется | `PROMETHEUS_MEMORY_LIMIT`, 256m |
| `grafana` | `grafana/grafana:11.4.0` | `GRAFANA_PORT`, 3000 | `GRAFANA_MEMORY_LIMIT`, 256m |

- Prometheus опрашивает `ai-gateway:8080/metrics` раз в 5 с
  (`deploy/prometheus/prometheus.yml`), хранит сутки и не больше 512 МБ.
- Grafana — только просмотр: анонимный вход с ролью Viewer; форма входа,
  basic auth и регистрация выключены, исходящих обращений (аналитика,
  обновления) нет. Источник данных и дашборд — файлы
  `deploy/grafana/provisioning/` и `deploy/grafana/dashboards/ai-gateway.json`,
  правка в интерфейсе запрещена.
- На VPS нужен открытый порт 3000 (`ufw allow 3000/tcp`, если включён ufw,
  и правило в панели хостинга).
- Сервис от мониторинга не зависит: упавший Prometheus или Grafana на
  `POST /process` не влияют, а поднять только сервис можно командой
  `docker compose up -d ai-gateway`.
- Замер 23.09 под нагрузкой ~21 тыс. запр/с (loopback): Grafana 111 МиБ,
  Prometheus 71 МиБ.

## Если адрес не отвечает

Публичный адрес — единственный отсекающий барьер конкурса, а держится он на
одном оплачиваемом VPS. 23.09 около 12:20–12:28 МСК хостинг отключал машину
за неоплату: хост не отвечал целиком (ICMP, 22, 8080). После включения сервис
поднялся сам — Docker в автозапуске, у контейнера `restart: unless-stopped`.

Наблюдение снаружи — `scripts/watch.sh`: раз в минуту `/healthz` и пара
«маска → восстановление» через `POST /process`, отказ — строкой «ОТКАЗ» и
уведомлением на macOS.

```bash
scripts/watch.sh http://94.228.167.253:8080
```

Порядок при отказе:

1. `ping` и `ssh` к хосту. Не отвечает ничего — баланс и статус VPS в панели
   хостинга; оплатить с запасом на весь период проверки (прогон может идти и
   после дедлайна загрузки).
2. Хост отвечает, порт нет — `cd /opt/ai-gateway && docker compose ps`, затем
   `docker compose up -d`.
3. Сверить версию: `curl http://<хост>:8080/healthz` — поле `version` равно
   ожидаемому коммиту; `scripts/demo.sh http://<хост>:8080` — 4 из 4.

Хранилище соответствий живёт в памяти: перезапуск теряет все пары, начатые до
него, и обратный шаг по ним не пройдёт. Персистентность `Store` сознательно не
сделана: снимок на диск не спасает при отключении питания, а оригиналы ПД на
диске — новый класс риска.
