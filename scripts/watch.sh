#!/usr/bin/env bash
#
# Наблюдение за доступностью развёрнутого сервиса снаружи.
#
# Раз в INTERVAL секунд проверяет /healthz и пару «маска → восстановление»
# через POST /process — ровно то, что делает проверяющая система. Печатает
# одну строку на проверку; при отказе строка начинается с «ОТКАЗ», а на macOS
# дополнительно приходит системное уведомление.
#
#   scripts/watch.sh http://94.228.167.253:8080          # раз в минуту
#   INTERVAL=20 scripts/watch.sh http://94.228.167.253:8080
#   ONCE=1 scripts/watch.sh http://94.228.167.253:8080   # одна проверка, код возврата
#
# Данные проверки синтетические. Каждая проверка берёт новый payload_id, чтобы
# не опираться на соответствие, потерянное при перезапуске.

set -uo pipefail

HOST="${1:-${HOST:-http://localhost:8080}}"
INTERVAL="${INTERVAL:-60}"
TEXT='Клиент Сидорова Анна Петровна, тел. +7 900 000-00-01'

notify() {
  command -v osascript >/dev/null 2>&1 &&
    osascript -e "display notification \"$1\" with title \"ai-gateway\"" >/dev/null 2>&1
  return 0
}

check() {
  local id="watch-$(date +%s)-$$" health masked restored
  health=$(curl -sS -m 10 "${HOST}/healthz" 2>&1) || { echo "healthz: ${health}"; return 1; }
  masked=$(curl -sS -m 10 -X POST "${HOST}/process" -H 'Content-Type: application/json' \
    --data-binary "$(python3 -c 'import json,sys; print(json.dumps({"payload":sys.argv[1],"payload_id":sys.argv[2]}))' "$TEXT" "$id")" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])' 2>&1) || { echo "process: ${masked}"; return 1; }
  [ "$masked" != "$TEXT" ] || { echo "маска не изменила текст"; return 1; }
  restored=$(curl -sS -m 10 -X POST "${HOST}/process" -H 'Content-Type: application/json' \
    --data-binary "$(python3 -c 'import json,sys; print(json.dumps({"payload":sys.argv[1],"payload_id":sys.argv[2]}))' "$masked" "$id")" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])' 2>&1) || { echo "restore: ${restored}"; return 1; }
  [ "$restored" = "$TEXT" ] || { echo "восстановление разошлось"; return 1; }
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print("ok версия %s, uptime %s с" % (d.get("version"), d.get("uptime_sec")))' "$health"
}

while :; do
  if out=$(check); then
    echo "$(date '+%F %T') ${out}"
    [ -n "${ONCE:-}" ] && exit 0
  else
    echo "$(date '+%F %T') ОТКАЗ ${HOST}: ${out}"
    notify "ОТКАЗ ${HOST}: ${out}"
    [ -n "${ONCE:-}" ] && exit 1
  fi
  sleep "$INTERVAL"
done
