#!/usr/bin/env bash
#
# check.sh — проверка работоспособности API AlfaGen (Enterprise Vibe Coding).
#
# Выполняет тестовый chat-completion запрос к модели и выводит ответ.
#
# Переменные окружения (с дефолтами):
#   ALFAGEN_API_KEY   — API-ключ (обязательно, без префикса "Bearer")
#   ALFAGEN_BASE_URL  — базовый URL, дефолт https://alfagen.alfabank.ru/continue-dev/v1
#   ALFAGEN_MODEL     — модель, дефолт deepseek-ai/DeepSeek-V4-Flash-0731
#
# Флаги:
#   -h, --help        — показать справку
#   -v, --verbose     — подробный вывод (заголовки, тело запроса)
#
# Примеры:
#   export ALFAGEN_API_KEY="ваш_ключ"
#   bash specs/api-alfagen/check.sh
#   bash specs/api-alfagen/check.sh -v
#   ALFAGEN_BASE_URL="https://alfagen.alfabank.ru/continue-dev/v1" bash specs/api-alfagen/check.sh
#
# Exit codes:
#   0 — успех
#   1 — ошибка (нет ключа, сеть, HTTP-ошибка, ошибка разбора)

set -euo pipefail

# --- Конфигурация по умолчанию ---------------------------------------------
DEFAULT_BASE_URL="https://alfagen.alfabank.ru/continue-dev/v1"
DEFAULT_MODEL="deepseek-ai/DeepSeek-V4-Flash-0731"

VERBOSE=0

usage() {
  cat <<'EOF'
Использование: check.sh [-h] [-v]

Проверка работоспособности API AlfaGen (chat completion).

Переменные окружения:
  ALFAGEN_API_KEY   API-ключ (обязательно, без префикса "Bearer")
  ALFAGEN_BASE_URL  базовый URL (дефолт: https://alfagen.alfabank.ru/continue-dev/v1)
  ALFAGEN_MODEL     модель (дефолт: deepseek-ai/DeepSeek-V4-Flash-0731)

Флаги:
  -h, --help    показать эту справку
  -v, --verbose подробный вывод
EOF
}

# --- Разбор аргументов ------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    *)
      echo "Ошибка: неизвестный аргумент: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# --- Загрузка ключа из .env (если файл существует) --------------------------
# Приоритет: переменная окружения ALFAGEN_API_KEY > файл .env в корне репозитория.
# Это позволяет работать на любом ПК: пользователь кладёт ключ в .env.
ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.env"
if [[ -z "${ALFAGEN_API_KEY:-}" && -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

# --- Проверка ключа ---------------------------------------------------------
if [[ -z "${ALFAGEN_API_KEY:-}" ]]; then
  echo "Ошибка: API-ключ AlfaGen не найден." >&2
  echo "Положите ключ в файл .env в корне репозитория:" >&2
  echo "  cp specs/api-alfagen/.env.example .env" >&2
  echo "  # вставьте ключ из раздела «Enterprise Vibe Coding» на https://alfagen.alfabank.ru/" >&2
  echo "или задайте переменную окружения: export ALFAGEN_API_KEY=\"ваш_ключ\"" >&2
  exit 1
fi

BASE_URL="${ALFAGEN_BASE_URL:-$DEFAULT_BASE_URL}"
MODEL="${ALFAGEN_MODEL:-$DEFAULT_MODEL}"

# --- Формирование запроса ---------------------------------------------------
ENDPOINT="${BASE_URL%/}/chat/completions"

# Тело запроса собираем через heredoc, чтобы избежать проблем с экранированием.
read -r -d '' PAYLOAD <<EOF || true
{
  "model": "${MODEL}",
  "messages": [
    { "role": "system", "content": "Ты — ассистент для проверки API." },
    { "role": "user", "content": "Ответь одним словом: работает?" }
  ],
  "temperature": 0.2,
  "max_tokens": 64,
  "stream": false
}
EOF

if [[ "$VERBOSE" -eq 1 ]]; then
  echo "== Конфигурация =="
  echo "Endpoint: ${ENDPOINT}"
  echo "Model:    ${MODEL}"
  echo "API key:  ${ALFAGEN_API_KEY:0:4}... (скрыт)"
  echo
  echo "== Тело запроса =="
  echo "${PAYLOAD}"
  echo
fi

# --- Выполнение запроса -----------------------------------------------------
# ВАЖНО: заголовок Authorization содержит ключ БЕЗ префикса "Bearer".
CURL_ARGS=(
  -sS
  --max-time 60
  -X POST
  "${ENDPOINT}"
  -H "Authorization: ${ALFAGEN_API_KEY}"
  -H "Content-Type: application/json"
  -d "${PAYLOAD}"
)

if [[ "$VERBOSE" -eq 1 ]]; then
  CURL_ARGS+=(-w $'\n\n== HTTP %{http_code}, время %{time_total}s ==\n')
fi

echo "== Запрос к AlfaGen =="
RESPONSE="$(curl "${CURL_ARGS[@]}")" || {
  code=$?
  echo "Ошибка сети при обращении к ${ENDPOINT} (curl exit code: ${code})." >&2
  echo "Проверьте подключение, наличие корневого сертификата «Russian Trusted Root CA»" >&2
  echo "и корректность ALFAGEN_BASE_URL." >&2
  exit 1
}

# --- Разбор ответа ----------------------------------------------------------
# Пытаемся извлечь текст ответа через python3 (доступен на macOS/Linux).
# Если python3 недоступен — выводим сырой ответ.
if command -v python3 >/dev/null 2>&1; then
  CONTENT="$(printf '%s' "$RESPONSE" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception as e:
    print("", end="")
    sys.exit(0)
if "error" in data:
    err = data["error"]
    print("API_ERROR: " + str(err.get("message", err)), end="")
    sys.exit(0)
choices = data.get("choices", [])
if choices:
    msg = choices[0].get("message", {})
    print(msg.get("content", ""), end="")
else:
    print("", end="")
')"

  if [[ -n "$CONTENT" ]]; then
    echo "== Ответ модели =="
    echo "${CONTENT}"
    echo
    echo "✅ API работает."
    exit 0
  fi
fi

# Если python3 недоступен или ответ не распознан — выводим сырой ответ.
echo "== Сырой ответ =="
echo "${RESPONSE}"
echo

# Проверяем, не является ли ответ ошибкой HTTP.
if [[ "$RESPONSE" == *'"error"'* ]]; then
  echo "❌ API вернул ошибку (см. выше)." >&2
  exit 1
fi

echo "⚠️  Не удалось распознать ответ. Проверьте формат контракта (см. specs/api-alfagen/alfagen-api-contract.md)." >&2
exit 1