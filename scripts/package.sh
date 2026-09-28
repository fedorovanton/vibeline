#!/usr/bin/env bash
#
# Сборка архива решения для загрузки.
#
# В архив попадает только исходный код. Не попадают: секреты, репозиторий,
# бинарники, каталоги сборки и зависимостей, корпуса и отчёты прогонов,
# а также всё скрытое — кроме точечных файлов из списка DOT_ALLOW.
#
# После сборки содержимое проверяется: запрещённые пути, скрытые каталоги,
# исполняемые файлы по сигнатуре, ключи в содержимом, крупные файлы, а затем
# сборка и go vet из распакованной копии — без .git, ровно так, как архив
# увидит проверяющий. Ошибка здесь стоит дороже всего остального, поэтому
# проверки не пропускаются и их результат определяет код возврата.
#
# Переменные окружения:
#   SKIP_BUILD=1  не собирать распакованную копию (например, без сети и без
#                 кэша модулей Go). Пропуск печатается явно и проверкой не
#                 считается.
#   QUIET=1       не печатать полный список файлов архива.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
NAME="ai-gateway-$(date +%Y%m%d-%H%M)"
OUT="${ROOT}/dist/${NAME}.zip"

mkdir -p "${ROOT}/dist"
rm -f "${OUT}"

echo "== Сборка ${NAME}.zip =="

# Точечные файлы, которые в архиве нужны. Единственный список: по нему
# файлы возвращаются в архив и по нему же проверяется, что ничего лишнего
# скрытого не просочилось.
DOT_ALLOW=(.gitignore .env.example .keep .dockerignore .golangci.yml)

# Скрытое не перечисляется поимённо. Каталоги вроде .git, .claude, .agents,
# .idea, .vscode, .github заводятся и исчезают сами, и поимённый список
# отстаёт от реальности молча — архив уезжает с лишним, а проверка молчит.
# Поэтому правило обратное: не идёт ничего, начинающееся с точки на любой
# глубине, а нужное возвращается ниже. Звёздочка в zip покрывает и слеш,
# так что '.*' убирает и сам каталог, и всё его содержимое.
zip -r -q "${OUT}" . \
  -x '.*' \
  -x '*/.*' \
  -x '*.env' \
  -x 'dist/*' \
  -x 'bin/*' \
  -x 'reports/*' \
  -x 'testdata/corpus*' \
  -x '*/testdata/corpus*' \
  -x '*.jsonl' \
  -x 'ai-gateway' \
  -x 'tools/*/corpusgen' \
  -x 'tools/*/qualitycheck' \
  -x 'tools/*/loadtest' \
  -x '*.test' \
  -x '*.prof' \
  -x '*.zip' \
  -x 'docs/init/*'

# Возврат разрешённых точечных файлов. Скрытые каталоги при обходе
# отсекаются: разрешение по имени файла не должно вытаскивать .keep
# из .claude или .env.example из .agents.
DOT_FIND=()
for name in "${DOT_ALLOW[@]}"; do
  DOT_FIND+=(-o -name "${name}")
done

DOT_KEEP=()
while IFS= read -r path; do
  DOT_KEEP+=("${path#./}")
done < <(find . -type d -name '.?*' -prune -o -type f \( -false "${DOT_FIND[@]}" \) -print)

if [ ${#DOT_KEEP[@]} -gt 0 ]; then
  zip -q -g "${OUT}" "${DOT_KEEP[@]}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# Архив распаковывается, и список снимается с распакованного дерева один раз
# в файл. Не с `unzip -Z1`: тот печатает кириллические имена знаками «?», и
# проверка содержимого по такому пути не нашла бы файл. И не потоком: `unzip |
# grep -q` под pipefail при раннем выходе grep получает SIGPIPE, и совпадение
# молча превращается в «не найдено».
EXTRACT="${TMP}/src"
mkdir -p "${EXTRACT}"
unzip -q "${OUT}" -d "${EXTRACT}"
LIST="${TMP}/list.txt"
LIST_ALL="${TMP}/list-all.txt"
(cd "${EXTRACT}" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) > "${LIST}"
(cd "${EXTRACT}" && find . -mindepth 1 | sed 's|^\./||' | LC_ALL=C sort) > "${LIST_ALL}"

if [ "${QUIET:-0}" != "1" ]; then
  echo
  echo "== Содержимое архива =="
  sed 's/^/  /' "${LIST}"
fi

echo
echo "== Проверка архива =="

FAIL=0
ok()   { echo "  ок      $1"; }
bad()  { echo "  ОШИБКА  $1"; FAIL=1; }
show() { head -10 | sed 's/^/          /'; }

# 1. Запрещённые пути. Каждый шаблон проверяется и печатается отдельно:
# по выводу видно, что именно искалось, а не только что «всё хорошо».
# Шаблон и его описание — два параллельных массива: в самих шаблонах есть
# «|», поэтому разбирать их из одной строки с разделителем нельзя.
FORBID_RE=(
  '(^|/)\.git(/|$)'
  '(^|/)\.(claude|agents)/'
  '^(bin|dist|reports)/'
  '(^|/)(node_modules|vendor)/'
  '\.jsonl$'
  '\.(zip|tar|tgz|gz)$'
  '\.(test|prof|exe|so|dylib|o|a)$'
  '^ai-gateway$'
)
FORBID_WHAT=(
  'каталог .git'
  'рабочие каталоги агентов .claude/ и .agents/'
  'каталоги сборки и прогонов bin/, dist/, reports/'
  'каталоги зависимостей node_modules/, vendor/'
  'корпуса *.jsonl'
  'вложенные архивы'
  'артефакты сборки и профилирования'
  'собранный бинарник сервиса в корне'
)
for i in "${!FORBID_RE[@]}"; do
  hits="$(grep -E "${FORBID_RE[$i]}" "${LIST}" || true)"
  if [ -n "${hits}" ]; then
    bad "${FORBID_WHAT[$i]}"
    echo "${hits}" | show
  else
    ok "нет: ${FORBID_WHAT[$i]}"
  fi
done

# Файлы окружения. .env.example — единственный разрешённый: в нём нет
# ключа, а его содержимое проверяется на ключ ниже вместе со всем архивом.
hits="$(grep -E '(^|/)\.env(\.[^/]+)?$' "${LIST}" | grep -vE '(^|/)\.env\.example$' || true)"
if [ -n "${hits}" ]; then
  bad "файлы .env"
  echo "${hits}" | show
else
  ok "нет: файлов .env (разрешён только .env.example)"
fi

# Приватные ключи и сертификаты: разрешены только открытые корневые
# сертификаты в deploy/certs/ (см. .gitignore).
hits="$(grep -E '\.(pem|key|p12|pfx|crt)$' "${LIST}" | grep -vE '^deploy/certs/[^/]+\.pem$' || true)"
if [ -n "${hits}" ]; then
  bad "файлы ключей и сертификатов вне deploy/certs/"
  echo "${hits}" | show
else
  ok "нет: файлов ключей вне deploy/certs/"
fi

# 2. Скрытые пути. Проверка ловит не известные имена, а само появление в
# архиве любого сегмента, начинающегося с точки, кроме разрешённых. Шаблон
# собирается из DOT_ALLOW, чтобы список не разъехался с тем, по которому
# файлы возвращались.
DOT_RE="$(printf '%s\n' "${DOT_ALLOW[@]}" | sed 's/\./\\./g' | paste -sd'|' -)"
DOT_FOUND="$(grep -E '(^|/)\.' "${LIST_ALL}" | grep -vE "(^|/)(${DOT_RE})\$" || true)"
if [ -n "${DOT_FOUND}" ]; then
  bad "скрытые пути вне списка разрешённых (${DOT_ALLOW[*]})"
  echo "${DOT_FOUND}" | show
else
  ok "нет: скрытых путей вне списка ${DOT_ALLOW[*]}"
fi

# 3. Исполняемые файлы по сигнатуре, а не по имени: собранный инструмент
# может лечь под любым именем, и поимённый список его пропустит.
# ELF 7f454c46, Mach-O feedface/feedfacf/cefaedfe/cffaedfe, fat cafebabe, PE 4d5a.
BIN_FOUND=""
while IFS= read -r f; do
  magic="$(head -c 4 "${EXTRACT}/${f}" 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)"
  case "${magic}" in
    7f454c46|feedface|feedfacf|cefaedfe|cffaedfe|cafebabe|4d5a*) BIN_FOUND+="${f}"$'\n' ;;
  esac
done < "${LIST}"
if [ -n "${BIN_FOUND}" ]; then
  bad "исполняемые файлы (ELF, Mach-O, PE)"
  printf '%s' "${BIN_FOUND}" | show
else
  ok "нет: исполняемых файлов ELF, Mach-O, PE"
fi

# 4. Секреты в содержимом. Ключ AlfaGen — основной риск: он лежит в .env,
# который исключён, но мог попасть в конфиг, в код или в документацию.
#
# Значения-заглушки в файлах-примерах ключом не являются и архив не портят.
# Отсеиваются по характерным словам, а не по имени файла: реальный ключ,
# случайно попавший в .env.example, обязан быть найден.
PLACEHOLDER='your-|ваш|<|xxx|changeme|example|placeholder|замен'

# Совпавшие строки не печатаются: в них и был бы ключ. Печатается только
# «файл:строка».
HITS="$(grep -rnIE 'ALFAGEN_API_KEY[[:space:]]*[=:][[:space:]]*[A-Za-z0-9_-]{16,}' "${EXTRACT}" 2>/dev/null \
        | grep -ivE "${PLACEHOLDER}" | cut -d: -f1,2 || true)"
if [ -n "${HITS}" ]; then
  bad "похожее на реальный ключ AlfaGen"
  echo "${HITS}" | sed "s|${EXTRACT}/||" | show
else
  ok "нет: значения ALFAGEN_API_KEY"
fi

HITS="$(grep -rIlE '(sk-[A-Za-z0-9]{20,}|BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,})' "${EXTRACT}" 2>/dev/null || true)"
if [ -n "${HITS}" ]; then
  bad "похожее на секрет: sk-…, приватный ключ, ключ AWS или токен GitHub"
  echo "${HITS}" | sed "s|${EXTRACT}/||" | show
else
  ok "нет: sk-…, приватных ключей, ключей AWS и токенов GitHub"
fi

# Ключи потребителей в YAML. Разрешены только пустые значения и
# демонстрационные ключи с суффиксом -for-jury: рабочий ключ, вписанный в
# config.yaml вместо переменной окружения, уехал бы в архив незамеченным.
HITS="$(grep -rInE --include='*.yaml' --include='*.yml' '^[[:space:]]*api_key:[[:space:]]*[^[:space:]#]' "${EXTRACT}" 2>/dev/null \
        | grep -vE 'api_key:[[:space:]]*(""|'"''"'|[A-Za-z0-9_-]+-for-jury)([[:space:]]|#|$)' | cut -d: -f1,2 || true)"
if [ -n "${HITS}" ]; then
  bad "ключ потребителя в YAML, не являющийся демонстрационным (*-for-jury)"
  echo "${HITS}" | sed "s|${EXTRACT}/||" | show
else
  ok "нет: ключей потребителей в YAML, кроме демонстрационных *-for-jury"
fi

# 5. Крупные файлы: автопроверка просит лёгкий архив. Это ошибка, а не
# предупреждение: собранный бинарник инструмента весит мегабайты и попадает
# сюда незаметно.
LARGE="$(find "${EXTRACT}" -type f -size +1M 2>/dev/null || true)"
if [ -n "${LARGE}" ]; then
  bad "файлы больше 1 МБ"
  echo "${LARGE}" | sed "s|${EXTRACT}/||" | show
else
  ok "нет: файлов больше 1 МБ"
fi

# 6. Сборка из распакованной копии. Репозитория там нет, поэтому проверяется
# ровно то, что получит проверяющий: все четыре модуля собираются и проходят
# go vet без .git и без файлов, исключённых выше.
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  echo "  ПРОПУСК сборка распакованной копии (SKIP_BUILD=1) — не проверено"
elif ! command -v go >/dev/null 2>&1; then
  echo "  ПРОПУСК сборка распакованной копии: go не найден — не проверено"
else
  for m in . tools/corpusgen tools/loadtest tools/qualitycheck; do
    [ -f "${EXTRACT}/${m}/go.mod" ] || { bad "в архиве нет модуля ${m}"; continue; }
    if log="$(cd "${EXTRACT}/${m}" && go build ./... 2>&1 && go vet ./... 2>&1)"; then
      ok "собирается и проходит go vet без .git: ${m}"
    else
      bad "сборка или go vet из архива: ${m}"
      echo "${log}" | show
    fi
  done
fi

SIZE="$(du -h "${OUT}" | cut -f1)"
COUNT="$(wc -l < "${LIST}" | tr -d ' ')"

echo
echo "  размер:  ${SIZE}"
echo "  файлов:  ${COUNT}"
echo "  путь:    ${OUT}"

if [ "${FAIL}" -ne 0 ]; then
  echo
  echo "== ПРОВЕРКА НЕ ПРОЙДЕНА: архив загружать нельзя =="
  exit 1
fi

echo
echo "== Проверка пройдена =="
