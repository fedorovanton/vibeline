# Сборка статического бинарника.
#
# CGO отключён: бинарник не зависит от системных библиотек и запускается в
# образе без дистрибутива. Зависимости скачиваются отдельным слоем, чтобы
# правка кода не инвалидировала кеш модулей.
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/ai-gateway ./cmd/ai-gateway

# Корневые сертификаты Минцифры добавляются к стандартному набору, а не
# заменяют его: модель подписана ими, всё остальное — обычными корнями.
#
# Расхождение проявляется только в контейнере. На машине разработчика вызов
# модели проходит, потому что сертификат стоит в системной связке по
# инструкции организаторов; в образе его нет, и обращение к модели
# отказывает на проверке сертификата уже после успешного маскирования.
COPY deploy/certs/russian-trusted-ca.pem /tmp/extra-ca.pem
RUN cat /etc/ssl/certs/ca-certificates.crt /tmp/extra-ca.pem > /out/ca-certificates.crt

# Рабочий образ.
#
# Без оболочки и пакетного менеджера: поверхность атаки минимальна, а сервису
# для работы нужен только бинарник, конфигурация и корневые сертификаты для
# вызова модели по HTTPS.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=build /out/ai-gateway /app/ai-gateway
COPY --from=build /out/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY config.yaml /app/config.yaml

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/app/ai-gateway"]
CMD ["-config", "/app/config.yaml", "-env", "/app/.env"]
