FROM golang:1.26.10-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server  && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker
FROM alpine:3.23
RUN apk add --no-cache ca-certificates wget && addgroup -S app && adduser -S app -G app  && mkdir -p /var/lib/sela/quarantine && chown -R app:app /var/lib/sela && chmod 0700 /var/lib/sela/quarantine
WORKDIR /app
COPY --from=build /out/server /out/worker /app/
USER app
EXPOSE 8080
VOLUME ["/var/lib/sela"]
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/server"]
