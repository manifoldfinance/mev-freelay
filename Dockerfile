# syntax=docker/dockerfile:1
FROM golang:1.19 as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
ENV CGO_CFLAGS="-O -D__BLST_PORTABLE__"
ENV CGO_CFLAGS_ALLOW="-O -D__BLST_PORTABLE__"
RUN --mount=type=cache,target=/root/.cache/go-build go test ./... && go build -o ./bin/mev-freelay ./cmd/freelay/main.go && go build -o ./bin/purge ./cmd/purge/main.go && go build -o ./bin/backup ./cmd/backup/main.go && go build -o ./bin/restore ./cmd/restore/main.go && go build -o ./bin/migrate ./cmd/migrate/main.go && go build -o ./bin/compact ./cmd/compact/main.go && go build -o ./bin/import ./cmd/import/main.go

FROM alpine
RUN apk add --no-cache libgcc libstdc++ libc6-compat
RUN mkdir /app
WORKDIR /app

ARG SHA_VERSION
ENV SHA_VERSION=$SHA_VERSION

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/bin/mev-freelay /app/mev-freelay
COPY --from=builder /build/bin/purge /app/purge
COPY --from=builder /build/bin/backup /app/backup
COPY --from=builder /build/bin/restore /app/restore
COPY --from=builder /build/bin/migrate /app/migrate
COPY --from=builder /build/bin/compact /app/compact
COPY --from=builder /build/bin/import /app/import
COPY --from=builder /build/web /app/web
EXPOSE 50051
EXPOSE 50052
EXPOSE 50053
EXPOSE 50054
EXPOSE 9000
ENTRYPOINT ["/app/mev-freelay"]