# syntax=docker/dockerfile:1
FROM golang:1.20-alpine as builder

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN --mount=type=cache,target=/root/.cache/go-build go mod download

ADD . .

# RUN --mount=type=cache,target=/root/.cache/go-build go test ./...

RUN apk add --no-cache gcc musl-dev git linux-headers
RUN --mount=type=cache,target=/root/.cache/go-build GOOS=linux go build -trimpath -ldflags "-s -linkmode external -extldflags '-static'" -o ./bin/mev-freelay ./main.go


FROM alpine
RUN apk add --no-cache libstdc++ libc6-compat
RUN mkdir /app
WORKDIR /app

ARG SHA_VERSION
ENV SHA_VERSION=$SHA_VERSION

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/bin/mev-freelay /app/mev-freelay
EXPOSE 50051 50052 9000 6060
ENTRYPOINT ["/app/mev-freelay"]