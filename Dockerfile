# syntax=docker/dockerfile:1
FROM golang:latest AS build
ENV GOARCH=amd64 GOOS=linux
# force the GO_VERSION above to be in sync with the `toolchain` directive in go.mod.
# This avoids downloading other Go Toolchains, which happens silently and would slow
# down our image builds.
ENV GOTOOLCHAIN=path
ENV GOPRIVATE=github.com/infracost/*

WORKDIR /go/src/app

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -v \
    -ldflags "-s -w" \
    -trimpath \
    -o /bin/passkey-proxy \
    .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /bin/passkey-proxy /app/passkey-proxy
USER nonroot:nonroot
ENTRYPOINT ["/app/passkey-proxy"]
