ARG BUILD_IMAGE=golang:1.25
ARG RUNTIME_IMAGE=alpine:3.19

FROM ${BUILD_IMAGE} AS build
WORKDIR /src
ARG GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY skills ./skills
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/Mininglamp-OSS/octo-cli/cmd.Version=${VERSION}" \
    -o /out/octo-cli ./cmd/octo-cli

FROM ${RUNTIME_IMAGE}
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/octo-cli /usr/local/bin/octo-cli
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/octo-cli"]
