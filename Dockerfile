# anvilkit-agent-mcp: built from this repository alone (the build context is
# the repository root; nothing from the parent checkout is read). The
# generated contract module is an ordinary versioned dependency resolved
# through GOPROXY: pass --build-arg GOPROXY=... (and GONOSUMDB=... for a
# module that is not in the public checksum database yet) to build against a
# private or local module proxy. The anvilkit_mcp migrations are applied by
# the parent repository's migration Job (jobs/migration) until MCP owns them;
# this image never runs DDL.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG GOPROXY=https://proxy.golang.org,direct
ARG GONOSUMDB=
ENV GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOPROXY=$GOPROXY GONOSUMDB=$GONOSUMDB
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/anvilkit-agent-mcp ./cmd/anvilkit-agent-mcp

# Runtime: the binary, the reviewed secret-free configuration file and a
# non-root user. Listeners, the NATS and Control placements and the secrets
# (the database URL, or a mounted secret file whose rotation publishes a new
# configuration generation) arrive through the allowlisted ANVILKIT_MCP_*
# environment; the file itself may be replaced by mounting one at the path
# named by ANVILKIT_MCP_CONFIG.
FROM alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a
# Alpine zlib CVE-2026-4738: the base ships 1.3.2-r1 and v3.24/main serves
# the fixed 1.4-r0. A floor, not a pin: the build fails while the index
# lacks it, and drop this step once the alpine:3.24 pin ships >= 1.4-r0.
# OpenSSL (libcrypto3, libssl3) is held at the 2026-11-23 scan's fixed
# 3.5.9-r1 the same way.
RUN apk add --no-cache 'zlib>=1.4-r0' 'libcrypto3>=3.5.9-r1' 'libssl3>=3.5.9-r1'
COPY --from=build /out/anvilkit-agent-mcp /usr/local/bin/anvilkit-agent-mcp
COPY config.yaml /etc/anvilkit/anvilkit-agent-mcp/config.yaml
ENV ANVILKIT_MCP_CONFIG=/etc/anvilkit/anvilkit-agent-mcp/config.yaml
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/anvilkit-agent-mcp"]
