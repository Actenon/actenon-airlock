# The agent's image plus a pinned Go toolchain and your module's dependencies, for
# `airlock protect --image ... --tests ...` on a Go project. Build it from your project:
#
#   docker build -f Dockerfile.go -t my-project-airlock:go /path/to/your/project
#
# The sealed container has no network, so everything `go vet` and `go test` need must be in
# the image. Dependencies are downloaded here, at build time, from go.mod and go.sum and
# checked against go.sum; the agent cannot change them. Same recipe as the Gate 7 Go image.
ARG AGENT_IMAGE=actenon-airlock-claude-code:v1
FROM golang@sha256:2c4c60ef415fbfa5e90300722293bef36c5e63fae17570ce18f580af933dbd73 AS go
WORKDIR /deps
COPY go.mod go.sum* ./
ENV GOMODCACHE=/opt/go-modules GOFLAGS=-mod=mod GOTOOLCHAIN=local
RUN mkdir -p /opt/go-modules && go mod download && chmod -R a+rX /opt/go-modules

FROM ${AGENT_IMAGE}
COPY --from=go /usr/local/go /usr/local/go
COPY --from=go /opt/go-modules /opt/go-modules
# Airlock clears image environment variables, so Go's settings live in $GOROOT/go.env.
RUN printf '%s\n' GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=mod \
        GOMODCACHE=/opt/go-modules GOTELEMETRY=off >> /usr/local/go/go.env \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go \
    && ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && go version
