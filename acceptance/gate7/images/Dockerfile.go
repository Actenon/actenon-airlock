# Gate 7 Go compute: the unchanged Claude Code image plus a pinned Go toolchain.
# Airlock clears image environment variables, so Go's defaults live in $GOROOT/go.env.
FROM golang@sha256:2c4c60ef415fbfa5e90300722293bef36c5e63fae17570ce18f580af933dbd73 AS go
FROM actenon-airlock-claude-code:v1
COPY --from=go /usr/local/go /usr/local/go
# Offline and local only: no toolchain or module downloads. The build cache is
# larger than the 64 MiB /tmp, so it lives in the workspace's excluded .tmp.
RUN printf '%s\n' GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=mod \
        GOCACHE=/workspace/.tmp/go-build GOTELEMETRY=off >> /usr/local/go/go.env \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go \
    && ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && go version
