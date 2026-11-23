# ==============================================================================
# Stage 1: Static Binary Builder (Go 1.26, Non-Root Build Workspace)
# ==============================================================================
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN adduser -D -u 10001 builder \
    && mkdir -p /home/builder/src /home/builder/go \
    && chown -R builder:builder /home/builder

USER builder:builder
ENV GOPATH=/home/builder/go \
    GOCACHE=/home/builder/.cache/go-build \
    GOMODCACHE=/home/builder/go/pkg/mod

WORKDIR /home/builder/src

# Cache dependencies first (explicit non-root workspace path, never /)
COPY --chown=builder:builder go.mod go.sum /home/builder/src/
RUN go mod download

# Copy source and compile a stripped, 100% static binary (zero libc dependency)
COPY --chown=builder:builder . /home/builder/src/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /home/builder/src/jgate ./cmd/jgate

# ==============================================================================
# Stage 2: Minimal Hardened Distroless Runtime (~12MB, Non-Root, No Shell)
# ==============================================================================
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /home/builder/src/jgate /app/jgate
COPY --chown=nonroot:nonroot jaguargate.yaml /app/jaguargate.yaml

USER nonroot:nonroot

ENV JAGUARGATE_LISTEN_ADDR="0.0.0.0:4010"

EXPOSE 4010 9091

ENTRYPOINT ["/app/jgate"]
CMD ["serve", "-c", "/app/jaguargate.yaml"]