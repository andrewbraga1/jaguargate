# ==============================================================================
# STAGE 1: Test & Build Environment (Go 1.23 + GCC for -race detector)
# ==============================================================================
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates build-base

WORKDIR /app

# Cache dependencies first
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Build a 100% static binary (zero C dependencies) stripped of debug symbols (-s -w)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /jgate ./cmd/jgate

# ==============================================================================
# STAGE 2: Zero-Trust Production Image (FROM scratch -> ~8MB, no shell!)
# ==============================================================================
FROM scratch

# Copy TLS certificates for HTTPS upstream calls (OpenAI / Anthropic)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary and default configuration contract
COPY --from=builder /jgate /jgate
COPY --from=builder /app/configs/jaguargate.yaml /configs/jaguargate.yaml

EXPOSE 4010 4011

ENTRYPOINT ["/jgate"]
CMD ["start", "-c", "/configs/jaguargate.yaml"]