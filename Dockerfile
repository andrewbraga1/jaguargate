# ==============================================================================
# Stage 1: Static Binary Builder (Go 1.23)
# ==============================================================================
FROM golang:1.23-alpine AS builder

WORKDIR /src

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy source and compile a stripped, 100% static binary (zero libc dependency)
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /out/jgate ./cmd/jgate

# ==============================================================================
# Stage 2: Minimal Hardened Distroless Runtime (~12MB, Non-Root, No Shell)
# ==============================================================================
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/jgate /app/jgate
COPY jaguargate.yaml /app/jaguargate.yaml

USER nonroot:nonroot

EXPOSE 4010 9091

ENTRYPOINT ["/app/jgate"]
CMD ["serve", "-c", "/app/jaguargate.yaml"]