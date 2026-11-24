#!/usr/bin/env bash
# JaguarGate Gate 5 — Self-Contained 4-Stage Bilateral Audit Runner
set -euo pipefail

GATEWAY_PORT="${1:-4010}"
MOCK_PORT="${2:-4020}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
BINARY_PATH="$REPO_ROOT/jgate"
FIXTURE_CFG="$SCRIPT_DIR/jaguargate.audit.yaml"

MOCK_PID=""
GATE_PID=""
RUNTIME_CFG=""

cleanup() {
    if [[ -n "$GATE_PID" ]]; then
        kill "$GATE_PID" 2>/dev/null || true
    fi
    if [[ -n "$MOCK_PID" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
    fi
    if [[ -n "$RUNTIME_CFG" && -f "$RUNTIME_CFG" ]]; then
        rm -f "$RUNTIME_CFG"
    fi
}
trap cleanup EXIT

if [[ ! -x "$BINARY_PATH" ]]; then
    echo "[i] Building static JaguarGate binary ($BINARY_PATH)..."
    (cd "$REPO_ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BINARY_PATH" ./cmd/jgate)
fi

if ! (exec 3<>"/dev/tcp/127.0.0.1/$MOCK_PORT") 2>/dev/null; then
    echo "[i] Starting bilateral mock_upstream.py on 127.0.0.1:$MOCK_PORT..."
    python3 "$SCRIPT_DIR/mock_upstream.py" "$MOCK_PORT" &
    MOCK_PID=$!
fi

if ! (exec 3<>"/dev/tcp/127.0.0.1/$GATEWAY_PORT") 2>/dev/null; then
    echo "[i] Starting JaguarGate on 127.0.0.1:$GATEWAY_PORT with fixture jaguargate.audit.yaml..."
    RUNTIME_CFG="$(mktemp /tmp/jaguargate-audit-runtime-XXXXXX.yaml)"
    sed -e "s/127.0.0.1:4010/127.0.0.1:$GATEWAY_PORT/g" \
        -e "s/127.0.0.1:4020/127.0.0.1:$MOCK_PORT/g" \
        "$FIXTURE_CFG" > "$RUNTIME_CFG"
    "$BINARY_PATH" serve -c "$RUNTIME_CFG" >/tmp/jaguargate-gate5-serve.log 2>&1 &
    GATE_PID=$!
fi

for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$GATEWAY_PORT") 2>/dev/null && (exec 3<>"/dev/tcp/127.0.0.1/$MOCK_PORT") 2>/dev/null; then
        break
    fi
    sleep 0.1
done

python3 "$SCRIPT_DIR/reproduce_audit.py" \
    "http://127.0.0.1:$GATEWAY_PORT" \
    "http://127.0.0.1:$MOCK_PORT" \
    "$BINARY_PATH" \
    "$FIXTURE_CFG"
