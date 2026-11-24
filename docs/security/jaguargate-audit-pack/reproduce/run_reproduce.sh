#!/usr/bin/env bash
# JaguarGate Gate 5 — Self-Contained Isolated 4-Stage Bilateral Audit Runner
set -euo pipefail

GATEWAY_PORT="${1:-4010}"
MOCK_PORT="${2:-4020}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
FIXTURE_CFG="$SCRIPT_DIR/jaguargate.audit.yaml"

MOCK_PID=""
GATE_PID=""
RUNTIME_CFG=""
ISOLATED_BIN=""
BINARY_PATH=""

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
    if [[ -n "$ISOLATED_BIN" && -f "$ISOLATED_BIN" ]]; then
        rm -f "$ISOLATED_BIN"
    fi
}
trap cleanup EXIT

if [[ "${JAGUARGATE_EXTERNAL_TARGET:-0}" == "1" ]]; then
    echo "[i] External target mode enabled (e.g. containerized gateway on :$GATEWAY_PORT)."
    BINARY_PATH="${JAGUARGATE_BINARY_PATH:-$REPO_ROOT/jgate}"
    RUNTIME_CFG="${JAGUARGATE_RUNTIME_CFG:-$FIXTURE_CFG}"
else
    # Fail loudly if ports are occupied by uncontrolled processes instead of silently reusing unknown binaries
    if (exec 3<>"/dev/tcp/127.0.0.1/$MOCK_PORT") 2>/dev/null; then
        echo "[!] Port 127.0.0.1:$MOCK_PORT is already in use. Stop existing process or choose an unused port."
        exit 1
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$GATEWAY_PORT") 2>/dev/null; then
        echo "[!] Port 127.0.0.1:$GATEWAY_PORT is already in use. Stop existing process or choose an unused port."
        exit 1
    fi

    # Always compile a fresh isolated binary from the current working tree into a temporary target
    ISOLATED_BIN="$(mktemp /tmp/jgate-audit-bin-XXXXXX)"
    echo "[i] Building fresh isolated JaguarGate binary ($ISOLATED_BIN)..."
    (cd "$REPO_ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$ISOLATED_BIN" ./cmd/jgate)
    BINARY_PATH="$ISOLATED_BIN"

    echo "[i] Starting controlled bilateral mock_upstream.py on 127.0.0.1:$MOCK_PORT..."
    python3 "$SCRIPT_DIR/mock_upstream.py" "$MOCK_PORT" &
    MOCK_PID=$!

    RUNTIME_CFG="$(mktemp /tmp/jaguargate-audit-runtime-XXXXXX.yaml)"
    sed -e "s/127.0.0.1:4010/127.0.0.1:$GATEWAY_PORT/g" \
        -e "s/127.0.0.1:4020/127.0.0.1:$MOCK_PORT/g" \
        "$FIXTURE_CFG" > "$RUNTIME_CFG"

    echo "[i] Starting controlled JaguarGate ($BINARY_PATH) on 127.0.0.1:$GATEWAY_PORT..."
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
    "$RUNTIME_CFG" \
    "$FIXTURE_CFG"
