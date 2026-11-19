#!/usr/bin/env bash
# JaguarGate Gate 5 — 4-Quadrant Bilateral Audit Verifier Runner
set -euo pipefail

GATEWAY_PORT="${1:-4010}"
MOCK_PORT="${2:-4020}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo " JaguarGate Gate 5 — 4-Quadrant Bilateral Audit Verifier"
echo " Gateway:       http://127.0.0.1:$GATEWAY_PORT"
echo " Mock Upstream: http://127.0.0.1:$MOCK_PORT"
echo "=========================================================="

if ! (exec 3<>"/dev/tcp/127.0.0.1/$GATEWAY_PORT") 2>/dev/null; then
    echo "[!] JaguarGate is not running on 127.0.0.1:$GATEWAY_PORT."
    echo "[i] Start mock upstream and JaguarGate:"
    echo "    python3 $SCRIPT_DIR/mock_upstream.py $MOCK_PORT"
    echo "    ./jgate serve -c jaguargate.yaml"
    exit 1
fi

if ! (exec 3<>"/dev/tcp/127.0.0.1/$MOCK_PORT") 2>/dev/null; then
    echo "[!] Bilateral mock_upstream.py is not running on 127.0.0.1:$MOCK_PORT."
    exit 1
fi

python3 "$SCRIPT_DIR/reproduce_audit.py" "http://127.0.0.1:$GATEWAY_PORT" "http://127.0.0.1:$MOCK_PORT"
