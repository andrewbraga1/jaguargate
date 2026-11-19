#!/usr/bin/env bash
# JaguarGate Gate 5 Independent Community Reproduction Script
set -e

PORT="${1:-4010}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo " JaguarGate Gate 5 Community Audit Verifier"
echo " Target port: $PORT"
echo "=========================================================="

# Check if target is running
if ! (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    echo "[!] JaguarGate is not running on 127.0.0.1:$PORT."
    echo "[i] Start JaguarGate in another terminal:"
    echo "    jgate serve -c jaguargate.yaml"
    echo "    (and if needed: python3 reproduce/mock_upstream.py 4020)"
    exit 1
fi

python3 "$SCRIPT_DIR/reproduce_audit.py" "http://127.0.0.1:$PORT"
