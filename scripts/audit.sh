#!/usr/bin/env bash
# ==============================================================================
# JaguarGate — Enterprise AppSec & Zero-CVE Audit Script (Tier 1)
# ==============================================================================
set -eo pipefail

export PATH="$PATH:$(go env GOPATH)/bin"
LOG_DIR="sec_audit_logs"
SUMMARY_FILE="$LOG_DIR/audit_summary.log"
IMAGE_NAME="${DOCKER_IMAGE_NAME:-jaguargate:latest}"
SKIPPED_CONTROLS=0

mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*

echo "===============================================================================" > "$SUMMARY_FILE"
echo "  JAGUARGATE ENTERPRISE SECURITY AUDIT SUMMARY: $(date -u '+%Y-%m-%d %H:%M:%SZ')" >> "$SUMMARY_FILE"
echo "===============================================================================" >> "$SUMMARY_FILE"

# --- 1. Static Analysis (go vet & race detector) ---
echo "⏳ [1/5] Running go vet and data-race detector..."
go vet ./... > "$LOG_DIR/govet.log" 2>&1
go test -race -count=1 ./... > "$LOG_DIR/gotest_race.log" 2>&1
echo "  [OK] Go Vet & Race Audit passed" >> "$SUMMARY_FILE"

# --- 2. GoSec (SAST static analysis) ---
echo "⏳ [2/5] Running GoSec (SAST)..."
if command -v gosec &>/dev/null; then
    gosec -fmt=text -out="$LOG_DIR/gosec.log" ./...
elif command -v docker &>/dev/null && docker info &>/dev/null; then
    docker run --rm \
        -e GOTOOLCHAIN=auto \
        -v gosec-gocache:/root/go \
        -v "$(pwd):/app" -w /app \
        securego/gosec:latest -exclude-dir=examples ./... 2>&1 | grep -v "^\\[gosec\\]" > "$LOG_DIR/gosec.log"
else
    echo "GoSec not installed locally and Docker daemon not reachable; control skipped." > "$LOG_DIR/gosec.log"
    SKIPPED_CONTROLS=$((SKIPPED_CONTROLS + 1))
fi
cat "$LOG_DIR/gosec.log" >> "$SUMMARY_FILE"

# --- 3. Govulncheck (Dependency Supply-Chain Audit) ---
echo "⏳ [3/5] Running Govulncheck..."
if command -v govulncheck &>/dev/null; then
    if govulncheck ./... > "$LOG_DIR/govulncheck.log" 2>&1; then
        echo "  [OK] Govulncheck: No supply-chain vulnerabilities found" >> "$SUMMARY_FILE"
    else
        VULN_STATUS=$?
        if grep -q -E "dial tcp|lookup vuln.go.dev" "$LOG_DIR/govulncheck.log"; then
            echo "govulncheck requires network access; skipped in offline environment." >> "$LOG_DIR/govulncheck.log"
            SKIPPED_CONTROLS=$((SKIPPED_CONTROLS + 1))
        else
            cat "$LOG_DIR/govulncheck.log" >> "$SUMMARY_FILE"
            exit "$VULN_STATUS"
        fi
    fi
else
    echo "govulncheck not installed; run 'go install golang.org/x/vuln/cmd/govulncheck@latest'; control skipped." > "$LOG_DIR/govulncheck.log"
    SKIPPED_CONTROLS=$((SKIPPED_CONTROLS + 1))
fi
cat "$LOG_DIR/govulncheck.log" >> "$SUMMARY_FILE"

# --- 4. Trivy (Docker Image CVE Scan) ---
echo "⏳ [4/5] Running Trivy container vulnerability scan..."
if command -v trivy &>/dev/null; then
    trivy image --exit-code 1 --quiet --severity HIGH,CRITICAL "$IMAGE_NAME" > "$LOG_DIR/trivy.log" 2>&1
elif command -v docker &>/dev/null && docker info &>/dev/null; then
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        -v trivy-cache:/root/.cache/ \
        aquasec/trivy image --exit-code 1 --quiet --severity HIGH,CRITICAL "$IMAGE_NAME" > "$LOG_DIR/trivy.log" 2>&1
else
    echo "Trivy not installed and Docker daemon not reachable; container image scan skipped." > "$LOG_DIR/trivy.log"
    SKIPPED_CONTROLS=$((SKIPPED_CONTROLS + 1))
fi
cat "$LOG_DIR/trivy.log" >> "$SUMMARY_FILE"

# --- 5. Built-in OWASP Red-Teaming (jgate pounce) ---
echo "⏳ [5/5] Running built-in OWASP LLM Top 10 Red-Teaming battery..."
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ./jgate ./cmd/jgate
./jgate pounce > "$LOG_DIR/pounce.log" 2>&1
cat "$LOG_DIR/pounce.log" >> "$SUMMARY_FILE"

echo "==============================================================================="
if [ "$SKIPPED_CONTROLS" -gt 0 ]; then
    echo "⚠️  Enterprise AppSec Audit INCOMPLETE ($SKIPPED_CONTROLS control(s) skipped/unavailable)."
    echo "📄 Aggregated summary: $SUMMARY_FILE"
    echo "==============================================================================="
    if [ "${ALLOW_PARTIAL_AUDIT:-0}" != "1" ]; then
        echo "❌ Audit failed: all controls are mandatory for enterprise release certification."
        echo "   (Set ALLOW_PARTIAL_AUDIT=1 to bypass for local developer smoke testing)"
        exit 1
    fi
else
    echo "✅ Enterprise AppSec Audit FULLY PASSED (all controls executed and clean)."
    echo "📄 Aggregated summary: $SUMMARY_FILE"
    echo "==============================================================================="
fi
