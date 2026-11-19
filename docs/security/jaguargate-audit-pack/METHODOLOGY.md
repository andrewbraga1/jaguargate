# 🏛️ JaguarGate Automated Security Verification Methodology

## 1. Overview & Scope Boundaries

This document describes the automated internal security test methodology executed against **JaguarGate** using the **Maestro Gate 5 Bilateral 4-Quadrant Protocol**.

- **Scope:** Validates deterministic HTTP/SSE/NDJSON/MCP proxy behavior, reversible PII vault isolation, `restore_secrets: false` enforcement, active output secret DLP (`JG-SEC-503`), Brazilian PII detectors (formatted & Mod-11 raw CPF, numeric & 2026 alphanumeric CNPJ, BR mobile/landline phone), Luhn credit card verification, and tool-call pruning veto headers (`X-JaguarGate-Veto`, `X-JaguarGate-Pruned-Tools`).
- **Explicit Limitation:** Automated internal suites verify only the configured policies, parsers, and synthetic vectors listed in `reproduce/test_vectors.json`. They do **not** replace external independent penetration testing, application-layer business authorization (e.g., RBAC/spending limits inside Pydantic AI), or adversarial evaluation of natural-language paraphrases outside configured signatures.

---

## 2. The 4-Quadrant Bilateral Invariant Protocol (Kaizen Standard)

Every vector in `reproduce/reproduce_audit.py` MUST verify **both sides of the network transaction** so that an HTTP 200 response can never mask an upstream leak:

1. **Quadrant 1 — Ingress Injection:**
   Sends canonical JSON payloads or raw wire-level byte sequences (`raw_body` bypassing `json.dumps` deduplication) with synthetic Brazilian PII, credentials, SSE streaming requests, or adversarial framing.
2. **Quadrant 2 — Upstream Egress Capture (Mandatory):**
   `reproduce/mock_upstream.py` captures the exact raw bytes of every incoming HTTP request and exposes them via `GET /_mock/last_request`. For every PII/secret vector, the runner asserts:
   - `must_not_reach_upstream`: raw sensitive strings MUST NOT exist in the captured upstream body.
   - `must_reach_upstream_masked`: expected `<JG_PII_*` or `jg_untrusted` marker MUST exist in the captured upstream body (proving the detector fired).
   - `must_reach_upstream_verbatim`: benign negative controls (e.g., Luhn-invalid 16-digit serial numbers) MUST arrive intact without false-positive masking.
3. **Quadrant 3 — Client Response & Output Policy:**
   The mock upstream echoes any `<JG_PII_...>` tokens it receives (in both JSON and fragmented SSE frames). The runner asserts:
   - `must_restore_in_client`: authorized session PII (CPF, CNPJ, Phone, Card) IS restored to the same session.
   - `must_not_leak_in_client`: vaulted secrets (`AWSKEY`, `SECRET`, `JWT`) remain masked even when echoed (`restore_secrets: false`), and spontaneous model secrets trigger `JG-SEC-503`.
   - `expect_warning_header`: expected warning/veto headers (`X-JaguarGate-Codes`, `X-JaguarGate-Veto`, `X-JaguarGate-Pruned-Tools`) are emitted.
4. **Quadrant 4 — Positive Control (Pre-Flight Proof):**
   Before running any gateway vector, the harness sends a raw Mod-11 CPF (`52998224725`) **directly to `mock_upstream.py`** (bypassing JaguarGate) and verifies that the mock captures the raw leak. If the positive control fails, the harness aborts with exit code 2.

---

## 3. Evaluation Fronts (30 Bilateral Vectors)

- **Front 1 — Protocol, Streaming & Structural Framing (10 vectors):**
  JSON-RPC batch arrays, real fragmented SSE token streaming (`stream: true`), SSE secret withholding, unexpected Content-Types, SSRF header override resistance, recursive JSON nesting, 8KB buffer stress with embedded CPF, Unicode BiDi controls, raw wire-level duplicate JSON keys (`raw_body`), and oversized single-token payloads.
- **Front 2 — PII, Secretário IA Coverage & Secret Withholding (10 vectors):**
  Formatted CPF, raw unformatted 11-digit CPF (Mod 11), legacy & 2026 alphanumeric CNPJ, Brazilian mobile phone (formatted & unformatted), Luhn-valid credit card, Luhn-invalid 16-digit serial negative control, canonical AWS Access Key (`AKIA...`), OpenAI API key (`sk-proj-...`), GitHub PAT (`ghp_...`), and canonical 3-segment JWT — all tested for both upstream masking (Q2) and echo response policy (Q3).
- **Front 3 — Injection Signatures, Deobfuscation & Spotlighting (10 vectors):**
  Direct prompt injection (`JG-SEC-401`), zero-width space obfuscated injection (`JG-SEC-402`), BiDi RTLO, benign academic framing (false-positive check), zero-width joiners, untrusted `tool` role spotlighting (`jg_untrusted`), Markdown/HTML polyglot, CRLF prompt smuggling, benign hypothetical explanation, and nested quote delimiters.

---

## 4. Reproducing Locally

```bash
# 1. Build static binary
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o jgate ./cmd/jgate

# 2. Start bilateral mock upstream on port 4020
python3 docs/security/jaguargate-audit-pack/reproduce/mock_upstream.py 4020 &

# 3. Start JaguarGate on port 4010 pointing to http://127.0.0.1:4020 (preset: balanced)
./jgate serve -c jaguargate.yaml &

# 4. Run 4-Quadrant Bilateral Verifier (outputs evidence to findings/full_campaign_report.json)
./docs/security/jaguargate-audit-pack/reproduce/run_reproduce.sh 4010 4020
```
