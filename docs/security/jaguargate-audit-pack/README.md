# 🛡️ JaguarGate Gate 5 — Bilateral 4-Quadrant Verification Pack

[![Bilateral Suite](https://img.shields.io/badge/Bilateral%20Suite-42%2F42%20Verified-blue.svg)](#)
[![GoSec SAST](https://img.shields.io/badge/GoSec%20SAST-0%20Issues%20%7C%200%20Nosec-success.svg)](#)
[![Govulncheck](https://img.shields.io/badge/Govulncheck-0%20Reachable%20CVEs-success.svg)](#)

This directory contains the reproducible **Strict 4-Stage Bilateral Automated Security Verification Pack** for **JaguarGate** (executed automatically in `.github/workflows/ci.yml`).

> **Scope Note:** This is an automated internal verification suite recording full payloads, SHA-256 provenance hashes, and asserting all 4 stages on every vector: Ingress (Stage 1), Structured Gateway Decision/Codes (Stage 2), Upstream Captured Payload or `upstream_reached: false` pre-block proof (Stage 3), and Upstream Egress / Mid-Token SSE Fragments vs. Exact Client Reconstruction (Stage 4), plus Q4 direct-bypass positive control and Q5 unsafe-mutation oracle self-check. It verifies the exact 42 synthetic vectors and versioned `jaguargate.audit.yaml` fixture documented below and does not replace an external third-party penetration test.

---

## 📁 Pack Contents

```text
jaguargate-audit-pack/
├── README.md                      # Overview & reproduction guide (EN)
├── README.pt-BR.md                # Visão geral e guia de reprodução (PT-BR)
├── CERTIFICATE_GATE5.md           # Scoped automated verification report
├── METHODOLOGY.md                 # 4-Quadrant Bilateral Invariant Protocol
├── findings/
│   ├── gate5_30_rounds_matrix.md  # Breakdown of tested vectors
│   └── full_campaign_report.json  # Reproducible upstream/client captured evidence
└── reproduce/
    ├── run_reproduce.sh           # Verification runner script (4010 / 4020)
    ├── reproduce_audit.py         # 4-Quadrant bilateral Python verifier
    ├── test_vectors.json          # 34 4-stage bilateral test vectors (raw JSON, nested metadata & mid-token SSE)
    └── mock_upstream.py           # Capturing upstream mock (/_mock/last_request + mid-token SSE fragmentation)
```

---

## 🚀 How to Reproduce Locally

1. **Start the capturing mock upstream on port `4020`:**
   ```bash
   python3 docs/security/jaguargate-audit-pack/reproduce/mock_upstream.py 4020
   ```

2. **Start JaguarGate on port `4010` pointing to `http://127.0.0.1:4020`:**
   ```bash
   ./jgate serve -c jaguargate.yaml
   ```

3. **Run the 4-Stage Bilateral Verifier:**
   ```bash
   ./docs/security/jaguargate-audit-pack/reproduce/run_reproduce.sh 4010 4020
   ```

The verifier first runs the **Q4 Positive Control** directly against the mock upstream (confirming raw leak capture), then validates and logs all 34 vectors across Stage 1 (ingress), Stage 2 (gateway decision/codes), Stage 3 (upstream captured body or `upstream_reached: false` pre-block), and Stage 4 (upstream SSE fragments vs. reconstructed client delivery), saving full evidence to `findings/full_campaign_report.json`.
