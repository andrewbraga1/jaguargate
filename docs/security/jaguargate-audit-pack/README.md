# 🛡️ JaguarGate Gate 5 — Bilateral 4-Quadrant Verification Pack

[![Bilateral Suite](https://img.shields.io/badge/Bilateral%20Suite-30%2F30%20Verified-blue.svg)](#)
[![GoSec SAST](https://img.shields.io/badge/GoSec%20SAST-0%20Issues%20%7C%200%20Nosec-success.svg)](#)
[![Govulncheck](https://img.shields.io/badge/Govulncheck-0%20Reachable%20CVEs-success.svg)](#)

This directory contains the reproducible **4-Quadrant Bilateral Automated Security Verification Pack** for **JaguarGate**.

> **Scope Note:** This is an automated internal verification suite with explicit upstream payload capture (Q2), client output verification (Q3), and direct-bypass positive control (Q4). It verifies the exact 30 synthetic vectors and configuration documented below and does not replace an external third-party penetration test.

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
    ├── test_vectors.json          # 30 bilateral test vectors (with raw wire & SSE frames)
    └── mock_upstream.py           # Capturing upstream mock (/_mock/last_request + token echo + SSE)
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

3. **Run the 4-Quadrant Bilateral Verifier:**
   ```bash
   ./docs/security/jaguargate-audit-pack/reproduce/run_reproduce.sh 4010 4020
   ```

The verifier first runs the **Q4 Positive Control** directly against the mock upstream (confirming raw leak capture), then validates all 30 vectors across Q1 (ingress), Q2 (upstream captured body), and Q3 (client response & secret withholding), saving full evidence to `findings/full_campaign_report.json`.
