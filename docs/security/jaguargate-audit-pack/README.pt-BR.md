# 🛡️ JaguarGate Gate 5 — Pacote de Verificação Bilateral 4 Quadrantes

[![Bilateral Suite](https://img.shields.io/badge/Su%C3%ADte%20Bilateral-30%2F30%20Verificados-blue.svg)](#)
[![GoSec SAST](https://img.shields.io/badge/GoSec%20SAST-0%20Issues%20%7C%200%20Nosec-success.svg)](#)
[![Govulncheck](https://img.shields.io/badge/Govulncheck-0%20CVEs%20Alcan%C3%A7%C3%A1veis-success.svg)](#)

Este diretório contém o pacote reproduzível da **Suíte Automatizada de Verificação Bilateral 4 Quadrantes** do **JaguarGate**.

> **Nota de Escopo:** Esta é uma bateria automatizada interna com captura explícita do corpo recebido pelo upstream (Q2), validação de saída no cliente (Q3) e controle positivo direto sem gateway (Q4). Os resultados são delimitados exatamente aos 30 vetores sintéticos e à configuração testada, não substituindo pentest externo independente.

---

## 📁 Conteúdo do Pacote

```text
jaguargate-audit-pack/
├── README.md                      # Visão geral e guia de reprodução (EN)
├── README.pt-BR.md                # Visão geral e guia de reprodução (PT-BR)
├── CERTIFICATE_GATE5.md           # Relatório delimitado da bateria automatizada
├── METHODOLOGY.md                 # Protocolo Invariante Bilateral 4 Quadrantes
├── findings/
│   ├── gate5_30_rounds_matrix.md  # Matriz detalhada dos vetores testados
│   └── full_campaign_report.json  # Evidências capturadas (upstream e cliente)
└── reproduce/
    ├── run_reproduce.sh           # Script executor (4010 / 4020)
    ├── reproduce_audit.py         # Verificador bilateral 4 quadrantes em Python
    ├── test_vectors.json          # 30 vetores bilaterais (JSON bruto e SSE real)
    └── mock_upstream.py           # Mock com captura (/_mock/last_request + eco de tokens + SSE)
```

---

## 🚀 Como Reproduzir Localmente

1. **Suba o mock upstream com captura na porta `4020`:**
   ```bash
   python3 docs/security/jaguargate-audit-pack/reproduce/mock_upstream.py 4020
   ```

2. **Suba o JaguarGate na porta `4010` apontando para `http://127.0.0.1:4020`:**
   ```bash
   ./jgate serve -c jaguargate.yaml
   ```

3. **Execute o Verificador Bilateral 4 Quadrantes:**
   ```bash
   ./docs/security/jaguargate-audit-pack/reproduce/run_reproduce.sh 4010 4020
   ```

O verificador executa primeiro o **Controle Positivo (Q4)** direto no mock (provando captura de vazamento cru) e depois valida todos os 30 vetores nos quadrantes Q1, Q2 e Q3, salvando as evidências em `findings/full_campaign_report.json`.
