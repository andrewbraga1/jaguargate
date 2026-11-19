# 🛡️ JaguarGate — Pacote de Auditoria e Certificação de Segurança Gate 5

[![Gate 5 Certified](https://img.shields.io/badge/Gate%205-Certified%20Zero--CVE-brightgreen.svg)](#)
[![Taxa de Neutralização](https://img.shields.io/badge/Neutraliza%C3%A7%C3%A3o-30%2F30%20(100%25)-blue.svg)](#)
[![Zero-Nosec](https://img.shields.io/badge/GoSec%20SAST-Zero%20Nosec-success.svg)](#)
[![Govulncheck](https://img.shields.io/badge/Govulncheck-Zero%20Vulnerabilidades-success.svg)](#)

Este diretório contém o dossiê completo de auditoria independente, evidências de execução, metodologia de testes adversariais e suíte de reprodução gerados pelo **Maestro Software Foundry** para o **JaguarGate** (commit `6d2057e`).

---

## 📁 Estrutura do Pacote de Auditoria

```text
jaguargate-audit-pack/
├── README.md                      # Visão geral e guia da comunidade (Inglês)
├── README.pt-BR.md                # Visão geral e guia da comunidade (Português)
├── CERTIFICATE_GATE5.md           # Certificado formal assinado pelo Maestro
├── METHODOLOGY.md                 # Metodologia dos 3 Frontes e 7 Fail-Safes
├── findings/
│   ├── gate5_30_rounds_matrix.md  # Detalhamento linha por linha das 30 sondas
│   └── full_campaign_report.json  # Relatório bruto estruturado em JSON
├── raw_logs/
│   ├── gate5_campaign_console.log # Log completo do console durante a bateria
│   ├── gate5_target_gateway.log   # Log de execução do binário JaguarGate
│   └── redteam_campaign_report.json
└── reproduce/
    ├── run_reproduce.sh           # Script em 1 comando para reproduzir a auditoria
    ├── reproduce_audit.py         # Executor determinístico em Python
    ├── test_vectors.json          # Definição congelada dos 30 vetores
    └── mock_upstream.py           # Mock local do upstream LLM (custo zero)
```

---

## 🚀 Como Reproduzir a Auditoria Localmente

Qualquer desenvolvedor ou pesquisador de segurança pode validar e reproduzir a bateria de 30 rodadas em menos de 15 segundos:

1. **Inicie o JaguarGate:**
   ```bash
   jgate serve -c jaguargate.yaml
   ```

2. **Execute o script de verificação:**
   ```bash
   cd reproduce
   ./run_reproduce.sh 4010
   ```

O script testará automaticamente as 3 frentes de ataque (FRONT-1: Confusão Estrutural, FRONT-2: Canários de Dados Sensíveis e PII, FRONT-3: Evasão Semântica) e certificará que nenhum canário vazou e que o gateway tratou todos os envelopes com sucesso.
