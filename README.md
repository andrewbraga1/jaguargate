# 🐆 JaguarGate (`jgate`)

> **Ultra-low latency AI, Autonomous Agent & MCP Security Gateway in Go.**  
> *Named after Panthera onca (the Brazilian Jaguar — from Tupi "Yaguara", the predator that neutralizes threats in a single leap).*

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20Aligned-critical)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Language](https://img.shields.io/badge/Docs-EN%20%7C%20PT--BR-success)](README_pt-BR.md)

🌍 **Read in other languages:** [Português (Brasil) 🇧🇷](README_pt-BR.md)

---

## ⚡ Why JaguarGate?

Traditional security proxies treat AI traffic like static web pages: if a single parameter violates a rule, they return an `HTTP 403/500`, **crashing your autonomous agent's entire reasoning loop** and wasting tokens.

**JaguarGate** is a resilient, sub-millisecond sidecar gateway built in pure Go (`CGO_ENABLED=0`) designed for **LLMs**, **Autonomous Agents** (AgentScope, LangChain, CrewAI, LiteLLM), and **MCP (Model Context Protocol)** servers:

* 🛡️ **Graceful Degradation (Selective Pass-Through):** If an agent calls 3 tools in parallel and 1 is unauthorized, JaguarGate surgically prunes only the unauthorized tool call, keeps the request alive (`HTTP 200`), and attaches lightweight **Warning Flags** (`X-JaguarGate-*`).
* 🚀 **Tri-Transport Architecture:** Standard **HTTP/REST** (`:4010`) for zero-code integration, **Unix Domain Sockets (UDS)** for near-zero kernel-level latency with local models (e.g., Ollama), and **gRPC** for high-throughput microservices.
* 🌊 **Rune-Aware Streaming Inspection (SSE):** Validates token-by-token responses in real time using a UTF-8 safe sliding window buffer without delaying Time-To-First-Token (TTFT).
* 🔐 **Reversible PII & Secrets Vault:** Masks sensitive data (CPF, CNPJ, Credit Cards, API Keys) with safe pseudonyms before leaving your infrastructure and restores them on the way back if authorized.
* 🔌 **MCP Guardrail & Wasm Extensibility:** Protects local (`stdio`) and remote (`HTTP/SSE`) MCP servers and supports sandboxed **WebAssembly (`wazero`)** community plugins.

---

## 🏗️ 6-Layer Architectural Pipeline

```mermaid
flowchart TD
    Client["🤖 AI Agent / App / MCP Client"]

    subgraph L1["Layer 1: Multi-Transport Ingestion & MCP Bridge"]
        HTTP["HTTP/REST (:4010)"]
        UDS["Unix Socket (/tmp/jaguargate.sock)"]
        GRPC["gRPC (:4011)"]
        MCP["MCP Interceptor (Stdio / SSE)"]
    end

    subgraph L2["Layer 2: Multimodal Triage & Deobfuscation"]
        Media["Base64 Media Bypass & EXIF Stripper"]
        Deob["Memory Deobfuscator (Base64 / Hex / Invisible Unicode)"]
    end

    subgraph L3["Layer 3: Core OWASP Engine & Resilient Whitelist"]
        Spot["Dynamic Crypto Spotlighting & Canary Tokens"]
        Vault["Reversible PII & Secrets Vault"]
        Tools["Selective Tool Call & MCP Firewall"]
        Modes["Modes: Shadow | Sanitize & Warn | Hard Block"]
    end

    subgraph L4["Layer 4: Hybrid State (L1/L2) & Wasm Sandbox"]
        State["L1 Lock-Free RAM (atomic.Pointer) + L2 AES-GCM Redis"]
        Loop["SHA-256 Canonical Loop Circuit Breaker"]
        Wasm["Pure-Go Wasm Plugin Sandbox (wazero < 2ms)"]
    end

    subgraph L5["Layer 5: Real-Time Streaming & Zero-Trust Telemetry"]
        Slide["Rune-Aware UTF-8 Sliding Window Buffer (SSE)"]
        Flags["Warning Flags (HTTP Headers / Trailers / SSE Event)"]
        Logs["Zero-Trust Redacted Logger (slog) & OTel"]
    end

    subgraph L6["Layer 6: Bilingual Governance & Built-in Red Teaming"]
        CLI["CLI: jgate check | jgate doctor | jgate pounce (bote)"]
    end

    Upstream["🧠 Upstream LLM (OpenAI / Anthropic / Ollama / LiteLLM)"]

    Client --> L1 --> L2 --> L3 --> L4 --> Upstream
    Upstream --> L5 --> Client
    L6 -.->|"Audits & Simulates Attacks"| L1
```

---

## 🚀 3-Line Quickstart (Zero-Code Configuration)

Beginners don't need to write complex regex rules. A complete `jaguargate.yaml` requires only **3 lines**:

```yaml
core:
  version: "1.0"
  language: "en"         # "en" or "pt-BR"
  preset: "balanced"     # "permissive" (learning) | "balanced" (recommended) | "strict" (maximum armor)
```

Point your SDK or agent's `BASE_URL` to `http://localhost:4010/v1` and start JaguarGate:

```bash
# Validate configuration syntax
jgate check

# Run built-in diagnostic and simulated OWASP attack battery ("The Jaguar's Pounce")
jgate pounce

# Start the gateway
jgate start -c configs/jaguargate.yaml
```

---

## 🌐 Language Configuration (`en` Default | `pt-BR`)

**[EN]** By default, JaguarGate outputs all CLI tables (`jgate doctor`, `jgate pounce`, `jgate check`) and operational logs in **English (`en`)** to maintain clean, single-language parsing in CI/CD pipelines and SIEM platforms. Users can switch the entire interface to **Portuguese (`pt-BR`)** via any of the three methods below:

1. **CLI Flag (Per-Command Override):**
   ```bash
   ./jgate doctor --lang pt-BR
   ./jgate pounce --lang pt-BR
   ```
2. **Environment Variable (Docker / Kubernetes / CI):**
   ```bash
   export JAGUARGATE_LANG="pt-BR"
   ./jgate serve -c jaguargate.yaml
   ```
3. **Configuration File (`jaguargate.yaml`):**
   ```yaml
   core:
     version: "1.0"
     preset: "balanced"
     language: "pt-BR" # Default: "en"
   ```

---

## 📊 OWASP LLM & Agentic Top 10 Coverage

| OWASP Threat | JaguarGate Defense Mechanism | Default Behavior (`sanitize_and_warn`) |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Base64/Hex deobfuscation + Dynamic Cryptographic Spotlighting tags | Neutralizes injection payload; forwards clean context + `JG-SEC-401` |
| **LLM02: Sensitive Info Disclosure** | Reversible PII & Secrets Vault (in-memory or AES-GCM Redis) | Replaces secret with `<JG_PII_TOKEN>` + `JG-PII-301` |
| **LLM05: Improper Output Handling** | Markdown image tracker blocker & script sanitizer | Strips malicious links in real-time SSE stream + `JG-SEC-502` |
| **LLM06: Excessive Agency** | Selective Tool Call & MCP Whitelist Firewall | Prunes unauthorized tool calls without crashing HTTP 200 + `JG-CFG-101` |
| **LLM07: System Prompt Leakage** | Invisible Canary Token injection & sliding-window detector | Immediately truncates leaked stream + `JG-SEC-501` |
| **LLM10: Unbounded Consumption** | Canonical SHA-256 Agent Loop Circuit Breaker & token caps | Halts repetitive identical tool loops gracefully + `JG-CFG-201` |

---

## 🗺️ Project Roadmap & Milestones

- [x] **Milestone 0 (`v0.1.0-spec`):** Configuration Contract (`YAML`/`JSON`), Compact Warning Flag Taxonomy (`JG-*`) & Bilingual Catalog (`EN`/`PT-BR`).
- [ ] **Milestone 1 (`v0.2.0-core`):** Lock-Free Config Engine (`atomic.Pointer`), Buffer Recycling (`sync.Pool`), Zero-Trust Redacted Logger & Base Proxy (HTTP + UDS).
- [ ] **Milestone 2 (`v0.4.0-input-guards`):** Pre-compiled RE2 Engine, Deobfuscator, Multimodal EXIF Hygiene, Dynamic Spotlighting & Local PII Vault.
- [ ] **Milestone 3 (`v0.6.0-streaming-tools`):** Rune-Aware UTF-8 Sliding Window SSE Inspector, Selective Tool Call Firewall & HTTP Trailers/SSE Warnings.
- [ ] **Milestone 4 (`v0.8.0-scale-mcp`):** Distributed L1/L2 State (Redis/Valkey AES-GCM), SHA-256 Loop Breaker, gRPC Transport & MCP Guardrail.
- [ ] **Milestone 5 (`v1.0.0-release`):** Pure-Go Wasm Sandbox (`wazero`), OpenTelemetry Exporter, Rate-Limited Webhooks & CLI (`jgate doctor` / `jgate pounce`).

---

## 📄 License

Distributed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for more information.
