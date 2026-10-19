# 📚 JaguarGate (`jgate`) — Real-World Use Cases & Configuration Examples

> **[EN]** Ready-to-use configuration profiles and interactive scenarios ranging from a **3-line beginner setup** to an **Enterprise Banking/HealthTech cluster**. Every `.yaml` file in this directory is automatically validated by `go test ./...`.  
> **[PT-BR]** Perfis prontos de configuração e cenários reais que vão desde um **guia de 3 linhas para iniciantes** até um **cluster corporativo Strict com MCP e Redis L2**. Todos os arquivos `.yaml` desta pasta são validados automaticamente pelo `go test ./...`.

---

## 🗺️ Scenario Matrix: Which Example Fits Your Use Case?

| Scenario | File | Target Audience | Key Capabilities Demonstrated |
| :--- | :--- | :--- | :--- |
| **00. The Privacy Bouncer** *(3-Line Setup)* | [`00-quickstart-beginner.yaml`](00-quickstart-beginner.yaml) | **Beginners / Non-Security Users** | Zero-config `balanced` preset. Automatically masks CPF, Alphanumeric CNPJ, Credit Cards, Emails & API keys before prompts leave your machine, restoring them on reply. |
| **01. AI Coding Assistant Guard** | [`01-ide-coding-assistant.yaml`](01-ide-coding-assistant.yaml) | **Software Engineers (VS Code Cline, Cursor, Continue)** | Protects local repositories against `.env` secret leaks (`AKIA*`, `sk-*`, `ghp_*`, `xoxb-*`, JWT) and activates the $O(1)$ SHA-256 Circuit Breaker against runaway agent loops. |
| **02. Enterprise Strict + MCP Firewall** | [`02-enterprise-strict-mcp.yaml`](02-enterprise-strict-mcp.yaml) | **SecOps / FinTech / HealthTech Production** | Enforces `hard_block` (`HTTP 403`), Tool & MCP JSON-RPC 2.0 whitelists, JPEG EXIF binary stripping, AES-256-GCM Redis L2 state, Prometheus `:9091`, and HMAC SIEM webhooks. |
| **03. Cloud-Native Docker Sidecar** | [`03-docker-compose-sidecar.yml`](03-docker-compose-sidecar.yml) | **DevOps / Platform Engineers** | Launches the static Distroless JaguarGate container alongside a Redis 7 L2 cache with a strict `GOMEMLIMIT=64MiB` memory ceiling. |
| **04. Live "X-Ray" Terminal Demo** | [`04-live-xray-demo.sh`](04-live-xray-demo.sh) | **Evaluators / Tech Recruiters / Quick Test** | Runs a complete End-to-End inspection & PII restoration test in 2 seconds using a local loopback contract server (**requires 0 MB of GPU/LLM RAM and no API keys**). |

---

## 🚀 How to Run Any Scenario

### 1. Run the Interactive "X-Ray" Demo (No LLM or API Key Needed!)
See what the AI provider receives vs. what the user gets back in ~300 microseconds:
```bash
./examples/04-live-xray-demo.sh
```

### 2. Validate & Diagnose Any Scenario Profile
Use `jgate check` or `jgate doctor` with the `-c` flag (add `--lang pt-BR` for Portuguese output):
```bash
# Beginner 3-line profile:
./jgate doctor -c examples/00-quickstart-beginner.yaml

# Developer IDE profile (in Portuguese):
./jgate doctor -c examples/01-ide-coding-assistant.yaml --lang pt-BR

# Enterprise Strict + MCP + Redis L2 profile:
./jgate doctor -c examples/02-enterprise-strict-mcp.yaml
```