# 🐆 JaguarGate — Warning Flags & Bilingual Code Catalog (`v0.1.0-spec`)

This document specifies the transport-level **Warning Flag protocol** and the **Bilingual Zero-Trust Dictionary (`EN` / `PT-BR`)** used across JaguarGate logs, CLI diagnostics (`jgate doctor`), and optional response telemetry.

---

## 1. Transport Protocol Specification (How Flags Are Delivered)

To avoid breaking strict AI SDK parsers (OpenAI, Anthropic, AgentScope, LangChain) and to respect the 8KB HTTP Header limit on reverse proxies (Nginx, Cloudflare, AWS ALB), JaguarGate emits compact metadata through three mechanisms:

### 1.1. Standard Request/Response (`stream: false`) — HTTP Headers / gRPC Metadata

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-JaguarGate-Status: SANITIZED
X-JaguarGate-Severity: CONFIG_WARNING
X-JaguarGate-Codes: JG-CFG-101,JG-PII-301
X-JaguarGate-Pruned-Count: 1
```

* **`X-JaguarGate-Status`**: `CLEAN` | `SANITIZED` | `SHADOW_FLAGGED` | `BLOCKED`
* **`X-JaguarGate-Severity`**: `NONE` | `CONFIG_WARNING` (Dev/DevOps action) | `INTRUSION_ALERT` (SecOps action)
* **`X-JaguarGate-Codes`**: Comma-separated list of compact event codes triggered during the request lifecycle.

### 1.2. Streaming Responses (`stream: true` / SSE) — HTTP Trailers + SSE Event

Because HTTP headers are flushed before the first token arrives, mid-stream detections are delivered at the end of the stream via **HTTP Trailers** and a custom **SSE Warning Event** right before `data: [DONE]`:

```http
event: jaguargate.warning
data: {"status":"SANITIZED","severity":"CONFIG_WARNING","codes":["JG-CFG-101"],"pruned_tools":1}

data: [DONE]
```

---

## 2. Official Bilingual Event Catalog (`EN` & `PT-BR`)

Every code below enforces **Zero-Trust Redaction**: sensitive payloads or PII values are replaced with `***[JG-REDACTED]***` before reaching any log or webhook.

### 🔹 `JG-CFG-1xx`: Tool Call, MCP & Domain Whitelist (`CONFIG_WARNING`)

| Code | Language | Summary Message | Action Taken (`sanitize_and_warn`) | CLI Doctor Fix Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **`JG-CFG-101`** | **EN** | Unauthorized tool call omitted (`tool: ***[JG-REDACTED]***`). | Surgically removed the unwhitelisted tool call; allowed remaining valid tools/text. | If this tool is legitimate, add its name to `whitelist.allowed_tools` in `jaguargate.yaml`. |
| **`JG-CFG-101`** | **PT-BR** | Chamada de ferramenta não autorizada omitida (`tool: ***[JG-REDACTED]***`). | A ferramenta fora da Whitelist foi removida cirurgicamente; o restante da requisição seguiu normalmente. | Se esta ferramenta for legítima, adicione o nome dela em `whitelist.allowed_tools` no `jaguargate.yaml`. |
| **`JG-CFG-102`** | **EN** | Unregistered MCP server or method blocked. | Filtered the unauthorized JSON-RPC 2.0 call without dropping the agent session. | Register the MCP server identifier under `whitelist.allowed_mcp_servers`. |
| **`JG-CFG-102`** | **PT-BR** | Servidor ou método MCP não cadastrado na Whitelist. | A chamada JSON-RPC 2.0 não autorizada foi filtrada sem derrubar a sessão do agente. | Cadastre o identificador do servidor MCP em `whitelist.allowed_mcp_servers`. |
| **`JG-CFG-103`** | **EN** | Tool parameter violated domain whitelist. | Stripped the unauthorized external domain parameter from the tool arguments. | Add the trusted domain pattern to `whitelist.allowed_domains`. |
| **`JG-CFG-103`** | **PT-BR** | Parâmetro de ferramenta violou a Whitelist de domínios. | O domínio externo não autorizado foi removido dos argumentos da ferramenta. | Adicione o domínio confiável na lista `whitelist.allowed_domains`. |

---

### 🔹 `JG-CFG-2xx`: Operational Limits, Loops & Fail-Open (`CONFIG_WARNING`)

| Code | Language | Summary Message | Action Taken (`sanitize_and_warn`) | CLI Doctor Fix Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **`JG-CFG-201`** | **EN** | Agent reasoning loop detected (identical canonical SHA-256 tool call repeated). | Circuit breaker halted the redundant tool execution and returned a loop-stop notice to the agent. | Review agent prompt logic or increase `whitelist.circuit_breaker.max_identical_tool_calls`. |
| **`JG-CFG-201`** | **PT-BR** | Loop de raciocínio detectado (chamada de ferramenta idêntica repetida pelo hash SHA-256). | O disjuntor interrompeu a repetição e devolveu aviso de parada suave ao agente. | Revise a lógica do agente ou aumente `whitelist.circuit_breaker.max_identical_tool_calls`. |
| **`JG-CFG-202`** | **EN** | Session token budget exceeded (`Denial of Wallet` protection). | Truncated request/response to fit the configured session token cap. | Adjust `whitelist.circuit_breaker.max_tokens_per_session` if higher consumption is expected. |
| **`JG-CFG-202`** | **PT-BR** | Limite de tokens da sessão atingido (proteção `Denial of Wallet`). | Requisição/resposta limitada ao teto configurado para evitar custo excessivo. | Ajuste `whitelist.circuit_breaker.max_tokens_per_session` caso o consumo maior seja esperado. |
| **`JG-CFG-205`** | **EN** | L2 Redis/Valkey state store unreachable; operating in L1 local memory (`Fail-Open`). | Traffic continues uninterrupted using local RAM vault. | Verify `extensions.state_store.redis_url` connectivity and credentials. |
| **`JG-CFG-205`** | **PT-BR** | Banco de estado L2 Redis/Valkey inacessível; operando em memória local L1 (`Fail-Open`). | O tráfego segue sem interrupção usando o cofre em memória RAM local. | Verifique a conectividade e as credenciais em `extensions.state_store.redis_url`. |

---

### 🔹 `JG-PII-3xx`: Reversible PII & Secrets Vault (`CONFIG_WARNING`)

| Code | Language | Summary Message | Action Taken (`sanitize_and_warn`) | CLI Doctor Fix Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **`JG-PII-301`** | **EN** | Personal Identifiable Information (CPF/CNPJ/Credit Card) masked in transit. | Replaced raw PII with reversible vault token `<JG_PII_...>` before sending to upstream LLM. | Expected protection behavior. Toggle specific entities under `guards.pii_vault.entities`. |
| **`JG-PII-301`** | **PT-BR** | Dado pessoal sensível (CPF/CNPJ/Cartão) mascarado em trânsito. | O dado real foi substituído pelo token seguro `<JG_PII_...>` antes de ir para o modelo de IA. | Comportamento normal de proteção. Gerencie as entidades em `guards.pii_vault.entities`. |
| **`JG-PII-302`** | **EN** | Cloud credential, API Key, or JWT secret intercepted and masked. | Stripped raw secret `***[JG-REDACTED]***` from outbound prompt to prevent credential leakage. | Rotate exposed development keys immediately and keep `guards.pii_vault.entities.api_secrets: true`. |
| **`JG-PII-302`** | **PT-BR** | Credencial de nuvem, chave de API ou token JWT interceptado e mascarado. | O segredo `***[JG-REDACTED]***` foi substituído antes de sair para o provedor de IA externo. | Rotacione chaves expostas em código e mantenha `guards.pii_vault.entities.api_secrets: true`. |

---

### 🔹 `JG-SEC-4xx`: Prompt Injection, Obfuscation & Multimodal Hygiene (`INTRUSION_ALERT`)

| Code | Language | Summary Message | Action Taken (`sanitize_and_warn`) | CLI Doctor Fix Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **`JG-SEC-401`** | **EN** | Direct or Indirect Prompt Injection pattern neutralized. | Stripped system-override instruction and isolated external context with dynamic crypto Spotlighting tags. | Inspect client session ID in audit logs; async intrusion webhook triggered. |
| **`JG-SEC-401`** | **PT-BR** | Tentativa de Prompt Injection (Direto ou Indireto) neutralizada. | A instrução maliciosa foi removida e o dado externo foi isolado com tags dinâmicas de Spotlighting. | Verifique o ID da sessão nos logs de auditoria; alerta assíncrono de invasão disparado. |
| **`JG-SEC-402`** | **EN** | Obfuscated payload detected (Base64 / Hex / Invisible Unicode Tags). | Deobfuscated hidden payload in memory and stripped malicious segment. | Keep `guards.deobfuscation.enabled: true` and `max_decode_depth: 2`. |
| **`JG-SEC-402`** | **PT-BR** | Payload camuflado detectado (Base64 / Hex / Caracteres Unicode Invisíveis). | O trecho oculto foi decodificado em memória e a instrução maliciosa foi removida. | Mantenha `guards.deobfuscation.enabled: true` e `max_decode_depth: 2`. |
| **`JG-SEC-403`** | **EN** | Suspicious EXIF/XMP metadata or mismatched Magic Bytes in multimodal attachment. | Stripped hidden metadata segments from image/document before forwarding to vision model. | Ensure `guards.multimodal.strip_exif_xmp_metadata: true` remains active. |
| **`JG-SEC-403`** | **PT-BR** | Metadados EXIF/XMP suspeitos ou assinatura de arquivo inválida em anexo multimodal. | Os metadados ocultos foram limpos da imagem/documento antes do envio ao modelo. | Mantenha `guards.multimodal.strip_exif_xmp_metadata: true` ativo. |

---

### 🔹 `JG-SEC-5xx`: System Prompt Leakage & Unsafe Output (`INTRUSION_ALERT`)

| Code | Language | Summary Message | Action Taken (`sanitize_and_warn`) | CLI Doctor Fix Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **`JG-SEC-501`** | **EN** | CRITICAL: System Prompt Canary Token detected in model output stream. | Immediately truncated output stream to prevent secret system instruction leakage. | Review upstream model vulnerability; intrusion alert dispatched to SecOps webhook. |
| **`JG-SEC-501`** | **PT-BR** | CRÍTICO: Canary Token do System Prompt detectado na saída do modelo. | A transmissão da resposta foi cortada no mesmo milissegundo para impedir vazamento de instruções internas. | Verifique a tentativa de extração nos logs; alerta crítico enviado via Webhook. |
| **`JG-SEC-502`** | **EN** | Malicious external Markdown image tracker or executable script sanitized in output. | Replaced unsafe Markdown/HTML tag with `[CONTEÚDO RESTRITO / RESTRICTED CONTENT]` during streaming. | Keep `guards.output_sanitizer.block_untrusted_markdown_images: true`. |
| **`JG-SEC-502`** | **PT-BR** | Imagem rastreadora externa em Markdown ou script executável bloqueado na saída. | A tag insegura foi substituída por `[CONTEÚDO RESTRITO / RESTRICTED CONTENT]` durante o streaming. | Mantenha `guards.output_sanitizer.block_untrusted_markdown_images: true`. |
