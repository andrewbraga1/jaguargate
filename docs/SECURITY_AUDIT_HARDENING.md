# 🛡️ JaguarGate (`jgate`) — Technical Security Audit & Hardening Report

> **Scope:** Static and dynamic audit of security invariants, multi-tenant state isolation, SSE sliding-window sanitization, Model Context Protocol (MCP JSON-RPC 2.0) guardrails, resource constraints, and zero-trust telemetry.  
> **Status:** 12/12 Findings Fully Remediated & Verified with Regression Testing (`go test -race ./...`).  
> **Language:** English (Official Project Language) | [Português (Brasil)](SECURITY_AUDIT_HARDENING_pt-BR.md)

---

## 📋 Remediation Matrix: Findings & Verifications

| ID | Severity | Component | Technical Finding | Implemented Remediation | Regression Test |
| :--- | :---: | :--- | :--- | :--- | :--- |
| **AUD-01** | **High** | `internal/guards/vault.go` | Shared PII Vault lacked session/tenant isolation; token entropy was degraded to 32 bits without collision handling. | Tokens are now strictly scoped to caller `sessionID` (`MaskTextWithSession` / `RestoreTextWithSession`), entropy expanded to **128 bits (`[16]byte`)** with collision prevention. | `TestPIIVaultCrossSessionIsolation` |
| **AUD-02** | **High** | `internal/guards/tools.go` `internal/guards/engine.go` `internal/stream/sse_inspector.go` | Domain whitelist sanitization (`JG-CFG-103`) mutated tool arguments in memory but failed to re-serialize the response when `pruned == 0`. | Mandatory re-serialization enforced whenever `pruned > 0 \|\| len(toolCodes) > 0` on ingress, egress, and SSE streaming. | `TestIsolatedDomainSanitizationWithoutToolPruning` |
| **AUD-03** | **High** | `internal/mcp/inspector.go` `internal/guards/engine.go` | MCP `tools/call` arguments (`params.arguments`) bypassed inspection when lacking standard chat keys (`messages`/`prompt`). | Implemented recursive JSON traversal (`inspectArbitraryJSONMap` / `inspectArbitraryJSONSlice`, depth $\le 8$) inspecting all string values against injections, obfuscations, PII, and domains. | `TestMCPJSONRPCToolFirewallAndExternalResourceSanitization` |
| **AUD-04** | **High** | `internal/stream/sse_inspector.go` | SSE sliding window required $\ge 3$ characters to buffer Canary tokens, and parser only handled OpenAI's `choices[].delta.content`. | Lowered Canary and marker holdback threshold to **1 character ($k \ge 1$)**; added native SSE parsing for Anthropic (`delta.text`) and Ollama (`message.content`, `response`, `token`). | `TestSSEOneAndTwoCharPrefixSplitsAndAnthropicFormat` |
| **AUD-05** | **High** | `internal/transport/proxy.go` `internal/state/circuit_breaker.go` | Session token budget (`JG-CFG-202`) only warned without halting requests; circuit breaker fingerprint was sensitive to JSON key ordering. | Quota violations now immediately reject ingress requests with `HTTP 429 Too Many Requests` (`res.Blocked = true`); SHA-256 fingerprint sorts JSON keys lexicographically. | `TestProxyTokenBudgetEnforcementAndDeferredSSEMetrics` `TestCircuitBreakerCanonicalLoopAndTokenBudget` |
| **AUD-06** | **Med/High** | `internal/transport/proxy.go` | `FilterLoopingToolCalls` (`JG-CFG-201`) was only linked to MCP traffic, leaving standard HTTP/REST LLM completions unmonitored. | Integrated `filterLLMResponseToolLoops` into `ModifyResponse`, pruning repetitive looping tool calls from standard LLM responses. | `TestFilterLoopingToolCallsPruningAndShadow` |
| **AUD-07** | **Med/High** | `internal/extensions/sandbox.go` | File-based Wasm sandbox verified 8-byte magic header and returned success without executing bytecode (operational false sense of security). | Explicitly returns `ErrWasmRuntimeNotLinked` when no runtime/hook is registered, triggering transparent Fail-Open and warning flag `JG-EXT-601`. | `TestSandboxWasmMagicBytesAndTimeoutFailOpen` |
| **AUD-08** | **High** | `internal/state/store.go` | Redis AES-256-GCM decryption errors fell open and returned raw ciphertext as plaintext; client lacked TLS (`rediss://`) and ACL user support. | Enforced cryptographic fail-closed policy (`ErrDecryptionFailed`) on corrupted or tampered ciphertext; added native TLS (`tls.DialWithDialer`) and `AUTH <user> <pass>`. | `TestHybridStoreAESGCMAndRedisFailOpen` |
| **AUD-09** | **Med/High** | `internal/transport/proxy.go` `internal/stream/sse_inspector.go` `internal/guards/vault.go` `internal/state/*` | Unbounded `io.ReadAll` on upstream responses; no line buffer cap in SSE; unbounded map growth across sessions (DoS / OOM vulnerability). | Wrapped response body with `io.LimitReader`; added 1MB un-newlined SSE buffer ceiling (`maxSSELineBytes`); implemented LRU-style eviction ($N \le 16384$) in Vault, Store, and Breaker. | Suite-wide state & stream tests |
| **AUD-10** | **Medium** | `internal/transport/proxy.go` | Hot-reload updated readiness probes (`/readyz`) while reverse proxy retained boot-time `targetURL`; risk of policy drift between ingress and egress. | Pinned configuration snapshot per request (`ctxConfigSnapKey`); dynamically resolved upstream destination during reverse proxy `Rewrite`. | `TestHTTPAndUnixSocketProxyWithSSEStreaming` |
| **AUD-11** | **Medium** | `internal/transport/proxy.go` `internal/telemetry/webhooks.go` | SSE metrics were recorded before stream consumption; webhook dispatcher incremented `sentCount` on HTTP 4xx/5xx responses. | Deferred SSE metrics & webhook emission to stream termination via `SetOnComplete`; webhook deliveries now strictly require HTTP 2xx to increment `sentCount`. | `TestPrometheusMetricsAndNonBlockingWebhook` |
| **AUD-12** | **Medium** | `cmd/jgate/main.go` `README.md` | Zero-Trust Logger constructor mistakenly received language code as redaction placeholder; documentation used `start`/`bote` while CLI only accepted `serve`/`pounce`. | Corrected placeholder to `***[JG-REDACTED]***`; added CLI aliases for `start`/`serve` and `bote`/`pounce`; aligned README quickstart instructions. | `./jgate check && ./jgate pounce` |

---

## 🔬 Technical Verification & Test Results

All mitigations were empirically validated with race-detection and zero memory regressions:

```bash
$ go vet ./...
$ go test -race ./...
ok  	github.com/andrewbraga1/jaguargate/internal/config	1.036s
ok  	github.com/andrewbraga1/jaguargate/internal/extensions	1.019s
ok  	github.com/andrewbraga1/jaguargate/internal/guards	1.029s
ok  	github.com/andrewbraga1/jaguargate/internal/mcp	1.042s
ok  	github.com/andrewbraga1/jaguargate/internal/multimodal	1.033s
ok  	github.com/andrewbraga1/jaguargate/internal/redteam	1.032s
ok  	github.com/andrewbraga1/jaguargate/internal/state	1.019s
ok  	github.com/andrewbraga1/jaguargate/internal/stream	1.055s
ok  	github.com/andrewbraga1/jaguargate/internal/telemetry	1.017s
ok  	github.com/andrewbraga1/jaguargate/internal/transport	1.050s
```

### Automated Red-Teaming Battery (`jgate pounce`)

```
===========================================================================================================
  JAGUARGATE RED-TEAMING SUITE (jgate pounce) — SECURITY AUDIT REPORT
===========================================================================================================
ID      | CATEGORY     | SIMULATED ATTACK SCENARIO                       | TRIGGERED FLAGS       | LAT.   | STATUS
-----------------------------------------------------------------------------------------------------------
VEC-01  | OWASP-LLM01  | Direct Prompt Injection Neutralization          | JG-SEC-401            |  133µs | PASS  
VEC-02  | OWASP-OBFUSC | Invisible Unicode + Base64 Smuggling Defense    | JG-SEC-402,JG-SEC-401 |  220µs | PASS  
VEC-03  | MULTIMODAL   | Binary JPEG EXIF Hidden Payload Stripping       | JG-SEC-403            |    3µs | PASS  
VEC-04  | OWASP-LLM02  | Reversible PII Vault (CPF + Alphanumeric CNPJ + Secret) | JG-PII-301,JG-PII-302 |   96µs | PASS  
VEC-05  | OWASP-LLM06  | Selective Unauthorized Tool Call Pruning        | JG-CFG-101            |   40µs | PASS  
VEC-06  | AGENT-LOOP   | O(1) SHA-256 Canonical Agent Loop Circuit Breaker | JG-CFG-201            |   34µs | PASS  
VEC-07  | MCP-GUARD    | MCP JSON-RPC 2.0 Untrusted Server & Tool Firewall | JG-CFG-102,JG-CFG-101 |   22µs | PASS  
VEC-08  | SSE-STREAM   | Real-Time SSE Canary Leak Stream Truncation     | JG-SEC-501            |   91µs | PASS  
-----------------------------------------------------------------------------------------------------------
  VERDICT: PASSED (8/8 Attack Vectors Neutralized) | Total Suite Duration: 670µs
===========================================================================================================
```
