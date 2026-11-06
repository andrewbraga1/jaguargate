# 📋 JaguarGate (`jgate`) — Pre-Hardening Security Audit Findings & Baseline Control

> **Document Purpose:** Official historical record and AppSec governance log documenting all architectural vulnerabilities, state isolation defects, streaming sanitization bypasses, and specification discrepancies identified in the original codebase prior to security hardening.  
> **Classification:** Internal Security Control & Verification Baseline (AppSec).  
> **Language:** English (Official Project Language) | [Português (Brasil)](AUDIT_FINDINGS_BASELINE_pt-BR.md)

---

## 1. Executive Summary

An independent static and architectural review of the JaguarGate codebase identified an idiomatic Go foundation (clean package boundaries, `sync.Pool` memory recycling, `atomic.Pointer` lock-free config snapshots, static Distroless containerization).

However, from an enterprise application security (AppSec) and multi-tenant isolation perspective, **12 critical vulnerabilities and architectural limitations** were uncovered in the original code. While the original unit test suite passed `go test -race ./...`, testing had suffered from confirmation bias: tests validated only selected positive scenarios while leaving critical security invariants unenforced.

This document serves as the immutable baseline of all 12 pre-hardening findings.

---

## 2. Comprehensive Inventory of Original Vulnerabilities

---

### 🔴 SEC-01: Cross-Session Data Leakage in Shared PII Vault
* **Severity:** **High (Critical Isolation Defect)**
* **Affected Component:** `internal/guards/vault.go` (`PIIVault`, methods `MaskText`, `RestoreText`, `storeValue`)
* **Pre-Hardening Behavior (Root Cause):**
  * The `PIIVault` instance was instantiated globally per `GatewayServer` without any tenant, session, or request boundary.
  * `RestoreText(output)` accepted an unauthenticated output string and scanned it using the regular expression `\x3cJG_PII_[A-Z]+_[0-9a-f]{8}\x3e`.
  * If the token matched any active unexpired entry in the in-memory map (or L2 Redis), the original plaintext secret was restored into the response **without checking the request's origin or caller identity**.
* **Production Impact:**
  * In multi-user or multi-tenant deployments, if an attacker or prompt injection manipulated the LLM to output a token belonging to another user, `RestoreText` decrypted and returned the sensitive PII/credential of that other user.
* **Entropy Degradation:**
  * Vault token identifiers were generated with only 4 random bytes (`var randBytes [4]byte`, yielding 8 hex characters = 32 bits of entropy).
  * No collision check was performed before writing `v.entries[token]`. Under sustained throughput, birthday-paradox collisions would silently overwrite active secrets of other users.

---

### 🔴 SEC-02: Silent Mutation Bug in Tool Call Domain Sanitization
* **Severity:** **High (Bypass of Egress Whitelist)**
* **Affected Component:** `internal/guards/tools.go` (`SanitizeToolCallsSlice`, `SanitizeOutputJSON`)
* **Pre-Hardening Behavior (Root Cause):**
  * `SanitizeToolCallsSlice` detected disallowed external URLs in `function.arguments` and rewrote them to `https://blocked.jaguargate.local/restricted`.
  * However, the function returned `([]any, []string, int)` where the integer returned was `prunedCount` (the count of *wholly omitted* tool definitions), not a general `modified` boolean flag.
  * The caller functions (`InspectJSONPayload`, `SanitizeOutputJSON`, and `handleSSELine`) checked `if !isShadow && pruned > 0` before re-serializing the JSON payload.
* **Production Impact:**
  * If a request or LLM response called an *authorized* tool name with an *unauthorized* external URL (e.g., `search_kb(url="https://evil-exfil.com")`), `pruned` was `0`. The warning code `JG-CFG-103` was added to headers, but **the modified body was discarded and the original malicious URL was delivered intact to the agent/client**.
* **Test Coverage Gap:**
  * The original unit test combined an unauthorized tool (`drop_production_db`) with an unauthorized domain. Removing the tool forced `pruned = 1`, which masked the failure of the domain-only scenario.

---

### 🔴 SEC-03: Blind Spot in MCP JSON-RPC 2.0 `tools/call` Arguments Inspection
* **Severity:** **High (Untrusted Tool Input Bypass)**
* **Affected Component:** `internal/mcp/inspector.go` (`inspectSingleRPCObject`) & `internal/guards/engine.go`
* **Pre-Hardening Behavior (Root Cause):**
  * Upon intercepting an MCP `tools/call` payload, `inspector.go` marshaled `params.arguments` to bytes and passed it to `ins.engine.InspectJSONPayload(argsBytes, cfg)`.
  * `InspectJSONPayload` performed `json.Unmarshal` and inspected *only* top-level keys `"tools"`, `"messages"`, and `"prompt"`.
  * MCP tool arguments contain arbitrary application-defined schemas (e.g., `{"query": "...", "cmd": "..."}`), none of which matched chat keys.
* **Production Impact:**
  * All arguments passed to MCP tools completely bypassed OWASP LLM01 Prompt Injection checks (`JG-SEC-401`), Deobfuscation (`JG-SEC-402`), and PII Vault masking (`JG-PII-301`/`302`).

---

### 🔴 SEC-04: Sliding Window SSE Buffer Bypassed on Short Prefixes (1–2 Chars)
* **Severity:** **High (Stream Leakage & Multi-Provider Incompatibility)**
* **Affected Component:** `internal/stream/sse_inspector.go` (`splitHoldbackSuffix`, `handleSSELine`)
* **Pre-Hardening Behavior (Root Cause):**
  * `splitHoldbackSuffix` checked for Canary Token splits using `for k := maxK; k >= 3; k--`. If network packet fragmentation split a Canary token after 1 or 2 characters (e.g., chunk 1 ends with `"j"` or `"jg"`), those characters were flushed immediately to the client. Subsequent chunks could never trigger `strings.Contains(chunk, canaryToken)`.
  * The same failure occurred with Markdown image trackers: holdback required at least `![`, leaving single `!` characters unbuffered.
  * The SSE parser only supported OpenAI's `choices[].delta.content` JSON format, ignoring other provider formats.
* **Production Impact:**
  * System Prompt Canary token leaks escaped detection under realistic chunk divisions;
  * SSE traffic from Anthropic (`delta.text`), Ollama (`message.content`, `response`), or custom gateways passed through completely uninspected.

---

### 🔴 SEC-05: Session Token Budget Circuit Breaker Failed to Block Traffic
* **Severity:** **High (Unbounded Consumption / LLM10)**
* **Affected Component:** `internal/transport/proxy.go` (`GatewayServer.Handler`) & `internal/state/circuit_breaker.go`
* **Pre-Hardening Behavior (Root Cause):**
  * When `CheckAndTrackTokens` determined that a session exceeded `max_tokens_per_session`, the gateway recorded warning code `JG-CFG-202` and set `res.Severity = "CONFIG_WARNING"`.
  * However, the code **never set `res.Blocked = true`**.
* **Production Impact:**
  * Even in `hard_block` mode, requests exceeding token quotas continued to be forwarded to upstream providers, providing no financial or rate-limiting protection against runaway agent loops.

---

### 🟠 SEC-06: Agent Loop Circuit Breaker Inactive for Standard LLM Completions
* **Severity:** **Medium/High (Policy Enforcement Gap)**
* **Affected Component:** `internal/state/circuit_breaker.go` & `internal/transport/proxy.go`
* **Pre-Hardening Behavior (Root Cause):**
  * The loop fingerprint calculation utilized `json.Compact`, which removes whitespace but preserves JSON key order. Thus, `{"a": 1, "b": 2}` and `{"b": 2, "a": 1}` produced different SHA-256 hashes, allowing identical semantic tool calls to evade detection.
  * `FilterLoopingToolCalls` was only hooked into the MCP inspector, remaining completely unconnected to standard OpenAI/Ollama HTTP completions (`choices[].message.tool_calls`).

---

### 🟠 SEC-07: Silent No-Op in Wasm Sandbox Plugin Execution
* **Severity:** **Medium/High (False Sense of Security)**
* **Affected Component:** `internal/extensions/sandbox.go` (`runSingleModule`)
* **Pre-Hardening Behavior (Root Cause):**
  * When a `.wasm` file path was specified in configuration, the sandbox read the file, checked the 8-byte magic header (`\x00asm\x01\x00\x00\x00`), and returned `input` with `nil` error without executing any bytecode.
* **Production Impact:**
  * Operators configuring Wasm compliance plugins believed custom validation was enforcing policy, while in reality the plugin executed no logic and returned `CLEAN`.

---

### 🔴 SEC-08: State Store AES-256-GCM Fail-Open on Decryption Failure
* **Severity:** **High (Cryptographic Insecurity)**
* **Affected Component:** `internal/state/store.go` (`HybridStore.Get`)
* **Pre-Hardening Behavior (Root Cause):**
  * When `s.Decrypt(raw)` failed (due to key mismatch, corruption, or tampered GCM tag), the code swallowed the error and executed `return raw, "", nil`.
* **Production Impact:**
  * The gateway returned raw Base64 ciphertext as plaintext data.
  * The minimal Redis client only used plain TCP (`net.DialTimeout`), ignoring `rediss://` (TLS) and user ACL authentication.

---

### 🟠 SEC-09: Unbounded Response Ingestion & Map Memory Leaks (DoS Vulnerability)
* **Severity:** **Medium/High (Resource Exhaustion)**
* **Affected Component:** `internal/transport/proxy.go`, `internal/stream/sse_inspector.go`, `internal/guards/vault.go`, `internal/state/*`
* **Pre-Hardening Behavior (Root Cause):**
  * Non-streaming responses were read via unbounded `io.ReadAll(resp.Body)`. A compromised or rogue upstream could stream gigabytes into memory, inducing OOM crashes.
  * In streaming SSE, an upstream sending lines without newline characters (`\n`) caused `rawBuf` to grow indefinitely.
  * Map entries in `CircuitBreaker` (`toolHistory` and `tokenUsage`) were never purged of expired sessions, steadily leaking memory over time.

---

### 🟡 SEC-10: Hot Reload Inconsistency in Reverse Proxy Routing
* **Severity:** **Medium (Configuration Drift)**
* **Affected Component:** `internal/transport/proxy.go` (`NewGatewayServer`, `ModifyResponse`)
* **Pre-Hardening Behavior (Root Cause):**
  * Upstream target URL was parsed once at server startup (`targetURL`).
  * If configuration hot-reloaded a new `upstream_url`, liveness probes tested the new host, while the reverse proxy continued routing live traffic to the old host.
  * `ModifyResponse` retrieved a fresh configuration snapshot from `cfgMgr.Get()`, risking policy drift between request ingress and response egress.

---

### 🟡 SEC-11: Premature SSE Metrics Recording and Unverified Webhooks
* **Severity:** **Medium (Observability Inaccuracy)**
* **Affected Component:** `internal/transport/proxy.go` & `internal/telemetry/webhooks.go`
* **Pre-Hardening Behavior (Root Cause):**
  * For SSE connections, `metrics.RecordRequest` was invoked upon connection establishment, prior to token streaming. If a Canary leak occurred mid-stream, Prometheus metrics permanently recorded the request as `CLEAN`.
  * The webhook dispatcher incremented `sentCount` upon receiving any HTTP response from the receiver endpoint, including HTTP `4xx` and `5xx` errors.

---

### 🟡 SEC-12: Zero-Trust Logger Secret Substitution Bug & CLI Discrepancy
* **Severity:** **Medium (Operational Hygiene)**
* **Affected Component:** `cmd/jgate/main.go` & `README.md`
* **Pre-Hardening Behavior (Root Cause):**
  * The logger initialization passed `snap.Core.Language` (e.g., `"en"` or `"pt-BR"`) into the 5th argument of `NewZeroTrustLogger`, which was the `placeholder string`. Consequently, masked secrets in logs were replaced with `"en"` or `"pt-BR"` instead of `***[JG-REDACTED]***`.
  * Documentation instructed users to run `jgate start`, whereas the CLI binary only registered `jgate serve`.

---

## 3. Pre-Hardening Traceability Matrix

| Finding ID | Primary Category | Original State | Hardened Condition | Verification Test |
| :--- | :--- | :---: | :--- | :--- |
| **SEC-01** | CWE-284 / OWASP LLM02 | **Vulnerable** | 128-bit tokens, session-bound mapping in RAM and Redis | `TestPIIVaultCrossSessionIsolation` |
| **SEC-02** | CWE-863 / OWASP LLM06 | **Vulnerable** | Enforced re-serialization whenever `len(toolCodes) > 0` | `TestIsolatedDomainSanitizationWithoutToolPruning` |
| **SEC-03** | CWE-20 / OWASP LLM01 | **Vulnerable** | Deep recursive inspection across arbitrary JSON fields | `TestMCPJSONRPCToolFirewallAndExternalResourceSanitization` |
| **SEC-04** | CWE-200 / OWASP LLM07 | **Vulnerable** | Holdback threshold lowered to $k \ge 1$; Anthropic/Ollama support | `TestSSEOneAndTwoCharPrefixSplitsAndAnthropicFormat` |
| **SEC-05** | CWE-400 / OWASP LLM10 | **Vulnerable** | Immediate `HTTP 429` rejection prior to upstream forwarding | `TestProxyTokenBudgetEnforcementAndDeferredSSEMetrics` |
| **SEC-06** | CWE-834 / OWASP LLM10 | **Vulnerable** | Normalized key order in SHA-256 fingerprint; LLM response filter | `TestFilterLoopingToolCallsPruningAndShadow` |
| **SEC-07** | CWE-390 / Integrity | **Vulnerable** | Returns `ErrWasmRuntimeNotLinked` with explicit `JG-EXT-601` warning | `TestSandboxWasmMagicBytesAndTimeoutFailOpen` |
| **SEC-08** | CWE-311 / CWE-327 | **Vulnerable** | Fail-closed on decryption error (`ErrDecryptionFailed`); TLS support | `TestHybridStoreAESGCMAndRedisFailOpen` |
| **SEC-09** | CWE-770 / DoS | **Vulnerable** | `io.LimitReader`, 1MB line cap, LRU-style eviction ($N \le 16384$) | State & Stream test suite |
| **SEC-10** | CWE-440 / Reliability | **Vulnerable** | Request-scoped config snapshot; dynamic upstream re-routing | `TestHTTPAndUnixSocketProxyWithSSEStreaming` |
| **SEC-11** | CWE-778 / Auditing | **Vulnerable** | Deferred metrics via `SetOnComplete`; `sentCount` gated by HTTP 2xx | `TestPrometheusMetricsAndNonBlockingWebhook` |
| **SEC-12** | CWE-532 / Usability | **Vulnerable** | Fixed redaction placeholder; added `start`/`bote` CLI aliases | `./jgate check && ./jgate pounce` |

---
*Maintained as part of the JaguarGate Core Security Documentation.*

