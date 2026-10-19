# 🔬 JaguarGate — Benchmark History: Stage 5 (`v1.0.0` Release)

> **[EN]** Final production performance, telemetry, sandbox, and Red-Teaming audit record for **Stage 5 (`v1.0.0` Release: Lock-Free Prometheus Metrics, Async HMAC Webhooks, Wasm Policy Sandbox, DevOps Doctor & Built-in Red-Teaming Suite `jgate pounce`)**.  
> **[PT-BR]** Registro histórico final de performance, telemetria, sandbox e Red-Teaming da **Etapa 5 (Lançamento `v1.0.0`: Métricas Prometheus Lock-Free, Webhooks HMAC Assíncronos, Sandbox Wasm, DevOps Doctor e Suíte Red-Teaming `jgate pounce`)**.

⬅️ **Back to Consolidated Index / Voltar ao Índice Consolidado:** [`docs/BENCHMARKS.md`](BENCHMARKS.md)

---

## 🖥️ Test Environment / Ambiente de Teste

* **Release Tag:** `v1.0.0`
* **CPU:** `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` (`GOMAXPROCS=4`)
* **OS / Arch:** `linux / amd64`
* **Go Toolchain:** `Go 1.23+` (`CGO_ENABLED=0` static binary)

---

## 📊 Stage 5 Summary Metrics

| Benchmark / Suite | Operation | Production Speed | Memory Footprint | Verification Notes |
| :--- | :--- | :--- | :--- | :--- |
| **`BenchmarkAtomicMetricsRecord-4`** | Lock-free `atomic.Uint64` Prometheus request status, latency & flag code counter update | **`85.14 ns/op`** *(**`0.085 µs`** — 15.9M ops)* | **`0 B/op` (`0 allocs/op`)** | Zero heap allocations on telemetry hot path |
| **`BenchmarkSandboxFastHook-4`** | Isolated goroutine policy hook execution with `context.WithTimeout` (`2ms` budget) & panic recovery (`JG-EXT-601`) | **`824.4 ns/op`** *(**`0.82 µs`** — 1.41M ops)* | **`656 B/op` (`8 allocs/op`)** | Enforces strict Fail-Open resilience on timeout |
| **`BenchmarkPounceFullSuite-4`** | Complete 8-vector OWASP LLM Top 10 & MCP Red-Teaming simulation (`jgate pounce`) | **`235,521 ns/op`** *(**`0.235 ms`** per full 8-vector suite)* | **`120,974 B/op`** | CLI execution completed in `375µs`–`603µs` (`8/8 PASS`) |
| **Full 10-Package Test & Race Audit** | `config`, `extensions`, `guards`, `mcp`, `multimodal`, `redteam`, `state`, `stream`, `telemetry`, `transport` | **`0.171s total`** (`-count=1`) | Pass (`100% leak-free`) | Verified under `go test -race ./...` (`0 data races`) |

---

## 💻 Raw Terminal Output — `jgate pounce` CLI Security Audit (`en` & `pt-BR`)

```text
$ ./jgate pounce

===============================================================================================
  JAGUARGATE RED-TEAMING SUITE (jgate pounce) — SECURITY AUDIT REPORT
===============================================================================================
ID      | CATEGORY     | SIMULATED ATTACK SCENARIO                       | FLAG       | LAT.   | STATUS
-----------------------------------------------------------------------------------------------
VEC-01  | OWASP-LLM01  | Direct Prompt Injection Neutralization          | JG-SEC-401 |  135µs | PASS  
VEC-02  | OWASP-OBFUSC | Invisible Unicode + Base64 Smuggling Defense    | JG-SEC-402 |  147µs | PASS  
VEC-03  | MULTIMODAL   | Binary JPEG EXIF Hidden Payload Stripping       | JG-SEC-403 |    2µs | PASS  
VEC-04  | OWASP-LLM02  | Reversible PII Vault (CPF + Alphanumeric CNPJ + Secret) | JG-PII-301 |   54µs | PASS  
VEC-05  | OWASP-LLM06  | Selective Unauthorized Tool Call Pruning        | JG-CFG-101 |   96µs | PASS  
VEC-06  | AGENT-LOOP   | O(1) SHA-256 Canonical Agent Loop Circuit Breaker | JG-CFG-201 |   14µs | PASS  
VEC-07  | MCP-GUARD    | MCP JSON-RPC 2.0 Untrusted Server & Tool Firewall | JG-CFG-102 |   20µs | PASS  
VEC-08  | SSE-STREAM   | Real-Time SSE Canary Leak Stream Truncation     | JG-SEC-501 |   99µs | PASS  
-----------------------------------------------------------------------------------------------
  VERDICT: PASSED (8/8 Attack Vectors Neutralized) | Total Suite Duration: 603µs
===============================================================================================

$ ./jgate pounce --lang pt-BR

===============================================================================================
  JAGUARGATE RED-TEAMING SUITE (jgate pounce) — RELATÓRIO DE AUDITORIA DE SEGURANÇA
===============================================================================================
ID      | CATEGORIA    | CENÁRIO DE ATAQUE SIMULADO                      | FLAG       | LAT.   | STATUS
-----------------------------------------------------------------------------------------------
VEC-01  | OWASP-LLM01  | Neutralização de Prompt Injection Direto        | JG-SEC-401 |   85µs | PASS  
VEC-02  | OWASP-OBFUSC | Desofuscação de Unicode Invisível + Base64      | JG-SEC-402 |   91µs | PASS  
VEC-03  | MULTIMODAL   | Remoção Binária de Payload Oculto em EXIF JPEG  | JG-SEC-403 |    1µs | PASS  
VEC-04  | OWASP-LLM02  | Cofre Reversível PII (CPF + CNPJ Alfanumérico + Secret) | JG-PII-301 |   34µs | PASS  
VEC-05  | OWASP-LLM06  | Poda Cirúrgica de Tool Call Não Autorizada      | JG-CFG-101 |   61µs | PASS  
VEC-06  | AGENT-LOOP   | Disjuntor O(1) SHA-256 contra Loop de Agente    | JG-CFG-201 |    9µs | PASS  
VEC-07  | MCP-GUARD    | Firewall JSON-RPC 2.0 para Servidor e Tool MCP  | JG-CFG-102 |   13µs | PASS  
VEC-08  | SSE-STREAM   | Corte em Tempo Real de Vazamento Canary em SSE  | JG-SEC-501 |   59µs | PASS  
-----------------------------------------------------------------------------------------------
  VEREDITO: APROVADO (8/8 Vetores Neutralizados) | Tempo Total da Suíte: 375µs
===============================================================================================
```

---

## ⚡ Raw Terminal Output — Complete `v1.0.0` Benchmark Suite (All 10 Packages)

```text
$ go test -bench=. -benchmem ./internal/...
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkAtomicConfigRead-4             1000000000               0.5056 ns/op          0 B/op          0 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)        0.567s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/extensions](https://github.com/andrewbraga1/jaguargate/internal/extensions)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkSandboxFastHook-4               1413870               824.4 ns/op           656 B/op          8 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/extensions](https://github.com/andrewbraga1/jaguargate/internal/extensions)    2.031s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkOWASPInputEngine-4                10000            113393 ns/op            3847 B/op        108 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)        1.149s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/mcp](https://github.com/andrewbraga1/jaguargate/internal/mcp)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkMCPJSONRPCInspection-4           259644              4650 ns/op            2734 B/op         58 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/mcp](https://github.com/andrewbraga1/jaguargate/internal/mcp)           2.240s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkStripJPEGMetadata-4            40508389                29.33 ns/op           32 B/op          1 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)    1.920s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/redteam](https://github.com/andrewbraga1/jaguargate/internal/redteam)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkPounceFullSuite-4                  5076            235521 ns/op          120974 B/op        499 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/redteam](https://github.com/andrewbraga1/jaguargate/internal/redteam)       2.073s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/state](https://github.com/andrewbraga1/jaguargate/internal/state)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkCircuitBreakerCheck-4           2229100               580.9 ns/op           160 B/op          4 allocs/op
BenchmarkAESGCMSealOpen-4                1594242               718.6 ns/op           288 B/op          8 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/state](https://github.com/andrewbraga1/jaguargate/internal/state)         3.761s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkSSERuneSlidingWindow-4           157609              7072 ns/op           11472 B/op         39 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)        1.204s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkBufferPoolCycle-4               4273653               277.8 ns/op            24 B/op          1 allocs/op
BenchmarkAtomicMetricsRecord-4          15916279                85.14 ns/op            0 B/op          0 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)     2.912s
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/transport](https://github.com/andrewbraga1/jaguargate/internal/transport)     0.026s
```