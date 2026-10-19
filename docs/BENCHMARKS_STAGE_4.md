# 🔬 JaguarGate — Benchmark History: Stage 4 (`v0.8.0-scale-mcp`)

> **[EN]** Immutable performance, cryptography, and concurrency audit record for **Stage 4 (Hybrid L1/L2 AES-256-GCM State Store, O(1) Agent Loop Circuit Breaker, MCP JSON-RPC 2.0 Guardrail & Table-Driven PII/Alphanumeric CNPJ Suite)**.  
> **[PT-BR]** Registro histórico imutável de performance, criptografia e concorrência da **Etapa 4 (Estado Híbrido L1/L2 com AES-256-GCM, Disjuntor Anti-Loop O(1) para Agentes, Guardrail MCP JSON-RPC 2.0 e Suíte Table-Driven de PII/CNPJ Alfanumérico)**.

⬅️ **Back to Consolidated Index / Voltar ao Índice Consolidado:** [`docs/BENCHMARKS.md`](BENCHMARKS.md)

---

## 🖥️ Test Environment / Ambiente de Teste

* **Release Tag:** `v0.8.0-scale-mcp`
* **CPU:** `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` (`GOMAXPROCS=4`)
* **OS / Arch:** `linux / amd64`
* **Go Toolchain:** `Go 1.23+`

---

## 📊 Stage 4 Summary Metrics

| Benchmark / Suite | Operation | Production Speed | Memory Footprint | Verification Notes |
| :--- | :--- | :--- | :--- | :--- |
| **`BenchmarkCircuitBreakerCheck-4`** | Canonical JSON compaction + `SHA-256` tool call fingerprint + dynamic $O(1)$ window counter (`JG-CFG-201`) | **`542.8 ns/op`** *(**`0.54 µs`** — 2.24M ops)* | **`160 B/op` (`4 allocs/op`)** | **191.4x speedup** after replacing slice history with inline $O(1)$ struct value counters |
| **`BenchmarkAESGCMSealOpen-4`** | Full **AES-256-GCM** authenticated encryption (`Seal` with 12-byte random nonce) + decryption (`Open`) for L1/L2 state | **`724.5 ns/op`** *(**`0.72 µs`** — 1.66M ops)* | **`288 B/op` (`8 allocs/op`)** | Hardware-accelerated AEAD with automatic Redis Fail-Open (`JG-EXT-602`) |
| **`BenchmarkMCPJSONRPCInspection-4`** | Native **MCP JSON-RPC 2.0** `tools/call` & `resources/read` inspection, batch capping & tool whitelist | **`4,598 ns/op`** *(**`4.59 µs`** — 261K ops)* | **`2,733 B/op` (`58 allocs/op`)** | Supports single RPC objects and batch arrays (`[{}]`) |
| **Table-Driven PII & CNPJ Suite** | 14 sub-tests: Legacy Numeric CNPJ, **2026 Alphanumeric CNPJ** (upper/lower/semi-formatted), CPF, Cards, Email, AWS/OpenAI/GitHub/Slack/JWT & SKU false-positive check | **`0.005s`** (`14/14 PASS`) | Zero leaks | 100% reversible restoration verified on all masked entities |

---

## 💻 Raw Terminal Output — Full Test Suite & Table-Driven Subtests

```text
$ go test -v -count=1 ./...
=== RUN   TestMinimalThreeLineConfigAndPresets
--- PASS: TestMinimalThreeLineConfigAndPresets (0.00s)
=== RUN   TestEnvVarInterpolation
--- PASS: TestEnvVarInterpolation (0.00s)
=== RUN   TestConcurrentLockFreeAtomicReadsAndWrites
--- PASS: TestConcurrentLockFreeAtomicReadsAndWrites (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)        0.003s
=== RUN   TestDeobfuscatorUnicodeSmugglingAndNestedBase64
--- PASS: TestDeobfuscatorUnicodeSmugglingAndNestedBase64 (0.00s)
=== RUN   TestReversiblePIIVaultMaskAndRestore
--- PASS: TestReversiblePIIVaultMaskAndRestore (0.00s)
=== RUN   TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/CPF_Standard (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/CNPJ_Legacy_Numeric_Formatted (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/CNPJ_Legacy_Numeric_Unformatted_14Digits (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/CNPJ_2026_Alphanumeric_Uppercase (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/CNPJ_2026_Alphanumeric_Lowercase (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/CNPJ_2026_Alphanumeric_SemiFormatted_SlashHyphen (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/CreditCard_16Digits_Spaced (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/Email_Corporate (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/AWS_AccessKeyID_AKIA (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/OpenAI_API_Key_sk (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/GitHub_PersonalAccessToken_ghp (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/Slack_BotToken_xoxb (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/JWT_Bearer_Token (0.00s)
    --- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats/FalsePositive_ProductSKU_14Chars (0.00s)
--- PASS: TestPIIVaultTableDrivenAllEntitiesAndCNPJFormats (0.00s)
=== RUN   TestEngineThreeModesSpotlightingAndCanary
--- PASS: TestEngineThreeModesSpotlightingAndCanary (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)        0.005s
=== RUN   TestMCPJSONRPCToolFirewallAndExternalResourceSanitization
--- PASS: TestMCPJSONRPCToolFirewallAndExternalResourceSanitization (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/mcp](https://github.com/andrewbraga1/jaguargate/internal/mcp)           0.011s
=== RUN   TestJPEGMetadataStrippingAndMagicBytes
--- PASS: TestJPEGMetadataStrippingAndMagicBytes (0.00s)
=== RUN   TestSpoofedMagicBytesDetection
--- PASS: TestSpoofedMagicBytesDetection (0.00s)
=== RUN   FuzzStripJPEGMetadata
--- PASS: FuzzStripJPEGMetadata (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)    0.006s
=== RUN   TestCircuitBreakerCanonicalLoopAndTokenBudget
--- PASS: TestCircuitBreakerCanonicalLoopAndTokenBudget (0.00s)
=== RUN   TestFilterLoopingToolCallsPruningAndShadow
--- PASS: TestFilterLoopingToolCallsPruningAndShadow (0.00s)
=== RUN   TestCircuitBreakerConcurrentAccess
--- PASS: TestCircuitBreakerConcurrentAccess (0.00s)
=== RUN   TestHybridStoreAESGCMAndRedisFailOpen
--- PASS: TestHybridStoreAESGCMAndRedisFailOpen (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/state](https://github.com/andrewbraga1/jaguargate/internal/state)         0.042s
=== RUN   TestSelectiveToolCallFirewallPruning
--- PASS: TestSelectiveToolCallFirewallPruning (0.00s)
=== RUN   TestChaoticSplitSSEStreamPIIRestoreAndMarkdownSanitizer
--- PASS: TestChaoticSplitSSEStreamPIIRestoreAndMarkdownSanitizer (0.00s)
=== RUN   TestSSECanaryLeakImmediateTruncation
--- PASS: TestSSECanaryLeakImmediateTruncation (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)        0.031s
=== RUN   TestZeroTrustLoggerRedaction
--- PASS: TestZeroTrustLoggerRedaction (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)     0.020s
=== RUN   TestHTTPAndUnixSocketProxyWithSSEStreaming
--- PASS: TestHTTPAndUnixSocketProxyWithSSEStreaming (0.02s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/transport](https://github.com/andrewbraga1/jaguargate/internal/transport)     0.025s
```

---

## ⚡ Raw Terminal Output — Production Benchmarks (Stage 1 + 2 + 3 + 4)

```text
$ go test -bench=. -benchmem ./internal/...
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkAtomicConfigRead-4             1000000000               0.5172 ns/op          0 B/op          0 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)        0.591s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkOWASPInputEngine-4                  10000             107697 ns/op            3852 B/op        108 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)        1.087s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/mcp](https://github.com/andrewbraga1/jaguargate/internal/mcp)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkMCPJSONRPCInspection-4             261030               4598 ns/op            2733 B/op         58 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/mcp](https://github.com/andrewbraga1/jaguargate/internal/mcp)           2.150s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkStripJPEGMetadata-4              39810364               29.93 ns/op           32 B/op          1 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)    2.154s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/state](https://github.com/andrewbraga1/jaguargate/internal/state)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkCircuitBreakerCheck-4             2241871               542.8 ns/op           160 B/op          4 allocs/op
BenchmarkAESGCMSealOpen-4                  1668648               724.5 ns/op           288 B/op          8 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/state](https://github.com/andrewbraga1/jaguargate/internal/state)         3.597s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkSSERuneSlidingWindow-4             156950               6678 ns/op           11483 B/op         39 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)        1.132s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkBufferPoolCycle-4                 4384428               272.4 ns/op           24 B/op          1 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)     1.476s
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/transport](https://github.com/andrewbraga1/jaguargate/internal/transport)     0.027s
```