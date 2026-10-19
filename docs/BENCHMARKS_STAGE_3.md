# 🔬 JaguarGate — Benchmark History: Stage 3 (`v0.6.0-streaming-tools`)

> **[EN]** Immutable performance and concurrency audit record for **Stage 3 (Rune-Aware UTF-8 Sliding Window SSE Inspector, Selective Tool Call Firewall & Output Sanitizer)**.  
> **[PT-BR]** Registro histórico imutável de performance e auditoria de concorrência da **Etapa 3 (Inspetor SSE de Janela Deslizante UTF-8, Firewall Seletivo de Tool Calls e Sanitizador de Saída)**.

⬅️ **Back to Consolidated Index / Voltar ao Índice Consolidado:** [`docs/BENCHMARKS.md`](BENCHMARKS.md)

---

## 🖥️ Test Environment / Ambiente de Teste

* **Release Tag:** `v0.6.0-streaming-tools`
* **CPU:** `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` (`GOMAXPROCS=4`)
* **OS / Arch:** `linux / amd64`
* **Go Toolchain:** `Go 1.23+`

---

## 📊 Stage 3 Summary Metrics

| Benchmark / Suite | Operation | Production Speed | Memory Footprint | Verification Notes |
| :--- | :--- | :--- | :--- | :--- |
| **`BenchmarkSSERuneSlidingWindow-4`** | Real-time SSE (`text/event-stream`) chunk parsing, UTF-8 rune boundary reassembly, cross-chunk holdback window, Canary leak check, Markdown tracker filter & PII restoration | **`7,548 ns/op`** *(**`7.54 µs`** / **`0.0075 ms`**)* | **`11,469 B/op` (`39 allocs/op`)** | **143,875 SSE streams** processed in 2.07s; zero allocation string writes (`WriteString`/`WriteByte`) |
| **`BenchmarkOWASPInputEngine-4`** | Full Input JSON OWASP inspection + Selective Tool Call Whitelist pruning (`JG-CFG-101`, `JG-CFG-103`) | **`129,785 ns/op`** *(**`0.129 ms`** / req)* | **`3,848 B/op` (`108 allocs/op`)** | Includes input `tools` & `tool_calls` array inspection |
| **Full Unit & E2E Suite** | All 6 packages (`config`, `guards`, `multimodal`, `stream`, `telemetry`, `transport`) | **`0.052s total`** (`-count=1`) | Pass | `go test -race ./...` passed (`0 data races`) |

---

## 💻 Raw Terminal Output — Unit Tests & Concurrency Audit (`-race`)

```text
$ go test -v -count=1 ./...
=== RUN   TestMinimalThreeLineConfigAndPresets
--- PASS: TestMinimalThreeLineConfigAndPresets (0.00s)
=== RUN   TestEnvVarInterpolation
--- PASS: TestEnvVarInterpolation (0.00s)
=== RUN   TestConcurrentLockFreeAtomicReadsAndWrites
--- PASS: TestConcurrentLockFreeAtomicReadsAndWrites (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)        0.012s
=== RUN   TestDeobfuscatorUnicodeSmugglingAndNestedBase64
--- PASS: TestDeobfuscatorUnicodeSmugglingAndNestedBase64 (0.00s)
=== RUN   TestReversiblePIIVaultMaskAndRestore
--- PASS: TestReversiblePIIVaultMaskAndRestore (0.00s)
=== RUN   TestEngineThreeModesSpotlightingAndCanary
--- PASS: TestEngineThreeModesSpotlightingAndCanary (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)        0.003s
=== RUN   TestJPEGMetadataStrippingAndMagicBytes
--- PASS: TestJPEGMetadataStrippingAndMagicBytes (0.00s)
=== RUN   TestSpoofedMagicBytesDetection
--- PASS: TestSpoofedMagicBytesDetection (0.00s)
=== RUN   FuzzStripJPEGMetadata
--- PASS: FuzzStripJPEGMetadata (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)    0.003s
=== RUN   TestSelectiveToolCallFirewallPruning
--- PASS: TestSelectiveToolCallFirewallPruning (0.00s)
=== RUN   TestChaoticSplitSSEStreamPIIRestoreAndMarkdownSanitizer
--- PASS: TestChaoticSplitSSEStreamPIIRestoreAndMarkdownSanitizer (0.00s)
=== RUN   TestSSECanaryLeakImmediateTruncation
--- PASS: TestSSECanaryLeakImmediateTruncation (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)        0.004s
=== RUN   TestZeroTrustLoggerRedaction
--- PASS: TestZeroTrustLoggerRedaction (0.00s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)     0.005s
=== RUN   TestHTTPAndUnixSocketProxyWithSSEStreaming
--- PASS: TestHTTPAndUnixSocketProxyWithSSEStreaming (0.02s)
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/transport](https://github.com/andrewbraga1/jaguargate/internal/transport)     0.025s

$ go test -race ./...
ok      [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)        0.313s
ok      [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)        0.072s
ok      [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)    (cached)
ok      [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)        1.026s
ok      [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)     (cached)
ok      [github.com/andrewbraga1/jaguargate/internal/transport](https://github.com/andrewbraga1/jaguargate/internal/transport)     1.043s
```

---

## ⚡ Raw Terminal Output — Production Benchmarks (Stage 1 + 2 + 3)

```text
$ go test -bench=. -benchmem ./internal/...
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkAtomicConfigRead-4      1000000000               0.5862 ns/op          0 B/op          0 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/config](https://github.com/andrewbraga1/jaguargate/internal/config)        0.660s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkOWASPInputEngine-4           10000             129785 ns/op            3848 B/op        108 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/guards](https://github.com/andrewbraga1/jaguargate/internal/guards)        1.311s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkStripJPEGMetadata-4       39120382               38.81 ns/op           32 B/op          1 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/multimodal](https://github.com/andrewbraga1/jaguargate/internal/multimodal)    2.378s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkSSERuneSlidingWindow-4      143875               7548 ns/op           11469 B/op         39 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/stream](https://github.com/andrewbraga1/jaguargate/internal/stream)        2.073s
goos: linux
goarch: amd64
pkg: [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkBufferPoolCycle-4          4056189               294.9 ns/op           24 B/op          1 allocs/op
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/telemetry](https://github.com/andrewbraga1/jaguargate/internal/telemetry)     1.502s
PASS
ok      [github.com/andrewbraga1/jaguargate/internal/transport](https://github.com/andrewbraga1/jaguargate/internal/transport)     0.027s
```