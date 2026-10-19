# ⚡ JaguarGate (`jgate`) — Consolidated Performance Evolution & Benchmark Index (`v1.0.0`)

> **[EN]** Master benchmark index tracking the empirical latency, memory footprint, and concurrency verification of **JaguarGate (`jgate`)** across all 5 engineering stages up to `v1.0.0`.  
> **[PT-BR]** Índice mestre de benchmarks acompanhando a evolução empírica de latência, consumo de memória e auditoria de concorrência do **JaguarGate (`jgate`)** em todas as 5 etapas até a `v1.0.0`.

---

## 🖥️ Baseline Reference Hardware / Hardware de Referência

To prove that JaguarGate delivers sub-millisecond protection without requiring expensive server-grade CPUs, all baseline benchmarks were captured on consumer dual-core/quad-thread hardware:

* **CPU:** `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` (4 Threads / `GOMAXPROCS=4`)
* **OS / Arch:** `linux / amd64`
* **Toolchain:** `Go 1.23+` (`CGO_ENABLED=0` static binary)
* **Target SLA Budget:** `< 1.0 ms` (`1,000,000 ns`) total proxy inspection overhead per request.

---

## 🗺️ Stage-by-Stage Benchmark History (Immutable Reports)

Click on any stage below to inspect the raw `go test -bench`, `-race`, `-fuzz`, and `jgate pounce` terminal logs:

| Stage | Milestone Tag | Architectural Scope | Detailed Report | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 1** | `v0.2.0-core` | Lock-Free Config (`atomic.Pointer`), `sync.Pool` Buffer Recycling, Zero-Trust Logger & HTTP/UDS Proxy | [📄 `BENCHMARKS_STAGE_1.md`](BENCHMARKS_STAGE_1.md) | ✅ Verified |
| **Stage 2** | `v0.4.0-input-guards` | Pre-compiled RE2 OWASP Engine, Deobfuscator, Binary EXIF Stripper, Spotlighting & Reversible PII Vault | [📄 `BENCHMARKS_STAGE_2.md`](BENCHMARKS_STAGE_2.md) | ✅ Verified |
| **Stage 3** | `v0.6.0-streaming-tools` | Rune-Aware UTF-8 Sliding Window SSE Inspector, Selective Tool Call Firewall & Output Sanitizer | [📄 `BENCHMARKS_STAGE_3.md`](BENCHMARKS_STAGE_3.md) | ✅ Verified |
| **Stage 4** | `v0.8.0-scale-mcp` | Distributed L1/L2 State (AES-256-GCM Redis), $O(1)$ SHA-256 Loop Breaker & MCP JSON-RPC 2.0 Guardrail | [📄 `BENCHMARKS_STAGE_4.md`](BENCHMARKS_STAGE_4.md) | ✅ Verified |
| **Stage 5** | **`v1.0.0`** | Lock-Free Prometheus Metrics, Async HMAC Webhooks, Wasm Policy Sandbox, `jgate doctor` & `jgate pounce` | [📄 `BENCHMARKS_STAGE_5.md`](BENCHMARKS_STAGE_5.md) | ✅ **Released** |

---

## 📈 Complete `v1.0.0` Performance Matrix (All 10 Benchmarks)

| Benchmark Name | Package | Stage | Latency (`ns/op`) | Latency (`ms`) | Memory (`B/op`) | Allocs (`allocs/op`) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`BenchmarkAtomicConfigRead-4`** | `internal/config` | Stage 1 | **`0.5056 ns/op`** | `0.0000005 ms` | **`0 B/op`** | **`0 allocs/op`** |
| **`BenchmarkStripJPEGMetadata-4`** | `internal/multimodal` | Stage 2 | **`29.33 ns/op`** | `0.000029 ms` | **`32 B/op`** | **`1 allocs/op`** |
| **`BenchmarkAtomicMetricsRecord-4`** | `internal/telemetry` | Stage 5 | **`85.14 ns/op`** | `0.000085 ms` | **`0 B/op`** | **`0 allocs/op`** |
| **`BenchmarkBufferPoolCycle-4`** | `internal/telemetry` | Stage 1 | **`277.8 ns/op`** | `0.000278 ms` | **`24 B/op`** | **`1 allocs/op`** |
| **`BenchmarkCircuitBreakerCheck-4`** | `internal/state` | Stage 4 | **`580.9 ns/op`** | `0.000581 ms` | **`160 B/op`** | `4 allocs/op` |
| **`BenchmarkAESGCMSealOpen-4`** | `internal/state` | Stage 4 | **`718.6 ns/op`** | `0.000719 ms` | **`288 B/op`** | `8 allocs/op` |
| **`BenchmarkSandboxFastHook-4`** | `internal/extensions` | Stage 5 | **`824.4 ns/op`** | `0.000824 ms` | **`656 B/op`** | `8 allocs/op` |
| **`BenchmarkMCPJSONRPCInspection-4`** | `internal/mcp` | Stage 4 | **`4,650 ns/op`** | **`0.0046 ms`** | **`2,734 B/op`** | `58 allocs/op` |
| **`BenchmarkSSERuneSlidingWindow-4`** | `internal/stream` | Stage 3 | **`7,072 ns/op`** | **`0.0070 ms`** | **`11,472 B/op`** | `39 allocs/op` |
| **`BenchmarkOWASPInputEngine-4`** | `internal/guards` | Stage 2 | **`113,393 ns/op`** | **`0.1133 ms`** | **`3,847 B/op`** | `108 allocs/op` |
| **`BenchmarkPounceFullSuite-4`** *(All 8 Attacks)* | `internal/redteam` | Stage 5 | **`235,521 ns/op`** | **`0.2355 ms`** | `120,974 B/op` | `499 allocs/op` |
| **Total Cumulative Hot-Path Overhead** | **All Stages (1–5)** | **`v1.0.0`** | **`~127,632 ns/op`** | **`~0.127 ms`** | **`~19,213 B/op`** | **87.3% under `< 1.0 ms` SLA** |

---

## 🧪 Cumulative Quality & Security Gates (Stage 1 ➔ `v1.0.0`)

| Verification Gate | Command | Stage 1 | Stage 2 | Stage 3 | Stage 4 | Stage 5 (`v1.0.0`) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Unit & E2E Execution Speed** | `go test -count=1 ./...` | `0.066s` (3 pkgs) | `0.058s` (5 pkgs) | `0.052s` (6 pkgs) | `0.143s` (8 pkgs) | **`0.171s` (10 pkgs)** |
| **Concurrency Data-Race Audit** | `go test -race ./...` | `PASS` | `PASS` | `PASS` | `PASS` | **`PASS` (0 races across 10 pkgs)** |
| **Coverage-Guided Fuzzing** | `go test -fuzz=Fuzz...` | N/A | `PASS` (`46.5k/s`) | `PASS` | `PASS` | **`PASS` (`46.5k/s`, 0 panics)** |
| **Built-In Red-Teaming Audit** | `./jgate pounce` | N/A | N/A | N/A | N/A | **`PASS` (`8/8` vectors in `375µs`)** |