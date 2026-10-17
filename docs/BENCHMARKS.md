# ⚡ JaguarGate — Consolidated Performance Evolution & Benchmark Index

> **[EN]** Master benchmark index tracking the empirical latency, memory footprint, and concurrency verification of **JaguarGate (`jgate`)** across every engineering stage up to `v1.0.0`.  
> **[PT-BR]** Índice mestre de benchmarks acompanhando a evolução empírica de latência, consumo de memória e auditoria de concorrência do **JaguarGate (`jgate`)** em cada etapa até a `v1.0.0`.

---

## 🖥️ Baseline Reference Hardware / Hardware de Referência

To prove that JaguarGate delivers sub-millisecond protection without requiring expensive server-grade CPUs, all baseline benchmarks are captured on consumer dual-core/quad-thread hardware:

* **CPU:** `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` (4 Threads / `GOMAXPROCS=4`)
* **OS / Arch:** `linux / amd64`
* **Toolchain:** `Go 1.23+` (`CGO_ENABLED=0` static binary)
* **Target SLA Budget:** `< 1.0 ms` (`1,000,000 ns`) total proxy inspection overhead per request.

---

## 🗺️ Stage-by-Stage Benchmark History (Detailed Reports)

Click on any completed stage below to inspect the raw `go test -bench`, `-race`, and `-fuzz` terminal logs:

| Stage | Milestone Tag | Architectural Scope | Detailed Report | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 1** | `v0.2.0-core` | Lock-Free Config (`atomic.Pointer`), `sync.Pool` Buffer Recycling, Zero-Trust Logger & HTTP/UDS Proxy | [📄 `BENCHMARKS_STAGE_1.md`](BENCHMARKS_STAGE_1.md) | ✅ Verified |
| **Stage 2** | `v0.4.0-input-guards` | Pre-compiled RE2 OWASP Engine, Deobfuscator, Binary EXIF Stripper, Spotlighting & Reversible PII Vault | [📄 `BENCHMARKS_STAGE_2.md`](BENCHMARKS_STAGE_2.md) | ✅ Verified |
| **Stage 3** | `v0.6.0-streaming-tools` | Rune-Aware UTF-8 Sliding Window SSE Inspector & Selective Tool Call Firewall | `BENCHMARKS_STAGE_3.md` | ⏳ Next |
| **Stage 4** | `v0.8.0-scale-mcp` | Distributed L1/L2 State (AES-GCM Redis), SHA-256 Loop Breaker, gRPC & MCP Guardrail | `BENCHMARKS_STAGE_4.md` | ⏳ Planned |
| **Stage 5** | `v1.0.0-release` | Pure-Go Wasm Sandbox (`wazero`), OpenTelemetry, Webhooks & Built-in Red Teaming (`jgate pounce`) | `BENCHMARKS_STAGE_5.md` | ⏳ Planned |

---

## 📈 Consolidated Evolution Matrix (Stage 1 ➔ Current)

| Component / Benchmark | Stage Introduced | Latency (ns/op) | Latency (ms) | Memory (`B/op`) | Allocations (`allocs/op`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`BenchmarkAtomicConfigRead-4`** *(Lock-Free Config)* | Stage 1 | **`0.51 ns/op`** | `0.0000005 ms` | **`0 B/op`** | **`0 allocs/op`** |
| **`BenchmarkBufferPoolCycle-4`** *(32KB Scrub & Recycle)* | Stage 1 | **`273.1 ns/op`** | `0.000273 ms` | **`24 B/op`** | **`1 allocs/op`** |
| **`BenchmarkStripJPEGMetadata-4`** *(Binary EXIF Hygiene)* | Stage 2 | **`31.44 ns/op`** | `0.000031 ms` | **`32 B/op`** | **`1 allocs/op`** |
| **`BenchmarkOWASPInputEngine-4`** *(Full JSON OWASP + PII Vault)* | Stage 2 | **`118,794 ns/op`** | **`0.1187 ms`** | **`3,839 B/op`** | `108 allocs/op` |
| **Cumulative Hot-Path Overhead** *(Stage 1 + Stage 2)* | **Current** | **`~119,099 ns/op`** | **`~0.119 ms`** | **`~3,895 B/op`** | **88.1% under `< 1.0 ms` SLA** |

---

## 🧪 Cumulative Quality & Security Gates

| Verification Gate | Command | Stage 1 Result | Stage 2 Result |
| :--- | :--- | :--- | :--- |
| **Unit & E2E Execution Speed** | `go test -count=1 ./...` | `0.066s` (3 pkgs) | **`0.058s` (5 pkgs)** |
| **Concurrency Data-Race Audit** | `go test -race ./...` | `PASS` (0 races) | **`PASS` (0 races)** |
| **Coverage-Guided Binary Fuzzing** | `go test -fuzz=Fuzz...` | N/A | **`PASS` (`46,573 execs/sec`, 19 paths, 0 panics)** |