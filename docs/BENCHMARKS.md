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
| **Stage 3** | `v0.6.0-streaming-tools` | Rune-Aware UTF-8 Sliding Window SSE Inspector, Selective Tool Call Firewall & Output Sanitizer | [📄 `BENCHMARKS_STAGE_3.md`](BENCHMARKS_STAGE_3.md) | ✅ Verified |
| **Stage 4** | `v0.8.0-scale-mcp` | Distributed L1/L2 State (AES-256-GCM Redis), $O(1)$ SHA-256 Loop Breaker & MCP JSON-RPC 2.0 Guardrail | [📄 `BENCHMARKS_STAGE_4.md`](BENCHMARKS_STAGE_4.md) | ✅ Verified |
| **Stage 5** | `v1.0.0-release` | Policy Sandbox Engine, Prometheus/OTel Metrics, Async Webhooks, `jgate doctor` & Red-Teaming (`jgate pounce`) | `BENCHMARKS_STAGE_5.md` | ⏳ Next |

---

## 📈 Consolidated Evolution Matrix (Stage 1 ➔ Stage 4)

| Component / Benchmark | Stage Introduced | Latency (ns/op) | Latency (ms) | Memory (`B/op`) | Allocations (`allocs/op`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`BenchmarkAtomicConfigRead-4`** *(Lock-Free Config)* | Stage 1 | **`0.51 ns/op`** | `0.0000005 ms` | **`0 B/op`** | **`0 allocs/op`** |
| **`BenchmarkBufferPoolCycle-4`** *(32KB Scrub & Recycle)* | Stage 1 | **`272.4 ns/op`** | `0.000272 ms` | **`24 B/op`** | **`1 allocs/op`** |
| **`BenchmarkStripJPEGMetadata-4`** *(Binary EXIF Hygiene)* | Stage 2 | **`29.93 ns/op`** | `0.000030 ms` | **`32 B/op`** | **`1 allocs/op`** |
| **`BenchmarkOWASPInputEngine-4`** *(Full JSON OWASP + Tool Firewall + PII Vault)* | Stage 2 / 3 | **`107,697 ns/op`** | **`0.1076 ms`** | **`3,852 B/op`** | `108 allocs/op` |
| **`BenchmarkSSERuneSlidingWindow-4`** *(Real-Time UTF-8 SSE Stream Inspector)* | Stage 3 | **`6,678 ns/op`** | **`0.0066 ms`** | **`11,483 B/op`** | `39 allocs/op` |
| **`BenchmarkCircuitBreakerCheck-4`** *($O(1)$ SHA-256 Agent Loop Breaker)* | Stage 4 | **`542.8 ns/op`** | `0.000543 ms` | **`160 B/op`** | `4 allocs/op` |
| **`BenchmarkAESGCMSealOpen-4`** *(AES-256-GCM State Encryption)* | Stage 4 | **`724.5 ns/op`** | `0.000725 ms` | **`288 B/op`** | `8 allocs/op` |
| **`BenchmarkMCPJSONRPCInspection-4`** *(MCP JSON-RPC 2.0 Guardrail)* | Stage 4 | **`4,598 ns/op`** | **`0.0045 ms`** | **`2,733 B/op`** | `58 allocs/op` |
| **Cumulative Hot-Path Overhead** *(Stages 1–4 Combined)* | **Current** | **`~120,513 ns/op`** | **`~0.120 ms`** | **`~18,572 B/op`** | **88.0% under `< 1.0 ms` SLA** |

---

## 🧪 Cumulative Quality & Security Gates

| Verification Gate | Command | Stage 1 | Stage 2 | Stage 3 | Stage 4 |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Unit & E2E Execution Speed** | `go test -count=1 ./...` | `0.066s` (3 pkgs) | `0.058s` (5 pkgs) | `0.052s` (6 pkgs) | **`0.143s` (8 pkgs + 14 subtests)** |
| **Concurrency Data-Race Audit** | `go test -race ./...` | `PASS` | `PASS` | `PASS` | **`PASS` (0 races)** |
| **Coverage-Guided Binary Fuzzing** | `go test -fuzz=Fuzz...` | N/A | `PASS` (`46.5k/s`) | `PASS` | **`PASS` (`46.5k/s`, 0 panics)** |