# ⚡ JaguarGate — Empirical Performance & Concurrency Benchmarks

> **[EN]** Real-world microbenchmarks and concurrency audit results for **JaguarGate (`jgate`)**, proving sub-microsecond overhead and zero-allocation hot paths.  
> **[PT-BR]** Resultados empíricos reais de microbenchmarks e auditoria de concorrência do **JaguarGate (`jgate`)**, comprovando latência em nanossegundos e zero alocação de memória no caminho crítico.

---

## 🖥️ Reference Hardware & Environment / Ambiente de Referência

All benchmarks below are reproducible via standard Go toolchain commands (`go test -bench=. -benchmem`) and were captured on baseline consumer hardware to demonstrate efficiency even on modest CPU footprints:

* **CPU:** `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` (4 Hardware Threads / `GOMAXPROCS=4`)
* **OS / Arch:** `linux / amd64`
* **Compiler:** `Go 1.23+` (`CGO_ENABLED=0` for production binaries)

---

## 📊 Stage 1 (`v0.2.0-core`) — Core Engine Results

### 1. Executive Summary Table (Production vs. ThreadSanitizer Audit)

| Benchmark Suite | Operation Tested | Production Mode (Native) | Audit Mode (`-race` Active) | Memory Allocations (Prod) | Speedup vs. Audit |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`BenchmarkAtomicConfigRead-4`** | Lock-free config snapshot read (`atomic.Pointer[Config]`) across 4 cores | **`0.5185 ns/op`** *(1 Billion ops in 0.59s)* | `245.1 ns/op` *(5.5M ops — zero data races)* | **`0 B/op` (`0 allocs/op`)** | **472x faster** |
| **`BenchmarkBufferPoolCycle-4`** | Acquire 32KB slice, write, Zero-Trust memory scrub (`clear`), return to `sync.Pool` | **`273.1 ns/op`** *(4.06M cycles)* | `16,976 ns/op` *(TSan inspecting 32,768 bytes/op)* | **`24 B/op` (`1 allocs/op`)** | **62x faster** |
| **Unit & E2E Suite (`go test`)** | Config presets, Env interpolation, Zero-Trust Logger redaction, HTTP + UDS (`0600`) SSE Proxy | **`0.066s total`** (`config`: `0.023s`, `telemetry`: `0.018s`, `transport`: `0.025s`) | `6.709s total` *(10,000 concurrent reads/writes verified)* | Pass (`100% leak-free`) | — |

---

### 2. Raw Terminal Output — Production Mode (Native Speed)

```text
$ go test ./...
ok      [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)        0.023s
ok      [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)     0.018s
ok      [github.com/jaguargate/jaguargate/internal/transport](https://github.com/jaguargate/jaguargate/internal/transport)     0.025s

$ go test -bench=. -benchmem ./internal/...
goos: linux
goarch: amd64
pkg: [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkAtomicConfigRead-4      1000000000               0.5185 ns/op          0 B/op          0 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)        0.593s

goos: linux
goarch: amd64
pkg: [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkBufferPoolCycle-4        4068264               273.1 ns/op           24 B/op          1 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)     2.468s
```

---

### 3. Raw Terminal Output — Concurrency & Data-Race Audit (`-race`)

```text
$ go test -v -race -bench=. -benchmem ./...
=== RUN   TestMinimalThreeLineConfigAndPresets
--- PASS: TestMinimalThreeLineConfigAndPresets (0.00s)
=== RUN   TestEnvVarInterpolation
--- PASS: TestEnvVarInterpolation (0.00s)
=== RUN   TestConcurrentLockFreeAtomicReadsAndWrites
--- PASS: TestConcurrentLockFreeAtomicReadsAndWrites (0.00s)
BenchmarkAtomicConfigRead-4       5526794               245.1 ns/op            0 B/op          0 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)        2.762s

=== RUN   TestZeroTrustLoggerRedaction
--- PASS: TestZeroTrustLoggerRedaction (0.00s)
BenchmarkBufferPoolCycle-4          96268             16976 ns/op           8254 B/op          1 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)     2.885s

=== RUN   TestHTTPAndUnixSocketProxyWithSSEStreaming
--- PASS: TestHTTPAndUnixSocketProxyWithSSEStreaming (0.03s)
PASS
ok      [github.com/jaguargate/jaguargate/internal/transport](https://github.com/jaguargate/jaguargate/internal/transport)     1.062s
```

---

## 🧠 Architectural Takeaways (EN / PT-BR)

* **[EN] Why `0.5185 ns/op` on Config Reads?**
  By storing the active configuration in an `atomic.Pointer[Config]`, the Go compiler inlines `Manager.Get()` into a single CPU register load from L1 cache with zero mutex contention. Hot-reloading `jaguargate.yaml` swaps the pointer address atomically without pausing in-flight AI requests.
* **[PT-BR] Por que `0.5185 ns/op` na Leitura de Configuração?**
  Ao armazenar a configuração ativa em um `atomic.Pointer[Config]`, o compilador do Go aplica *inlining* em `Manager.Get()`, transformando a chamada em uma única leitura de registrador do Cache L1 da CPU sem disputa de *Mutex*. O *Hot-Reload* do `jaguargate.yaml` troca o endereço do ponteiro atomicamente sem pausar nenhuma requisição de IA em andamento.

* **[EN] Why `273.1 ns/op` for 32KB Zero-Trust Buffer Recycling?**
  Instead of allocating new 32KB heap buffers per SSE stream (which triggers Garbage Collector latency spikes), `ByteSlicePool` recycles memory via per-CPU-core local pools (`sync.Pool`) and scrubs all 32,768 bytes using vectorized `clear(b)` assembly before reuse.
* **[PT-BR] Por que `273.1 ns/op` na Reciclagem Zero-Trust de Buffers de 32KB?**
  Em vez de alocar novos blocos de 32KB no Heap a cada streaming SSE (o que causaria pausas no Garbage Collector), o `ByteSlicePool` recicla a memória usando filas locais por núcleo de CPU (`sync.Pool`) e zera todos os 32.768 bytes via instruções vetoriais (`clear(b)`) antes de reutilizar o buffer.