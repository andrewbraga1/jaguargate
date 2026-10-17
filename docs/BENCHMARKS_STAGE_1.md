# 🔬 JaguarGate — Benchmark History: Stage 1 (`v0.2.0-core`)

> **[EN]** Immutable performance and concurrency audit record for **Stage 1 (Core Lock-Free Config, Zero-Trust Logger & HTTP/UDS Base Proxy)**.  
> **[PT-BR]** Registro histórico imutável de performance e concorrência da **Etapa 1 (Configuração Lock-Free, Logger Zero-Trust e Proxy Base HTTP/UDS)**.

⬅️ **Back to Consolidated Index / Voltar ao Índice Consolidado:** [`docs/BENCHMARKS.md`](BENCHMARKS.md)

---

## 🖥️ Test Environment / Ambiente de Teste

* **Release Tag:** `v0.2.0-core`
* **CPU:** `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` (`GOMAXPROCS=4`)
* **OS / Arch:** `linux / amd64`
* **Go Toolchain:** `Go 1.23+`

---

## 📊 Stage 1 Summary Metrics

| Benchmark / Suite | Operation | Production Mode | Audit Mode (`-race`) | Allocations (Prod) |
| :--- | :--- | :--- | :--- | :--- |
| **`BenchmarkAtomicConfigRead-4`** | Lock-free config snapshot read (`atomic.Pointer[Config]`) | **`0.5185 ns/op`** *(1B ops)* | `245.1 ns/op` *(5.52M ops)* | **`0 B/op` (`0 allocs/op`)** |
| **`BenchmarkBufferPoolCycle-4`** | 32KB slice acquire, Zero-Trust `clear(b)` scrub & recycle (`sync.Pool`) | **`273.1 ns/op`** *(4.06M ops)* | `16,976 ns/op` *(96.2K ops)* | **`24 B/op` (`1 allocs/op`)** |
| **Unit & E2E Suite** | Presets, Env vars, Zero-Trust Logger, HTTP + UDS (`0600`) SSE Proxy | **`0.066s total`** | `6.709s total` | `PASS` (Zero data races) |

---

## 💻 Raw Terminal Output — Production Mode (Native Speed)

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
PASS
ok      [github.com/jaguargate/jaguargate/internal/transport](https://github.com/jaguargate/jaguargate/internal/transport)     0.025s
```

---

## 🛡️ Raw Terminal Output — ThreadSanitizer Audit (`-race`)

```text
$ go test -v -race -bench=. -benchmem ./...
=== RUN   TestMinimalThreeLineConfigAndPresets
--- PASS: TestMinimalThreeLineConfigAndPresets (0.00s)
=== RUN   TestEnvVarInterpolation
--- PASS: TestEnvVarInterpolation (0.00s)
=== RUN   TestConcurrentLockFreeAtomicReadsAndWrites
--- PASS: TestConcurrentLockFreeAtomicReadsAndWrites (0.00s)
goos: linux
goarch: amd64
pkg: [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkAtomicConfigRead
BenchmarkAtomicConfigRead-4       5526794               245.1 ns/op            0 B/op          0 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)        2.762s
=== RUN   TestZeroTrustLoggerRedaction
--- PASS: TestZeroTrustLoggerRedaction (0.00s)
goos: linux
goarch: amd64
pkg: [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkBufferPoolCycle
BenchmarkBufferPoolCycle-4          96268             16976 ns/op           8254 B/op          1 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)     2.885s
=== RUN   TestHTTPAndUnixSocketProxyWithSSEStreaming
--- PASS: TestHTTPAndUnixSocketProxyWithSSEStreaming (0.03s)
PASS
ok      [github.com/jaguargate/jaguargate/internal/transport](https://github.com/jaguargate/jaguargate/internal/transport)     1.062s
```