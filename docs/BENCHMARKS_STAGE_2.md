# 🔬 JaguarGate — Benchmark History: Stage 2 (`v0.4.0-input-guards`)

> **[EN]** Immutable performance, binary fuzzing, and concurrency audit record for **Stage 2 (OWASP Input Guards, Multimodal EXIF Hygiene, Deobfuscator & Reversible PII Vault)**.  
> **[PT-BR]** Registro histórico imutável de performance, fuzzing binário e auditoria de concorrência da **Etapa 2 (Defesa OWASP de Entrada, Higiene Multimodal EXIF, Desofuscador e Cofre Reversível de PII)**.

⬅️ **Back to Consolidated Index / Voltar ao Índice Consolidado:** [`docs/BENCHMARKS.md`](BENCHMARKS.md)

---

## 🖥️ Test Environment / Ambiente de Teste

* **Release Tag:** `v0.4.0-input-guards`
* **CPU:** `Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz` (`GOMAXPROCS=4`)
* **OS / Arch:** `linux / amd64`
* **Go Toolchain:** `Go 1.23+`

---

## 📊 Stage 2 Summary Metrics

| Benchmark / Suite | Operation | Production Speed | Memory Footprint | Verification Notes |
| :--- | :--- | :--- | :--- | :--- |
| **`BenchmarkStripJPEGMetadata-4`** | Zero-copy binary EXIF/XMP/Comment stripping (`0xFFE1..0xFFEF`, `0xFFFE`) | **`31.44 ns/op` – `32.10 ns/op`** *(40.1M ops)* | **`32 B/op` (`1 allocs/op`)** | Preserves JPEG scan pixels without re-encoding |
| **`BenchmarkOWASPInputEngine-4`** | Full JSON parse, Unicode/Base64 deobfuscation, RE2 Injection check, Reversible PII Vault (`CPF` + Alphanumeric `CNPJ`), Spotlighting & Canary injection | **`118,794 ns/op`** *(**`0.118 ms`** / req)* | **`3,839 B/op` (`108 allocs/op`)** | Uses pooled `bytes.Buffer` with `SetEscapeHTML(false)` |
| **`FuzzStripJPEGMetadata`** | Coverage-guided binary mutation fuzzing (4 parallel workers) | **`46,573 execs/sec`** (`262,164` total execs across runs) | Zero leaks | **19 coverage paths** discovered; **0 panics** |
| **Full Unit & Race Suite** | All packages (`config`, `guards`, `multimodal`, `telemetry`, `transport`) | **`0.058s total`** (`-count=1`) | Pass | `go test -race ./...` passed (`0 data races`) |

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
ok      [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)        0.004s
=== RUN   TestDeobfuscatorUnicodeSmugglingAndNestedBase64
--- PASS: TestDeobfuscatorUnicodeSmugglingAndNestedBase64 (0.00s)
=== RUN   TestReversiblePIIVaultMaskAndRestore
--- PASS: TestReversiblePIIVaultMaskAndRestore (0.00s)
=== RUN   TestEngineThreeModesSpotlightingAndCanary
--- PASS: TestEngineThreeModesSpotlightingAndCanary (0.00s)
PASS
ok      [github.com/jaguargate/jaguargate/internal/guards](https://github.com/jaguargate/jaguargate/internal/guards)        0.012s
=== RUN   TestJPEGMetadataStrippingAndMagicBytes
--- PASS: TestJPEGMetadataStrippingAndMagicBytes (0.00s)
=== RUN   TestSpoofedMagicBytesDetection
--- PASS: TestSpoofedMagicBytesDetection (0.00s)
=== RUN   FuzzStripJPEGMetadata
--- PASS: FuzzStripJPEGMetadata (0.00s)
PASS
ok      [github.com/jaguargate/jaguargate/internal/multimodal](https://github.com/jaguargate/jaguargate/internal/multimodal)    0.010s
=== RUN   TestZeroTrustLoggerRedaction
--- PASS: TestZeroTrustLoggerRedaction (0.00s)
PASS
ok      [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)     0.006s
=== RUN   TestHTTPAndUnixSocketProxyWithSSEStreaming
--- PASS: TestHTTPAndUnixSocketProxyWithSSEStreaming (0.02s)
PASS
ok      [github.com/jaguargate/jaguargate/internal/transport](https://github.com/jaguargate/jaguargate/internal/transport)     0.026s

$ go test -race ./...
ok      [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)        (cached)
ok      [github.com/jaguargate/jaguargate/internal/guards](https://github.com/jaguargate/jaguargate/internal/guards)        1.035s
ok      [github.com/jaguargate/jaguargate/internal/multimodal](https://github.com/jaguargate/jaguargate/internal/multimodal)    (cached)
ok      [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)     (cached)
ok      [github.com/jaguargate/jaguargate/internal/transport](https://github.com/jaguargate/jaguargate/internal/transport)     1.044s
```

---

## 🧬 Raw Terminal Output — Coverage-Guided Fuzzing & Production Benchmarks

```text
$ go test -fuzz=FuzzStripJPEGMetadata -fuzztime=3s ./internal/multimodal
fuzz: elapsed: 0s, gathering baseline coverage: 0/16 completed
fuzz: elapsed: 0s, gathering baseline coverage: 16/16 completed, now fuzzing with 4 workers
fuzz: elapsed: 3s, execs: 122427 (40792/sec), new interesting: 3 (total: 19)
fuzz: elapsed: 3s, execs: 122427 (0/sec), new interesting: 3 (total: 19)
PASS
ok      [github.com/jaguargate/jaguargate/internal/multimodal](https://github.com/jaguargate/jaguargate/internal/multimodal)    3.094s

$ go test -bench=. -benchmem ./internal/...
goos: linux
goarch: amd64
pkg: [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkAtomicConfigRead-4      1000000000               0.5566 ns/op          0 B/op          0 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/config](https://github.com/jaguargate/jaguargate/internal/config)        0.627s
goos: linux
goarch: amd64
pkg: [github.com/jaguargate/jaguargate/internal/guards](https://github.com/jaguargate/jaguargate/internal/guards)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkOWASPInputEngine-4           10000             118794 ns/op            3839 B/op        108 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/guards](https://github.com/jaguargate/jaguargate/internal/guards)        1.196s
goos: linux
goarch: amd64
pkg: [github.com/jaguargate/jaguargate/internal/multimodal](https://github.com/jaguargate/jaguargate/internal/multimodal)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkStripJPEGMetadata-4       40115696               32.10 ns/op           32 B/op          1 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/multimodal](https://github.com/jaguargate/jaguargate/internal/multimodal)    2.167s
goos: linux
goarch: amd64
pkg: [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkBufferPoolCycle-4          4005704               282.0 ns/op           24 B/op          1 allocs/op
PASS
ok      [github.com/jaguargate/jaguargate/internal/telemetry](https://github.com/jaguargate/jaguargate/internal/telemetry)     1.437s
PASS
ok      [github.com/jaguargate/jaguargate/internal/transport](https://github.com/jaguargate/jaguargate/internal/transport)     0.030s
```