package extensions

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

func TestSandboxWasmMagicBytesAndTimeoutFailOpen(t *testing.T) {
	// 1. Validate Wasm Magic Header (\x00asm\x01\x00\x00\x00)
	validWasm := []byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04}
	if !ValidateWasmBinary(validWasm) {
		t.Fatal("expected valid Wasm binary header to pass verification")
	}
	if ValidateWasmBinary([]byte("not-a-wasm-file")) {
		t.Fatal("expected invalid Wasm header to be rejected")
	}

	// 2. Test strict 2ms timeout & Fail-Open (JG-EXT-601) when a custom plugin hangs
	sb := NewSandbox()
	sb.RegisterHook("slow_compliance_plugin", func(ctx context.Context, payload []byte) ([]byte, error) {
		time.Sleep(25 * time.Millisecond) // Exceeds 2ms budget!
		return []byte("corrupted"), nil
	})

	cfg := config.WasmPluginsConfig{
		Enabled:            true,
		MaxExecutionTimeMs: 2,
		Modules: []config.WasmModuleEntry{
			{Name: "slow_compliance_plugin", OnTimeout: "fail_open_and_warn"},
		},
	}

	original := []byte(`{"messages":[{"role":"user","content":"Hello JaguarGate"}]}`)
	res := sb.Execute(context.Background(), original, cfg)

	if !res.TimedOut {
		t.Fatal("expected slow plugin to trigger timeout")
	}
	if !slices.Contains(res.WarningCodes, "JG-EXT-601") {
		t.Errorf("expected warning code JG-EXT-601 on plugin timeout, got %v", res.WarningCodes)
	}
	if string(res.ModifiedPayload) != string(original) {
		t.Fatalf("Fail-Open violated: original payload was altered despite timeout: %s", string(res.ModifiedPayload))
	}
}

func TestSandboxWazeroExecutionAndModuleCompilation(t *testing.T) {
	ctx := context.Background()
	sb := NewSandbox()
	defer func() { _ = sb.Close(ctx) }()

	// 1. Valid minimal 8-byte WebAssembly binary
	validEmptyWasm := []byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00}
	wasmFile, err := os.CreateTemp("", "test_plugin_*.wasm")
	if err != nil {
		t.Fatalf("failed to create temp wasm file: %v", err)
	}
	defer os.Remove(wasmFile.Name())

	if _, err := wasmFile.Write(validEmptyWasm); err != nil {
		t.Fatalf("failed to write wasm file: %v", err)
	}
	_ = wasmFile.Close()

	cfg := config.WasmPluginsConfig{
		Enabled:            true,
		MaxExecutionTimeMs: 100,
		Modules: []config.WasmModuleEntry{
			{Name: "valid_wasm_plugin", Path: wasmFile.Name()},
		},
	}

	payload := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"ping"}]}`)
	res := sb.Execute(ctx, payload, cfg)

	if res.TimedOut {
		t.Fatal("valid wasm module unexpectedly timed out")
	}
	if len(res.WarningCodes) > 0 {
		t.Fatalf("expected 0 warning codes on valid wasm execution, got %v", res.WarningCodes)
	}
	if string(res.ModifiedPayload) != string(payload) {
		t.Fatalf("expected unmodified payload on passthrough, got %s", string(res.ModifiedPayload))
	}

	// 2. Second execution tests the compiled module cache (getOrCompile)
	resCached := sb.Execute(ctx, payload, cfg)
	if len(resCached.WarningCodes) > 0 {
		t.Fatalf("expected 0 warning codes on cached wasm execution, got %v", resCached.WarningCodes)
	}

	// 3. Test invalid Wasm binary triggers fail-open with JG-EXT-601
	corruptedFile, err := os.CreateTemp("", "corrupt_plugin_*.wasm")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(corruptedFile.Name())
	_, _ = corruptedFile.WriteString("NOT_WASM_BINARY_DATA")
	_ = corruptedFile.Close()

	badCfg := config.WasmPluginsConfig{
		Enabled:            true,
		MaxExecutionTimeMs: 100,
		Modules: []config.WasmModuleEntry{
			{Name: "corrupt_wasm", Path: corruptedFile.Name()},
		},
	}
	resCorrupt := sb.Execute(ctx, payload, badCfg)
	if !slices.Contains(resCorrupt.WarningCodes, "JG-EXT-601") {
		t.Errorf("expected JG-EXT-601 on corrupted wasm binary, got %v", resCorrupt.WarningCodes)
	}
	if string(resCorrupt.ModifiedPayload) != string(payload) {
		t.Fatalf("fail-open violated on corrupt wasm: %s", string(resCorrupt.ModifiedPayload))
	}

	// 4. Test non-existent file triggers fail-open with JG-EXT-601
	missingCfg := config.WasmPluginsConfig{
		Enabled:            true,
		MaxExecutionTimeMs: 100,
		Modules: []config.WasmModuleEntry{
			{Name: "missing_wasm", Path: "/non/existent/path/plugin.wasm"},
		},
	}
	resMissing := sb.Execute(ctx, payload, missingCfg)
	if !slices.Contains(resMissing.WarningCodes, "JG-EXT-601") {
		t.Errorf("expected JG-EXT-601 on missing wasm file, got %v", resMissing.WarningCodes)
	}
}

func BenchmarkSandboxFastHook(b *testing.B) {
	sb := NewSandbox()
	sb.RegisterHook("fast_header_check", func(ctx context.Context, payload []byte) ([]byte, error) {
		return payload, nil
	})
	cfg := config.WasmPluginsConfig{
		Enabled:            true,
		MaxExecutionTimeMs: 2,
		Modules: []config.WasmModuleEntry{
			{Name: "fast_header_check"},
		},
	}
	sample := []byte(`{"model":"qwen2.5-coder:14b"}`)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = sb.Execute(context.Background(), sample, cfg)
		}
	})
}
