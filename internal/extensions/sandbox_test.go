package extensions

import (
	"context"
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
