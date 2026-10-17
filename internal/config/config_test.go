package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMinimalThreeLineConfigAndPresets(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "jaguargate.yaml")

	minimalYAML := `
core:
  version: "1.0"
  language: "pt-BR"
  preset: "strict"
`
	if err := os.WriteFile(cfgFile, []byte(minimalYAML), 0600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadFromFile(cfgFile)
	if err != nil {
		t.Fatalf("expected valid 3-line config, got error: %v", err)
	}

	if cfg.Core.Mode != "hard_block" {
		t.Errorf("expected strict preset to set mode='hard_block', got %q", cfg.Core.Mode)
	}
	if !cfg.Whitelist.EnforceToolWhitelist {
		t.Errorf("expected strict preset to enable EnforceToolWhitelist")
	}
}

func TestEnvVarInterpolation(t *testing.T) {
	t.Setenv("JAGUARGATE_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/X00")
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "jaguargate.yaml")

	yamlContent := `
core:
  version: "1.0"
  language: "en"
  preset: "balanced"
telemetry:
  webhooks:
    enabled: true
    url: "${JAGUARGATE_WEBHOOK_URL}"
`
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Telemetry.Webhooks.URL != "https://hooks.slack.com/services/T00/B00/X00" {
		t.Errorf("env interpolation failed, got %q", cfg.Telemetry.Webhooks.URL)
	}
}

func TestConcurrentLockFreeAtomicReadsAndWrites(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "jaguargate.yaml")

	initial := `
core:
  version: "1.0"
  language: "pt-BR"
  preset: "balanced"
`
	if err := os.WriteFile(cfgFile, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}

	mgr, err := NewManager(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	var wg sync.WaitGroup
	// Spawn 50 concurrent reader goroutines doing 200 reads each (10,000 reads)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				snap := mgr.Get()
				if snap.Core.Version != "1.0" {
					t.Errorf("unexpected version: %s", snap.Core.Version)
				}
			}
		}()
	}

	// Concurrently swap configuration pointers 50 times
	wg.Add(1)
	go func() {
		defer wg.Done()
		for k := 0; k < 50; k++ {
			alt := DefaultConfig()
			if k%2 == 0 {
				alt.Core.Preset = "strict"
			} else {
				alt.Core.Preset = "permissive"
			}
			alt.ApplyPreset()
			mgr.current.Store(&alt)
		}
	}()

	wg.Wait()
}

func BenchmarkAtomicConfigRead(b *testing.B) {
	tmpDir := b.TempDir()
	cfgFile := filepath.Join(tmpDir, "jaguargate.yaml")
	_ = os.WriteFile(cfgFile, []byte("core:\n  version: \"1.0\"\n  language: \"en\"\n  preset: \"balanced\"\n"), 0600)

	mgr, err := NewManager(cfgFile)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = mgr.Get()
		}
	})
}
