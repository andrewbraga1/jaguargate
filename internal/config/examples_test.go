package config

import (
	"path/filepath"
	"testing"
)

func TestRepositoryExamplesAreValid(t *testing.T) {
	files, err := filepath.Glob("../../examples/*.yaml")
	if err != nil {
		t.Fatalf("glob examples: %v", err)
	}
	if len(files) < 3 {
		t.Fatalf("expected at least 3 YAML example files in examples/, found %d", len(files))
	}

	files = append(files, "../../jaguargate.yaml")

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			cfg, err := LoadFromFile(file)
			if err != nil {
				t.Fatalf("example config %s failed validation: %v", file, err)
			}
			if cfg.Core.Version != "1.0" {
				t.Fatalf("example config %s has unexpected version %q", file, cfg.Core.Version)
			}
		})
	}
}
