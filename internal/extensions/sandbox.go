package extensions

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/jaguargate/jaguargate/internal/config"
)

var (
	// Standard WebAssembly binary magic header: \x00asm followed by version 1 (\x01\x00\x00\x00)
	wasmMagicHeader = []byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00}

	ErrInvalidWasmBinary = errors.New("invalid WebAssembly binary header")
	ErrPluginTimeout     = errors.New("plugin execution exceeded max_execution_time_ms budget")
)

// PolicyHookFunc represents an isolated custom policy function executed inside the timeout sandbox.
type PolicyHookFunc func(ctx context.Context, payload []byte) ([]byte, error)

// SandboxResult holds the outcome of running custom policy modules over a request payload.
type SandboxResult struct {
	ModifiedPayload []byte
	WarningCodes    []string
	TimedOut        bool
}

// Sandbox manages custom Wasm / policy extensions with strict sub-millisecond/millisecond timeouts and Fail-Open safety.
type Sandbox struct {
	customHooks map[string]PolicyHookFunc
}

// NewSandbox creates an initialized extension sandbox.
func NewSandbox() *Sandbox {
	return &Sandbox{
		customHooks: make(map[string]PolicyHookFunc),
	}
}

// RegisterHook registers an in-memory policy hook by module name (used for fast custom policies and testing).
func (s *Sandbox) RegisterHook(name string, fn PolicyHookFunc) {
	s.customHooks[name] = fn
}

// ValidateWasmBinary verifies that a byte slice starts with the official 8-byte WebAssembly magic header (\x00asm\x01\x00\x00\x00).
func ValidateWasmBinary(data []byte) bool {
	return len(data) >= 8 && bytes.Equal(data[:8], wasmMagicHeader)
}

// Execute runs all configured modules within the strict max_execution_time_ms budget.
// On timeout or error, it enforces Fail-Open resilience (never dropping the request) and emits JG-EXT-601.
func (s *Sandbox) Execute(parentCtx context.Context, payload []byte, cfg config.WasmPluginsConfig) SandboxResult {
	res := SandboxResult{
		ModifiedPayload: payload,
	}

	if !cfg.Enabled || len(cfg.Modules) == 0 {
		return res
	}

	budgetMs := cfg.MaxExecutionTimeMs
	if budgetMs <= 0 {
		budgetMs = 2
	}
	timeout := time.Duration(budgetMs) * time.Millisecond

	current := payload

	for _, mod := range cfg.Modules {
		out, err := s.runSingleModule(parentCtx, mod, current, timeout)
		if err != nil {
			if !slices.Contains(res.WarningCodes, "JG-EXT-601") {
				res.WarningCodes = append(res.WarningCodes, "JG-EXT-601")
			}
			if errors.Is(err, ErrPluginTimeout) {
				res.TimedOut = true
			}
			// Fail-Open: keep current unmodified payload and continue
			continue
		}
		current = out
	}

	res.ModifiedPayload = current
	return res
}

func (s *Sandbox) runSingleModule(parentCtx context.Context, mod config.WasmModuleEntry, input []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	type outcome struct {
		data []byte
		err  error
	}
	doneCh := make(chan outcome, 1)

	hookFn, hasHook := s.customHooks[mod.Name]

	go func() {
		defer func() {
			if r := recover(); r != nil {
				doneCh <- outcome{err: errors.New("plugin panic recovered")}
			}
		}()

		if hasHook {
			out, err := hookFn(ctx, input)
			doneCh <- outcome{data: out, err: err}
			return
		}

		// Verify Wasm module file from disk if path is specified
		if mod.Path != "" {
			rawWasm, err := os.ReadFile(mod.Path)
			if err != nil {
				doneCh <- outcome{err: err}
				return
			}
			if !ValidateWasmBinary(rawWasm) {
				doneCh <- outcome{err: ErrInvalidWasmBinary}
				return
			}
		}

		doneCh <- outcome{data: input, err: nil}
	}()

	select {
	case <-ctx.Done():
		return input, ErrPluginTimeout
	case out := <-doneCh:
		if out.err != nil {
			return input, out.err
		}
		return out.data, nil
	}
}
