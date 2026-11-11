package extensions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

var (
	// Standard WebAssembly binary magic header: \x00asm followed by version 1 (\x01\x00\x00\x00)
	wasmMagicHeader = []byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00}

	ErrInvalidWasmBinary    = errors.New("invalid WebAssembly binary header")
	ErrPluginTimeout        = errors.New("plugin execution exceeded max_execution_time_ms budget")
	ErrWasmRuntimeNotLinked = errors.New("external Wasm bytecode runtime not linked; register a Go policy hook or provide a valid .wasm binary (JG-EXT-601)")
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
	mu            sync.RWMutex
	customHooks   map[string]PolicyHookFunc
	wazeroRuntime wazero.Runtime
	compiledCache map[string]wazero.CompiledModule
}

// NewSandbox creates an initialized extension sandbox with real Wazero WebAssembly runtime support.
func NewSandbox() *Sandbox {
	ctx := context.Background()
	rConfig := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	r := wazero.NewRuntimeWithConfig(ctx, rConfig)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	return &Sandbox{
		customHooks:   make(map[string]PolicyHookFunc),
		wazeroRuntime: r,
		compiledCache: make(map[string]wazero.CompiledModule),
	}
}

// Close gracefully terminates the WebAssembly runtime and releases all compiled modules.
func (s *Sandbox) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wazeroRuntime != nil {
		return s.wazeroRuntime.Close(ctx)
	}
	return nil
}

// RegisterHook registers an in-memory policy hook by module name (used for fast custom policies and testing).
func (s *Sandbox) RegisterHook(name string, fn PolicyHookFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *Sandbox) getOrCompile(ctx context.Context, path string, data []byte) (wazero.CompiledModule, error) {
	s.mu.RLock()
	compiled, ok := s.compiledCache[path]
	s.mu.RUnlock()
	if ok {
		return compiled, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if compiled, ok := s.compiledCache[path]; ok {
		return compiled, nil
	}

	c, err := s.wazeroRuntime.CompileModule(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("compile wasm %s: %w", path, err)
	}
	s.compiledCache[path] = c
	return c, nil
}

func (s *Sandbox) runSingleModule(parentCtx context.Context, mod config.WasmModuleEntry, input []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	type outcome struct {
		data []byte
		err  error
	}
	doneCh := make(chan outcome, 1)

	s.mu.RLock()
	hookFn, hasHook := s.customHooks[mod.Name]
	s.mu.RUnlock()

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

		// Execute Wasm module file from disk if path is specified
		if mod.Path != "" {
			cleanPath := filepath.Clean(mod.Path)
			rawWasm, err := os.ReadFile(cleanPath)
			if err != nil {
				doneCh <- outcome{err: err}
				return
			}
			if !ValidateWasmBinary(rawWasm) {
				doneCh <- outcome{err: ErrInvalidWasmBinary}
				return
			}

			compiled, err := s.getOrCompile(ctx, cleanPath, rawWasm)
			if err != nil {
				doneCh <- outcome{err: err}
				return
			}

			var stdoutBuf, stderrBuf bytes.Buffer
			stdinReader := bytes.NewReader(input)
			instName := fmt.Sprintf("%s-%d", mod.Name, time.Now().UnixNano())

			modConfig := wazero.NewModuleConfig().
				WithName(instName).
				WithStdin(stdinReader).
				WithStdout(&stdoutBuf).
				WithStderr(&stderrBuf).
				WithArgs(mod.Name)

			modInst, instErr := s.wazeroRuntime.InstantiateModule(ctx, compiled, modConfig)
			if modInst != nil {
				_ = modInst.Close(ctx)
			}

			if instErr != nil {
				if exitErr, ok := instErr.(*sys.ExitError); ok {
					if exitErr.ExitCode() == 0 {
						outBytes := input
						if stdoutBuf.Len() > 0 {
							outBytes = stdoutBuf.Bytes()
						}
						doneCh <- outcome{data: outBytes, err: nil}
						return
					}
					doneCh <- outcome{err: fmt.Errorf("wasm module exited with code %d: %s", exitErr.ExitCode(), stderrBuf.String())}
					return
				}
				doneCh <- outcome{err: instErr}
				return
			}

			outBytes := input
			if stdoutBuf.Len() > 0 {
				outBytes = stdoutBuf.Bytes()
			}
			doneCh <- outcome{data: outBytes, err: nil}
			return
		}

		doneCh <- outcome{data: input, err: ErrWasmRuntimeNotLinked}
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
