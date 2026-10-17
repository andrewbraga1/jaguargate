package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

var envVarRegex = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)

// Manager holds the active configuration behind a lock-free atomic pointer.
type Manager struct {
	current  atomic.Pointer[Config]
	filePath string
	watcher  *fsnotify.Watcher
	stopCh   chan struct{}
}

// NewManager loads, validates, and stores the initial configuration atomically.
func NewManager(filePath string) (*Manager, error) {
	cfg, err := LoadFromFile(filePath)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		filePath: filePath,
		stopCh:   make(chan struct{}),
	}
	m.current.Store(cfg)
	return m, nil
}

// Get returns the current immutable Config snapshot in O(1) lock-free time.
func (m *Manager) Get() *Config {
	return m.current.Load()
}

// LoadFromFile parses YAML or JSON, expands ${ENV_VAR}, applies presets, and validates.
func LoadFromFile(filePath string) (*Config, error) {
	rawBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", filePath, err)
	}

	expanded := interpolateEnvVars(string(rawBytes))
	cfg := DefaultConfig()

	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".json":
		if err := json.Unmarshal([]byte(expanded), &cfg); err != nil {
			return nil, fmt.Errorf("parse JSON config: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
			return nil, fmt.Errorf("parse YAML config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config extension '%s' (use .yaml, .yml, or .json)", ext)
	}

	cfg.ApplyPreset()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func interpolateEnvVars(content string) string {
	return envVarRegex.ReplaceAllStringFunc(content, func(match string) string {
		sub := envVarRegex.FindStringSubmatch(match)
		if len(sub) == 2 {
			if val, exists := os.LookupEnv(sub[1]); exists {
				return val
			}
			return ""
		}
		return match
	})
}

// StartHotReload watches the configuration file and atomically swaps the pointer on valid edits.
func (m *Manager) StartHotReload(onReload func(newCfg *Config), onError func(err error)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = watcher

	dir := filepath.Dir(m.filePath)
	base := filepath.Base(m.filePath)

	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return err
	}

	go func() {
		var debounceTimer *time.Timer
		for {
			select {
			case <-m.stopCh:
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if filepath.Base(event.Name) != base {
					continue
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
					if debounceTimer != nil {
						debounceTimer.Stop()
					}
					debounceTimer = time.AfterFunc(80*time.Millisecond, func() {
						newCfg, err := LoadFromFile(m.filePath)
						if err != nil {
							if onError != nil {
								onError(err)
							}
							return
						}
						m.current.Store(newCfg)
						if onReload != nil {
							onReload(newCfg)
						}
					})
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				if onError != nil {
					onError(err)
				}
			}
		}
	}()

	return nil
}

// Close stops the file watcher gracefully.
func (m *Manager) Close() error {
	close(m.stopCh)
	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}