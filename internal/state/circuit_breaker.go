package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

type loopCounter struct {
	count     int
	expiresAt time.Time
}

type tokenCounter struct {
	tokens    int
	expiresAt time.Time
}

// CircuitBreaker tracks agent tool-call loops (JG-CFG-201) and per-session token budgets (JG-CFG-202) in O(1) time.
type CircuitBreaker struct {
	mu          sync.Mutex
	toolHistory map[string]loopCounter
	tokenUsage  map[string]tokenCounter
}

// NewCircuitBreaker creates an initialized agent circuit breaker.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		toolHistory: make(map[string]loopCounter, 256),
		tokenUsage:  make(map[string]tokenCounter, 256),
	}
}

// CheckAndTrackTokens estimates token consumption (~4 chars per token) and verifies session budget.
// Returns true if the session exceeded max_tokens_per_session (JG-CFG-202).
func (cb *CircuitBreaker) CheckAndTrackTokens(sessionID string, payloadBytes int, cfg config.CircuitBreakerConfig) bool {
	if cfg.MaxTokensPerSession <= 0 || payloadBytes <= 0 {
		return false
	}
	if sessionID == "" {
		sessionID = "default_session"
	}

	estimatedTokens := max(1, payloadBytes/4)
	window := time.Duration(cfg.WindowSeconds) * time.Second
	if window <= 0 {
		window = 2 * time.Minute
	}

	now := time.Now()
	cb.mu.Lock()
	defer cb.mu.Unlock()

	entry, exists := cb.tokenUsage[sessionID]
	if !exists || now.After(entry.expiresAt) {
		entry = tokenCounter{
			tokens:    0,
			expiresAt: now.Add(window),
		}
	}

	entry.tokens += estimatedTokens
	cb.tokenUsage[sessionID] = entry

	return entry.tokens > cfg.MaxTokensPerSession
}

// CheckToolCallLoop computes a canonical SHA-256 fingerprint of (sessionID + toolName + canonicalArgs)
// and dynamically checks if identical calls exceed cfg.MaxIdenticalToolCalls within cfg.WindowSeconds in O(1) time.
func (cb *CircuitBreaker) CheckToolCallLoop(sessionID, toolName, rawArgs string, cfg config.CircuitBreakerConfig) bool {
	if cfg.MaxIdenticalToolCalls <= 0 || toolName == "" {
		return false
	}
	if sessionID == "" {
		sessionID = "default_session"
	}

	window := time.Duration(cfg.WindowSeconds) * time.Second
	if window <= 0 {
		window = 2 * time.Minute
	}

	hashKey := computeToolCallFingerprint(sessionID, toolName, rawArgs)
	now := time.Now()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	rec, exists := cb.toolHistory[hashKey]
	if !exists || now.After(rec.expiresAt) {
		rec = loopCounter{
			count:     0,
			expiresAt: now.Add(window),
		}
	}

	rec.count++
	cb.toolHistory[hashKey] = rec

	return rec.count > cfg.MaxIdenticalToolCalls
}

// FilterLoopingToolCalls inspects an assistant tool_calls slice and prunes any call that trips the loop breaker (JG-CFG-201).
func (cb *CircuitBreaker) FilterLoopingToolCalls(sessionID string, rawTools []any, cfg config.CircuitBreakerConfig, isShadow bool) ([]any, []string, int) {
	if cfg.MaxIdenticalToolCalls <= 0 || len(rawTools) == 0 {
		return rawTools, nil, 0
	}

	kept := make([]any, 0, len(rawTools))
	var codes []string
	pruned := 0

	for _, item := range rawTools {
		toolMap, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}

		name, args := extractNameAndArgs(toolMap)
		if cb.CheckToolCallLoop(sessionID, name, args, cfg) {
			pruned++
			if !slices.Contains(codes, "JG-CFG-201") {
				codes = append(codes, "JG-CFG-201")
			}
			if isShadow {
				kept = append(kept, item)
			}
			continue
		}
		kept = append(kept, item)
	}

	return kept, codes, pruned
}

func extractNameAndArgs(toolMap map[string]any) (string, string) {
	if fn, ok := toolMap["function"].(map[string]any); ok {
		name, _ := fn["name"].(string)
		args, _ := fn["arguments"].(string)
		return strings.TrimSpace(name), strings.TrimSpace(args)
	}
	name, _ := toolMap["name"].(string)
	args, _ := toolMap["arguments"].(string)
	return strings.TrimSpace(name), strings.TrimSpace(args)
}

func computeToolCallFingerprint(sessionID, toolName, rawArgs string) string {
	canonicalArgs := strings.TrimSpace(rawArgs)
	if len(canonicalArgs) > 0 && (canonicalArgs[0] == '{' || canonicalArgs[0] == '[') {
		var compactBuf bytes.Buffer
		if err := json.Compact(&compactBuf, []byte(canonicalArgs)); err == nil {
			canonicalArgs = compactBuf.String()
		}
	}

	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(toolName)))
	h.Write([]byte{0})
	h.Write([]byte(canonicalArgs))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16]) // 128-bit collision-resistant prefix
}
