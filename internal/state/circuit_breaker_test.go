package state

import (
	"slices"
	"sync"
	"testing"

	"github.com/jaguargate/jaguargate/internal/config"
)

func TestCircuitBreakerCanonicalLoopAndTokenBudget(t *testing.T) {
	cb := NewCircuitBreaker()
	cfg := config.CircuitBreakerConfig{
		MaxIdenticalToolCalls: 3,
		WindowSeconds:         120,
		MaxTokensPerSession:   100,
	}

	// Calls 1, 2, and 3 with varying JSON whitespace should be allowed (up to MaxIdenticalToolCalls = 3)
	if cb.CheckToolCallLoop("sess-1", "query_db", `{"id": 42, "table": "users"}`, cfg) {
		t.Fatal("call 1 should not trip loop breaker")
	}
	if cb.CheckToolCallLoop("sess-1", "query_db", `{"id":42,"table":"users"}`, cfg) {
		t.Fatal("call 2 should not trip loop breaker")
	}
	if cb.CheckToolCallLoop("sess-1", "query_db", `{  "id" : 42 , "table" : "users" }`, cfg) {
		t.Fatal("call 3 should not trip loop breaker")
	}

	// Call 4 (identical canonical JSON) MUST trip the loop breaker (JG-CFG-201)
	if !cb.CheckToolCallLoop("sess-1", "query_db", `{"id":42,"table":"users"}`, cfg) {
		t.Fatal("expected 4th identical canonical tool call to trip loop circuit breaker!")
	}

	// Different arguments on the same tool must NOT trip the breaker
	if cb.CheckToolCallLoop("sess-1", "query_db", `{"id":99,"table":"users"}`, cfg) {
		t.Fatal("different tool arguments should not trip loop breaker")
	}

	// Test Token Budget Circuit Breaker (JG-CFG-202): 500 bytes ~ 125 tokens > MaxTokensPerSession (100)
	if !cb.CheckAndTrackTokens("sess-budget", 500, cfg) {
		t.Fatal("expected session exceeding token budget to trip JG-CFG-202")
	}
}

func TestFilterLoopingToolCallsPruningAndShadow(t *testing.T) {
	cb := NewCircuitBreaker()
	cfg := config.CircuitBreakerConfig{
		MaxIdenticalToolCalls: 2, // Allow at most 2 identical calls
		WindowSeconds:         120,
	}

	// Simulate an agent sending a batch of 4 tool calls where "fetch_url" with the same URL is repeated 3 times
	// plus 1 distinct "send_report" call.
	rawTools := []any{
		map[string]any{"function": map[string]any{"name": "fetch_url", "arguments": `{"url": "https://api.internal/v1"}`}},
		map[string]any{"function": map[string]any{"name": "fetch_url", "arguments": `{"url":"https://api.internal/v1"}`}},
		map[string]any{"function": map[string]any{"name": "fetch_url", "arguments": `{ "url" : "https://api.internal/v1" }`}}, // 3rd identical -> LOOP!
		map[string]any{"function": map[string]any{"name": "send_report", "arguments": `{"ok":true}`}},
	}

	kept, codes, pruned := cb.FilterLoopingToolCalls("sess-filter", rawTools, cfg, false)
	if pruned != 1 {
		t.Fatalf("expected 1 looping tool call to be pruned, got %d", pruned)
	}
	if len(kept) != 3 {
		t.Fatalf("expected 3 non-looping tool calls to be kept, got %d", len(kept))
	}
	if !slices.Contains(codes, "JG-CFG-201") {
		t.Errorf("expected code JG-CFG-201, got %v", codes)
	}

	// In Shadow mode, the 4th identical call should be flagged with JG-CFG-201 but NOT removed from kept slice
	shadowTools := []any{
		map[string]any{"function": map[string]any{"name": "fetch_url", "arguments": `{"url":"https://api.internal/v1"}`}},
	}
	keptShadow, codesShadow, prunedShadow := cb.FilterLoopingToolCalls("sess-filter", shadowTools, cfg, true)
	if prunedShadow != 1 || !slices.Contains(codesShadow, "JG-CFG-201") {
		t.Errorf("expected shadow mode to detect loop (pruned=%d, codes=%v)", prunedShadow, codesShadow)
	}
	if len(keptShadow) != 1 {
		t.Errorf("expected shadow mode to preserve tool call in slice, got len=%d", len(keptShadow))
	}
}

func TestCircuitBreakerConcurrentAccess(t *testing.T) {
	cb := NewCircuitBreaker()
	cfg := config.CircuitBreakerConfig{
		MaxIdenticalToolCalls: 100,
		WindowSeconds:         60,
		MaxTokensPerSession:   50000,
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_ = cb.CheckToolCallLoop("concurrent-sess", "tool_a", `{"k":"v"}`, cfg)
				_ = cb.CheckAndTrackTokens("concurrent-sess", 64, cfg)
			}
		}()
	}
	wg.Wait()
}

func BenchmarkCircuitBreakerCheck(b *testing.B) {
	cb := NewCircuitBreaker()
	cfg := config.CircuitBreakerConfig{
		MaxIdenticalToolCalls: 1000000000,
		WindowSeconds:         120,
		MaxTokensPerSession:   1000000000,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cb.CheckToolCallLoop("bench-sess", "search_docs", `{"query":"JaguarGate"}`, cfg)
		}
	})
}
