package stream

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/andrewbraga1/jaguargate/internal/config"
	"github.com/andrewbraga1/jaguargate/internal/guards"
)

func TestSelectiveToolCallFirewallPruning(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.EnforceToolWhitelist = true
	cfg.Whitelist.AllowedTools = []string{"get_weather", "search_knowledge_base"}
	cfg.Whitelist.AllowedDomains = []string{"*.yourdomain.com", "api.github.com"}

	engine := guards.NewEngine(guards.NewPIIVault())

	// Model tries to call 3 tools in parallel: 2 allowed + 1 unauthorized ("drop_production_db")
	// Also passes an unauthorized external URL inside arguments
	llmResponse := `{
		"id": "chatcmpl-123",
		"choices": [{
			"index": 0,
			"finish_reason": "tool_calls",
			"message": {
				"role": "assistant",
				"content": null,
				"tool_calls": [
					{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Sorocaba\"}"}},
					{"id": "call_2", "type": "function", "function": {"name": "drop_production_db", "arguments": "{\"force\":true}"}},
					{"id": "call_3", "type": "function", "function": {"name": "search_knowledge_base", "arguments": "{\"url\":\"https://evil-exfil.com/steal\"}"}}
				]
			}
		}]
	}`

	res := engine.SanitizeOutputJSON([]byte(llmResponse), guards.InspectionResult{}, &cfg)

	if res.PrunedTools != 1 {
		t.Fatalf("expected exactly 1 unauthorized tool to be pruned, got %d", res.PrunedTools)
	}
	if !slices.Contains(res.Codes, "JG-CFG-101") || !slices.Contains(res.Codes, "JG-CFG-103") {
		t.Errorf("expected JG-CFG-101 and JG-CFG-103 in codes, got %v", res.Codes)
	}

	outStr := string(res.ModifiedBody)
	if strings.Contains(outStr, "drop_production_db") {
		t.Fatalf("SECURITY FAILURE: unauthorized tool call 'drop_production_db' was not pruned!")
	}
	if !strings.Contains(outStr, "get_weather") || !strings.Contains(outStr, "search_knowledge_base") {
		t.Errorf("legitimate whitelisted tools must remain intact: %s", outStr)
	}
	if strings.Contains(outStr, "evil-exfil.com") {
		t.Errorf("unauthorized domain in tool arguments was not sanitized: %s", outStr)
	}
}

func TestIsolatedDomainSanitizationWithoutToolPruning(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.EnforceToolWhitelist = true
	cfg.Whitelist.AllowedTools = []string{"search_knowledge_base"}
	cfg.Whitelist.AllowedDomains = []string{"*.yourdomain.com"}

	engine := guards.NewEngine(guards.NewPIIVault())

	// Single ALLOWED tool call containing a DISALLOWED domain (pruned == 0, but JG-CFG-103 triggered)
	llmResponse := `{"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"search_knowledge_base","arguments":"{\"url\":\"https://evil-exfil.com/steal\"}"}}]}}]}`

	res := engine.SanitizeOutputJSON([]byte(llmResponse), guards.InspectionResult{}, &cfg)
	if res.PrunedTools != 0 {
		t.Fatalf("expected 0 pruned tools, got %d", res.PrunedTools)
	}
	if !slices.Contains(res.Codes, "JG-CFG-103") {
		t.Fatalf("expected JG-CFG-103 flag code, got %v", res.Codes)
	}
	if strings.Contains(string(res.ModifiedBody), "evil-exfil.com") {
		t.Fatalf("SECURITY FAILURE: disallowed domain survived in ModifiedBody when pruned==0: %s", string(res.ModifiedBody))
	}
}

func TestSSEOneAndTwoCharPrefixSplitsAndAnthropicFormat(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.AllowedDomains = []string{"*.trusted.com"}

	canary := "jg_cnry_112233445566"

	// 1. Split Canary right after 1st char ("j") and 2nd char ("g"), and use Anthropic delta.text SSE format
	sseStream := strings.Join([]string{
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Início j"}}`,
		"",
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"g"}}`,
		"",
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"_cnry_112233445566 EXFIL"}}`,
		"",
		`data: [DONE]`,
		"",
	}, "\n")

	trailers := make(http.Header)
	inspector := NewSSEInspector(
		io.NopCloser(strings.NewReader(sseStream)),
		&cfg,
		guards.NewPIIVault(),
		guards.InspectionResult{CanaryToken: canary, Status: "CLEAN", Severity: "NONE"},
		trailers,
	)

	outBytes, err := io.ReadAll(inspector)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(outBytes)
	if strings.Contains(outStr, "EXFIL") || strings.Contains(outStr, "112233445566") {
		t.Fatalf("SECURITY FAILURE: 1-char/2-char split Canary leaked in Anthropic SSE stream:\n%s", outStr)
	}
	if trailers.Get("X-JaguarGate-Status") != "BLOCKED" {
		t.Errorf("expected BLOCKED status trailer, got %q", trailers.Get("X-JaguarGate-Status"))
	}

	// 2. Split Markdown image right between "!" and "[spy](http://evil.org/x.png)"
	mdStream := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"content":"Olhe !"}}]}`,
		"",
		`data: {"choices":[{"index":0,"delta":{"content":"[spy](http://evil.org/x.png) fim"}}]}`,
		"",
		`data: [DONE]`,
		"",
	}, "\n")
	mdInsp := NewSSEInspector(
		io.NopCloser(strings.NewReader(mdStream)),
		&cfg,
		guards.NewPIIVault(),
		guards.InspectionResult{Status: "CLEAN", Severity: "NONE"},
		make(http.Header),
	)
	mdOut, _ := io.ReadAll(mdInsp)
	if strings.Contains(string(mdOut), "evil.org") {
		t.Fatalf("SECURITY FAILURE: Markdown image split after '!' bypassed SSE filter:\n%s", string(mdOut))
	}
}

func TestChaoticSplitSSEStreamPIIRestoreAndMarkdownSanitizer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.AllowedDomains = []string{"*.trusted.com"}

	vault := guards.NewPIIVault()
	maskedPrompt, _, _ := vault.MaskText("CPF 123.456.789-01", cfg.Guards.PIIVault, false)
	tokenStart := strings.Index(maskedPrompt, piiOpenPrefix)
	if tokenStart == -1 {
		t.Fatalf("expected masked token in %q", maskedPrompt)
	}
	piiToken := maskedPrompt[tokenStart:]

	// Split the PII token right in the middle across two separate SSE chunks
	half1 := piiToken[:10]
	half2 := piiToken[10:]

	sseStream := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"content":"Olá Ação! Seu documento é ` + half1 + `"}}]}`,
		"",
		`data: {"choices":[{"index":0,"delta":{"content":"` + half2 + ` e imagem ![spy](http://tracker.evil.org/p.png) fim."}}]}`,
		"",
		`data: [DONE]`,
		"",
	}, "\n")

	trailers := make(http.Header)
	inspector := NewSSEInspector(
		io.NopCloser(strings.NewReader(sseStream)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", Severity: "NONE"},
		trailers,
	)

	outputBytes, err := io.ReadAll(inspector)
	if err != nil {
		t.Fatalf("unexpected SSE read error: %v", err)
	}
	output := string(outputBytes)

	// 1. Verify split PII token was reassembled across SSE chunks and restored to "123.456.789-01"
	if !strings.Contains(output, "123.456.789-01") {
		t.Errorf("expected split PII token to be restored to original CPF across SSE chunks, got:\n%s", output)
	}
	// 2. Verify malicious external Markdown image tracker was neutralized (JG-SEC-502)
	if strings.Contains(output, "tracker.evil.org") {
		t.Errorf("SECURITY FAILURE: untrusted markdown image tracker survived SSE stream:\n%s", output)
	}
	// 3. Verify SSE Warning Event and HTTP Trailers were emitted
	if !strings.Contains(output, "event: jaguargate.warning") {
		t.Errorf("expected event: jaguargate.warning before [DONE], got:\n%s", output)
	}
	if trailers.Get("X-JaguarGate-Codes") != "JG-SEC-502" {
		t.Errorf("expected HTTP Trailer X-JaguarGate-Codes='JG-SEC-502', got %q", trailers.Get("X-JaguarGate-Codes"))
	}
}

func TestSSECanaryLeakImmediateTruncation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()

	canary := "jg_cnry_998877665544"
	// Canary token split across chunk 1 and chunk 2, followed by chunk 3 that MUST NEVER be transmitted
	sseStream := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"content":"Segredo interno: jg_cnry_9988"}}]}`,
		"",
		`data: {"choices":[{"index":0,"delta":{"content":"77665544 vazado!"}}]}`,
		"",
		`data: {"choices":[{"index":0,"delta":{"content":"ESTE TEXTO NUNCA DEVE CHEGAR AO CLIENTE"}}]}`,
		"",
		`data: [DONE]`,
		"",
	}, "\n")

	trailers := make(http.Header)
	inspector := NewSSEInspector(
		io.NopCloser(strings.NewReader(sseStream)),
		&cfg,
		guards.NewPIIVault(),
		guards.InspectionResult{CanaryToken: canary, Status: "CLEAN", Severity: "NONE"},
		trailers,
	)

	outputBytes, err := io.ReadAll(inspector)
	if err != nil {
		t.Fatal(err)
	}
	output := string(outputBytes)

	if strings.Contains(output, "77665544") || strings.Contains(output, "ESTE TEXTO NUNCA DEVE CHEGAR") {
		t.Fatalf("SECURITY FAILURE: SSE stream was not immediately truncated on Canary leak:\n%s", output)
	}
	if trailers.Get("X-JaguarGate-Status") != "BLOCKED" || !strings.Contains(trailers.Get("X-JaguarGate-Codes"), "JG-SEC-501") {
		t.Errorf("expected BLOCKED status and JG-SEC-501 trailer on canary leak, got %v", trailers)
	}
}

func TestSSEFragmentedToolCallsAcrossChunksAndDomainDetection(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.EnforceToolWhitelist = true
	cfg.Whitelist.AllowedTools = []string{"fetch_safe"}
	cfg.Whitelist.AllowedDomains = []string{"*.trusted.com"}

	// Stream with:
	// 1. Tool call 0: forbidden tool "execute_shell", split across chunk 1 (name) and chunk 2 (arguments)
	// 2. Tool call 1: allowed tool "fetch_safe", but URL split across chunk 2 ("https://ev") and chunk 3 ("il.example/exfil")
	sseStream := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_0","type":"function","function":{"name":"execute_shell","arguments":""}}]}}]}`,
		"",
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"cmd\":\"rm -rf /\"}"}},{"index":1,"id":"call_1","type":"function","function":{"name":"fetch_safe","arguments":"{\"url\":\"https://ev"}}]}}]}`,
		"",
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"il.example/exfil\"}"}}]}}]}`,
		"",
		`data: [DONE]`,
		"",
	}, "\n")

	trailers := make(http.Header)
	inspector := NewSSEInspector(
		io.NopCloser(strings.NewReader(sseStream)),
		&cfg,
		guards.NewPIIVault(),
		guards.InspectionResult{Status: "CLEAN", Severity: "NONE"},
		trailers,
	)

	outBytes, err := io.ReadAll(inspector)
	if err != nil {
		t.Fatal(err)
	}
	output := string(outBytes)

	// 1. Forbidden tool execute_shell should be completely pruned, including its arguments in chunk 2!
	if strings.Contains(output, "execute_shell") || strings.Contains(output, "rm -rf") {
		t.Fatalf("SECURITY FAILURE: forbidden tool call fragments survived in SSE output:\n%s", output)
	}

	// 2. Fragmented domain "https://ev" + "il.example/exfil" must be caught across chunks
	codesTrailer := trailers.Get("X-JaguarGate-Codes")
	if !strings.Contains(codesTrailer, "JG-CFG-103") {
		t.Errorf("expected JG-CFG-103 for fragmented evil.example domain, got %q", codesTrailer)
	}
	if !strings.Contains(codesTrailer, "JG-CFG-101") {
		t.Errorf("expected JG-CFG-101 for pruned execute_shell, got %q", codesTrailer)
	}

	// 3. Verify evil.example is replaced with blocked domain in output
	if strings.Contains(output, "il.example/exfil") {
		t.Errorf("SECURITY FAILURE: fragmented forbidden domain survived in SSE output:\n%s", output)
	}
}

func TestAnthropicStreamingToolUseAndDomainSanitization(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.EnforceToolWhitelist = true
	cfg.Whitelist.AllowedTools = []string{"safe_tool"}
	cfg.Whitelist.AllowedDomains = []string{"*.trusted.com"}

	anthropicSSE := "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool_bad\",\"name\":\"drop_db\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"force\\\":true}\"}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool_ok\",\"name\":\"safe_tool\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"url\\\":\\\"https://ev\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"il.example/path\\\"}\"}}\n\n" +
		"data: [DONE]\n\n"

	vault := guards.NewPIIVault()
	insp := NewSSEInspector(
		io.NopCloser(strings.NewReader(anthropicSSE)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-anthropic-sse"},
		nil,
	)

	outBytes, err := io.ReadAll(insp)
	if err != nil {
		t.Fatalf("failed to read Anthropic SSE stream: %v", err)
	}
	outStr := string(outBytes)

	// 1. Unauthorized tool 'drop_db' must be pruned (JG-CFG-101) and suppressed from stream
	if !slices.Contains(insp.codes, "JG-CFG-101") {
		t.Errorf("expected JG-CFG-101 for unauthorized Anthropic tool, got %v", insp.codes)
	}
	if strings.Contains(outStr, "drop_db") {
		t.Errorf("SECURITY FAILURE (JG-03): unauthorized Anthropic tool 'drop_db' survived in stream:\n%s", outStr)
	}
	if strings.Contains(outStr, `"force":true`) {
		t.Errorf("SECURITY FAILURE (JG-03): pruned tool arguments survived in stream:\n%s", outStr)
	}

	// 2. Fragmented domain violation must be detected (JG-CFG-103) and stripped
	if !slices.Contains(insp.codes, "JG-CFG-103") {
		t.Errorf("expected JG-CFG-103 for fragmented forbidden domain in Anthropic tool, got %v", insp.codes)
	}
	if strings.Contains(outStr, "evil.example") {
		t.Errorf("SECURITY FAILURE (JG-03): forbidden domain survived in Anthropic tool stream:\n%s", outStr)
	}
}

func TestOllamaNDJSONStreamingInspection(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.EnforceToolWhitelist = true
	cfg.Whitelist.AllowedTools = []string{"get_weather", "search_knowledge_base"}
	cfg.Whitelist.AllowedDomains = []string{"*.yourdomain.com"}

	// Scenario 1: Ollama /api/chat NDJSON stream containing 2 tool calls (1 forbidden tool, 1 allowed tool with disallowed domain)
	ollamaToolNDJSON := `{"model":"llama3.2","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"drop_production_db","arguments":{"force":true}}},{"function":{"name":"search_knowledge_base","arguments":{"url":"https://evil-exfil.com/data"}}}]},"done":false}` + "\n" +
		`{"model":"llama3.2","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"get_weather","arguments":{"city":"Sorocaba"}}}]},"done":true}` + "\n"

	vault := guards.NewPIIVault()
	inspTool := NewSSEInspector(
		io.NopCloser(strings.NewReader(ollamaToolNDJSON)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-ollama-ndjson"},
		nil,
	)

	outBytes, err := io.ReadAll(inspTool)
	if err != nil {
		t.Fatalf("failed to read Ollama NDJSON stream: %v", err)
	}
	outStr := string(outBytes)

	// 1a. Forbidden tool must be pruned (JG-CFG-101)
	if !slices.Contains(inspTool.codes, "JG-CFG-101") {
		t.Errorf("expected JG-CFG-101 in Ollama NDJSON tool stream, got %v", inspTool.codes)
	}
	if strings.Contains(outStr, "drop_production_db") {
		t.Errorf("SECURITY FAILURE (JG-03): forbidden tool survived in Ollama NDJSON stream:\n%s", outStr)
	}

	// 1b. Forbidden domain must be sanitized (JG-CFG-103)
	if !slices.Contains(inspTool.codes, "JG-CFG-103") {
		t.Errorf("expected JG-CFG-103 in Ollama NDJSON tool stream, got %v", inspTool.codes)
	}
	if strings.Contains(outStr, "evil-exfil.com") {
		t.Errorf("SECURITY FAILURE (JG-03): forbidden domain survived in Ollama NDJSON tool stream:\n%s", outStr)
	}

	// 1c. Allowed tool must remain intact
	if !strings.Contains(outStr, "get_weather") {
		t.Errorf("allowed tool get_weather was improperly removed from Ollama NDJSON stream:\n%s", outStr)
	}

	// Scenario 2: Ollama /api/generate NDJSON stream with Canary Leak (JG-SEC-501)
	canary := "jg_cnry_ollama_987654321"
	ollamaCanaryNDJSON := fmt.Sprintf("{\"model\":\"llama3.2\",\"response\":\"Inicio de resposta: %s\",\"done\":false}\n{\"model\":\"llama3.2\",\"response\":\" ESTE DADO NUNCA DEVE SER TRANSMITIDO\",\"done\":false}\n", canary)

	inspCanary := NewSSEInspector(
		io.NopCloser(strings.NewReader(ollamaCanaryNDJSON)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", CanaryToken: canary, SessionID: "sess-ollama-canary"},
		nil,
	)

	canaryOutBytes, err := io.ReadAll(inspCanary)
	if err != nil {
		t.Fatalf("failed to read Ollama canary stream: %v", err)
	}
	canaryOutStr := string(canaryOutBytes)

	if !slices.Contains(inspCanary.codes, "JG-SEC-501") {
		t.Errorf("expected JG-SEC-501 in Ollama NDJSON canary leak, got %v", inspCanary.codes)
	}
	if strings.Contains(canaryOutStr, canary) {
		t.Errorf("SECURITY FAILURE (JG-03): canary token leaked in Ollama NDJSON stream:\n%s", canaryOutStr)
	}
	if strings.Contains(canaryOutStr, "ESTE DADO NUNCA DEVE SER TRANSMITIDO") {
		t.Errorf("SECURITY FAILURE (JG-03): post-canary data leaked in Ollama NDJSON stream:\n%s", canaryOutStr)
	}

	// Scenario 3: Ollama NDJSON Split PII Vault Token Restoration
	maskedPrompt, _, _ := vault.MaskTextWithSession("sess-ollama-pii", "CPF 123.456.789-01", cfg.Guards.PIIVault, false)
	tokenStart := strings.Index(maskedPrompt, piiOpenPrefix)
	if tokenStart == -1 {
		t.Fatalf("expected masked token in %q", maskedPrompt)
	}
	piiToken := maskedPrompt[tokenStart:]
	half1 := piiToken[:8]
	half2 := piiToken[8:]

	ollamaPIINDJSON := fmt.Sprintf("{\"model\":\"llama3.2\",\"response\":\"Seu documento é %s\",\"done\":false}\n{\"model\":\"llama3.2\",\"response\":\"%s com sucesso.\",\"done\":true}\n", half1, half2)

	inspPII := NewSSEInspector(
		io.NopCloser(strings.NewReader(ollamaPIINDJSON)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-ollama-pii"},
		nil,
	)

	piiOutBytes, err := io.ReadAll(inspPII)
	if err != nil {
		t.Fatalf("failed to read Ollama PII stream: %v", err)
	}
	piiOutStr := string(piiOutBytes)

	if !strings.Contains(piiOutStr, "123.456.789-01") {
		t.Errorf("expected split PII token to be restored in Ollama NDJSON stream, got:\n%s", piiOutStr)
	}
}

func TestSSETrackerMemoryBoundsAndLimits(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()

	// 1. Tool call exceeding maxToolArgsBytes (256 KB)
	hugeChunk := strings.Repeat("A", 300*1024)
	streamPayload := fmt.Sprintf("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"test_tool\",\"arguments\":\"%s\"}}]}}]}\n\ndata: [DONE]\n\n", hugeChunk)

	vault := guards.NewPIIVault()
	insp := NewSSEInspector(
		io.NopCloser(strings.NewReader(streamPayload)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-limit-test"},
		nil,
	)

	_, _ = io.ReadAll(insp)

	if !slices.Contains(insp.codes, "JG-CFG-202") {
		t.Errorf("SECURITY FAILURE (JG-05): expected JG-CFG-202 for tool arguments exceeding maxToolArgsBytes, got %v", insp.codes)
	}

	// 2. Exceeding maxTrackersPerStream (35 distinct indices > 32)
	var multiTrackers strings.Builder
	for i := 0; i < 35; i++ {
		multiTrackers.WriteString(fmt.Sprintf("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":%d,\"function\":{\"name\":\"tool_%d\",\"arguments\":\"{}\"}}]}}]}\n\n", i, i))
	}
	multiTrackers.WriteString("data: [DONE]\n\n")

	inspMulti := NewSSEInspector(
		io.NopCloser(strings.NewReader(multiTrackers.String())),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-limit-trackers"},
		nil,
	)

	_, _ = io.ReadAll(inspMulti)

	if !slices.Contains(inspMulti.codes, "JG-CFG-202") {
		t.Errorf("SECURITY FAILURE (JG-05): expected JG-CFG-202 for stream exceeding maxTrackersPerStream, got %v", inspMulti.codes)
	}

	// 3. Test R2: Anthropic stream with 50 distinct indices must strictly cap toolTrackers map to <= 32
	var anthropicMultiTrackers strings.Builder
	for i := 0; i < 50; i++ {
		anthropicMultiTrackers.WriteString(fmt.Sprintf("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call_%d\",\"name\":\"tool_%d\"}}\n\n", i, i, i))
		anthropicMultiTrackers.WriteString(fmt.Sprintf("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":%d,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n", i))
		anthropicMultiTrackers.WriteString(fmt.Sprintf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", i))
	}
	anthropicMultiTrackers.WriteString("data: [DONE]\n\n")

	inspAnthropicMulti := NewSSEInspector(
		io.NopCloser(strings.NewReader(anthropicMultiTrackers.String())),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-anthropic-trackers"},
		nil,
	)

	_, _ = io.ReadAll(inspAnthropicMulti)

	if len(inspAnthropicMulti.toolTrackers) > 32 {
		t.Fatalf("SECURITY FAILURE (R2): Anthropic toolTrackers map exceeded limit: %d > 32", len(inspAnthropicMulti.toolTrackers))
	}
	if !slices.Contains(inspAnthropicMulti.codes, "JG-CFG-202") {
		t.Errorf("expected JG-CFG-202 for Anthropic stream exceeding maxTrackersPerStream, got %v", inspAnthropicMulti.codes)
	}
}

func TestAnthropicStreamingBlockLifecycleAndNoOrphanEvents(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.EnforceToolWhitelist = true
	cfg.Whitelist.AllowedTools = []string{"allowed_tool"}

	// Stream containing 1 forbidden tool (index 0) and 1 allowed tool (index 1)
	anthropicStream := "event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call_bad\",\"name\":\"drop_db\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"force\\\":true}\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call_good\",\"name\":\"allowed_tool\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\\\"Sorocaba\\\"}\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":1}\n\n"

	insp := NewSSEInspector(
		io.NopCloser(strings.NewReader(anthropicStream)),
		&cfg,
		guards.NewPIIVault(),
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-anthropic-lifecycle"},
		nil,
	)

	outBytes, err := io.ReadAll(insp)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	outStr := string(outBytes)

	// 1. Forbidden tool drop_db and its arguments must be completely absent
	if strings.Contains(outStr, "drop_db") || strings.Contains(outStr, `"force":true`) {
		t.Fatalf("SECURITY FAILURE (R3): forbidden tool survived stream:\n%s", outStr)
	}

	// 2. No orphan event: headers or orphan stop blocks for pruned index 0
	lines := strings.Split(outStr, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "event:") {
			// Next non-empty line must be data:
			foundData := false
			for j := i + 1; j < len(lines); j++ {
				subTrim := strings.TrimSpace(lines[j])
				if subTrim == "" {
					continue
				}
				if strings.HasPrefix(subTrim, "data:") {
					foundData = true
				}
				break
			}
			if !foundData {
				t.Fatalf("PROTOCOL VIOLATION (R3): orphan SSE event line found with no matching data:\n%s", trimmed)
			}
		}
	}

	// 3. Verify allowed tool is fully preserved with start, delta, and stop
	if !strings.Contains(outStr, "allowed_tool") || !strings.Contains(outStr, "Sorocaba") {
		t.Fatalf("allowed tool was incorrectly corrupted:\n%s", outStr)
	}
}

func TestOllamaNDJSONChatVsGenerateFormatDistinction(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	vault := guards.NewPIIVault()

	// Mask CPF token
	masked, _, _ := vault.MaskTextWithSession("sess-ollama-chat", "CPF 123.456.789-01", cfg.Guards.PIIVault, false)
	tokenStart := strings.Index(masked, piiOpenPrefix)
	piiToken := masked[tokenStart:]
	half1 := piiToken[:8]
	half2 := piiToken[8:]

	// Ollama /api/chat format with split PII token
	chatNDJSON := fmt.Sprintf("{\"model\":\"llama3.2\",\"message\":{\"role\":\"assistant\",\"content\":\"Ola! Seu CPF e %s\"},\"done\":false}\n"+
		"{\"model\":\"llama3.2\",\"message\":{\"role\":\"assistant\",\"content\":\"%s confirmado com sucesso.\"},\"done\":true}\n", half1, half2)

	inspChat := NewSSEInspector(
		io.NopCloser(strings.NewReader(chatNDJSON)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-ollama-chat"},
		nil,
	)

	chatBytes, err := io.ReadAll(inspChat)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	// Parse each NDJSON line as a real client would
	chatLines := strings.Split(strings.TrimSpace(string(chatBytes)), "\n")
	foundRestored := false
	sawTerminalDone := false
	for _, l := range chatLines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(l), &parsed); err != nil {
			t.Fatalf("invalid NDJSON line: %s", l)
		}

		if sawTerminalDone {
			t.Fatalf("PROTOCOL VIOLATION (R4): data received after done:true in Ollama NDJSON:\n%s", l)
		}

		if doneVal, _ := parsed["done"].(bool); doneVal {
			sawTerminalDone = true
		}

		// Verify that /api/chat emits message.content, NOT response
		if _, hasResp := parsed["response"]; hasResp {
			t.Fatalf("PROTOCOL VIOLATION (R4): /api/chat received event with top-level 'response' instead of 'message':\n%s", l)
		}

		if msgMap, ok := parsed["message"].(map[string]any); ok {
			content, _ := msgMap["content"].(string)
			if strings.Contains(content, "123.456.789-01") {
				foundRestored = true
			}
		}
	}

	if !foundRestored {
		t.Fatalf("expected restored CPF in message.content of /api/chat NDJSON stream, got:\n%s", string(chatBytes))
	}
}

func TestSSEActiveSecretDLPAndVetoTrailers(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	cfg.Whitelist.EnforceToolWhitelist = true
	cfg.Whitelist.AllowedTools = []string{"get_weather"}
	vault := guards.NewPIIVault()

	// Stream emits both a spontaneous AWS key split across chunks AND an unauthorized tool call
	ssePayload := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Chave vazada: AKIAIOSF\"}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ODNN7EXAMPLE fim.\"}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_bad\",\"function\":{\"name\":\"exec_shell\",\"arguments\":\"{}\"}}]}}]}\n\n" +
		"data: [DONE]\n\n"

	trailers := make(http.Header)
	insp := NewSSEInspector(
		io.NopCloser(strings.NewReader(ssePayload)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-sse-dlp"},
		trailers,
	)
	outBytes, err := io.ReadAll(insp)
	if err != nil {
		t.Fatalf("SSE read failed: %v", err)
	}
	outStr := string(outBytes)
	if strings.Contains(outStr, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("SECURITY FAILURE: spontaneous AWS key leaked across SSE chunks: %s", outStr)
	}
	if !strings.Contains(outStr, "JG-SEC-503") {
		t.Errorf("expected JG-SEC-503 redaction marker in SSE stream, got: %s", outStr)
	}
	if !strings.Contains(trailers.Get("X-JaguarGate-Codes"), "JG-SEC-503") {
		t.Errorf("expected JG-SEC-503 in X-JaguarGate-Codes trailer, got %q", trailers.Get("X-JaguarGate-Codes"))
	}
	if trailers.Get("X-JaguarGate-Veto") != "tool_unauthorized" {
		t.Errorf("expected X-JaguarGate-Veto='tool_unauthorized' trailer, got %q", trailers.Get("X-JaguarGate-Veto"))
	}
	if trailers.Get("X-JaguarGate-Pruned-Tools") != "exec_shell" {
		t.Errorf("expected X-JaguarGate-Pruned-Tools='exec_shell' trailer, got %q", trailers.Get("X-JaguarGate-Pruned-Tools"))
	}
}

func TestSSEToolCallArgumentsDLPAndStatefulMultiChunkPEM(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	vault := guards.NewPIIVault()

	pemHeader := "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
	pemFooter := "-----" + "END RSA PRIVATE KEY" + "-----"
	longBase64ChunkA := strings.Repeat("MIIETESTSYNTHETICKEYBODYCHUNK1", 5) // 150 chars (> 64-rune window!)
	longBase64ChunkB := strings.Repeat("99887766554433221100SYNTHETIC2", 5) // 150 chars

	// 1. OpenAI SSE: tool_calls arguments containing split AWS key across chunks + valid JSON reconstruction
	openAIToolSSE := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_dlp","type":"function","function":{"name":"audit_log","arguments":"{\"aws\":\"AKIAZ9X8"}}]}}]}`,
		"",
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"W7V6U5T4S3R2\",\"ok\":true}"}}]}}]}`,
		"",
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		"",
		`data: [DONE]`,
		"",
	}, "\n")

	inspOA := NewSSEInspector(
		io.NopCloser(strings.NewReader(openAIToolSSE)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-oa-tool-sse"},
		nil,
	)
	outOA, err := io.ReadAll(inspOA)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(outOA), "AKIAZ9X8W7V6U5T4S3R2") || strings.Contains(string(outOA), "AKIAZ9X8") {
		t.Fatalf("SECURITY FAILURE (JG-R2 OpenAI SSE): split secret leaked in tool_calls arguments:\n%s", string(outOA))
	}
	if !slices.Contains(inspOA.codes, "JG-SEC-503") {
		t.Errorf("expected JG-SEC-503 on OpenAI SSE tool arguments, got %v", inspOA.codes)
	}
	// Reconstruct emitted OpenAI tool arguments and verify valid JSON!
	var oaArgs strings.Builder
	for _, ln := range strings.Split(string(outOA), "\n") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(ln), "data:"); ok {
			p := strings.TrimSpace(after)
			if p == "[DONE]" {
				continue
			}
			var obj map[string]any
			if json.Unmarshal([]byte(p), &obj) == nil {
				if chs, ok := obj["choices"].([]any); ok && len(chs) > 0 {
					if cm, ok := chs[0].(map[string]any); ok {
						if dm, ok := cm["delta"].(map[string]any); ok {
							if tcs, ok := dm["tool_calls"].([]any); ok && len(tcs) > 0 {
								if tm, ok := tcs[0].(map[string]any); ok {
									if fm, ok := tm["function"].(map[string]any); ok {
										if a, ok := fm["arguments"].(string); ok {
											oaArgs.WriteString(a)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	var parsedOA map[string]any
	if err := json.Unmarshal([]byte(oaArgs.String()), &parsedOA); err != nil {
		t.Fatalf("reconstructed OpenAI tool arguments is invalid JSON (%v): %q", err, oaArgs.String())
	}

	// 2. Anthropic SSE: input_json_delta containing split sk-... secret + valid JSON reconstruction
	anthToolSSE := "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_dlp\",\"name\":\"audit_log\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"key\\\":\\\"sk-proj-123456\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"7890abcdefghijklmnop\\\"}\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"data: [DONE]\n\n"

	inspAnth := NewSSEInspector(
		io.NopCloser(strings.NewReader(anthToolSSE)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-anth-tool-sse"},
		nil,
	)
	outAnth, err := io.ReadAll(inspAnth)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(outAnth), "sk-proj-123456") || strings.Contains(string(outAnth), "7890abcdefghijklmnop") {
		t.Fatalf("SECURITY FAILURE (JG-R2 Anthropic SSE): split secret leaked in input_json_delta:\n%s", string(outAnth))
	}

	// 3. Multi-chunk 300+ char PEM block with split END footer + Second stream with truncated EOF PEM (JG-R3)
	pemSSE := strings.Join([]string{
		fmt.Sprintf(`data: {"choices":[{"index":0,"delta":{"content":"Prefixo %s"}}]}`, pemHeader[:14]),
		"",
		fmt.Sprintf(`data: {"choices":[{"index":0,"delta":{"content":"%s\n%s"}}]}`, pemHeader[14:], longBase64ChunkA),
		"",
		fmt.Sprintf(`data: {"choices":[{"index":0,"delta":{"content":"%s\n%s"}}]}`, longBase64ChunkB, pemFooter[:12]),
		"",
		fmt.Sprintf(`data: {"choices":[{"index":0,"delta":{"content":"%s Sufixo seguro."}}]}`, pemFooter[12:]),
		"",
		`data: [DONE]`,
		"",
	}, "\n")

	inspPEM := NewSSEInspector(
		io.NopCloser(strings.NewReader(pemSSE)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-pem-sse"},
		nil,
	)
	outPEMBytes, err := io.ReadAll(inspPEM)
	if err != nil {
		t.Fatal(err)
	}
	outPEM := string(outPEMBytes)
	if strings.Contains(outPEM, "MIIETEST") || strings.Contains(outPEM, "SYNTHETIC2") || strings.Contains(outPEM, "PRIVATE KEY") {
		t.Fatalf("SECURITY FAILURE (JG-R3 SSE): multi-chunk PEM key body or footer leaked:\n%s", outPEM)
	}
	if !strings.Contains(outPEM, "Sufixo seguro.") {
		t.Errorf("post-PEM safe text was erroneously swallowed:\n%s", outPEM)
	}

	// 3b. Truncated EOF PEM without END marker
	truncPEMSSE := fmt.Sprintf("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Leak: %s\\n%s\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"%s\"}}]}\n\n",
		pemHeader, longBase64ChunkA, longBase64ChunkB)
	inspTrunc := NewSSEInspector(
		io.NopCloser(strings.NewReader(truncPEMSSE)),
		&cfg,
		vault,
		guards.InspectionResult{Status: "CLEAN", SessionID: "sess-pem-trunc"},
		nil,
	)
	outTruncBytes, err := io.ReadAll(inspTrunc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(outTruncBytes), "MIIETEST") || strings.Contains(string(outTruncBytes), "SYNTHETIC2") {
		t.Fatalf("SECURITY FAILURE (JG-R3 EOF): unclosed PEM body leaked on EOF:\n%s", string(outTruncBytes))
	}
}

func BenchmarkSSERuneSlidingWindow(b *testing.B) {
	cfg := config.DefaultConfig()
	cfg.ApplyPreset()
	vault := guards.NewPIIVault()

	sampleSSE := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" Transferência autorizada com sucesso para a conta informada.\"}}]}\n\ndata: [DONE]\n\n"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			insp := NewSSEInspector(
				io.NopCloser(strings.NewReader(sampleSSE)),
				&cfg,
				vault,
				guards.InspectionResult{CanaryToken: "jg_cnry_abcdef123456"},
				nil,
			)
			_, _ = io.Copy(io.Discard, insp)
		}
	})
}
