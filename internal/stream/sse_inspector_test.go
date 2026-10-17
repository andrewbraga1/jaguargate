package stream

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jaguargate/jaguargate/internal/config"
	"github.com/jaguargate/jaguargate/internal/guards"
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
