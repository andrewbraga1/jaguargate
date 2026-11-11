package guards

import (
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

var (
	// Matches Markdown external image trackers: ![alt](https://evil.com/pixel.png)
	reMarkdownImageURL = regexp.MustCompile(`!\[[^\]]*\]\(\s*(https?://[^)\s]+)[^)]*\)`)
	// Matches inline executable HTML/JS script tags or javascript: URIs
	reExecutableScript = regexp.MustCompile(`(?is)(?:<\s*script[^>]*>.*?<\s*/\s*script\s*>|javascript\s*:)`)
	// Extracts URLs inside tool call JSON arguments for domain whitelist validation
	reURLInArgs = regexp.MustCompile(`https?://[^\s"'<>\\]+`)
)

// OutputInspectionResult holds the outcome of inspecting a non-streaming LLM response.
type OutputInspectionResult struct {
	ModifiedBody []byte
	Status       string
	Severity     string
	Codes        []string
	PrunedTools  int
	CanaryLeaked bool
}

// SanitizeToolCallsSlice inspects a JSON array of tool_calls (or tools definitions),
// surgically pruning unauthorized tools (JG-CFG-101) and untrusted domains (JG-CFG-103).
func SanitizeToolCallsSlice(rawTools []any, cfg config.WhitelistConfig, isShadow bool) ([]any, []string, int) {
	if !cfg.EnforceToolWhitelist || len(rawTools) == 0 {
		return rawTools, nil, 0
	}

	kept := make([]any, 0, len(rawTools))
	var codes []string
	prunedCount := 0

	for _, item := range rawTools {
		toolMap, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}

		toolName := extractToolName(toolMap)
		if toolName != "" && !isToolAllowed(toolName, cfg.AllowedTools) {
			prunedCount++
			if !slices.Contains(codes, "JG-CFG-101") {
				codes = append(codes, "JG-CFG-101")
			}
			if isShadow {
				kept = append(kept, item)
			}
			continue
		}

		// Inspect tool arguments for unauthorized external domains
		if fnMap, ok := toolMap["function"].(map[string]any); ok {
			if argsStr, ok := fnMap["arguments"].(string); ok && len(cfg.AllowedDomains) > 0 {
				cleanedArgs, violated := sanitizeDomainsInText(argsStr, cfg.AllowedDomains, isShadow)
				if violated {
					if !slices.Contains(codes, "JG-CFG-103") {
						codes = append(codes, "JG-CFG-103")
					}
					if !isShadow {
						fnMap["arguments"] = cleanedArgs
						toolMap["function"] = fnMap
					}
				}
			}
		}

		kept = append(kept, toolMap)
	}

	return kept, codes, prunedCount
}

// SanitizeOutputText checks a text segment for Canary Token leaks (JG-SEC-501),
// untrusted Markdown image trackers or scripts (JG-SEC-502), and restores PII tokens for the default session.
func SanitizeOutputText(text, canaryToken string, cfg *config.Config, vault *PIIVault) (string, []string, bool) {
	return SanitizeOutputTextWithSession("default_session", text, canaryToken, cfg, vault)
}

// SanitizeOutputTextWithSession checks a text segment for Canary Token leaks (JG-SEC-501),
// untrusted Markdown image trackers or scripts (JG-SEC-502), and restores PII tokens ONLY for the authorized sessionID.
func SanitizeOutputTextWithSession(sessionID, text, canaryToken string, cfg *config.Config, vault *PIIVault) (string, []string, bool) {
	if text == "" {
		return "", nil, false
	}
	if sessionID == "" {
		sessionID = "default_session"
	}

	isShadow := cfg.Core.Mode == "shadow"
	isPT := isPortuguese(cfg.Core.Language)
	var codes []string

	// 1. Critical System Prompt Canary Leak Detection (JG-SEC-501)
	if cfg.Guards.CanaryTokens.Enabled && canaryToken != "" && strings.Contains(text, canaryToken) {
		codes = append(codes, "JG-SEC-501")
		if cfg.Guards.CanaryTokens.TruncateStreamOnLeak && !isShadow {
			if isPT {
				return "[CONTEÚDO RESTRITO: Vazamento de System Prompt Bloqueado (JG-SEC-501)]", codes, true
			}
			return "[RESTRICTED CONTENT: System Prompt Leak Prevented (JG-SEC-501)]", codes, true
		}
	}

	working := text

	// 2. Block Untrusted External Markdown Image Trackers (JG-SEC-502)
	if cfg.Guards.OutputSanitizer.BlockUntrustedMarkdownImages {
		matches := reMarkdownImageURL.FindAllStringSubmatch(working, -1)
		for _, m := range matches {
			if len(m) >= 2 && !IsDomainAllowed(m[1], cfg.Whitelist.AllowedDomains) {
				if !slices.Contains(codes, "JG-SEC-502") {
					codes = append(codes, "JG-SEC-502")
				}
				if !isShadow {
					replacement := "[RESTRICTED IMAGE (JG-SEC-502)]"
					if isPT {
						replacement = "[IMAGEM RESTRITA (JG-SEC-502)]"
					}
					working = strings.ReplaceAll(working, m[0], replacement)
				}
			}
		}
	}

	// 3. Strip Executable Scripts (JG-SEC-502)
	if cfg.Guards.OutputSanitizer.StripExecutableScripts && reExecutableScript.MatchString(working) {
		if !slices.Contains(codes, "JG-SEC-502") {
			codes = append(codes, "JG-SEC-502")
		}
		if !isShadow {
			replacement := "[RESTRICTED SCRIPT (JG-SEC-502)]"
			if isPT {
				replacement = "[SCRIPT RESTRITO (JG-SEC-502)]"
			}
			working = reExecutableScript.ReplaceAllString(working, replacement)
		}
	}

	// 4. Reversible PII Vault Restoration (scoped strictly to sessionID)
	if vault != nil && cfg.Guards.PIIVault.Enabled && cfg.Guards.PIIVault.RestoreOnOutput && !isShadow {
		working = vault.RestoreTextWithSession(sessionID, working)
	}

	return working, codes, false
}

// SanitizeOutputJSON inspects a complete non-streaming LLM response body (choices[].message.content & tool_calls).
func (e *Engine) SanitizeOutputJSON(body []byte, inboundRes InspectionResult, cfg *config.Config) OutputInspectionResult {
	sessionID := inboundRes.SessionID
	if sessionID == "" {
		sessionID = "default_session"
	}

	out := OutputInspectionResult{
		ModifiedBody: body,
		Status:       inboundRes.Status,
		Severity:     inboundRes.Severity,
		Codes:        slices.Clone(inboundRes.Codes),
		PrunedTools:  inboundRes.PrunedTools,
	}
	if out.Status == "" {
		out.Status = "CLEAN"
		out.Severity = "NONE"
	}

	if len(body) == 0 {
		return out
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		cleaned, codes, leaked := SanitizeOutputTextWithSession(sessionID, string(body), inboundRes.CanaryToken, cfg, e.vault)
		out.CanaryLeaked = leaked
		for _, c := range codes {
			out.addOutputCode(c)
		}
		out.finalizeOutputMode(cfg.Core.Mode)
		if cfg.Core.Mode != "shadow" && cleaned != string(body) {
			out.ModifiedBody = []byte(cleaned)
		}
		return out
	}

	isShadow := cfg.Core.Mode == "shadow"
	isPT := isPortuguese(cfg.Core.Language)
	modified := false

	// Inspect OpenAI / LiteLLM / vLLM "choices" array
	if choices, ok := payload["choices"].([]any); ok {
		for i, chItem := range choices {
			chMap, ok := chItem.(map[string]any)
			if !ok {
				continue
			}
			if msgMap, ok := chMap["message"].(map[string]any); ok {
				// 1. Inspect assistant text content
				if contentStr, ok := msgMap["content"].(string); ok && contentStr != "" {
					cleaned, codes, leaked := SanitizeOutputTextWithSession(sessionID, contentStr, inboundRes.CanaryToken, cfg, e.vault)
					if leaked {
						out.CanaryLeaked = true
					}
					for _, c := range codes {
						out.addOutputCode(c)
					}
					if !isShadow && cleaned != contentStr {
						msgMap["content"] = cleaned
						modified = true
					}
				}

				// 2. Inspect & selectively prune assistant tool_calls
				if rawTools, ok := msgMap["tool_calls"].([]any); ok && len(rawTools) > 0 {
					keptTools, toolCodes, pruned := SanitizeToolCallsSlice(rawTools, cfg.Whitelist, isShadow)
					out.PrunedTools += pruned
					for _, c := range toolCodes {
						out.addOutputCode(c)
					}
					if !isShadow && (pruned > 0 || len(toolCodes) > 0) {
						modified = true
						if len(keptTools) > 0 {
							msgMap["tool_calls"] = keptTools
						} else {
							// Enterprise SDK safety: normalize finish_reason when all tools are pruned
							delete(msgMap, "tool_calls")
							if chMap["finish_reason"] == "tool_calls" {
								chMap["finish_reason"] = "stop"
							}
							if msgMap["content"] == nil || msgMap["content"] == "" {
								if isPT {
									msgMap["content"] = "[JaguarGate: Chamada de ferramenta não autorizada omitida pela política (JG-CFG-101)]"
								} else {
									msgMap["content"] = "[JaguarGate: Unauthorized tool call omitted by policy (JG-CFG-101)]"
								}
							}
						}
					}
				}
				chMap["message"] = msgMap
			}
			choices[i] = chMap
		}
		payload["choices"] = choices
	}

	// Also support Ollama native "/api/chat" top-level "message" object
	if msgMap, ok := payload["message"].(map[string]any); ok {
		if contentStr, ok := msgMap["content"].(string); ok && contentStr != "" {
			cleaned, codes, leaked := SanitizeOutputTextWithSession(sessionID, contentStr, inboundRes.CanaryToken, cfg, e.vault)
			if leaked {
				out.CanaryLeaked = true
			}
			for _, c := range codes {
				out.addOutputCode(c)
			}
			if !isShadow && cleaned != contentStr {
				msgMap["content"] = cleaned
				modified = true
			}
		}
		if rawTools, ok := msgMap["tool_calls"].([]any); ok && len(rawTools) > 0 {
			keptTools, toolCodes, pruned := SanitizeToolCallsSlice(rawTools, cfg.Whitelist, isShadow)
			out.PrunedTools += pruned
			for _, c := range toolCodes {
				out.addOutputCode(c)
			}
			if !isShadow && (pruned > 0 || len(toolCodes) > 0) {
				modified = true
				if len(keptTools) > 0 {
					msgMap["tool_calls"] = keptTools
				} else {
					delete(msgMap, "tool_calls")
				}
			}
		}
		payload["message"] = msgMap
	}

	// Also support Anthropic Messages API format: top-level "content" array with text & tool_use blocks
	if rawContent, ok := payload["content"].([]any); ok {
		for i, blockItem := range rawContent {
			blockMap, ok := blockItem.(map[string]any)
			if !ok {
				continue
			}
			blockType, _ := blockMap["type"].(string)

			// 1. Text content block
			if blockType == "text" || blockType == "" {
				if textStr, ok := blockMap["text"].(string); ok && textStr != "" {
					cleaned, codes, leaked := SanitizeOutputTextWithSession(sessionID, textStr, inboundRes.CanaryToken, cfg, e.vault)
					if leaked {
						out.CanaryLeaked = true
					}
					for _, c := range codes {
						out.addOutputCode(c)
					}
					if !isShadow && cleaned != textStr {
						blockMap["text"] = cleaned
						modified = true
					}
				}
			}

			// 2. Tool use block
			if blockType == "tool_use" {
				toolName, _ := blockMap["name"].(string)
				if cfg.Whitelist.EnforceToolWhitelist && toolName != "" {
					if !IsToolAllowed(toolName, cfg.Whitelist.AllowedTools) {
						out.PrunedTools++
						out.addOutputCode("JG-CFG-101")
						if !isShadow {
							blockMap["name"] = "unauthorized_tool_omitted"
							if isPT {
								blockMap["input"] = map[string]any{
									"error": "JaguarGate: Chamada de ferramenta não autorizada omitida pela política (JG-CFG-101)",
								}
							} else {
								blockMap["input"] = map[string]any{
									"error": "JaguarGate: Unauthorized tool call omitted by policy (JG-CFG-101)",
								}
							}
							modified = true
						}
					}
				}

				// Inspect tool inputs for unauthorized domains
				if inputMap, ok := blockMap["input"].(map[string]any); ok && len(cfg.Whitelist.AllowedDomains) > 0 {
					if inputBytes, err := json.Marshal(inputMap); err == nil {
						cleanedInput, violated := SanitizeDomainsInText(string(inputBytes), cfg.Whitelist.AllowedDomains, isShadow)
						if violated {
							out.addOutputCode("JG-CFG-103")
							if !isShadow {
								var newInputs map[string]any
								if err := json.Unmarshal([]byte(cleanedInput), &newInputs); err == nil {
									blockMap["input"] = newInputs
									modified = true
								}
							}
						}
					}
				}
			}
			rawContent[i] = blockMap
		}
		if modified && !isShadow {
			payload["content"] = rawContent
		}
	}

	out.finalizeOutputMode(cfg.Core.Mode)

	if cfg.Telemetry.WarningFlags.IncludeBodyTelemetry && len(out.Codes) > 0 {
		payload["_jaguargate"] = map[string]any{
			"status":       out.Status,
			"severity":     out.Severity,
			"codes":        out.Codes,
			"pruned_tools": out.PrunedTools,
		}
		modified = true
	}

	if modified {
		if updatedBytes, err := marshalJSONUnescaped(payload); err == nil {
			out.ModifiedBody = updatedBytes
		}
	}

	return out
}

func (r *OutputInspectionResult) addOutputCode(code string) {
	if code == "" {
		return
	}
	if !slices.Contains(r.Codes, code) {
		r.Codes = append(r.Codes, code)
	}
	if strings.HasPrefix(code, "JG-SEC-") {
		r.Severity = "INTRUSION_ALERT"
	} else if r.Severity == "" || r.Severity == "NONE" {
		r.Severity = "CONFIG_WARNING"
	}
}

func (r *OutputInspectionResult) finalizeOutputMode(mode string) {
	if len(r.Codes) == 0 {
		r.Status = "CLEAN"
		r.Severity = "NONE"
		return
	}
	if r.CanaryLeaked {
		r.Status = "BLOCKED"
		r.Severity = "INTRUSION_ALERT"
		return
	}
	if mode == "shadow" {
		r.Status = "SHADOW_FLAGGED"
		return
	}
	r.Status = "SANITIZED"
}

func extractToolName(toolMap map[string]any) string {
	if fn, ok := toolMap["function"].(map[string]any); ok {
		if name, ok := fn["name"].(string); ok {
			return strings.TrimSpace(name)
		}
	}
	if name, ok := toolMap["name"].(string); ok {
		return strings.TrimSpace(name)
	}
	return ""
}

// IsToolAllowed returns true if the tool name matches the whitelist.
func IsToolAllowed(toolName string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || strings.EqualFold(strings.TrimSpace(a), toolName) {
			return true
		}
	}
	return false
}

func isToolAllowed(toolName string, allowed []string) bool {
	return IsToolAllowed(toolName, allowed)
}

// IsDomainAllowed checks if a raw URL's host matches the configured domain whitelist (supports "*.domain.com").
func IsDomainAllowed(rawURL string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, pattern := range allowedDomains {
		p := strings.ToLower(strings.TrimSpace(pattern))
		if p == "*" || p == host {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".yourdomain.com"
			if strings.HasSuffix(host, suffix) || host == p[2:] {
				return true
			}
		}
	}
	return false
}

// SanitizeDomainsInText inspects URLs in text against allowed domain patterns.
func SanitizeDomainsInText(input string, allowedDomains []string, isShadow bool) (string, bool) {
	violated := false
	out := reURLInArgs.ReplaceAllStringFunc(input, func(foundURL string) string {
		if !IsDomainAllowed(foundURL, allowedDomains) {
			violated = true
			if isShadow {
				return foundURL
			}
			return "https://blocked.jaguargate.local/restricted"
		}
		return foundURL
	})
	return out, violated
}

func sanitizeDomainsInText(input string, allowedDomains []string, isShadow bool) (string, bool) {
	return SanitizeDomainsInText(input, allowedDomains, isShadow)
}

func isPortuguese(lang string) bool {
	l := strings.TrimSpace(lang)
	return strings.EqualFold(l, "pt-BR") || strings.EqualFold(l, "pt")
}
