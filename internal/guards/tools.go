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
	ModifiedBody    []byte
	Status          string
	Severity        string
	Codes           []string
	PrunedTools     int
	PrunedToolNames []string
	CanaryLeaked    bool
}

// SanitizeToolCallsSlice inspects a JSON array of tool_calls (or tools definitions),
// surgically pruning unauthorized tools (JG-CFG-101) and untrusted domains (JG-CFG-103).
func SanitizeToolCallsSlice(rawTools []any, cfg config.WhitelistConfig, isShadow bool) ([]any, []string, int) {
	kept, codes, prunedNames := SanitizeToolCallsSliceDetailed(rawTools, cfg, isShadow)
	return kept, codes, len(prunedNames)
}

// SanitizeToolCallsSliceDetailed inspects a JSON array of tool_calls (or tool definitions)
// and also returns the exact names of all pruned unauthorized tools for semantic feedback headers.
func SanitizeToolCallsSliceDetailed(rawTools []any, cfg config.WhitelistConfig, isShadow bool) ([]any, []string, []string) {
	if !cfg.EnforceToolWhitelist || len(rawTools) == 0 {
		return rawTools, nil, nil
	}

	kept := make([]any, 0, len(rawTools))
	var codes []string
	var prunedNames []string

	for _, item := range rawTools {
		toolMap, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}

		toolName := extractToolName(toolMap)
		if toolName != "" && !isToolAllowed(toolName, cfg.AllowedTools) {
			prunedNames = append(prunedNames, sanitizeHeaderToken(toolName))
			if !slices.Contains(codes, "JG-CFG-101") {
				codes = append(codes, "JG-CFG-101")
			}
			if isShadow {
				kept = append(kept, item)
			}
			continue
		}

		// Inspect tool arguments for unauthorized external domains
		if fnMap, ok := toolMap["function"].(map[string]any); ok && len(cfg.AllowedDomains) > 0 {
			if argsStr, ok := fnMap["arguments"].(string); ok {
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
			} else if argsMap, ok := fnMap["arguments"].(map[string]any); ok {
				if argsBytes, err := json.Marshal(argsMap); err == nil {
					cleanedArgs, violated := sanitizeDomainsInText(string(argsBytes), cfg.AllowedDomains, isShadow)
					if violated {
						if !slices.Contains(codes, "JG-CFG-103") {
							codes = append(codes, "JG-CFG-103")
						}
						if !isShadow {
							var newMap map[string]any
							if json.Unmarshal([]byte(cleanedArgs), &newMap) == nil {
								fnMap["arguments"] = newMap
							}
							toolMap["function"] = fnMap
						}
					}
				}
			}
		}

		kept = append(kept, toolMap)
	}

	return kept, codes, prunedNames
}

func sanitizeHeaderToken(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", "")
	s = strings.ReplaceAll(s, ",", "_")
	return strings.TrimSpace(s)
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
	lang := cfg.Core.Language
	var codes []string

	// 1. Critical System Prompt Canary Leak Detection (JG-SEC-501)
	if cfg.Guards.CanaryTokens.Enabled && canaryToken != "" && strings.Contains(text, canaryToken) {
		codes = append(codes, "JG-SEC-501")
		if cfg.Guards.CanaryTokens.TruncateStreamOnLeak && !isShadow {
			return config.T(lang, config.MsgCanaryPrevented), codes, true
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
					working = strings.ReplaceAll(working, m[0], config.T(lang, config.MsgRestrictedImage))
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
			working = reExecutableScript.ReplaceAllString(working, config.T(lang, config.MsgRestrictedScript))
		}
	}

	// 4. Reversible PII Vault Restoration (scoped strictly to sessionID; secrets withheld unless restore_secrets=true)
	if vault != nil && cfg.Guards.PIIVault.Enabled && cfg.Guards.PIIVault.RestoreOnOutput && !isShadow {
		working = vault.RestoreTextWithOptions(sessionID, working, cfg.Guards.PIIVault.RestoreSecrets)
	}

	// 5. Active Output Secret DLP (JG-SEC-503): redact spontaneous/unmapped credentials emitted by the LLM
	if cfg.Guards.PIIVault.Enabled && !cfg.Guards.PIIVault.RestoreSecrets {
		replacement := config.T(lang, config.MsgRestrictedSecret)
		if isShadow {
			if _, leakedSecret := RedactSecretsInText(working, cfg.Guards.PIIVault, ""); leakedSecret {
				if !slices.Contains(codes, "JG-SEC-503") {
					codes = append(codes, "JG-SEC-503")
				}
			}
		} else {
			if redacted, leakedSecret := RedactSecretsInText(working, cfg.Guards.PIIVault, replacement); leakedSecret {
				working = redacted
				if !slices.Contains(codes, "JG-SEC-503") {
					codes = append(codes, "JG-SEC-503")
				}
			}
		}
	}

	return working, codes, false
}

// SanitizeOutputToolArgChunk sanitizes a streaming JSON tool-call argument fragment (OpenAI delta.tool_calls
// or Anthropic input_json_delta) for Canary leaks (JG-SEC-501), stateful PEM blocks & active secrets (JG-SEC-503),
// scripts/trackers (JG-SEC-502), and JSON-safe session PII restoration while preserving JSON string syntax.
func SanitizeOutputToolArgChunk(
	sessionID, text, canaryToken string,
	cfg *config.Config,
	vault *PIIVault,
	pemState *PEMStreamState,
) (string, []string, bool) {
	if text == "" && (pemState == nil || !pemState.Active) {
		return "", nil, false
	}
	if sessionID == "" {
		sessionID = "default_session"
	}

	isShadow := cfg.Core.Mode == "shadow"
	lang := cfg.Core.Language
	var codes []string

	if cfg.Guards.CanaryTokens.Enabled && canaryToken != "" && strings.Contains(text, canaryToken) {
		codes = append(codes, "JG-SEC-501")
		if cfg.Guards.CanaryTokens.TruncateStreamOnLeak && !isShadow {
			return config.T(lang, config.MsgCanaryPrevented), codes, true
		}
	}

	working := text

	// Stateful PEM block suppression across tool argument chunks
	if cfg.Guards.PIIVault.Enabled && !cfg.Guards.PIIVault.RestoreSecrets && pemState != nil {
		pemRepl := config.T(lang, config.MsgRestrictedSecret)
		if isShadow {
			pemRepl = ""
		}
		cleanedPEM, pemHit := StripStreamingPEM(working, pemState, pemRepl, true)
		if pemHit {
			if !slices.Contains(codes, "JG-SEC-503") {
				codes = append(codes, "JG-SEC-503")
			}
			if !isShadow {
				working = cleanedPEM
			}
		}
	}

	// JSON-safe reversible PII restoration (secrets remain masked when restore_secrets=false)
	if vault != nil && cfg.Guards.PIIVault.Enabled && cfg.Guards.PIIVault.RestoreOnOutput && !isShadow {
		working = vault.RestoreTextJSONSafeWithOptions(sessionID, working, cfg.Guards.PIIVault.RestoreSecrets)
	}

	// Active Output Secret DLP (JG-SEC-503)
	if cfg.Guards.PIIVault.Enabled && !cfg.Guards.PIIVault.RestoreSecrets {
		replacement := config.T(lang, config.MsgRestrictedSecret)
		if isShadow {
			if _, leakedSecret := RedactSecretsInText(working, cfg.Guards.PIIVault, ""); leakedSecret && !slices.Contains(codes, "JG-SEC-503") {
				codes = append(codes, "JG-SEC-503")
			}
		} else {
			if redacted, leakedSecret := RedactSecretsInText(working, cfg.Guards.PIIVault, replacement); leakedSecret {
				working = redacted
				if !slices.Contains(codes, "JG-SEC-503") {
					codes = append(codes, "JG-SEC-503")
				}
			}
		}
	}

	return working, codes, false
}

func (e *Engine) sanitizeOutputJSONValue(val any, sessionID, canaryToken string, cfg *config.Config, out *OutputInspectionResult, depth int) (any, bool) {
	if depth > 16 {
		return val, false
	}
	isShadow := cfg.Core.Mode == "shadow"
	switch v := val.(type) {
	case string:
		cleaned, codes, leaked := SanitizeOutputTextWithSession(sessionID, v, canaryToken, cfg, e.vault)
		if leaked {
			out.CanaryLeaked = true
		}
		for _, c := range codes {
			out.addOutputCode(c)
		}
		if len(cfg.Whitelist.AllowedDomains) > 0 {
			domCleaned, domViolated := SanitizeDomainsInText(cleaned, cfg.Whitelist.AllowedDomains, isShadow)
			if domViolated {
				out.addOutputCode("JG-CFG-103")
				if !isShadow {
					cleaned = domCleaned
				}
			}
		}
		if !isShadow && cleaned != v {
			return cleaned, true
		}
		return v, false
	case map[string]any:
		mut := false
		for k, sub := range v {
			newSub, subMut := e.sanitizeOutputJSONValue(sub, sessionID, canaryToken, cfg, out, depth+1)
			if subMut {
				v[k] = newSub
				mut = true
			}
		}
		return v, mut
	case []any:
		mut := false
		for i, sub := range v {
			newSub, subMut := e.sanitizeOutputJSONValue(sub, sessionID, canaryToken, cfg, out, depth+1)
			if subMut {
				v[i] = newSub
				mut = true
			}
		}
		return v, mut
	default:
		return val, false
	}
}

// SanitizeOutputToolCallsSlice applies Active Output DLP (JG-SEC-503), Canary check (JG-SEC-501),
// and session PII restoration to non-delta tool_calls arrays (e.g. Ollama NDJSON chunks).
func SanitizeOutputToolCallsSlice(
	tools []any,
	sessionID, canaryToken string,
	cfg *config.Config,
	vault *PIIVault,
) ([]any, []string, bool, bool) {
	eng := NewEngine(vault)
	out := OutputInspectionResult{}
	mut := eng.sanitizeOutputToolCallsArgs(tools, sessionID, canaryToken, cfg, &out)
	return tools, out.Codes, out.CanaryLeaked, mut
}

func (e *Engine) sanitizeOutputToolCallsArgs(tools []any, sessionID, canaryToken string, cfg *config.Config, out *OutputInspectionResult) bool {
	isShadow := cfg.Core.Mode == "shadow"
	modified := false
	for i, item := range tools {
		tMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		fnMap, ok := tMap["function"].(map[string]any)
		if !ok {
			continue
		}
		switch rawArgs := fnMap["arguments"].(type) {
		case string:
			if rawArgs == "" {
				continue
			}
			var parsed any
			if err := json.Unmarshal([]byte(rawArgs), &parsed); err == nil {
				cleanedVal, mut := e.sanitizeOutputJSONValue(parsed, sessionID, canaryToken, cfg, out, 1)
				if mut && !isShadow {
					if b, mErr := marshalJSONUnescaped(cleanedVal); mErr == nil {
						fnMap["arguments"] = string(b)
						tMap["function"] = fnMap
						tools[i] = tMap
						modified = true
					}
				}
			} else {
				var pemState PEMStreamState
				cleaned, codes, leaked := SanitizeOutputToolArgChunk(sessionID, rawArgs, canaryToken, cfg, e.vault, &pemState)
				if leaked {
					out.CanaryLeaked = true
				}
				for _, c := range codes {
					out.addOutputCode(c)
				}
				if !isShadow && cleaned != rawArgs {
					fnMap["arguments"] = cleaned
					tMap["function"] = fnMap
					tools[i] = tMap
					modified = true
				}
			}
		case map[string]any:
			if _, mut := e.sanitizeOutputJSONValue(rawArgs, sessionID, canaryToken, cfg, out, 1); mut && !isShadow {
				fnMap["arguments"] = rawArgs
				tMap["function"] = fnMap
				tools[i] = tMap
				modified = true
			}
		}
	}
	return modified
}

// SanitizeOutputJSON inspects a complete non-streaming LLM response body (choices[].message.content & tool_calls).
func (e *Engine) SanitizeOutputJSON(body []byte, inboundRes InspectionResult, cfg *config.Config) OutputInspectionResult {
	sessionID := inboundRes.SessionID
	if sessionID == "" {
		sessionID = "default_session"
	}

	out := OutputInspectionResult{
		ModifiedBody:    body,
		Status:          inboundRes.Status,
		Severity:        inboundRes.Severity,
		Codes:           slices.Clone(inboundRes.Codes),
		PrunedTools:     inboundRes.PrunedTools,
		PrunedToolNames: slices.Clone(inboundRes.PrunedToolNames),
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

				// 2. Inspect & selectively prune assistant tool_calls + apply Output DLP & PII policy to arguments
				if rawTools, ok := msgMap["tool_calls"].([]any); ok && len(rawTools) > 0 {
					activeTools := rawTools
					if cfg.Whitelist.EnforceToolWhitelist {
						keptTools, toolCodes, prunedNames := SanitizeToolCallsSliceDetailed(rawTools, cfg.Whitelist, isShadow)
						pruned := len(prunedNames)
						out.PrunedTools += pruned
						for _, name := range prunedNames {
							if !slices.Contains(out.PrunedToolNames, name) {
								out.PrunedToolNames = append(out.PrunedToolNames, name)
							}
						}
						for _, c := range toolCodes {
							out.addOutputCode(c)
						}
						if !isShadow && (pruned > 0 || len(toolCodes) > 0) {
							modified = true
							activeTools = keptTools
						}
					}

					if len(activeTools) > 0 {
						if e.sanitizeOutputToolCallsArgs(activeTools, sessionID, inboundRes.CanaryToken, cfg, &out) {
							modified = true
						}
					}

					if modified && !isShadow {
						if len(activeTools) > 0 {
							msgMap["tool_calls"] = activeTools
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

			// Support legacy OpenAI / vLLM completions format: choices[].text
			if textStr, ok := chMap["text"].(string); ok && textStr != "" {
				cleaned, codes, leaked := SanitizeOutputTextWithSession(sessionID, textStr, inboundRes.CanaryToken, cfg, e.vault)
				if leaked {
					out.CanaryLeaked = true
				}
				for _, c := range codes {
					out.addOutputCode(c)
				}
				if !isShadow && cleaned != textStr {
					chMap["text"] = cleaned
					modified = true
				}
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
			activeTools := rawTools
			if cfg.Whitelist.EnforceToolWhitelist {
				keptTools, toolCodes, prunedNames := SanitizeToolCallsSliceDetailed(rawTools, cfg.Whitelist, isShadow)
				pruned := len(prunedNames)
				out.PrunedTools += pruned
				for _, name := range prunedNames {
					if !slices.Contains(out.PrunedToolNames, name) {
						out.PrunedToolNames = append(out.PrunedToolNames, name)
					}
				}
				for _, c := range toolCodes {
					out.addOutputCode(c)
				}
				if !isShadow && (pruned > 0 || len(toolCodes) > 0) {
					modified = true
					activeTools = keptTools
				}
			}
			if len(activeTools) > 0 && e.sanitizeOutputToolCallsArgs(activeTools, sessionID, inboundRes.CanaryToken, cfg, &out) {
				modified = true
			}
			if modified && !isShadow {
				if len(activeTools) > 0 {
					msgMap["tool_calls"] = activeTools
				} else {
					delete(msgMap, "tool_calls")
				}
			}
		}
		payload["message"] = msgMap
	}

	// JG-03: Also support Ollama native "/api/generate" top-level "response" string
	if respStr, ok := payload["response"].(string); ok && respStr != "" {
		cleaned, codes, leaked := SanitizeOutputTextWithSession(sessionID, respStr, inboundRes.CanaryToken, cfg, e.vault)
		if leaked {
			out.CanaryLeaked = true
		}
		for _, c := range codes {
			out.addOutputCode(c)
		}
		if !isShadow && cleaned != respStr {
			payload["response"] = cleaned
			modified = true
		}
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
				wasPruned := false
				if cfg.Whitelist.EnforceToolWhitelist && toolName != "" {
					if !IsToolAllowed(toolName, cfg.Whitelist.AllowedTools) {
						wasPruned = true
						out.PrunedTools++
						safeName := sanitizeHeaderToken(toolName)
						if safeName != "" && !slices.Contains(out.PrunedToolNames, safeName) {
							out.PrunedToolNames = append(out.PrunedToolNames, safeName)
						}
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

				// Inspect allowed tool_use inputs for Active Secret DLP (JG-SEC-503), PII restoration, Canary & Domains
				if !wasPruned {
					if rawInput, hasInput := blockMap["input"]; hasInput {
						cleanedInput, mut := e.sanitizeOutputJSONValue(rawInput, sessionID, inboundRes.CanaryToken, cfg, &out, 1)
						if mut && !isShadow {
							blockMap["input"] = cleanedInput
							modified = true
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

	// Support OpenAI Responses API format: top-level "output" array (message content & function_call arguments)
	if rawOutput, ok := payload["output"].([]any); ok {
		keptOut := make([]any, 0, len(rawOutput))
		outMod := false
		for _, outItem := range rawOutput {
			outMap, ok := outItem.(map[string]any)
			if !ok {
				keptOut = append(keptOut, outItem)
				continue
			}
			itemType, _ := outMap["type"].(string)
			if itemType == "function_call" {
				tName, _ := outMap["name"].(string)
				if cfg.Whitelist.EnforceToolWhitelist && tName != "" && !IsToolAllowed(tName, cfg.Whitelist.AllowedTools) {
					out.PrunedTools++
					safeName := sanitizeHeaderToken(tName)
					if safeName != "" && !slices.Contains(out.PrunedToolNames, safeName) {
						out.PrunedToolNames = append(out.PrunedToolNames, safeName)
					}
					out.addOutputCode("JG-CFG-101")
					if isShadow {
						keptOut = append(keptOut, outMap)
					} else {
						outMod = true
					}
					continue
				}
				if argsStr, ok := outMap["arguments"].(string); ok && argsStr != "" {
					var parsed any
					if err := json.Unmarshal([]byte(argsStr), &parsed); err == nil {
						if cleanedVal, mut := e.sanitizeOutputJSONValue(parsed, sessionID, inboundRes.CanaryToken, cfg, &out, 1); mut && !isShadow {
							if b, mErr := marshalJSONUnescaped(cleanedVal); mErr == nil {
								outMap["arguments"] = string(b)
								outMod = true
							}
						}
					}
				}
			} else if subContent, ok := outMap["content"].([]any); ok {
				if _, mut := e.sanitizeOutputJSONValue(subContent, sessionID, inboundRes.CanaryToken, cfg, &out, 1); mut && !isShadow {
					outMap["content"] = subContent
					outMod = true
				}
			}
			keptOut = append(keptOut, outMap)
		}
		if outMod && !isShadow {
			payload["output"] = keptOut
			modified = true
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
