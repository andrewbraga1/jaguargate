package stream

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/andrewbraga1/jaguargate/internal/config"
	"github.com/andrewbraga1/jaguargate/internal/guards"
)

const (
	piiOpenPrefix   = "\x3cJG_PII_"
	maxSSELineBytes = 1024 * 1024 // 1MB cap on un-newlined SSE buffer to prevent OOM DoS
)

// StreamCompleteFunc is invoked once when the SSE stream finishes or halts, reporting final telemetry.
type StreamCompleteFunc func(status, severity string, codes []string, prunedTools int)

const (
	maxTrackersPerStream = 32
	maxToolArgsBytes     = 256 * 1024 // 256 KB per tool call to prevent unbounded memory exhaustion
)

type streamToolCallTracker struct {
	toolName   string
	isPruned   bool
	rawArgs    strings.Builder
	domainFail bool
}

// SSEInspector wraps an upstream HTTP response body (io.ReadCloser) to inspect Server-Sent Events
// in real time using a Rune-Aware UTF-8 Sliding Holdback Window.
type SSEInspector struct {
	upstream    io.ReadCloser
	cfg         *config.Config
	vault       *guards.PIIVault
	sessionID   string
	canaryToken string
	trailers    http.Header
	onComplete  StreamCompleteFunc

	rawBuf       bytes.Buffer
	outBuf       bytes.Buffer
	holdback     string // Rune-safe holdback buffer for cross-chunk tokens
	utf8Rem      []byte // Holds incomplete multi-byte UTF-8 sequences split across TCP reads
	codes        []string
	status       string
	severity     string
	prunedTools  int
	halted       bool
	eofReached   bool
	reported     bool
	isAnthropic  bool
	isNDJSON     bool
	toolTrackers map[int]*streamToolCallTracker
}

// NewSSEInspector creates a streaming SSE inspector wrapping the upstream response body.
func NewSSEInspector(
	upstream io.ReadCloser,
	cfg *config.Config,
	vault *guards.PIIVault,
	inbound guards.InspectionResult,
	trailers http.Header,
) *SSEInspector {
	status := inbound.Status
	severity := inbound.Severity
	if status == "" {
		status = "CLEAN"
		severity = "NONE"
	}
	sessID := inbound.SessionID
	if sessID == "" {
		sessID = "default_session"
	}
	return &SSEInspector{
		upstream:    upstream,
		cfg:         cfg,
		vault:       vault,
		sessionID:   sessID,
		canaryToken: inbound.CanaryToken,
		trailers:    trailers,
		codes:        slices.Clone(inbound.Codes),
		status:       status,
		severity:     severity,
		prunedTools:  inbound.PrunedTools,
		toolTrackers: make(map[int]*streamToolCallTracker),
	}
}

// SetOnComplete registers a callback executed once when the SSE stream terminates or is halted.
func (s *SSEInspector) SetOnComplete(fn StreamCompleteFunc) {
	s.onComplete = fn
}

// Read implements io.Reader, processing complete SSE lines and flushing sanitized tokens immediately.
func (s *SSEInspector) Read(p []byte) (int, error) {
	for s.outBuf.Len() == 0 {
		if s.halted || s.eofReached {
			return 0, io.EOF
		}

		var chunk [4096]byte
		n, err := s.upstream.Read(chunk[:])
		if n > 0 {
			s.rawBuf.Write(chunk[:n])
			s.processAvailableLines(false)
		}

		if err != nil {
			if err == io.EOF {
				s.eofReached = true
				s.processAvailableLines(true)
				s.finalizeStream()
				if s.outBuf.Len() > 0 {
					break
				}
				return 0, io.EOF
			}
			return 0, err
		}
	}

	return s.outBuf.Read(p)
}

// Close closes the underlying upstream body and ensures final telemetry is reported.
func (s *SSEInspector) Close() error {
	s.reportCompletion()
	return s.upstream.Close()
}

func (s *SSEInspector) processAvailableLines(flushAll bool) {
	for !s.halted {
		data := s.rawBuf.Bytes()
		nlIdx := bytes.IndexByte(data, '\n')
		if nlIdx == -1 {
			if (flushAll && len(data) > 0) || len(data) >= maxSSELineBytes {
				line := string(data)
				s.rawBuf.Reset()
				s.handleSSELine(line)
			}
			return
		}

		line := string(data[:nlIdx+1])
		s.rawBuf.Next(nlIdx + 1)
		s.handleSSELine(line)
	}
}

func (s *SSEInspector) handleSSELine(line string) {
	trimmed := strings.TrimSpace(line)

	// Single-pass prefix check: support standard SSE ("data: ...") and Ollama NDJSON ("{...}")
	rawPayload, isDataLine := strings.CutPrefix(trimmed, "data:")
	isNDJSON := false
	if !isDataLine && strings.HasPrefix(trimmed, "{") {
		rawPayload = trimmed
		isNDJSON = true
		s.isNDJSON = true
	}
	if trimmed == "" || (!isDataLine && !isNDJSON) {
		s.outBuf.WriteString(line)
		return
	}

	payloadStr := strings.TrimSpace(rawPayload)
	isShadow := s.cfg != nil && s.cfg.Core.Mode == "shadow"

	// Check for stream completion marker: data: [DONE]
	if payloadStr == "[DONE]" {
		if s.holdback != "" && !s.halted {
			cleaned, codes, leaked := guards.SanitizeOutputTextWithSession(s.sessionID, s.holdback, s.canaryToken, s.cfg, s.vault)
			s.holdback = ""
			for _, c := range codes {
				s.recordCode(c)
			}
			if leaked {
				s.haltOnCanaryLeak()
				return
			}
			if !isShadow && cleaned != "" {
				s.emitSyntheticDeltaChunk(cleaned)
			}
		}

		s.emitWarningEventIfNeeded()
		s.outBuf.WriteString(line)
		s.populateTrailers()
		s.reportCompletion()
		return
	}

	// Parse JSON delta chunk (OpenAI / Anthropic / Ollama / LiteLLM SSE format)
	var eventObj map[string]any
	if err := json.Unmarshal([]byte(payloadStr), &eventObj); err != nil {
		outText, shouldEmit := s.inspectStreamFragment(payloadStr)
		if s.halted {
			return
		}
		if shouldEmit {
			if isNDJSON {
				s.outBuf.WriteString(outText)
				s.outBuf.WriteByte('\n')
			} else {
				s.outBuf.WriteString("data: ")
				s.outBuf.WriteString(outText)
				s.outBuf.WriteByte('\n')
			}
		}
		return
	}

	if _, ok := eventObj["delta"].(map[string]any); ok && eventObj["choices"] == nil {
		s.isAnthropic = true
	}
	if typeStr, _ := eventObj["type"].(string); strings.HasPrefix(typeStr, "content_block_") || typeStr == "message_start" {
		s.isAnthropic = true
	}

	modified := false

	// 1. OpenAI / LiteLLM / vLLM format: choices[].delta.content & choices[].delta.tool_calls
	if choices, ok := eventObj["choices"].([]any); ok {
		for i, chItem := range choices {
			chMap, ok := chItem.(map[string]any)
			if !ok {
				continue
			}
			if deltaMap, ok := chMap["delta"].(map[string]any); ok {
				// 1a. Inspect streaming token text inside delta.content
				if tokenStr, ok := deltaMap["content"].(string); ok && tokenStr != "" {
					safeText, shouldEmit := s.inspectStreamFragment(tokenStr)
					if s.halted {
						return
					}
					if !isShadow && (!shouldEmit || safeText != tokenStr) {
						deltaMap["content"] = safeText
						modified = true
					}
				}

				// 1b. Inspect streaming delta.tool_calls across fragmented chunks
				if rawTools, ok := deltaMap["tool_calls"].([]any); ok && len(rawTools) > 0 {
					var keptTools []any
					toolsMutated := false
					for _, rawTool := range rawTools {
						toolMap, ok := rawTool.(map[string]any)
						if !ok {
							keptTools = append(keptTools, rawTool)
							continue
						}

						tcIdx := 0
						if idxVal, ok := toolMap["index"].(float64); ok {
							tcIdx = int(idxVal)
						}

						tracker, exists := s.toolTrackers[tcIdx]
						if !exists {
							if len(s.toolTrackers) >= maxTrackersPerStream {
								s.recordCode("JG-CFG-202")
								tracker = &streamToolCallTracker{isPruned: true}
							} else {
								tracker = &streamToolCallTracker{}
								s.toolTrackers[tcIdx] = tracker
							}
						}

						fnMap, _ := toolMap["function"].(map[string]any)
						if fnMap != nil {
							if nameStr, ok := fnMap["name"].(string); ok && nameStr != "" {
								tracker.toolName = nameStr
								if s.cfg.Whitelist.EnforceToolWhitelist && !guards.IsToolAllowed(nameStr, s.cfg.Whitelist.AllowedTools) {
									if !tracker.isPruned {
										tracker.isPruned = true
										s.prunedTools++
										s.recordCode("JG-CFG-101")
									}
								}
							}

							if argsChunk, ok := fnMap["arguments"].(string); ok && argsChunk != "" {
								if tracker.rawArgs.Len()+len(argsChunk) > maxToolArgsBytes {
									s.recordCode("JG-CFG-202")
									tracker.isPruned = true
									toolsMutated = true
								} else {
									tracker.rawArgs.WriteString(argsChunk)
								}
							}
						}

						if tracker.isPruned {
							toolsMutated = true
							if isShadow {
								keptTools = append(keptTools, toolMap)
							}
							continue
						}

						// Check domain rules on complete accumulated arguments string
						if len(s.cfg.Whitelist.AllowedDomains) > 0 && fnMap != nil {
							accumulated := tracker.rawArgs.String()
							_, violated := guards.SanitizeDomainsInText(accumulated, s.cfg.Whitelist.AllowedDomains, isShadow)
							if violated || tracker.domainFail {
								if !tracker.domainFail {
									tracker.domainFail = true
									s.recordCode("JG-CFG-103")
								}
								if !isShadow {
									if argsChunk, ok := fnMap["arguments"].(string); ok && argsChunk != "" {
										cleanedChunk, vChunk := guards.SanitizeDomainsInText(argsChunk, s.cfg.Whitelist.AllowedDomains, isShadow)
										if vChunk {
											fnMap["arguments"] = cleanedChunk
											toolMap["function"] = fnMap
											toolsMutated = true
										} else if tracker.domainFail {
											tailOnly := stripDomainTail(argsChunk)
											if tailOnly != argsChunk {
												fnMap["arguments"] = tailOnly
												toolMap["function"] = fnMap
												toolsMutated = true
											}
										}
									}
								}
							}
						}

						keptTools = append(keptTools, toolMap)
					}

					if toolsMutated || len(keptTools) != len(rawTools) {
						modified = true
						if len(keptTools) > 0 {
							deltaMap["tool_calls"] = keptTools
						} else {
							delete(deltaMap, "tool_calls")
						}
					}
				}
				chMap["delta"] = deltaMap
			}
			choices[i] = chMap
		}
		eventObj["choices"] = choices
	}

	// 2. Anthropic SSE format: delta.text
	if deltaMap, ok := eventObj["delta"].(map[string]any); ok {
		if tokenStr, ok := deltaMap["text"].(string); ok && tokenStr != "" {
			safeText, shouldEmit := s.inspectStreamFragment(tokenStr)
			if s.halted {
				return
			}
			if !isShadow && (!shouldEmit || safeText != tokenStr) {
				deltaMap["text"] = safeText
				eventObj["delta"] = deltaMap
				modified = true
			}
		}
	}

	// 2b. Anthropic SSE format: content_block_start with tool_use (JG-03)
	if typeStr, _ := eventObj["type"].(string); typeStr == "content_block_start" {
		idx := 0
		if fIdx, ok := eventObj["index"].(float64); ok {
			idx = int(fIdx)
		}
		if cbMap, ok := eventObj["content_block"].(map[string]any); ok {
			if cbType, _ := cbMap["type"].(string); cbType == "tool_use" {
				toolName, _ := cbMap["name"].(string)
				tracker := &streamToolCallTracker{toolName: toolName}
				if s.cfg.Whitelist.EnforceToolWhitelist && !guards.IsToolAllowed(toolName, s.cfg.Whitelist.AllowedTools) {
					tracker.isPruned = true
					s.prunedTools++
					s.recordCode("JG-CFG-101")
				}
				if len(s.toolTrackers) >= maxTrackersPerStream {
					s.recordCode("JG-CFG-202")
					tracker.isPruned = true
				}
				s.toolTrackers[idx] = tracker

				if tracker.isPruned && !isShadow {
					return
				}
			}
		}
	}

	// 2c. Anthropic SSE format: content_block_delta with input_json_delta (JG-03)
	if typeStr, _ := eventObj["type"].(string); typeStr == "content_block_delta" {
		idx := 0
		if fIdx, ok := eventObj["index"].(float64); ok {
			idx = int(fIdx)
		}
		if deltaMap, ok := eventObj["delta"].(map[string]any); ok {
			if deltaType, _ := deltaMap["type"].(string); deltaType == "input_json_delta" {
				tracker, exists := s.toolTrackers[idx]
				if exists && tracker.isPruned && !isShadow {
					return
				}
				if partialJSON, ok := deltaMap["partial_json"].(string); ok && partialJSON != "" {
					if exists {
						if tracker.rawArgs.Len()+len(partialJSON) > maxToolArgsBytes {
							s.recordCode("JG-CFG-202")
							tracker.isPruned = true
							if !isShadow {
								return
							}
						} else {
							tracker.rawArgs.WriteString(partialJSON)
						}

						if len(s.cfg.Whitelist.AllowedDomains) > 0 {
							accumulated := tracker.rawArgs.String()
							_, violated := guards.SanitizeDomainsInText(accumulated, s.cfg.Whitelist.AllowedDomains, isShadow)
							if violated || tracker.domainFail {
								if !tracker.domainFail {
									tracker.domainFail = true
									s.recordCode("JG-CFG-103")
								}
								if !isShadow {
									cleanedChunk, vChunk := guards.SanitizeDomainsInText(partialJSON, s.cfg.Whitelist.AllowedDomains, isShadow)
									if vChunk {
										deltaMap["partial_json"] = cleanedChunk
										eventObj["delta"] = deltaMap
										modified = true
									} else if tracker.domainFail {
										tailOnly := stripDomainTail(partialJSON)
										if tailOnly != partialJSON {
											deltaMap["partial_json"] = tailOnly
											eventObj["delta"] = deltaMap
											modified = true
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

	// 3. Ollama / Custom SSE formats: message.content, response, or token fields
	if msgMap, ok := eventObj["message"].(map[string]any); ok {
		if tokenStr, ok := msgMap["content"].(string); ok && tokenStr != "" {
			safeText, shouldEmit := s.inspectStreamFragment(tokenStr)
			if s.halted {
				return
			}
			if !isShadow && (!shouldEmit || safeText != tokenStr) {
				msgMap["content"] = safeText
				eventObj["message"] = msgMap
				modified = true
			}
		}
		if rawTools, ok := msgMap["tool_calls"].([]any); ok && len(rawTools) > 0 {
			keptTools, toolCodes, pruned := guards.SanitizeToolCallsSlice(rawTools, s.cfg.Whitelist, isShadow)
			s.prunedTools += pruned
			for _, c := range toolCodes {
				s.recordCode(c)
			}
			if !isShadow && (pruned > 0 || len(toolCodes) > 0) {
				modified = true
				if len(keptTools) > 0 {
					msgMap["tool_calls"] = keptTools
				} else {
					delete(msgMap, "tool_calls")
				}
				eventObj["message"] = msgMap
			}
		}
	}
	if rawTools, ok := eventObj["tool_calls"].([]any); ok && len(rawTools) > 0 {
		keptTools, toolCodes, pruned := guards.SanitizeToolCallsSlice(rawTools, s.cfg.Whitelist, isShadow)
		s.prunedTools += pruned
		for _, c := range toolCodes {
			s.recordCode(c)
		}
		if !isShadow && (pruned > 0 || len(toolCodes) > 0) {
			modified = true
			if len(keptTools) > 0 {
				eventObj["tool_calls"] = keptTools
			} else {
				delete(eventObj, "tool_calls")
			}
		}
	}
	for _, topField := range []string{"response", "token", "text"} {
		if tokenStr, ok := eventObj[topField].(string); ok && tokenStr != "" {
			safeText, shouldEmit := s.inspectStreamFragment(tokenStr)
			if s.halted {
				return
			}
			if !isShadow && (!shouldEmit || safeText != tokenStr) {
				eventObj[topField] = safeText
				modified = true
			}
		}
	}

	if modified {
		if encoded, err := json.Marshal(eventObj); err == nil {
			if isNDJSON {
				s.outBuf.Write(encoded)
				s.outBuf.WriteByte('\n')
			} else {
				s.outBuf.WriteString("data: ")
				s.outBuf.Write(encoded)
				s.outBuf.WriteByte('\n')
			}
			return
		}
	}

	s.outBuf.WriteString(line)
}

// inspectStreamFragment combines the incoming token with the Rune-Aware Holdback Window
// so split tokens (PII Vault tokens, Canary markers, Markdown image trackers) across chunk boundaries are caught.
func (s *SSEInspector) inspectStreamFragment(fragment string) (string, bool) {
	rawBytes := append(s.utf8Rem, []byte(fragment)...)
	validBytes, remBytes := splitCompleteUTF8(rawBytes)
	s.utf8Rem = nil
	if len(remBytes) > 0 {
		s.utf8Rem = bytes.Clone(remBytes)
	}

	combined := s.holdback + string(validBytes)
	s.holdback = ""

	cleaned, codes, leaked := guards.SanitizeOutputTextWithSession(s.sessionID, combined, s.canaryToken, s.cfg, s.vault)
	for _, c := range codes {
		s.recordCode(c)
	}
	if leaked {
		s.haltOnCanaryLeak()
		return "", false
	}

	maxWindowRunes := s.cfg.Guards.OutputSanitizer.SlidingWindowRunes
	if maxWindowRunes <= 0 {
		maxWindowRunes = 64
	}

	safeEmit, hold := splitHoldbackSuffix(cleaned, s.canaryToken, maxWindowRunes)
	s.holdback = hold

	return safeEmit, true
}

func (s *SSEInspector) haltOnCanaryLeak() {
	s.halted = true
	s.status = "BLOCKED"
	s.severity = "INTRUSION_ALERT"

	lang := ""
	if s.cfg != nil {
		lang = strings.TrimSpace(s.cfg.Core.Language)
	}
	if strings.EqualFold(lang, "pt-BR") || strings.EqualFold(lang, "pt") {
		s.emitSyntheticDeltaChunk("[CONTEÚDO RESTRITO: Vazamento de System Prompt Interrompido (JG-SEC-501)]")
	} else {
		s.emitSyntheticDeltaChunk("[RESTRICTED CONTENT: System Prompt Leak Halted (JG-SEC-501)]")
	}

	s.emitWarningEventIfNeeded()
	if !s.isNDJSON {
		s.outBuf.WriteString("data: [DONE]\n\n")
	}
	s.populateTrailers()
	s.reportCompletion()
}

func (s *SSEInspector) emitSyntheticDeltaChunk(text string) {
	if s.isNDJSON {
		chunk := map[string]any{
			"response": text,
			"done":     s.halted,
		}
		if b, err := json.Marshal(chunk); err == nil {
			s.outBuf.Write(b)
			s.outBuf.WriteByte('\n')
		}
		return
	}
	if s.isAnthropic {
		chunk := map[string]any{
			"type":  "content_block_delta",
			"index": 0,
			"delta": map[string]any{
				"type": "text_delta",
				"text": text,
			},
		}
		if b, err := json.Marshal(chunk); err == nil {
			s.outBuf.WriteString("data: ")
			s.outBuf.Write(b)
			s.outBuf.WriteString("\n\n")
		}
		return
	}
	chunk := map[string]any{
		"choices": []any{
			map[string]any{
				"index": 0,
				"delta": map[string]any{"content": text},
			},
		},
	}
	if b, err := json.Marshal(chunk); err == nil {
		s.outBuf.WriteString("data: ")
		s.outBuf.Write(b)
		s.outBuf.WriteString("\n\n")
	}
}

func (s *SSEInspector) emitWarningEventIfNeeded() {
	if len(s.codes) == 0 || !s.cfg.Telemetry.WarningFlags.EmitSSEWarningEvent {
		return
	}
	if s.status == "CLEAN" {
		if s.cfg.Core.Mode == "shadow" {
			s.status = "SHADOW_FLAGGED"
		} else {
			s.status = "SANITIZED"
		}
	}
	warnPayload := map[string]any{
		"status":       s.status,
		"severity":     s.severity,
		"codes":        s.codes,
		"pruned_tools": s.prunedTools,
	}
	if s.isNDJSON {
		ndjsonWarn := map[string]any{"warning": warnPayload}
		if b, err := json.Marshal(ndjsonWarn); err == nil {
			s.outBuf.Write(b)
			s.outBuf.WriteByte('\n')
		}
		return
	}
	if b, err := json.Marshal(warnPayload); err == nil {
		s.outBuf.WriteString("event: jaguargate.warning\ndata: ")
		s.outBuf.Write(b)
		s.outBuf.WriteString("\n\n")
	}
}

func (s *SSEInspector) finalizeStream() {
	if s.holdback != "" && !s.halted {
		cleaned, codes, leaked := guards.SanitizeOutputTextWithSession(s.sessionID, s.holdback, s.canaryToken, s.cfg, s.vault)
		s.holdback = ""
		for _, c := range codes {
			s.recordCode(c)
		}
		if leaked {
			s.haltOnCanaryLeak()
			return
		}
		if cleaned != "" {
			s.emitSyntheticDeltaChunk(cleaned)
		}
	}
	s.populateTrailers()
	s.reportCompletion()
}

func (s *SSEInspector) reportCompletion() {
	if s.reported {
		return
	}
	s.reported = true
	if len(s.codes) > 0 && s.status == "CLEAN" {
		if s.cfg != nil && s.cfg.Core.Mode == "shadow" {
			s.status = "SHADOW_FLAGGED"
		} else {
			s.status = "SANITIZED"
		}
	}
	if s.onComplete != nil {
		s.onComplete(s.status, s.severity, s.codes, s.prunedTools)
	}
}

func (s *SSEInspector) populateTrailers() {
	if s.trailers == nil || !s.cfg.Telemetry.WarningFlags.EmitHTTPTrailersOnStream {
		return
	}
	if len(s.codes) > 0 && s.status == "CLEAN" {
		if s.cfg.Core.Mode == "shadow" {
			s.status = "SHADOW_FLAGGED"
		} else {
			s.status = "SANITIZED"
		}
	}
	s.trailers.Set("X-JaguarGate-Status", s.status)
	s.trailers.Set("X-JaguarGate-Severity", s.severity)
	if len(s.codes) > 0 {
		s.trailers.Set("X-JaguarGate-Codes", strings.Join(s.codes, ","))
	}
	if s.prunedTools > 0 {
		s.trailers.Set("X-JaguarGate-Pruned-Count", strconv.Itoa(s.prunedTools))
	}
}

func (s *SSEInspector) recordCode(code string) {
	if code == "" {
		return
	}
	if !slices.Contains(s.codes, code) {
		s.codes = append(s.codes, code)
	}
	if strings.HasPrefix(code, "JG-SEC-") {
		s.severity = "INTRUSION_ALERT"
	} else if s.severity == "" || s.severity == "NONE" {
		s.severity = "CONFIG_WARNING"
	}
}

// splitCompleteUTF8 separates complete UTF-8 runes from any trailing incomplete multi-byte sequence.
func splitCompleteUTF8(b []byte) ([]byte, []byte) {
	if utf8.Valid(b) {
		return b, nil
	}
	for i := 1; i <= 3 && i <= len(b); i++ {
		idx := len(b) - i
		if utf8.Valid(b[:idx]) {
			return b[:idx], b[idx:]
		}
	}
	return b, nil
}

// splitHoldbackSuffix checks if the tail of a rune slice contains a partially opened pattern
// that hasn't closed yet, holding it back for the next SSE chunk.
func splitHoldbackSuffix(text, canary string, maxRunes int) (string, string) {
	if text == "" {
		return "", ""
	}
	runes := []rune(text)
	windowStart := 0
	if len(runes) > maxRunes {
		windowStart = len(runes) - maxRunes
	}
	tail := string(runes[windowStart:])

	triggers := []struct {
		open  string
		close string
	}{
		{piiOpenPrefix, "\x3e"},
		{"\x3c", "\x3e"},
		{"[JG-CANARY:", "]"},
		{"![", ")"},
	}

	earliestHoldIdx := -1
	for _, tr := range triggers {
		lastOpen := strings.LastIndex(tail, tr.open)
		if lastOpen != -1 {
			afterOpen := tail[lastOpen+len(tr.open):]
			if !strings.Contains(afterOpen, tr.close) {
				if earliestHoldIdx == -1 || lastOpen < earliestHoldIdx {
					earliestHoldIdx = lastOpen
				}
			}
		}
	}

	// Also hold back any partial prefix of open markers (even 1-2 chars like "!" of "![" or "[" of "[JG-CANARY:")
	partialPrefixes := []string{piiOpenPrefix, "[JG-CANARY:", "!["}
	for _, pref := range partialPrefixes {
		maxP := min(len(pref)-1, len(tail))
		for k := maxP; k >= 1; k-- {
			if strings.HasSuffix(tail, pref[:k]) {
				idx := len(tail) - k
				if earliestHoldIdx == -1 || idx < earliestHoldIdx {
					earliestHoldIdx = idx
				}
				break
			}
		}
	}

	if canary != "" {
		maxK := min(len(canary)-1, len(tail))
		for k := maxK; k >= 1; k-- {
			if strings.HasSuffix(tail, canary[:k]) {
				idx := len(tail) - k
				if earliestHoldIdx == -1 || idx < earliestHoldIdx {
					earliestHoldIdx = idx
				}
				break
			}
		}
	}

	if earliestHoldIdx == -1 {
		return text, ""
	}

	prefixHead := string(runes[:windowStart])
	safeTail := tail[:earliestHoldIdx]
	holdPart := tail[earliestHoldIdx:]

	return prefixHead + safeTail, holdPart
}

func stripDomainTail(fragment string) string {
	idx := strings.IndexAny(fragment, "\"' ,}]")
	if idx == -1 {
		return ""
	}
	return fragment[idx:]
}
