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

	"github.com/jaguargate/jaguargate/internal/config"
	"github.com/jaguargate/jaguargate/internal/guards"
)

const piiOpenPrefix = "\x3cJG_PII_"

// SSEInspector wraps an upstream HTTP response body (io.ReadCloser) to inspect Server-Sent Events
// in real time using a Rune-Aware UTF-8 Sliding Holdback Window.
type SSEInspector struct {
	upstream    io.ReadCloser
	cfg         *config.Config
	vault       *guards.PIIVault
	canaryToken string
	trailers    http.Header

	rawBuf      bytes.Buffer
	outBuf      bytes.Buffer
	holdback    string // Rune-safe holdback buffer for cross-chunk tokens
	utf8Rem     []byte // Holds incomplete multi-byte UTF-8 sequences split across TCP reads
	codes       []string
	status      string
	severity    string
	prunedTools int
	halted      bool
	eofReached  bool
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
	return &SSEInspector{
		upstream:    upstream,
		cfg:         cfg,
		vault:       vault,
		canaryToken: inbound.CanaryToken,
		trailers:    trailers,
		codes:       slices.Clone(inbound.Codes),
		status:      status,
		severity:    severity,
		prunedTools: inbound.PrunedTools,
	}
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

// Close closes the underlying upstream body.
func (s *SSEInspector) Close() error {
	return s.upstream.Close()
}

func (s *SSEInspector) processAvailableLines(flushAll bool) {
	for !s.halted {
		data := s.rawBuf.Bytes()
		nlIdx := bytes.IndexByte(data, '\n')
		if nlIdx == -1 {
			if flushAll && len(data) > 0 {
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

	// Pass through empty keep-alive lines and SSE comments
	if trimmed == "" || !strings.HasPrefix(trimmed, "data:") {
		s.outBuf.WriteString(line)
		return
	}

	payloadStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))

	// Check for stream completion marker: data: [DONE]
	if payloadStr == "[DONE]" {
		if s.holdback != "" && !s.halted {
			cleaned, codes, leaked := guards.SanitizeOutputText(s.holdback, s.canaryToken, s.cfg, s.vault)
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

		s.emitWarningEventIfNeeded()
		s.outBuf.WriteString(line)
		return
	}

	// Parse JSON delta chunk (OpenAI / Ollama / LiteLLM SSE format)
	var eventObj map[string]any
	if err := json.Unmarshal([]byte(payloadStr), &eventObj); err != nil {
		outText, shouldEmit := s.inspectStreamFragment(payloadStr)
		if s.halted {
			return
		}
		if shouldEmit {
			s.outBuf.WriteString("data: ")
			s.outBuf.WriteString(outText)
			s.outBuf.WriteByte('\n')
		}
		return
	}

	isShadow := s.cfg.Core.Mode == "shadow"
	modified := false

	if choices, ok := eventObj["choices"].([]any); ok {
		for i, chItem := range choices {
			chMap, ok := chItem.(map[string]any)
			if !ok {
				continue
			}
			if deltaMap, ok := chMap["delta"].(map[string]any); ok {
				// 1. Inspect streaming token text inside delta.content
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

				// 2. Inspect streaming delta.tool_calls against whitelist
				if rawTools, ok := deltaMap["tool_calls"].([]any); ok && len(rawTools) > 0 && s.cfg.Whitelist.EnforceToolWhitelist {
					keptTools, toolCodes, pruned := guards.SanitizeToolCallsSlice(rawTools, s.cfg.Whitelist, isShadow)
					s.prunedTools += pruned
					for _, c := range toolCodes {
						s.recordCode(c)
					}
					if !isShadow && pruned > 0 {
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

	if modified {
		if encoded, err := json.Marshal(eventObj); err == nil {
			s.outBuf.WriteString("data: ")
			s.outBuf.Write(encoded)
			s.outBuf.WriteByte('\n')
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

	cleaned, codes, leaked := guards.SanitizeOutputText(combined, s.canaryToken, s.cfg, s.vault)
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
	s.outBuf.WriteString("data: [DONE]\n\n")
	s.populateTrailers()
}

func (s *SSEInspector) emitSyntheticDeltaChunk(text string) {
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
	if b, err := json.Marshal(warnPayload); err == nil {
		s.outBuf.WriteString("event: jaguargate.warning\ndata: ")
		s.outBuf.Write(b)
		s.outBuf.WriteString("\n\n")
	}
}

func (s *SSEInspector) finalizeStream() {
	if s.holdback != "" && !s.halted {
		cleaned, codes, leaked := guards.SanitizeOutputText(s.holdback, s.canaryToken, s.cfg, s.vault)
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

	if canary != "" {
		maxK := min(len(canary)-1, len(tail))
		for k := maxK; k >= 3; k-- {
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
