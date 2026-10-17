package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jaguargate/jaguargate/internal/config"
	"github.com/jaguargate/jaguargate/internal/guards"
	"github.com/jaguargate/jaguargate/internal/state"
	"github.com/jaguargate/jaguargate/internal/telemetry"
)

// MCPInspectionResult summarizes all actions taken on a JSON-RPC 2.0 MCP payload.
type MCPInspectionResult struct {
	ModifiedBody []byte
	Status       string
	Severity     string
	Codes        []string
	PrunedCount  int
	Blocked      bool
}

// Inspector enforces JaguarGate guardrails over Model Context Protocol (MCP) JSON-RPC 2.0 traffic.
type Inspector struct {
	engine  *guards.Engine
	breaker *state.CircuitBreaker
}

// NewInspector creates an MCP protocol inspector connected to the OWASP Engine and CircuitBreaker.
func NewInspector(engine *guards.Engine, breaker *state.CircuitBreaker) *Inspector {
	return &Inspector{
		engine:  engine,
		breaker: breaker,
	}
}

// IsJSONRPCPayload quickly checks if a JSON body represents a JSON-RPC 2.0 single or batch message.
func IsJSONRPCPayload(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 10 {
		return false
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return false
	}
	return bytes.Contains(trimmed, []byte(`"jsonrpc"`))
}

// InspectPayload processes an incoming or outgoing MCP JSON-RPC 2.0 message (single object or batch array).
func (ins *Inspector) InspectPayload(body []byte, sessionID, mcpServerHeader string, cfg *config.Config) MCPInspectionResult {
	res := MCPInspectionResult{
		ModifiedBody: body,
		Status:       "CLEAN",
		Severity:     "NONE",
	}

	if !cfg.Network.MCP.Enabled || len(body) == 0 {
		return res
	}

	isShadow := cfg.Core.Mode == "shadow"

	// 1. Validate MCP Target Server Whitelist (JG-CFG-102) if configured
	if len(cfg.Whitelist.AllowedMCPServers) > 0 && mcpServerHeader != "" {
		if !isMCPServerAllowed(mcpServerHeader, cfg.Whitelist.AllowedMCPServers) {
			res.addCode("JG-CFG-102", false)
		}
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return res
	}

	// 2. Check if JSON-RPC Batch Array ([{...}, {...}])
	if trimmed[0] == '[' {
		var batch []map[string]any
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return res
		}

		maxBatch := cfg.Network.MCP.MaxRPCBatchSize
		if maxBatch <= 0 {
			maxBatch = 20
		}

		modified := false
		if len(batch) > maxBatch {
			res.addCode("JG-CFG-202", false)
			if !isShadow {
				batch = batch[:maxBatch]
				modified = true
			}
		}

		keptBatch := make([]map[string]any, 0, len(batch))
		for _, item := range batch {
			mutated, dropItem := ins.inspectSingleRPCObject(item, sessionID, cfg, &res)
			if mutated {
				modified = true
			}
			if dropItem && !isShadow {
				modified = true
				continue
			}
			keptBatch = append(keptBatch, item)
		}

		res.finalize(cfg.Core.Mode)
		if modified && !isShadow && !res.Blocked {
			if b, err := marshalUnescaped(keptBatch); err == nil {
				res.ModifiedBody = b
			}
		}
		return res
	}

	// 3. Single JSON-RPC Object ({...})
	var rpcObj map[string]any
	if err := json.Unmarshal(trimmed, &rpcObj); err != nil {
		return res
	}

	modified, dropItem := ins.inspectSingleRPCObject(rpcObj, sessionID, cfg, &res)
	if dropItem && !isShadow {
		rpcObj["error"] = map[string]any{
			"code":    -32600,
			"message": "JaguarGate: MCP tool or server call omitted by security policy",
			"data":    res.Codes,
		}
		delete(rpcObj, "method")
		delete(rpcObj, "params")
		modified = true
	}

	res.finalize(cfg.Core.Mode)
	if modified && !isShadow && !res.Blocked {
		if b, err := marshalUnescaped(rpcObj); err == nil {
			res.ModifiedBody = b
		}
	}

	return res
}

func (ins *Inspector) inspectSingleRPCObject(rpcObj map[string]any, sessionID string, cfg *config.Config, res *MCPInspectionResult) (bool, bool) {
	isShadow := cfg.Core.Mode == "shadow"
	modified := false

	method, _ := rpcObj["method"].(string)
	params, hasParams := rpcObj["params"].(map[string]any)

	if hasParams && len(cfg.Whitelist.AllowedMCPServers) > 0 {
		if srvName, ok := params["server"].(string); ok && srvName != "" {
			if !isMCPServerAllowed(srvName, cfg.Whitelist.AllowedMCPServers) {
				res.addCode("JG-CFG-102", false)
				res.PrunedCount++
				return true, true
			}
		}
	}

	// A. Inspect MCP Request: "tools/call"
	if method == "tools/call" && hasParams {
		toolName, _ := params["name"].(string)
		if cfg.Whitelist.EnforceToolWhitelist && toolName != "" {
			if !isMCPToolAllowed(toolName, cfg.Whitelist.AllowedTools) {
				res.addCode("JG-CFG-101", false)
				res.PrunedCount++
				return true, true
			}
		}

		if rawArgs, ok := params["arguments"]; ok {
			argsBytes, _ := marshalUnescaped(rawArgs)
			argsStr := string(argsBytes)

			if ins.breaker != nil && ins.breaker.CheckToolCallLoop(sessionID, toolName, argsStr, cfg.Whitelist.CircuitBreaker) {
				res.addCode("JG-CFG-201", false)
				res.PrunedCount++
				return true, true
			}

			inspRes := ins.engine.InspectJSONPayload(argsBytes, cfg)
			for _, c := range inspRes.Codes {
				res.addCode(c, inspRes.Severity == "INTRUSION_ALERT")
			}
			if !isShadow && !bytes.Equal(inspRes.ModifiedBody, argsBytes) {
				var cleanedArgs any
				if err := json.Unmarshal(inspRes.ModifiedBody, &cleanedArgs); err == nil {
					params["arguments"] = cleanedArgs
					rpcObj["params"] = params
					modified = true
				}
			}
		}
	}

	// B. Inspect MCP Response / External Resource Content ("result.content" or "result.contents")
	if resultObj, ok := rpcObj["result"].(map[string]any); ok && cfg.Network.MCP.SanitizeExternalResources {
		if contents, ok := resultObj["contents"].([]any); ok {
			if ins.sanitizeMCPContentArray(contents, cfg, res) {
				resultObj["contents"] = contents
				rpcObj["result"] = resultObj
				modified = true
			}
		}
		if content, ok := resultObj["content"].([]any); ok {
			if ins.sanitizeMCPContentArray(content, cfg, res) {
				resultObj["content"] = content
				rpcObj["result"] = resultObj
				modified = true
			}
		}
	}

	return modified, false
}

func (ins *Inspector) sanitizeMCPContentArray(items []any, cfg *config.Config, res *MCPInspectionResult) bool {
	isShadow := cfg.Core.Mode == "shadow"
	modified := false

	for i, item := range items {
		itemMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		txt, ok := itemMap["text"].(string)
		if !ok || txt == "" {
			continue
		}

		// Wrap external MCP resource as a "tool" role message to trigger OWASP Injection check, PII Vault & Spotlighting
		syntheticPayload := map[string]any{
			"messages": []any{
				map[string]any{"role": "tool", "content": txt},
			},
		}
		rawBytes, _ := marshalUnescaped(syntheticPayload)
		insp := ins.engine.InspectJSONPayload(rawBytes, cfg)
		for _, c := range insp.Codes {
			res.addCode(c, insp.Severity == "INTRUSION_ALERT")
		}

		if !isShadow {
			var parsed map[string]any
			if err := json.Unmarshal(insp.ModifiedBody, &parsed); err == nil {
				if msgs, ok := parsed["messages"].([]any); ok {
					// Locate the "tool" role message specifically (since auto-injected Canary may occupy index 0)
					for _, mItem := range msgs {
						if mMap, ok := mItem.(map[string]any); ok && mMap["role"] == "tool" {
							if cleanedTxt, ok := mMap["content"].(string); ok && cleanedTxt != txt {
								itemMap["text"] = cleanedTxt
								items[i] = itemMap
								modified = true
							}
							break
						}
					}
				}
			}
		}
	}
	return modified
}

func (r *MCPInspectionResult) addCode(code string, isIntrusion bool) {
	if code == "" {
		return
	}
	if !slices.Contains(r.Codes, code) {
		r.Codes = append(r.Codes, code)
	}
	if isIntrusion || strings.HasPrefix(code, "JG-SEC-") {
		r.Severity = "INTRUSION_ALERT"
	} else if r.Severity == "" || r.Severity == "NONE" {
		r.Severity = "CONFIG_WARNING"
	}
}

func (r *MCPInspectionResult) finalize(mode string) {
	if len(r.Codes) == 0 {
		r.Status = "CLEAN"
		r.Severity = "NONE"
		return
	}
	switch mode {
	case "shadow":
		r.Status = "SHADOW_FLAGGED"
		r.Blocked = false
	case "hard_block":
		if r.Severity == "INTRUSION_ALERT" {
			r.Status = "BLOCKED"
			r.Blocked = true
		} else {
			r.Status = "SANITIZED"
			r.Blocked = false
		}
	default:
		r.Status = "SANITIZED"
		r.Blocked = false
	}
}

func isMCPServerAllowed(server string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(server)) {
			return true
		}
	}
	return false
}

func isMCPToolAllowed(tool string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(tool)) {
			return true
		}
	}
	return false
}

func marshalUnescaped(v any) ([]byte, error) {
	buf := telemetry.AcquireBuffer()
	defer telemetry.ReleaseBuffer(buf)

	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode json: %w", err)
	}
	raw := buf.Bytes()
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
	}
	return bytes.Clone(raw), nil
}
