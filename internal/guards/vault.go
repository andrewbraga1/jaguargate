package guards

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

var customRegexCache sync.Map

func getOrCompileRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := customRegexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	customRegexCache.Store(pattern, re)
	return re, nil
}

func resolvePattern(override string, fallback *regexp.Regexp) *regexp.Regexp {
	trimmed := strings.TrimSpace(override)
	if trimmed == "" {
		return fallback
	}
	re, err := getOrCompileRegex(trimmed)
	if err != nil {
		return fallback
	}
	return re
}

func sanitizeLabel(name string) string {
	name = strings.ToUpper(strings.TrimSpace(name))
	if name == "" {
		return "CUSTOM"
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "CUSTOM"
	}
	return b.String()
}

const maxVaultEntries = 16384

// ExternalKV allows PIIVault to replicate masked tokens into the Stage 4 Hybrid L1/L2 State Store.
type ExternalKV interface {
	Set(key, value string, ttl time.Duration) (string, error)
	Get(key string) (string, string, error)
}

type vaultEntry struct {
	sessionID     string
	originalValue string
	entityType    string
	isSecret      bool
	expiresAt     time.Time
}

// vaultEnvelope is the structured payload persisted in the L2 ExternalKV (Redis)
// so that secret classification and entity metadata survive restarts and failovers.
type vaultEnvelope struct {
	SessionID     string `json:"s"`
	OriginalValue string `json:"v"`
	IsSecret      bool   `json:"sec"`
	EntityType    string `json:"t,omitempty"`
}

// PIIVault provides a concurrency-safe, reversible masking store with optional L2 Redis backing.
type PIIVault struct {
	mu       sync.RWMutex
	entries  map[string]vaultEntry
	extStore ExternalKV
}

// NewPIIVault creates an initialized local PII masking vault.
func NewPIIVault() *PIIVault {
	return &PIIVault{
		entries: make(map[string]vaultEntry, 256),
	}
}

// SetExternalStore attaches an optional Stage 4 HybridStore (L1/L2 Redis with AES-GCM).
func (v *PIIVault) SetExternalStore(store ExternalKV) {
	v.mu.Lock()
	v.extStore = store
	v.mu.Unlock()
}

// MaskText replaces configured PII and secret entities with reversible tokens under the default session scope.
func (v *PIIVault) MaskText(input string, cfg config.PIIVaultConfig, redactOnly bool) (string, []string, int) {
	return v.MaskTextWithSession("default_session", input, cfg, redactOnly)
}

// MaskTextWithSession replaces configured PII and secret entities with 128-bit session-bound tokens.
func (v *PIIVault) MaskTextWithSession(sessionID, input string, cfg config.PIIVaultConfig, redactOnly bool) (string, []string, int) {
	if !cfg.Enabled || input == "" {
		return input, nil, 0
	}
	if sessionID == "" {
		sessionID = "default_session"
	}

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	out := input
	maskedCount := 0
	hasPII := false
	hasSecret := false
	var extraCodes []string

	replaceEntity := func(re *regexp.Regexp, label string, isSecret bool, validator func(string) bool) {
		out = re.ReplaceAllStringFunc(out, func(match string) string {
			if validator != nil && !validator(match) {
				return match
			}
			maskedCount++
			if isSecret {
				hasSecret = true
			} else {
				hasPII = true
			}
			if redactOnly {
				return match
			}
			token, warnCode := v.storeValue(sessionID, label, match, isSecret, ttl)
			if warnCode != "" && !slices.Contains(extraCodes, warnCode) {
				extraCodes = append(extraCodes, warnCode)
			}
			return token
		})
	}

	// Evaluate declarative built-in detector catalog in priority order (Secrets -> Numeric/Text PII)
	for _, spec := range builtinEntityDetectors {
		if !spec.Enabled(cfg.Entities) {
			continue
		}
		overrideStr := strings.TrimSpace(spec.Override(cfg.PatternOverrides))
		if spec.SkipOnOverride && overrideStr != "" {
			continue
		}
		re := resolvePattern(overrideStr, spec.DefaultRegex)
		var validator func(string) bool
		if overrideStr == "" {
			validator = spec.Validator
		}
		replaceEntity(re, spec.Label, spec.IsSecret, validator)
	}

	for _, cp := range cfg.CustomPatterns {
		if !cp.IsEnabled() || strings.TrimSpace(cp.Regex) == "" {
			continue
		}
		re, err := getOrCompileRegex(cp.Regex)
		if err != nil {
			continue
		}
		label := sanitizeLabel(cp.Name)
		replaceEntity(re, label, cp.IsSecret, nil)
	}

	var codes []string
	if hasPII {
		codes = append(codes, "JG-PII-301")
	}
	if hasSecret {
		codes = append(codes, "JG-PII-302")
	}
	codes = append(codes, extraCodes...)

	return out, codes, maskedCount
}

// RestoreText replaces any active non-secret PII tokens in the model output belonging to the default session.
// Secrets (isSecret=true) are NOT restored by default.
func (v *PIIVault) RestoreText(output string) string {
	return v.RestoreTextWithOptions("default_session", output, false)
}

// RestoreTextWithSession replaces active non-secret PII tokens in the model output ONLY if they belong to the given sessionID.
// Secrets (isSecret=true) are NOT restored by default.
func (v *PIIVault) RestoreTextWithSession(sessionID, output string) string {
	return v.RestoreTextWithOptions(sessionID, output, false)
}

// RestoreTextWithOptions replaces active tokens belonging to sessionID, respecting the restoreSecrets policy.
// When restoreSecrets is false (the secure default), entries marked isSecret=true remain masked even if echoed by the LLM.
func (v *PIIVault) RestoreTextWithOptions(sessionID, output string, restoreSecrets bool) string {
	return v.restoreInternal(sessionID, output, restoreSecrets, false)
}

// RestoreTextJSONSafeWithOptions restores active tokens inside a raw JSON string stream (e.g. SSE tool arguments),
// JSON-escaping only the substituted PII value so surrounding JSON structure remains valid.
func (v *PIIVault) RestoreTextJSONSafeWithOptions(sessionID, output string, restoreSecrets bool) string {
	return v.restoreInternal(sessionID, output, restoreSecrets, true)
}

func (v *PIIVault) restoreInternal(sessionID, output string, restoreSecrets, jsonEscapeVal bool) string {
	if output == "" {
		return ""
	}
	if sessionID == "" {
		sessionID = "default_session"
	}
	formatVal := func(val string) string {
		if !jsonEscapeVal {
			return val
		}
		if b, err := json.Marshal(val); err == nil && len(b) >= 2 {
			return string(b[1 : len(b)-1])
		}
		return val
	}
	now := time.Now()
	return reVaultToken.ReplaceAllStringFunc(output, func(token string) string {
		v.mu.RLock()
		entry, exists := v.entries[token]
		ext := v.extStore
		v.mu.RUnlock()

		if exists && now.Before(entry.expiresAt) {
			if entry.sessionID != sessionID {
				return token
			}
			if entry.isSecret && !restoreSecrets {
				return token
			}
			return formatVal(entry.originalValue)
		}

		if ext != nil {
			if val, _, err := ext.Get(token); err == nil && val != "" {
				if env, ok := decodeVaultEnvelope(token, val); ok {
					if env.SessionID != sessionID {
						return token
					}
					if env.IsSecret && !restoreSecrets {
						return token
					}
					return formatVal(env.OriginalValue)
				}
			}
		}
		return token
	})
}

func (v *PIIVault) storeValue(sessionID, label, rawValue string, isSecret bool, ttl time.Duration) (string, string) {
	v.mu.Lock()
	var token string
	for range 8 {
		var randBytes [16]byte
		_, _ = rand.Read(randBytes[:])
		candidate := fmt.Sprintf("\x3cJG_PII_%s_%s\x3e", label, hex.EncodeToString(randBytes[:]))
		if _, collision := v.entries[candidate]; !collision {
			token = candidate
			break
		}
	}

	now := time.Now()
	if len(v.entries) >= 4096 {
		for k, e := range v.entries {
			if now.After(e.expiresAt) {
				delete(v.entries, k)
			}
		}
		if len(v.entries) >= maxVaultEntries {
			var oldestKey string
			var oldestTime time.Time
			for k, e := range v.entries {
				if oldestKey == "" || e.expiresAt.Before(oldestTime) {
					oldestKey = k
					oldestTime = e.expiresAt
				}
			}
			if oldestKey != "" {
				delete(v.entries, oldestKey)
			}
		}
	}

	v.entries[token] = vaultEntry{
		sessionID:     sessionID,
		originalValue: rawValue,
		entityType:    label,
		isSecret:      isSecret,
		expiresAt:     now.Add(ttl),
	}
	ext := v.extStore
	v.mu.Unlock()

	warnCode := ""
	if ext != nil {
		env := vaultEnvelope{
			SessionID:     sessionID,
			OriginalValue: rawValue,
			IsSecret:      isSecret,
			EntityType:    label,
		}
		if envBytes, err := json.Marshal(env); err == nil {
			warnCode, _ = ext.Set(token, string(envBytes), ttl)
		}
	}

	return token, warnCode
}

func decodeVaultEnvelope(token, stored string) (vaultEnvelope, bool) {
	if strings.HasPrefix(stored, "{") {
		var env vaultEnvelope
		if err := json.Unmarshal([]byte(stored), &env); err == nil && env.SessionID != "" {
			return env, true
		}
	}
	// Legacy fallback ("sessionID\x00rawValue") lacks reliable IsSecret metadata:
	// fail-closed (IsSecret=true) for ALL legacy records so unclassified or custom secret
	// tokens persisted before upgrade are never restored by default.
	ownerSess, rawVal, ok := splitSessionBoundValue(stored)
	if !ok {
		return vaultEnvelope{}, false
	}
	_ = token
	return vaultEnvelope{
		SessionID:     ownerSess,
		OriginalValue: rawVal,
		IsSecret:      true,
	}, true
}

func splitSessionBoundValue(stored string) (string, string, bool) {
	for i := 0; i < len(stored); i++ {
		if stored[i] == 0 {
			return stored[:i], stored[i+1:], true
		}
	}
	return "default_session", stored, true
}

// isValidCPFMod11 validates an 11-digit Brazilian CPF using the official Modulo 11 checksum algorithm.
func isValidCPFMod11(raw string) bool {
	if len(raw) != 11 {
		return false
	}
	allEqual := true
	for i := 0; i < 11; i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return false
		}
		if raw[i] != raw[0] {
			allEqual = false
		}
	}
	if allEqual {
		return false
	}

	sum1 := 0
	for i := 0; i < 9; i++ {
		sum1 += int(raw[i]-'0') * (10 - i)
	}
	d1 := (sum1 * 10) % 11
	if d1 == 10 {
		d1 = 0
	}
	if d1 != int(raw[9]-'0') {
		return false
	}

	sum2 := 0
	for i := 0; i < 10; i++ {
		sum2 += int(raw[i]-'0') * (11 - i)
	}
	d2 := (sum2 * 10) % 11
	if d2 == 10 {
		d2 = 0
	}
	return d2 == int(raw[10]-'0')
}

// isValidLuhn validates a 13-to-19 digit payment card number using the Luhn checksum algorithm.
func isValidLuhn(raw string) bool {
	var digits [19]int
	n := 0
	allZero := true
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == ' ' || ch == '-' {
			continue
		}
		if ch < '0' || ch > '9' {
			return false
		}
		if n >= 19 {
			return false
		}
		d := int(ch - '0')
		if d != 0 {
			allZero = false
		}
		digits[n] = d
		n++
	}
	if n < 13 || n > 19 || allZero {
		return false
	}

	sum := 0
	double := false
	for i := n - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// RedactSecretsInText performs active output DLP scanning for spontaneous/unmapped secrets
// emitted by the LLM (AWS keys, API secrets, JWTs, private key headers, and custom is_secret patterns).
func RedactSecretsInText(text string, cfg config.PIIVaultConfig, replacement string) (string, bool) {
	if !cfg.Enabled || text == "" {
		return text, false
	}

	out := text
	found := false

	apply := func(re *regexp.Regexp) {
		if re != nil && re.MatchString(out) {
			found = true
			if replacement != "" {
				out = re.ReplaceAllString(out, replacement)
			}
		}
	}

	// Apply all active secret detectors from the unified declarative catalog
	for _, spec := range builtinEntityDetectors {
		if !spec.IsSecret || !spec.Enabled(cfg.Entities) {
			continue
		}
		apply(resolvePattern(spec.Override(cfg.PatternOverrides), spec.DefaultRegex))
	}

	for _, cp := range cfg.CustomPatterns {
		if !cp.IsEnabled() || !cp.IsSecret || strings.TrimSpace(cp.Regex) == "" {
			continue
		}
		if re, err := getOrCompileRegex(cp.Regex); err == nil {
			apply(re)
		}
	}

	return out, found
}

// PEMStreamState maintains stateful PEM block suppression across arbitrarily many SSE/NDJSON chunks,
// including split "-----END ... PRIVATE KEY-----" footers and unclosed EOF streams.
type PEMStreamState struct {
	Active bool
	Tail   string
}

// StripStreamingPEM enforces stateful PEM private-key suppression across arbitrarily many
// streaming SSE/NDJSON chunks (independent of sliding window size, including unclosed EOF keys).
// When inJSONString is true, an unescaped '"' closes the JSON string field without swallowing
// the surrounding JSON delimiter structure.
func StripStreamingPEM(text string, state *PEMStreamState, replacement string, inJSONString bool) (string, bool) {
	if state == nil || (text == "" && state.Tail == "") {
		return text, false
	}

	var b strings.Builder
	rem := state.Tail + text
	state.Tail = ""
	triggered := false

	for len(rem) > 0 {
		if state.Active {
			triggered = true
			endLoc := reVaultPrivateKeyEnd.FindStringIndex(rem)
			if inJSONString {
				quoteIdx := findUnescapedJSONQuote(rem)
				if quoteIdx != -1 && (endLoc == nil || quoteIdx < endLoc[1]) {
					state.Active = false
					rem = rem[quoteIdx:]
					continue
				}
			}
			if endLoc == nil {
				if replacement == "" {
					b.WriteString(rem)
				} else {
					state.Tail = extractPotentialPEMFooterSuffix(rem)
				}
				rem = ""
				break
			}
			if replacement == "" {
				b.WriteString(rem[:endLoc[1]])
			}
			state.Active = false
			rem = rem[endLoc[1]:]
			continue
		}

		beginLoc := reVaultPrivateKeyBegin.FindStringIndex(rem)
		if beginLoc == nil {
			b.WriteString(rem)
			break
		}

		triggered = true
		b.WriteString(rem[:beginLoc[0]])
		if replacement == "" {
			b.WriteString(rem[beginLoc[0]:beginLoc[1]])
		} else {
			b.WriteString(replacement)
		}
		state.Active = true
		rem = rem[beginLoc[1]:]
	}

	return b.String(), triggered
}

func extractPotentialPEMFooterSuffix(s string) string {
	// Keep at most the last 48 bytes after any line break if they begin a partial "-" / "-----END..." footer
	start := 0
	if len(s) > 48 {
		start = len(s) - 48
	}
	tail := s[start:]
	if lastNL := strings.LastIndexAny(tail, "\r\n\""); lastNL != -1 {
		tail = tail[lastNL+1:]
	}
	if idx := strings.IndexByte(tail, '-'); idx != -1 {
		return tail[idx:]
	}
	return ""
}

func findUnescapedJSONQuote(s string) int {
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == '"' {
			return i
		}
	}
	return -1
}
