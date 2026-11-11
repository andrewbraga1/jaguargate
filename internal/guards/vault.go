package guards

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

var (
	reVaultCPF        = regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`)
	reVaultCNPJ       = regexp.MustCompile(`\b(?:[A-Za-z0-9]{2}\.[A-Za-z0-9]{3}\.[A-Za-z0-9]{3}/[A-Za-z0-9]{4}-\d{2}|[A-Za-z0-9]{8}/[A-Za-z0-9]{4}-\d{2}|\d{14})\b`)
	reVaultCreditCard = regexp.MustCompile(`\b(?:\d{4}[ -]?){3}\d{4}\b`)
	reVaultEmail      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	reVaultAWSKey     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reVaultAPISecret  = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)
	reVaultJWT        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	reVaultToken      = regexp.MustCompile(`\x3cJG_PII_[A-Z0-9_]+_[0-9a-f]{8,32}\x3e`)
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
	isSecret      bool
	expiresAt     time.Time
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

	replaceEntity := func(re *regexp.Regexp, label string, isSecret bool) {
		out = re.ReplaceAllStringFunc(out, func(match string) string {
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

	cpfRe := resolvePattern(cfg.PatternOverrides.CPF, reVaultCPF)
	cnpjRe := resolvePattern(cfg.PatternOverrides.CNPJ, reVaultCNPJ)
	cardRe := resolvePattern(cfg.PatternOverrides.CreditCard, reVaultCreditCard)
	emailRe := resolvePattern(cfg.PatternOverrides.Email, reVaultEmail)
	awsRe := resolvePattern(cfg.PatternOverrides.AWSKeys, reVaultAWSKey)
	secretRe := resolvePattern(cfg.PatternOverrides.APISecrets, reVaultAPISecret)
	jwtRe := resolvePattern(cfg.PatternOverrides.JWTTokens, reVaultJWT)

	if cfg.Entities.CPF {
		replaceEntity(cpfRe, "CPF", false)
	}
	if cfg.Entities.CNPJ {
		replaceEntity(cnpjRe, "CNPJ", false)
	}
	if cfg.Entities.CreditCard {
		replaceEntity(cardRe, "CARD", false)
	}
	if cfg.Entities.Email {
		replaceEntity(emailRe, "EMAIL", false)
	}
	if cfg.Entities.AWSKeys {
		replaceEntity(awsRe, "AWSKEY", true)
	}
	if cfg.Entities.APISecrets {
		replaceEntity(secretRe, "SECRET", true)
	}
	if cfg.Entities.JWTTokens {
		replaceEntity(jwtRe, "JWT", true)
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
		replaceEntity(re, label, cp.IsSecret)
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

// RestoreText replaces any active tokens in the model output belonging to the default session.
func (v *PIIVault) RestoreText(output string) string {
	return v.RestoreTextWithSession("default_session", output)
}

// RestoreTextWithSession replaces active tokens in the model output ONLY if they belong to the given sessionID.
func (v *PIIVault) RestoreTextWithSession(sessionID, output string) string {
	if output == "" {
		return ""
	}
	if sessionID == "" {
		sessionID = "default_session"
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
			return entry.originalValue
		}

		if ext != nil {
			if val, _, err := ext.Get(token); err == nil && val != "" {
				if ownerSess, rawVal, ok := splitSessionBoundValue(val); ok {
					if ownerSess == sessionID {
						return rawVal
					}
					return token
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
		isSecret:      isSecret,
		expiresAt:     now.Add(ttl),
	}
	ext := v.extStore
	v.mu.Unlock()

	warnCode := ""
	if ext != nil {
		boundVal := sessionID + "\x00" + rawValue
		warnCode, _ = ext.Set(token, boundVal, ttl)
	}

	return token, warnCode
}

func splitSessionBoundValue(stored string) (string, string, bool) {
	for i := 0; i < len(stored); i++ {
		if stored[i] == 0 {
			return stored[:i], stored[i+1:], true
		}
	}
	return "default_session", stored, true
}
