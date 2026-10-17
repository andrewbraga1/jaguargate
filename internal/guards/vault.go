package guards

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/jaguargate/jaguargate/internal/config"
)

var (
	reVaultCPF        = regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`)
	reVaultCNPJ       = regexp.MustCompile(`\b(?:[A-Za-z0-9]{2}\.[A-Za-z0-9]{3}\.[A-Za-z0-9]{3}/[A-Za-z0-9]{4}-\d{2}|[A-Za-z0-9]{8}/[A-Za-z0-9]{4}-\d{2}|\d{14})\b`)
	reVaultCreditCard = regexp.MustCompile(`\b(?:\d{4}[ -]?){3}\d{4}\b`)
	reVaultEmail      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	reVaultAWSKey     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reVaultAPISecret  = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)
	reVaultJWT        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	reVaultToken      = regexp.MustCompile(`<JG_PII_[A-Z]+_[0-9a-f]{8}>`)
)

type vaultEntry struct {
	originalValue string
	expiresAt     time.Time
}

// PIIVault provides a concurrency-safe, reversible in-memory masking store with TTL expiration.
type PIIVault struct {
	mu      sync.RWMutex
	entries map[string]vaultEntry
}

// NewPIIVault creates an initialized local PII masking vault.
func NewPIIVault() *PIIVault {
	return &PIIVault{
		entries: make(map[string]vaultEntry, 256),
	}
}

// MaskText replaces configured PII and secret entities with reversible <JG_PII_...> tokens.
func (v *PIIVault) MaskText(input string, cfg config.PIIVaultConfig, redactOnly bool) (string, []string, int) {
	if !cfg.Enabled || input == "" {
		return input, nil, 0
	}

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	out := input
	maskedCount := 0
	hasPII := false
	hasSecret := false

	replaceEntity := func(re *regexp.Regexp, label string, isSecret bool) {
		out = re.ReplaceAllStringFunc(out, func(match string) string {
			maskedCount++
			if isSecret {
				hasSecret = true
			} else {
				hasPII = true
			}
			if redactOnly {
				return match // Shadow mode: detect & flag without modifying payload
			}
			token := v.storeValue(label, match, ttl)
			return token
		})
	}

	if cfg.Entities.CPF {
		replaceEntity(reVaultCPF, "CPF", false)
	}
	if cfg.Entities.CNPJ {
		replaceEntity(reVaultCNPJ, "CNPJ", false)
	}
	if cfg.Entities.CreditCard {
		replaceEntity(reVaultCreditCard, "CARD", false)
	}
	if cfg.Entities.Email {
		replaceEntity(reVaultEmail, "EMAIL", false)
	}
	if cfg.Entities.AWSKeys {
		replaceEntity(reVaultAWSKey, "AWSKEY", true)
	}
	if cfg.Entities.APISecrets {
		replaceEntity(reVaultAPISecret, "SECRET", true)
	}
	if cfg.Entities.JWTTokens {
		replaceEntity(reVaultJWT, "JWT", true)
	}

	var codes []string
	if hasPII {
		codes = append(codes, "JG-PII-301")
	}
	if hasSecret {
		codes = append(codes, "JG-PII-302")
	}

	return out, codes, maskedCount
}

// RestoreText replaces any active <JG_PII_...> tokens in the model output with their original values.
func (v *PIIVault) RestoreText(output string) string {
	if output == "" {
		return ""
	}
	now := time.Now()
	return reVaultToken.ReplaceAllStringFunc(output, func(token string) string {
		v.mu.RLock()
		entry, exists := v.entries[token]
		v.mu.RUnlock()
		if !exists || now.After(entry.expiresAt) {
			return token
		}
		return entry.originalValue
	})
}

func (v *PIIVault) storeValue(label, rawValue string, ttl time.Duration) string {
	var randBytes [4]byte
	_, _ = rand.Read(randBytes[:])
	token := fmt.Sprintf("<JG_PII_%s_%s>", label, hex.EncodeToString(randBytes[:]))

	v.mu.Lock()
	// Opportunistic expired entry cleanup when map grows large
	if len(v.entries) > 4096 {
		now := time.Now()
		for k, e := range v.entries {
			if now.After(e.expiresAt) {
				delete(v.entries, k)
			}
		}
	}
	v.entries[token] = vaultEntry{
		originalValue: rawValue,
		expiresAt:     time.Now().Add(ttl),
	}
	v.mu.Unlock()

	return token
}
