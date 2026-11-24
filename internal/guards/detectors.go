package guards

import (
	"regexp"
	"strings"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

var (
	reVaultCPF             = regexp.MustCompile(config.RegexExprCPFFormatted)
	reVaultCPFRaw          = regexp.MustCompile(config.RegexExprCPFRaw)
	reVaultCNPJ            = regexp.MustCompile(config.RegexExprCNPJ)
	reVaultCreditCard      = regexp.MustCompile(config.RegexExprPaymentNumber)
	reVaultPhone           = regexp.MustCompile(config.RegexExprPhoneBR)
	reVaultEmail           = regexp.MustCompile(config.RegexExprEmail)
	reVaultAWSKey          = regexp.MustCompile(config.RegexExprCloudAccessID)
	reVaultAPISecret       = regexp.MustCompile(config.RegexExprProviderFormat)
	reVaultJWT             = regexp.MustCompile(config.RegexExprThreePartJWS)
	reVaultPrivateKey      = regexp.MustCompile(config.RegexExprPEMBlock)
	reVaultPrivateKeyBegin = regexp.MustCompile(config.RegexExprPEMBegin)
	reVaultPrivateKeyEnd   = regexp.MustCompile(config.RegexExprPEMEnd)
	reVaultToken           = regexp.MustCompile(config.RegexExprVaultPlaceholder)
)

// Default prompt injection clauses (EN + PT-BR) compiled once into a linear-time RE2 automaton.
var defaultPromptInjectionPatterns = []string{
	`ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules|directions)`,
	`disregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts|rules)`,
	`ignore\s+(?:todas\s+as\s+)?(?:instru[çc][õo]es|regras|diretrizes)\s+(?:anteriores|acima|do\s+sistema)`,
	`esque[çc]a\s+(?:todas\s+as\s+)?(?:instru[çc][õo]es|regras)\s+anteriores`,
	`system\s*override\s*:`,
	`you\s+are\s+now\s+DAN\b`,
	`voc[êe]\s+agora\s+[ée]\s+DAN\b`,
	`reveal\s+your\s+(?:secret\s+)?system\s+prompt`,
	`mostre\s+(?:o\s+)?seu\s+system\s+prompt`,
}

var rePromptInjection = regexp.MustCompile(`(?i)(?:` + strings.Join(defaultPromptInjectionPatterns, `|`) + `)`)

// EntityDetectorSpec defines a single declarative PII or Secret detector rule in the ordered catalog.
type EntityDetectorSpec struct {
	ID             string
	Label          string
	IsSecret       bool
	StreamPrefixes []string
	DefaultRegex   *regexp.Regexp
	Validator      func(string) bool
	SkipOnOverride bool
	Enabled        func(config.PIIEntitiesConfig) bool
	Override       func(config.PIIPatternOverrides) string
}

// Ordered declarative detector registry:
// Secrets and full PEM blocks execute BEFORE numeric PII so digits inside Base64/JWT payloads
// are never partially tokenized as phones or cards before the whole secret is vaulted.
var builtinEntityDetectors = []EntityDetectorSpec{
	{
		ID:             "private_keys",
		Label:          "PRIVKEY",
		IsSecret:       true,
		StreamPrefixes: []string{"-----BEGIN"},
		DefaultRegex:   reVaultPrivateKey,
		Enabled:        func(e config.PIIEntitiesConfig) bool { return e.APISecrets },
		Override:       func(o config.PIIPatternOverrides) string { return o.PrivateKeys },
	},
	{
		ID:             "api_secrets",
		Label:          "SECRET",
		IsSecret:       true,
		StreamPrefixes: []string{"sk-", "ghp_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"},
		DefaultRegex:   reVaultAPISecret,
		Enabled:        func(e config.PIIEntitiesConfig) bool { return e.APISecrets },
		Override:       func(o config.PIIPatternOverrides) string { return o.APISecrets },
	},
	{
		ID:             "aws_keys",
		Label:          "AWSKEY",
		IsSecret:       true,
		StreamPrefixes: []string{"AKIA", "ASIA"},
		DefaultRegex:   reVaultAWSKey,
		Enabled:        func(e config.PIIEntitiesConfig) bool { return e.AWSKeys },
		Override:       func(o config.PIIPatternOverrides) string { return o.AWSKeys },
	},
	{
		ID:             "jwt_tokens",
		Label:          "JWT",
		IsSecret:       true,
		StreamPrefixes: []string{"eyJ"},
		DefaultRegex:   reVaultJWT,
		Enabled:        func(e config.PIIEntitiesConfig) bool { return e.JWTTokens },
		Override:       func(o config.PIIPatternOverrides) string { return o.JWTTokens },
	},
	{
		ID:           "cnpj",
		Label:        "CNPJ",
		IsSecret:     false,
		DefaultRegex: reVaultCNPJ,
		Enabled:      func(e config.PIIEntitiesConfig) bool { return e.CNPJ },
		Override:     func(o config.PIIPatternOverrides) string { return o.CNPJ },
	},
	{
		ID:           "credit_card",
		Label:        "CARD",
		IsSecret:     false,
		DefaultRegex: reVaultCreditCard,
		Validator:    isValidLuhn,
		Enabled:      func(e config.PIIEntitiesConfig) bool { return e.CreditCard },
		Override:     func(o config.PIIPatternOverrides) string { return o.CreditCard },
	},
	{
		ID:           "cpf_formatted",
		Label:        "CPF",
		IsSecret:     false,
		DefaultRegex: reVaultCPF,
		Enabled:      func(e config.PIIEntitiesConfig) bool { return e.CPF },
		Override:     func(o config.PIIPatternOverrides) string { return o.CPF },
	},
	{
		ID:             "cpf_raw_mod11",
		Label:          "CPF",
		IsSecret:       false,
		DefaultRegex:   reVaultCPFRaw,
		Validator:      isValidCPFMod11,
		SkipOnOverride: true,
		Enabled:        func(e config.PIIEntitiesConfig) bool { return e.CPF },
		Override:       func(o config.PIIPatternOverrides) string { return o.CPF },
	},
	{
		ID:           "phone",
		Label:        "PHONE",
		IsSecret:     false,
		DefaultRegex: reVaultPhone,
		Enabled:      func(e config.PIIEntitiesConfig) bool { return e.Phone },
		Override:     func(o config.PIIPatternOverrides) string { return o.Phone },
	},
	{
		ID:           "email",
		Label:        "EMAIL",
		IsSecret:     false,
		DefaultRegex: reVaultEmail,
		Enabled:      func(e config.PIIEntitiesConfig) bool { return e.Email },
		Override:     func(o config.PIIPatternOverrides) string { return o.Email },
	},
}

var cachedSecretStreamPrefixes = func() []string {
	var out []string
	for _, spec := range builtinEntityDetectors {
		if spec.IsSecret {
			out = append(out, spec.StreamPrefixes...)
		}
	}
	return out
}()

// SecretStreamHoldbackPrefixes returns all open-token prefixes for built-in secret detectors,
// allowing SSEInspector to hold back partial credentials across chunks without hardcoding a duplicate list.
func SecretStreamHoldbackPrefixes() []string {
	return cachedSecretStreamPrefixes
}
