package guards

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jaguargate/jaguargate/internal/config"
)

var (
	// Matches candidate Base64 tokens of at least 16 characters
	reBase64Candidate = regexp.MustCompile(`\b[A-Za-z0-9+/]{16,}={0,2}\b`)
	// Matches continuous Hex strings (e.g. 49676e6f7265...) or \x49\x67 escaped sequences
	reHexCandidate = regexp.MustCompile(`(?:\b[0-9a-fA-F]{20,}\b|(?:\\x[0-9a-fA-F]{2}){6,})`)
)

// DeobfuscationResult holds the sanitized visible text and any hidden decoded strings for inspection.
type DeobfuscationResult struct {
	CleanedText     string
	DecodedPayloads []string
	WasObfuscated   bool
}

// Deobfuscate strips invisible Unicode smuggling runes and recursively decodes hidden Base64/Hex payloads.
func Deobfuscate(input string, cfg config.DeobfuscationConfig) DeobfuscationResult {
	if !cfg.Enabled || input == "" {
		return DeobfuscationResult{CleanedText: input}
	}

	cleaned := input
	wasObfuscated := false

	// 1. Strip invisible Unicode Tag smuggling (U+E0000..U+E007F) and zero-width characters
	if cfg.StripInvisibleUnicode {
		var stripped bool
		cleaned, stripped = StripInvisibleUnicode(cleaned)
		if stripped {
			wasObfuscated = true
		}
	}

	maxDepth := cfg.MaxDecodeDepth
	if maxDepth <= 0 || maxDepth > 5 {
		maxDepth = 2
	}

	var decodedList []string
	queue := []string{cleaned}

	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		var nextQueue []string

		for _, current := range queue {
			if cfg.DecodeBase64 {
				matches := reBase64Candidate.FindAllString(current, 10)
				for _, m := range matches {
					if decoded, ok := tryDecodePrintableBase64(m); ok {
						decodedList = append(decodedList, decoded)
						nextQueue = append(nextQueue, decoded)
						wasObfuscated = true
					}
				}
			}

			if cfg.DecodeHex {
				matches := reHexCandidate.FindAllString(current, 10)
				for _, m := range matches {
					if decoded, ok := tryDecodePrintableHex(m); ok {
						decodedList = append(decodedList, decoded)
						nextQueue = append(nextQueue, decoded)
						wasObfuscated = true
					}
				}
			}
		}

		queue = nextQueue
	}

	return DeobfuscationResult{
		CleanedText:     cleaned,
		DecodedPayloads: decodedList,
		WasObfuscated:   wasObfuscated,
	}
}

// StripInvisibleUnicode removes Unicode Tag characters (ASCII Smuggling) and zero-width format characters.
func StripInvisibleUnicode(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	stripped := false

	for _, r := range s {
		if isInvisibleSmugglingRune(r) {
			stripped = true
			continue
		}
		b.WriteRune(r)
	}

	if !stripped {
		return s, false
	}
	return b.String(), true
}

func isInvisibleSmugglingRune(r rune) bool {
	// Unicode Tags block (U+E0000 to U+E007F) used in LLM ASCII smuggling attacks
	if r >= 0xE0000 && r <= 0xE007F {
		return true
	}
	// Zero-width spaces, joiners, directional overrides, and BOM
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202E:
		return true
	}
	return false
}

func tryDecodePrintableBase64(candidate string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(candidate)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(candidate)
		if err != nil {
			return "", false
		}
	}
	if !isMostlyPrintableUTF8(raw) {
		return "", false
	}
	return string(raw), true
}

func tryDecodePrintableHex(candidate string) (string, bool) {
	cleanHex := strings.ReplaceAll(candidate, `\x`, "")
	if len(cleanHex)%2 != 0 {
		return "", false
	}
	raw, err := hex.DecodeString(cleanHex)
	if err != nil || !isMostlyPrintableUTF8(raw) {
		return "", false
	}
	return string(raw), true
}

func isMostlyPrintableUTF8(data []byte) bool {
	if len(data) < 6 || !utf8.Valid(data) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range string(data) {
		total++
		if (r >= 0x20 && r <= 0x7E) || r == '\n' || r == '\r' || r == '\t' || r >= 0xA0 {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.85
}
