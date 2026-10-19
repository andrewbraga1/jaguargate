package guards

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jaguargate/jaguargate/internal/config"
)

var (
	reBase64Candidate = regexp.MustCompile(`\b[A-Za-z0-9+/]{16,}={0,2}\b`)
	reHexCandidate    = regexp.MustCompile(`\b(?:0x)?([0-9a-fA-F]{16,})\b`)
)

// DeobfuscationResult holds the sanitized text and any decoded hidden payloads.
type DeobfuscationResult struct {
	CleanedText     string
	DecodedPayloads []string
	WasObfuscated   bool
}

// Deobfuscate strips invisible Unicode smuggling runes and recursively decodes Base64/Hex payloads.
func Deobfuscate(input string, cfg config.DeobfuscationConfig) DeobfuscationResult {
	res := DeobfuscationResult{CleanedText: input}
	if !cfg.Enabled || input == "" {
		return res
	}

	if cfg.StripInvisibleUnicode {
		cleaned, stripped := stripInvisibleRunes(input)
		if stripped {
			res.CleanedText = cleaned
			res.WasObfuscated = true
		}
	}

	maxDepth := cfg.MaxDecodeDepth
	if maxDepth <= 0 {
		maxDepth = 2
	}

	frontier := []string{res.CleanedText}
	seen := make(map[string]struct{}, 8)

	// Modern Go (1.22+): integer range loop without unused index variable
	for range maxDepth {
		var nextFrontier []string
		for _, text := range frontier {
			if cfg.DecodeBase64 {
				for _, match := range reBase64Candidate.FindAllString(text, -1) {
					if decoded, ok := tryDecodeBase64(match); ok {
						if _, exists := seen[decoded]; !exists {
							seen[decoded] = struct{}{}
							res.DecodedPayloads = append(res.DecodedPayloads, decoded)
							nextFrontier = append(nextFrontier, decoded)
							res.WasObfuscated = true
						}
					}
				}
			}
			if cfg.DecodeHex {
				for _, sub := range reHexCandidate.FindAllStringSubmatch(text, -1) {
					if len(sub) == 2 && len(sub[1])%2 == 0 {
						if decoded, ok := tryDecodeHex(sub[1]); ok {
							if _, exists := seen[decoded]; !exists {
								seen[decoded] = struct{}{}
								res.DecodedPayloads = append(res.DecodedPayloads, decoded)
								nextFrontier = append(nextFrontier, decoded)
								res.WasObfuscated = true
							}
						}
					}
				}
			}
		}
		if len(nextFrontier) == 0 {
			break
		}
		frontier = nextFrontier
	}

	return res
}

func stripInvisibleRunes(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	stripped := false

	for _, r := range s {
		if isSmugglingRune(r) {
			stripped = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), stripped
}

func isSmugglingRune(r rune) bool {
	// Zero-width spaces, joiners, directional overrides, BOM, and Unicode Tag block (U+E0000..U+E007F)
	if (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) ||
		(r >= 0x2060 && r <= 0x206F) || r == 0xFEFF ||
		(r >= 0xE0000 && r <= 0xE007F) {
		return true
	}
	return unicode.Is(unicode.Cf, r)
}

func tryDecodeBase64(candidate string) (string, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if raw, err := enc.DecodeString(candidate); err == nil && isPrintableUTF8(raw) {
			return string(raw), true
		}
	}
	return "", false
}

func tryDecodeHex(candidate string) (string, bool) {
	raw, err := hex.DecodeString(candidate)
	if err == nil && isPrintableUTF8(raw) {
		return string(raw), true
	}
	return "", false
}

func isPrintableUTF8(b []byte) bool {
	if len(b) < 4 || !utf8.Valid(b) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.85
}
