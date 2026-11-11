package telemetry

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

// Pre-compiled linear-time RE2 expressions for Zero-Trust log redaction.
var (
	reOpenAIKey = regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`)
	reAWSKey    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reBearer    = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*`)
	reCPF       = regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`)
	reCNPJ      = regexp.MustCompile(`\b(?:[A-Za-z0-9]{2}\.[A-Za-z0-9]{3}\.[A-Za-z0-9]{3}/[A-Za-z0-9]{4}-\d{2}|[A-Za-z0-9]{8}/[A-Za-z0-9]{4}-\d{2}|\d{14})\b`)
)

var defaultSensitiveFieldNames = map[string]struct{}{
	"authorization": {},
	"api_key":       {},
	"apikey":        {},
	"secret":        {},
	"password":      {},
	"token":         {},
	"cpf":           {},
	"cnpj":          {},
	"credit_card":   {},
}

// sensitiveFieldNames preserved for backward compatibility.
var sensitiveFieldNames = defaultSensitiveFieldNames

// Redactor scrubs known PII, secrets, and corporate custom patterns in O(n) time.
type Redactor struct {
	mu              sync.RWMutex
	patterns        []*regexp.Regexp
	sensitiveFields map[string]struct{}
	placeholder     string
}

// NewRedactor creates a thread-safe Redactor initialized with default scrubbers plus custom rules.
func NewRedactor(placeholder string, customPatterns []string, customFields []string) *Redactor {
	if placeholder == "" {
		placeholder = "***[JG-REDACTED]***"
	}
	r := &Redactor{
		patterns: []*regexp.Regexp{
			reOpenAIKey,
			reAWSKey,
			reBearer,
			reCPF,
			reCNPJ,
		},
		sensitiveFields: make(map[string]struct{}, len(defaultSensitiveFieldNames)+len(customFields)),
		placeholder:     placeholder,
	}

	for k := range defaultSensitiveFieldNames {
		r.sensitiveFields[k] = struct{}{}
	}
	for _, f := range customFields {
		trimmed := strings.ToLower(strings.TrimSpace(f))
		if trimmed != "" {
			r.sensitiveFields[trimmed] = struct{}{}
		}
	}

	for _, pat := range customPatterns {
		trimmed := strings.TrimSpace(pat)
		if trimmed == "" {
			continue
		}
		if compiled, err := regexp.Compile(trimmed); err == nil {
			r.patterns = append(r.patterns, compiled)
		}
	}

	return r
}

var defaultRedactor = NewRedactor("***[JG-REDACTED]***", nil, nil)

// RedactString scrubs known PII and secret patterns from any string in O(n) time using default patterns.
func RedactString(input, placeholder string) string {
	if placeholder == "" || placeholder == defaultRedactor.placeholder {
		return defaultRedactor.Redact(input)
	}
	return defaultRedactor.RedactWithPlaceholder(input, placeholder)
}

// Redact applies all configured regex scrubbers to the input string.
func (r *Redactor) Redact(input string) string {
	return r.RedactWithPlaceholder(input, r.placeholder)
}

// RedactWithPlaceholder applies all configured regex scrubbers with an explicit placeholder.
func (r *Redactor) RedactWithPlaceholder(input, placeholder string) string {
	if input == "" {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := input
	for _, pat := range r.patterns {
		if pat == reBearer {
			out = pat.ReplaceAllString(out, "Bearer "+placeholder)
		} else {
			out = pat.ReplaceAllString(out, placeholder)
		}
	}
	return out
}

// IsSensitiveField returns true if the field name matches any default or custom sensitive field.
func (r *Redactor) IsSensitiveField(fieldName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, found := r.sensitiveFields[strings.ToLower(fieldName)]
	return found
}

// SanitizeLogCRLF removes CRLF characters to prevent Log Injection / Log Forgery (CWE-117 / GoSec G706).
func SanitizeLogCRLF(input string) string {
	if input == "" {
		return ""
	}
	return strings.ReplaceAll(strings.ReplaceAll(input, "\n", " "), "\r", " ")
}

type zeroTrustHandler struct {
	inner       slog.Handler
	enabled     bool
	redactor    *Redactor
	placeholder string
}

// NewZeroTrustLogger creates a structured slog.Logger with automatic secret and PII redaction.
func NewZeroTrustLogger(w io.Writer, levelStr string, jsonFormat bool, redact bool, placeholder string, customPatterns ...string) *slog.Logger {
	redactor := NewRedactor(placeholder, customPatterns, nil)
	return newZeroTrustLoggerWithRedactor(w, levelStr, jsonFormat, redact, redactor)
}

// NewZeroTrustLoggerWithConfig creates a structured slog.Logger configured from config.LoggingConfig.
func NewZeroTrustLoggerWithConfig(w io.Writer, cfg config.LoggingConfig) *slog.Logger {
	placeholder := cfg.RedactionPlaceholder
	if placeholder == "" {
		placeholder = "***[JG-REDACTED]***"
	}
	isRedact := cfg.ZeroTrustRedaction || cfg.ZeroTrustPrompts
	isJSON := strings.EqualFold(cfg.Format, "json")
	redactor := NewRedactor(placeholder, cfg.CustomPatterns, cfg.SensitiveFields)
	return newZeroTrustLoggerWithRedactor(w, cfg.Level, isJSON, isRedact, redactor)
}

func newZeroTrustLoggerWithRedactor(w io.Writer, levelStr string, jsonFormat bool, redact bool, redactor *Redactor) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	placeholder := redactor.placeholder

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if !redact {
				if a.Value.Kind() == slog.KindString {
					return slog.String(a.Key, SanitizeLogCRLF(a.Value.String()))
				}
				return a
			}
			keyLower := strings.ToLower(a.Key)
			if redactor.IsSensitiveField(keyLower) {
				return slog.String(a.Key, placeholder)
			}
			if a.Value.Kind() == slog.KindString {
				return slog.String(a.Key, SanitizeLogCRLF(redactor.Redact(a.Value.String())))
			}
			return a
		},
	}

	var baseHandler slog.Handler
	if jsonFormat {
		baseHandler = slog.NewJSONHandler(w, opts)
	} else {
		baseHandler = slog.NewTextHandler(w, opts)
	}

	return slog.New(&zeroTrustHandler{
		inner:       baseHandler,
		enabled:     redact,
		redactor:    redactor,
		placeholder: placeholder,
	})
}

func (h *zeroTrustHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *zeroTrustHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.enabled && h.redactor != nil {
		r.Message = h.redactor.Redact(r.Message)
	}
	r.Message = SanitizeLogCRLF(r.Message)
	return h.inner.Handle(ctx, r)
}

func (h *zeroTrustHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &zeroTrustHandler{
		inner:       h.inner.WithAttrs(attrs),
		enabled:     h.enabled,
		redactor:    h.redactor,
		placeholder: h.placeholder,
	}
}

func (h *zeroTrustHandler) WithGroup(name string) slog.Handler {
	return &zeroTrustHandler{
		inner:       h.inner.WithGroup(name),
		enabled:     h.enabled,
		redactor:    h.redactor,
		placeholder: h.placeholder,
	}
}
