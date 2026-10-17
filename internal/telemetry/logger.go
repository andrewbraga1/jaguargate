package telemetry

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// Pre-compiled linear-time RE2 expressions for Zero-Trust log redaction.
var (
	reOpenAIKey = regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`)
	reAWSKey    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reBearer    = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*`)
	reCPF       = regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`)
	reCNPJ      = regexp.MustCompile(`\b(?:[A-Za-z0-9]{2}\.[A-Za-z0-9]{3}\.[A-Za-z0-9]{3}/[A-Za-z0-9]{4}-\d{2}|[A-Za-z0-9]{8}/[A-Za-z0-9]{4}-\d{2}|\d{14})\b`)
)

var sensitiveFieldNames = map[string]struct{}{
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

// RedactString scrubs known PII and secret patterns from any string in O(n) time.
func RedactString(input, placeholder string) string {
	if input == "" {
		return ""
	}
	out := reOpenAIKey.ReplaceAllString(input, placeholder)
	out = reAWSKey.ReplaceAllString(out, placeholder)
	out = reBearer.ReplaceAllString(out, "Bearer "+placeholder)
	out = reCPF.ReplaceAllString(out, placeholder)
	out = reCNPJ.ReplaceAllString(out, placeholder)
	return out
}

type zeroTrustHandler struct {
	inner       slog.Handler
	enabled     bool
	placeholder string
}

// NewZeroTrustLogger creates a structured slog.Logger with automatic secret and PII redaction.
func NewZeroTrustLogger(w io.Writer, levelStr string, jsonFormat bool, redact bool, placeholder string) *slog.Logger {
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

	if placeholder == "" {
		placeholder = "***[JG-REDACTED]***"
	}

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if !redact {
				return a
			}
			keyLower := strings.ToLower(a.Key)
			if _, isSensitive := sensitiveFieldNames[keyLower]; isSensitive {
				return slog.String(a.Key, placeholder)
			}
			if a.Value.Kind() == slog.KindString {
				return slog.String(a.Key, RedactString(a.Value.String(), placeholder))
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
		placeholder: placeholder,
	})
}

func (h *zeroTrustHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *zeroTrustHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.enabled {
		r.Message = RedactString(r.Message, h.placeholder)
	}
	return h.inner.Handle(ctx, r)
}

func (h *zeroTrustHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &zeroTrustHandler{
		inner:       h.inner.WithAttrs(attrs),
		enabled:     h.enabled,
		placeholder: h.placeholder,
	}
}

func (h *zeroTrustHandler) WithGroup(name string) slog.Handler {
	return &zeroTrustHandler{
		inner:       h.inner.WithGroup(name),
		enabled:     h.enabled,
		placeholder: h.placeholder,
	}
}
