package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/andrewbraga1/jaguargate/internal/config"
)

func TestZeroTrustLoggerRedaction(t *testing.T) {
	var buf bytes.Buffer
	placeholder := "***[JG-REDACTED]***"
	logger := NewZeroTrustLogger(&buf, "info", true, true, placeholder)

	rawSecretKey := "sk-proj-1234567890abcdefghijklmnop"
	rawCPF := "123.456.789-01"
	rawAWS := "AKIAIOSFODNN7EXAMPLE"

	logger.Info("intercepted suspicious request with key "+rawSecretKey,
		slog.String("authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
		slog.String("user_note", "Cliente CPF "+rawCPF+" e AWS "+rawAWS),
	)

	output := buf.String()
	if strings.Contains(output, rawSecretKey) {
		t.Fatalf("SECURITY FAILURE: OpenAI key leaked in logs: %s", output)
	}
	if strings.Contains(output, rawCPF) {
		t.Fatalf("SECURITY FAILURE: CPF leaked in logs: %s", output)
	}
	if strings.Contains(output, rawAWS) {
		t.Fatalf("SECURITY FAILURE: AWS key leaked in logs: %s", output)
	}
	if !strings.Contains(output, placeholder) {
		t.Fatalf("expected redaction placeholder %q in log output: %s", placeholder, output)
	}
}

func TestZeroTrustLoggerCRLFInjectionSanitization(t *testing.T) {
	var buf bytes.Buffer
	logger := NewZeroTrustLogger(&buf, "info", false, true, "***[JG-REDACTED]***")

	maliciousInput := "admin\r\nLEVEL=ERROR Fake log entry injected\r\n"
	logger.Info(maliciousInput, slog.String("detail", "test\r\nsecond line"))

	output := buf.String()
	// Output should have only a single trailing newline from slog, not multiple injected newlines
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		t.Fatalf("CRLF injection detected: expected 1 log line, got %d:\n%s", len(lines), output)
	}
	if strings.Contains(output, "admin\r\n") || strings.Contains(output, "test\r\n") {
		t.Fatalf("CRLF characters were not sanitized from log output:\n%s", output)
	}
}

func TestZeroTrustLoggerCustomPatternsAndSensitiveFields(t *testing.T) {
	var buf bytes.Buffer
	customPattern := `\bCORP-SECRET-[0-9]{6}\b`
	logger := NewZeroTrustLogger(&buf, "info", true, true, "[CONFIDENTIAL]", customPattern)

	rawSecret := "CORP-SECRET-998877"
	logger.Info("auditing transaction with internal code "+rawSecret,
		slog.String("custom_token", "raw-secret-value-1234"),
	)

	output := buf.String()
	if strings.Contains(output, rawSecret) {
		t.Fatalf("SECURITY FAILURE: custom corporate pattern leaked in logs: %s", output)
	}
	if !strings.Contains(output, "[CONFIDENTIAL]") {
		t.Fatalf("expected custom placeholder [CONFIDENTIAL] in log output: %s", output)
	}
}

func TestZeroTrustLoggerWithConfig(t *testing.T) {
	var buf bytes.Buffer
	cfg := config.LoggingConfig{
		Format:               "json",
		Level:                "info",
		ZeroTrustRedaction:   true,
		RedactionPlaceholder: "***[MASKED]***",
		CustomPatterns:       []string{`\bEMP-[A-Z0-9]{5}\b`},
		SensitiveFields:      []string{"client_secret", "master_key"},
	}

	logger := NewZeroTrustLoggerWithConfig(&buf, cfg)
	empID := "EMP-99A88"
	logger.Info("processing employee "+empID,
		slog.String("client_secret", "top-secret-cleartext"),
		slog.String("master_key", "super-secret-hex"),
		slog.String("safe_field", "normal-data"),
	)

	output := buf.String()
	if strings.Contains(output, empID) {
		t.Fatalf("custom pattern was not redacted: %s", output)
	}
	if strings.Contains(output, "top-secret-cleartext") {
		t.Fatalf("custom sensitive field client_secret leaked: %s", output)
	}
	if strings.Contains(output, "super-secret-hex") {
		t.Fatalf("custom sensitive field master_key leaked: %s", output)
	}
	if !strings.Contains(output, "normal-data") {
		t.Fatalf("non-sensitive field should not be redacted: %s", output)
	}
	if !strings.Contains(output, "***[MASKED]***") {
		t.Fatalf("expected configured placeholder in output: %s", output)
	}
}

func BenchmarkBufferPoolCycle(b *testing.B) {
	pool := NewByteSlicePool()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			slice := pool.Get()
			slice[0] = 'J'
			pool.Put(slice)
		}
	})
}