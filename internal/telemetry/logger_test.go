package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
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