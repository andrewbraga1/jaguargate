package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jaguargate/jaguargate/internal/config"
)

func TestPrometheusMetricsAndNonBlockingWebhook(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordRequest("SANITIZED", []string{"JG-SEC-401", "JG-PII-301"}, 2, 118)
	mc.RecordRequest("CLEAN", nil, 0, 45)

	promText := mc.RenderPrometheusText()
	if !strings.Contains(promText, `jaguargate_requests_total{status="SANITIZED"} 1`) {
		t.Errorf("expected SANITIZED counter in Prometheus output:\n%s", promText)
	}
	if !strings.Contains(promText, `jaguargate_flag_triggers_total{code="JG-SEC-401"} 1`) {
		t.Errorf("expected JG-SEC-401 trigger counter in Prometheus output:\n%s", promText)
	}
	if !strings.Contains(promText, `jaguargate_pruned_tools_total 2`) {
		t.Errorf("expected pruned tools counter = 2:\n%s", promText)
	}

	// Test Async Non-Blocking Webhook with HMAC-SHA256 signature
	t.Setenv("JAGUARGATE_WEBHOOK_SECRET", "enterprise-hmac-secret")
	receivedCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig := r.Header.Get("X-JaguarGate-Signature-256")
		receivedCh <- sig
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	disp := NewWebhookDispatcher()
	whCfg := config.WebhooksConfig{
		Enabled:   true,
		Endpoints: []string{srv.URL},
		TriggerOn: []string{"INTRUSION_ALERT"},
	}

	queued := disp.Enqueue(WebhookEvent{
		Status:   "SANITIZED",
		Severity: "INTRUSION_ALERT",
		Codes:    []string{"JG-SEC-401"},
		Path:     "/v1/chat/completions",
	}, whCfg)

	if !queued {
		t.Fatal("expected webhook alert to be enqueued")
	}

	select {
	case sig := <-receivedCh:
		if !strings.HasPrefix(sig, "sha256=") {
			t.Errorf("expected HMAC-SHA256 header signature, got %q", sig)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async webhook delivery")
	}
}

func BenchmarkAtomicMetricsRecord(b *testing.B) {
	mc := NewMetricsCollector()
	codes := []string{"JG-SEC-401", "JG-PII-301"}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mc.RecordRequest("SANITIZED", codes, 1, 115)
		}
	})
}
