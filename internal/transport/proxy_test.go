package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
	"github.com/andrewbraga1/jaguargate/internal/telemetry"
)

func TestHTTPAndUnixSocketProxyWithSSEStreaming(t *testing.T) {
	// 1. Mock Upstream AI Provider (simulating Ollama / OpenAI SSE stream)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected http.Flusher")
		}
		_, _ = w.Write([]byte("data: {\"token\":\"Jaguar\"}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	// 2. Write temporary config enabling Unix Socket + HTTP
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "jgate_test.sock")
	cfgPath := filepath.Join(tmpDir, "jaguargate.yaml")

	yamlCfg := `
core:
  version: "1.0"
  language: "pt-BR"
  preset: "balanced"
network:
  ingress:
    http:
      enabled: true
      listen_addr: "127.0.0.1:0"
    unix_socket:
      enabled: true
      socket_path: "` + sockPath + `"
      socket_mode: "0600"
  egress:
    upstream_url: "` + upstream.URL + `"
`
	if err := os.WriteFile(cfgPath, []byte(yamlCfg), 0600); err != nil {
		t.Fatal(err)
	}

	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	logger := telemetry.NewZeroTrustLogger(io.Discard, "error", true, true, "***")
	gw, err := NewGatewayServer(mgr, logger)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Test HTTP Handler & Warning Flag Headers
	proxyServer := httptest.NewServer(gw.Handler())
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("X-JaguarGate-Status"); got != "CLEAN" {
		t.Errorf("expected X-JaguarGate-Status='CLEAN', got %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"token":"Jaguar"`) {
		t.Errorf("unexpected SSE stream body: %s", string(body))
	}

	// 4. Test Unix Domain Socket Listener & 0600 Permissions
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Disable TCP HTTP for the background Start() call so we test the actual UDS socket file
	cfgSnap := *mgr.Get()
	cfgSnap.Network.Ingress.HTTP.Enabled = false
	mgr2, _ := config.NewManager(cfgPath)
	gwUDS, _ := NewGatewayServer(mgr2, logger)

	// Override listen_addr with a free local port
	go func() {
		_ = gwUDS.Start(ctx)
	}()

	// Wait up to 1s for the Unix Socket file to be created
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("unix socket not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected strict 0600 socket permission, got %o", perm)
	}

	udsClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}

	udsResp, err := udsClient.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("UDS request failed: %v", err)
	}
	defer func() { _ = udsResp.Body.Close() }()
	if udsResp.StatusCode != http.StatusOK {
		t.Errorf("expected UDS healthz 200 OK, got %d", udsResp.StatusCode)
	}
}

func TestProxyTokenBudgetEnforcementAndDeferredSSEMetrics(t *testing.T) {
	upstreamCalled := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled++
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Segredo: [JG-CANARY:\"}}]}\n\n"))
	}))
	defer upstream.Close()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "jaguargate.yaml")
	yamlCfg := `
core:
  version: "1.0"
  preset: "balanced"
network:
  ingress:
    http:
      enabled: true
      listen_addr: "127.0.0.1:0"
  egress:
    upstream_url: "` + upstream.URL + `"
whitelist:
  circuit_breaker:
    max_tokens_per_session: 10
    window_seconds: 120
`
	if err := os.WriteFile(cfgPath, []byte(yamlCfg), 0600); err != nil {
		t.Fatal(err)
	}

	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Close() }()

	logger := telemetry.NewZeroTrustLogger(io.Discard, "error", true, true, "***")
	gw, err := NewGatewayServer(mgr, logger)
	if err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(gw.Handler())
	defer proxyServer.Close()

	// Payload of ~100 bytes (~25 tokens > max_tokens_per_session: 10) MUST be blocked before calling upstream
	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"Esta mensagem ultrapassa o limite de 10 tokens configurado para a sessao."}]}`))
	req.Header.Set("X-JaguarGate-Session-ID", "sess-over-budget")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected HTTP 429 Too Many Requests when token budget is exceeded, got %d", resp.StatusCode)
	}
	if upstreamCalled != 0 {
		t.Fatalf("SECURITY FAILURE: upstream LLM was called (%d times) despite session exceeding token budget!", upstreamCalled)
	}
}