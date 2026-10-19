package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
	"github.com/andrewbraga1/jaguargate/internal/extensions"
	"github.com/andrewbraga1/jaguargate/internal/guards"
	"github.com/andrewbraga1/jaguargate/internal/mcp"
	"github.com/andrewbraga1/jaguargate/internal/state"
	"github.com/andrewbraga1/jaguargate/internal/stream"
	"github.com/andrewbraga1/jaguargate/internal/telemetry"
)

type ctxInspectionKey struct{}
type ctxInboundLatencyUsKey struct{}
type ctxUpstreamStartTimeKey struct{}

// GatewayServer manages the multi-transport listeners, telemetry, and the low-latency reverse proxy.
type GatewayServer struct {
	cfgMgr         *config.Manager
	logger         *slog.Logger
	bufferPool     *telemetry.ByteSlicePool
	metrics        *telemetry.MetricsCollector
	webhooks       *telemetry.WebhookDispatcher
	sandbox        *extensions.Sandbox
	stateStore     *state.HybridStore
	circuitBreaker *state.CircuitBreaker
	guardEngine    *guards.Engine
	mcpInspector   *mcp.Inspector
	proxy          *httputil.ReverseProxy
	httpServer     *http.Server
	udsServer      *http.Server
	rpcServer      *http.Server
	metricsServer  *http.Server
	udsPath        string
}

// NewGatewayServer initializes the reverse proxy with pre-warmed keep-alive pools, L1/L2 state, Wasm sandbox, MCP, OWASP & Telemetry.
func NewGatewayServer(cfgMgr *config.Manager, logger *slog.Logger) (*GatewayServer, error) {
	snap := cfgMgr.Get()
	targetURL, err := url.Parse(snap.Network.Egress.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	bufPool := telemetry.NewByteSlicePool()
	metrics := telemetry.NewMetricsCollector()
	webhooks := telemetry.NewWebhookDispatcher()
	sandbox := extensions.NewSandbox()

	stateStore, err := state.NewHybridStore(snap.Extensions.StateStore)
	if err != nil {
		return nil, fmt.Errorf("initialize state store: %w", err)
	}

	vault := guards.NewPIIVault()
	vault.SetExternalStore(stateStore)

	circuitBreaker := state.NewCircuitBreaker()
	guardEngine := guards.NewEngine(vault)
	mcpInspector := mcp.NewInspector(guardEngine, circuitBreaker)

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	customTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          snap.Network.Egress.KeepAlivePoolSize,
		MaxIdleConnsPerHost:   snap.Network.Egress.KeepAlivePoolSize,
		IdleConnTimeout:       time.Duration(snap.Network.Egress.IdleConnTimeoutSec) * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !snap.Network.Egress.TLSVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}

	if snap.Network.Egress.UpstreamUnixSocket != "" {
		sockPath := snap.Network.Egress.UpstreamUnixSocket
		customTransport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", sockPath)
		}
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)
			pr.Out.Host = targetURL.Host
		},
		Transport:     customTransport,
		FlushInterval: -1, // Immediate token-by-token flush for SSE streaming
		BufferPool:    bufPool,
		ModifyResponse: func(resp *http.Response) error {
			outboundStart := time.Now()
			activeCfg := cfgMgr.Get()
			inboundRes, _ := resp.Request.Context().Value(ctxInspectionKey{}).(guards.InspectionResult)
			inboundUs, _ := resp.Request.Context().Value(ctxInboundLatencyUsKey{}).(int64)

			if upstreamStart, ok := resp.Request.Context().Value(ctxUpstreamStartTimeKey{}).(time.Time); ok {
				upstreamMs := time.Since(upstreamStart).Milliseconds()
				resp.Header.Set("X-JaguarGate-Upstream-Ms", strconv.FormatInt(upstreamMs, 10))
			}

			contentType := resp.Header.Get("Content-Type")
			isSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream")

			if isSSE && resp.Body != nil {
				resp.Header.Set("X-Accel-Buffering", "no")
				resp.Header.Set("Cache-Control", "no-cache, no-transform")
				resp.Header.Del("Content-Length")

				status := inboundRes.Status
				severity := inboundRes.Severity
				if status == "" {
					status = "CLEAN"
					severity = "NONE"
				}

				gatewayUs := max(1, inboundUs+time.Since(outboundStart).Microseconds())
				resp.Header.Set("X-JaguarGate-Latency-Us", strconv.FormatInt(gatewayUs, 10))

				if activeCfg.Telemetry.WarningFlags.EmitHTTPHeaders {
					resp.Header.Set("X-JaguarGate-Status", status)
					resp.Header.Set("X-JaguarGate-Severity", severity)
					if len(inboundRes.Codes) > 0 {
						resp.Header.Set("X-JaguarGate-Codes", strings.Join(inboundRes.Codes, ","))
					}
					if inboundRes.PrunedTools > 0 {
						resp.Header.Set("X-JaguarGate-Pruned-Count", strconv.Itoa(inboundRes.PrunedTools))
					}
				}

				if activeCfg.Telemetry.WarningFlags.EmitHTTPTrailersOnStream {
					resp.Header.Set("Trailer", "X-JaguarGate-Status, X-JaguarGate-Severity, X-JaguarGate-Codes, X-JaguarGate-Pruned-Count")
					if resp.Trailer == nil {
						resp.Trailer = make(http.Header)
					}
				}

				metrics.RecordRequest(status, inboundRes.Codes, inboundRes.PrunedTools, gatewayUs)
				resp.Body = stream.NewSSEInspector(resp.Body, activeCfg, guardEngine.Vault(), inboundRes, resp.Trailer)
				return nil
			}

			if resp.Body != nil {
				rawResp, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err == nil {
					if activeCfg.Network.MCP.Enabled && mcp.IsJSONRPCPayload(rawResp) {
						sessionID := extractSessionID(resp.Request)
						mcpRes := mcpInspector.InspectPayload(rawResp, sessionID, "", activeCfg)
						for _, c := range mcpRes.Codes {
							if !slices.Contains(inboundRes.Codes, c) {
								inboundRes.Codes = append(inboundRes.Codes, c)
							}
						}
						rawResp = mcpRes.ModifiedBody
					}

					outRes := guardEngine.SanitizeOutputJSON(rawResp, inboundRes, activeCfg)
					gatewayUs := max(1, inboundUs+time.Since(outboundStart).Microseconds())
					resp.Header.Set("X-JaguarGate-Latency-Us", strconv.FormatInt(gatewayUs, 10))

					if activeCfg.Telemetry.WarningFlags.EmitHTTPHeaders {
						resp.Header.Set("X-JaguarGate-Status", outRes.Status)
						resp.Header.Set("X-JaguarGate-Severity", outRes.Severity)
						if len(outRes.Codes) > 0 {
							resp.Header.Set("X-JaguarGate-Codes", strings.Join(outRes.Codes, ","))
						}
						if outRes.PrunedTools > 0 {
							resp.Header.Set("X-JaguarGate-Pruned-Count", strconv.Itoa(outRes.PrunedTools))
						}
					}

					metrics.RecordRequest(outRes.Status, outRes.Codes, outRes.PrunedTools, gatewayUs)
					if len(outRes.Codes) > 0 {
						webhooks.Enqueue(telemetry.WebhookEvent{
							Status:      outRes.Status,
							Severity:    outRes.Severity,
							Codes:       outRes.Codes,
							Path:        resp.Request.URL.Path,
							PrunedTools: outRes.PrunedTools,
						}, activeCfg.Telemetry.Webhooks)
					}

					resp.Body = io.NopCloser(bytes.NewReader(outRes.ModifiedBody))
					resp.ContentLength = int64(len(outRes.ModifiedBody))
					resp.Header.Set("Content-Length", strconv.Itoa(len(outRes.ModifiedBody)))
					return nil
				}
			}

			gatewayUs := max(1, inboundUs+time.Since(outboundStart).Microseconds())
			resp.Header.Set("X-JaguarGate-Latency-Us", strconv.FormatInt(gatewayUs, 10))
			if activeCfg.Telemetry.WarningFlags.EmitHTTPHeaders && resp.Header.Get("X-JaguarGate-Status") == "" {
				resp.Header.Set("X-JaguarGate-Status", "CLEAN")
				resp.Header.Set("X-JaguarGate-Severity", "NONE")
			}
			metrics.RecordRequest("CLEAN", nil, 0, gatewayUs)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("upstream proxy communication error",
				slog.String("path", r.URL.Path),
				slog.String("error", err.Error()),
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-JaguarGate-Status", "UPSTREAM_UNAVAILABLE")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":{"message":"JaguarGate could not reach upstream AI provider","code":"JG-NET-502"}}`))
		},
	}

	return &GatewayServer{
		cfgMgr:         cfgMgr,
		logger:         logger,
		bufferPool:     bufPool,
		metrics:        metrics,
		webhooks:       webhooks,
		sandbox:        sandbox,
		stateStore:     stateStore,
		circuitBreaker: circuitBreaker,
		guardEngine:    guardEngine,
		mcpInspector:   mcpInspector,
		proxy:          rp,
	}, nil
}

// Handler wraps the reverse proxy with Stage 2-5 Guards, Sandbox, Liveness/Readiness Probes, and Prometheus Metrics.
func (s *GatewayServer) Handler() http.Handler {
	mux := http.NewServeMux()

	// Modern Go (1.22+): explicit method routing in ServeMux ("GET /healthz", "GET /readyz", "GET /metrics")
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		cfg := s.cfgMgr.Get()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-JaguarGate-Status", "CLEAN")

		if r.URL.Query().Get("check") == "upstream" {
			reachable := probeUpstream(cfg.Network.Egress)
			statusStr := "ok"
			if !reachable {
				statusStr = "degraded"
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"status":%q,"version":%q,"mode":%q,"preset":%q,"upstream_reachable":%v}`,
				statusStr, cfg.Core.Version, cfg.Core.Mode, cfg.Core.Preset, reachable)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","version":%q,"mode":%q,"preset":%q}`,
			cfg.Core.Version, cfg.Core.Mode, cfg.Core.Preset)
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		cfg := s.cfgMgr.Get()
		reachable := probeUpstream(cfg.Network.Egress)
		w.Header().Set("Content-Type", "application/json")
		if !reachable {
			w.Header().Set("X-JaguarGate-Status", "UPSTREAM_UNAVAILABLE")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, `{"status":"not_ready","upstream_reachable":false,"upstream":%q}`, cfg.Network.Egress.UpstreamURL)
			return
		}
		w.Header().Set("X-JaguarGate-Status", "CLEAN")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ready","upstream_reachable":true,"upstream":%q}`, cfg.Network.Egress.UpstreamURL)
	})

	mux.Handle("GET /metrics", s.metrics.Handler())

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		inboundStart := time.Now()

		cfg := s.cfgMgr.Get()
		maxBytes := cfg.Network.Ingress.HTTP.MaxPayloadMB * 1024 * 1024
		if maxBytes > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}

		var inboundLatencyUs int64

		if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
			buf := telemetry.AcquireBuffer()
			_, readErr := buf.ReadFrom(r.Body)
			_ = r.Body.Close()

			if readErr != nil {
				telemetry.ReleaseBuffer(buf)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-JaguarGate-Status", "BLOCKED")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = w.Write([]byte(`{"error":{"message":"Payload exceeds max_payload_mb limit","code":"JG-CFG-202"}}`))
				return
			}

			rawBody := bytes.Clone(buf.Bytes())
			telemetry.ReleaseBuffer(buf)

			// Optional Stage 5 Wasm / Custom Policy Sandbox Execution (with Fail-Open JG-EXT-601)
			sbRes := s.sandbox.Execute(r.Context(), rawBody, cfg.Extensions.WasmPlugins)
			rawBody = sbRes.ModifiedPayload

			sessionID := extractSessionID(r)
			var res guards.InspectionResult

			// Route 1: Model Context Protocol (MCP JSON-RPC 2.0) Traffic
			if cfg.Network.MCP.Enabled && mcp.IsJSONRPCPayload(rawBody) {
				mcpSrv := r.Header.Get("X-MCP-Server")
				mcpRes := s.mcpInspector.InspectPayload(rawBody, sessionID, mcpSrv, cfg)
				res = guards.InspectionResult{
					ModifiedBody: mcpRes.ModifiedBody,
					Status:       mcpRes.Status,
					Severity:     mcpRes.Severity,
					Codes:        mcpRes.Codes,
					PrunedTools:  mcpRes.PrunedCount,
					Blocked:      mcpRes.Blocked,
				}
			} else {
				// Route 2: Standard LLM Chat / Agent Completions Traffic
				res = s.guardEngine.InspectJSONPayload(rawBody, cfg)
			}

			// Merge any sandbox Fail-Open warning codes (JG-EXT-601)
			for _, sc := range sbRes.WarningCodes {
				if !slices.Contains(res.Codes, sc) {
					res.Codes = append(res.Codes, sc)
				}
				if res.Status == "CLEAN" {
					if cfg.Core.Mode == "shadow" {
						res.Status = "SHADOW_FLAGGED"
					} else {
						res.Status = "SANITIZED"
					}
					res.Severity = "CONFIG_WARNING"
				}
			}

			// Enforce Session Token Budget Circuit Breaker (JG-CFG-202)
			if s.circuitBreaker.CheckAndTrackTokens(sessionID, len(rawBody), cfg.Whitelist.CircuitBreaker) {
				if !slices.Contains(res.Codes, "JG-CFG-202") {
					res.Codes = append(res.Codes, "JG-CFG-202")
				}
				if res.Status == "CLEAN" {
					if cfg.Core.Mode == "shadow" {
						res.Status = "SHADOW_FLAGGED"
					} else {
						res.Status = "SANITIZED"
					}
					res.Severity = "CONFIG_WARNING"
				}
			}

			inboundLatencyUs = max(1, time.Since(inboundStart).Microseconds())

			if len(res.Codes) > 0 {
				s.logger.Warn("JaguarGate guard triggered",
					slog.String("status", res.Status),
					slog.String("severity", res.Severity),
					slog.String("codes", strings.Join(res.Codes, ",")),
					slog.String("path", r.URL.Path),
				)
			}

			if res.Blocked {
				s.metrics.RecordRequest(res.Status, res.Codes, res.PrunedTools, inboundLatencyUs)
				s.webhooks.Enqueue(telemetry.WebhookEvent{
					Status:      res.Status,
					Severity:    res.Severity,
					Codes:       res.Codes,
					Path:        r.URL.Path,
					PrunedTools: res.PrunedTools,
				}, cfg.Telemetry.Webhooks)

				if cfg.Telemetry.WarningFlags.EmitHTTPHeaders {
					w.Header().Set("X-JaguarGate-Status", res.Status)
					w.Header().Set("X-JaguarGate-Severity", res.Severity)
					w.Header().Set("X-JaguarGate-Codes", strings.Join(res.Codes, ","))
					w.Header().Set("X-JaguarGate-Latency-Us", strconv.FormatInt(inboundLatencyUs, 10))
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprintf(w, `{"error":{"message":"Request blocked by JaguarGate strict policy","codes":%q}}`, strings.Join(res.Codes, ","))
				return
			}

			r.Body = io.NopCloser(bytes.NewReader(res.ModifiedBody))
			r.ContentLength = int64(len(res.ModifiedBody))
			r.Header.Set("Content-Length", strconv.Itoa(len(res.ModifiedBody)))
			r = r.WithContext(context.WithValue(r.Context(), ctxInspectionKey{}, res))
		} else {
			inboundLatencyUs = max(1, time.Since(inboundStart).Microseconds())
		}

		ctx := context.WithValue(r.Context(), ctxInboundLatencyUsKey{}, inboundLatencyUs)
		ctx = context.WithValue(ctx, ctxUpstreamStartTimeKey{}, time.Now())
		r = r.WithContext(ctx)

		s.proxy.ServeHTTP(w, r)
	})

	return mux
}

// Start launches the configured HTTP, Unix Domain Socket, RPC, and Prometheus Metrics listeners concurrently.
func (s *GatewayServer) Start(ctx context.Context) error {
	cfg := s.cfgMgr.Get()
	handler := s.Handler()

	readTimeout := time.Duration(cfg.Network.Ingress.HTTP.ReadTimeoutMs) * time.Millisecond
	writeTimeout := time.Duration(cfg.Network.Ingress.HTTP.WriteTimeoutMs) * time.Millisecond

	errCh := make(chan error, 4)
	var wg sync.WaitGroup

	if cfg.Network.Ingress.HTTP.Enabled {
		s.httpServer = &http.Server{
			Addr:              cfg.Network.Ingress.HTTP.ListenAddr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.logger.Info(config.T(cfg.Core.Language, config.MsgServerStarting,
				cfg.Network.Ingress.HTTP.ListenAddr, cfg.Network.Egress.UpstreamURL, cfg.Core.Mode))
			if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("HTTP listener error: %w", err)
			}
		}()
	}

	if cfg.Network.Ingress.UnixSocket.Enabled {
		sockPath := cfg.Network.Ingress.UnixSocket.SocketPath
		s.udsPath = sockPath
		_ = os.Remove(sockPath)

		listener, err := net.Listen("unix", sockPath)
		if err != nil {
			return fmt.Errorf("unix socket listen (%s): %w", sockPath, err)
		}

		modeVal, err := strconv.ParseUint(cfg.Network.Ingress.UnixSocket.SocketMode, 8, 32)
		if err != nil || modeVal == 0 {
			modeVal = 0600
		}
		if err := os.Chmod(sockPath, os.FileMode(modeVal)); err != nil {
			_ = listener.Close()
			return fmt.Errorf("chmod unix socket: %w", err)
		}

		s.udsServer = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.logger.Info(config.T(cfg.Core.Language, config.MsgUDSStarting,
				sockPath, cfg.Network.Ingress.UnixSocket.SocketMode))
			if err := s.udsServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("UDS listener error: %w", err)
			}
		}()
	}

	if cfg.Network.Ingress.GRPC.Enabled && cfg.Network.Ingress.GRPC.ListenAddr != "" {
		s.rpcServer = &http.Server{
			Addr:              cfg.Network.Ingress.GRPC.ListenAddr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.rpcServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("RPC listener error: %w", err)
			}
		}()
	}

	if cfg.Telemetry.OpenTelemetry.Enabled && cfg.Telemetry.OpenTelemetry.PrometheusListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", s.metrics.Handler())
		s.metricsServer = &http.Server{
			Addr:              cfg.Telemetry.OpenTelemetry.PrometheusListen,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("Prometheus metrics listener error: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		s.logger.Info(config.T(cfg.Core.Language, config.MsgServerShutdown))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if s.httpServer != nil {
			_ = s.httpServer.Shutdown(shutdownCtx)
		}
		if s.udsServer != nil {
			_ = s.udsServer.Shutdown(shutdownCtx)
		}
		if s.rpcServer != nil {
			_ = s.rpcServer.Shutdown(shutdownCtx)
		}
		if s.metricsServer != nil {
			_ = s.metricsServer.Shutdown(shutdownCtx)
		}
		if s.udsPath != "" {
			_ = os.Remove(s.udsPath)
		}
		wg.Wait()
		return nil
	case err := <-errCh:
		return err
	}
}

func probeUpstream(egress config.EgressConfig) bool {
	if egress.UpstreamUnixSocket != "" {
		conn, err := net.DialTimeout("unix", egress.UpstreamUnixSocket, 300*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	u, err := url.Parse(egress.UpstreamURL)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	conn, err := net.DialTimeout("tcp", host, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func extractSessionID(r *http.Request) string {
	if r == nil {
		return "default_session"
	}
	if sid := strings.TrimSpace(r.Header.Get("X-JaguarGate-Session-ID")); sid != "" {
		return sid
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return "default_session"
}
