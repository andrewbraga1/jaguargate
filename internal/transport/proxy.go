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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jaguargate/jaguargate/internal/config"
	"github.com/jaguargate/jaguargate/internal/guards"
	"github.com/jaguargate/jaguargate/internal/stream"
	"github.com/jaguargate/jaguargate/internal/telemetry"
)

type ctxInspectionKey struct{}
type ctxStartTimeKey struct{}

// GatewayServer manages the multi-transport listeners and the low-latency reverse proxy.
type GatewayServer struct {
	cfgMgr      *config.Manager
	logger      *slog.Logger
	bufferPool  *telemetry.ByteSlicePool
	guardEngine *guards.Engine
	proxy       *httputil.ReverseProxy
	httpServer  *http.Server
	udsServer   *http.Server
	udsPath     string
}

// NewGatewayServer initializes the reverse proxy with pre-warmed keep-alive pools, buffer recycling, and OWASP/Stream guards.
func NewGatewayServer(cfgMgr *config.Manager, logger *slog.Logger) (*GatewayServer, error) {
	snap := cfgMgr.Get()
	targetURL, err := url.Parse(snap.Network.Egress.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	bufPool := telemetry.NewByteSlicePool()
	guardEngine := guards.NewEngine(guards.NewPIIVault())

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
			activeCfg := cfgMgr.Get()
			inboundRes, _ := resp.Request.Context().Value(ctxInspectionKey{}).(guards.InspectionResult)

			// Calculate monotonic gateway latency in microseconds for DevOps/APM observability
			if startTime, ok := resp.Request.Context().Value(ctxStartTimeKey{}).(time.Time); ok {
				resp.Header.Set("X-JaguarGate-Latency-Us", strconv.FormatInt(time.Since(startTime).Microseconds(), 10))
			}

			contentType := resp.Header.Get("Content-Type")
			isSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream")

			if isSSE && resp.Body != nil {
				// Enterprise SSE Anti-Buffering headers for Nginx, Traefik, Cloudflare & Docker
				resp.Header.Set("X-Accel-Buffering", "no")
				resp.Header.Set("Cache-Control", "no-cache, no-transform")
				resp.Header.Del("Content-Length")

				if activeCfg.Telemetry.WarningFlags.EmitHTTPHeaders {
					status := inboundRes.Status
					severity := inboundRes.Severity
					if status == "" {
						status = "CLEAN"
						severity = "NONE"
					}
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

				resp.Body = stream.NewSSEInspector(resp.Body, activeCfg, guardEngine.Vault(), inboundRes, resp.Trailer)
				return nil
			}

			// Non-streaming response: inspect output JSON (Tool Call Firewall + Canary Leak + Output Sanitizer + PII Restore)
			if resp.Body != nil {
				rawResp, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err == nil {
					outRes := guardEngine.SanitizeOutputJSON(rawResp, inboundRes, activeCfg)
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
					resp.Body = io.NopCloser(bytes.NewReader(outRes.ModifiedBody))
					resp.ContentLength = int64(len(outRes.ModifiedBody))
					resp.Header.Set("Content-Length", strconv.Itoa(len(outRes.ModifiedBody)))
					return nil
				}
			}

			if activeCfg.Telemetry.WarningFlags.EmitHTTPHeaders && resp.Header.Get("X-JaguarGate-Status") == "" {
				resp.Header.Set("X-JaguarGate-Status", "CLEAN")
				resp.Header.Set("X-JaguarGate-Severity", "NONE")
			}
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
		cfgMgr:      cfgMgr,
		logger:      logger,
		bufferPool:  bufPool,
		guardEngine: guardEngine,
		proxy:       rp,
	}, nil
}

// Handler wraps the reverse proxy with OWASP Input Guards, payload size limits, and healthcheck.
func (s *GatewayServer) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		cfg := s.cfgMgr.Get()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-JaguarGate-Status", "CLEAN")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","version":%q,"mode":%q,"preset":%q}`,
			cfg.Core.Version, cfg.Core.Mode, cfg.Core.Preset)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		ctx := context.WithValue(r.Context(), ctxStartTimeKey{}, startTime)
		r = r.WithContext(ctx)

		cfg := s.cfgMgr.Get()
		maxBytes := cfg.Network.Ingress.HTTP.MaxPayloadMB * 1024 * 1024
		if maxBytes > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}

		// Execute OWASP Input Inspection on requests carrying a body
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

			res := s.guardEngine.InspectJSONPayload(rawBody, cfg)
			if len(res.Codes) > 0 {
				s.logger.Warn("JaguarGate input guard triggered",
					slog.String("status", res.Status),
					slog.String("severity", res.Severity),
					slog.String("codes", strings.Join(res.Codes, ",")),
					slog.String("path", r.URL.Path),
				)
			}

			if res.Blocked {
				if cfg.Telemetry.WarningFlags.EmitHTTPHeaders {
					w.Header().Set("X-JaguarGate-Status", res.Status)
					w.Header().Set("X-JaguarGate-Severity", res.Severity)
					w.Header().Set("X-JaguarGate-Codes", strings.Join(res.Codes, ","))
					w.Header().Set("X-JaguarGate-Latency-Us", strconv.FormatInt(time.Since(startTime).Microseconds(), 10))
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
		}

		s.proxy.ServeHTTP(w, r)
	})

	return mux
}

// Start launches the configured HTTP and/or Unix Domain Socket listeners concurrently.
func (s *GatewayServer) Start(ctx context.Context) error {
	cfg := s.cfgMgr.Get()
	handler := s.Handler()

	readTimeout := time.Duration(cfg.Network.Ingress.HTTP.ReadTimeoutMs) * time.Millisecond
	writeTimeout := time.Duration(cfg.Network.Ingress.HTTP.WriteTimeoutMs) * time.Millisecond

	errCh := make(chan error, 2)
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
		if s.udsPath != "" {
			_ = os.Remove(s.udsPath)
		}
		wg.Wait()
		return nil
	case err := <-errCh:
		return err
	}
}
