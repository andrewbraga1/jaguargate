package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jaguargate/jaguargate/internal/config"
	"github.com/jaguargate/jaguargate/internal/telemetry"
)

// GatewayServer manages the multi-transport listeners and the low-latency reverse proxy.
type GatewayServer struct {
	cfgMgr     *config.Manager
	logger     *slog.Logger
	bufferPool *telemetry.ByteSlicePool
	proxy      *httputil.ReverseProxy
	httpServer *http.Server
	udsServer  *http.Server
	udsPath    string
}

// NewGatewayServer initializes the reverse proxy with pre-warmed keep-alive pools and buffer recycling.
func NewGatewayServer(cfgMgr *config.Manager, logger *slog.Logger) (*GatewayServer, error) {
	snap := cfgMgr.Get()
	targetURL, err := url.Parse(snap.Network.Egress.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	bufPool := telemetry.NewByteSlicePool()

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Custom Transport supporting both high-concurrency TCP/HTTP2 and Kernel-level Unix Socket Egress
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
			if activeCfg.Telemetry.WarningFlags.EmitHTTPHeaders {
				if resp.Header.Get("X-JaguarGate-Status") == "" {
					resp.Header.Set("X-JaguarGate-Status", "CLEAN")
					resp.Header.Set("X-JaguarGate-Severity", "NONE")
				}
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
		cfgMgr:     cfgMgr,
		logger:     logger,
		bufferPool: bufPool,
		proxy:      rp,
	}, nil
}

// Handler wraps the reverse proxy with payload size protection and healthcheck endpoint.
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
		cfg := s.cfgMgr.Get()
		maxBytes := cfg.Network.Ingress.HTTP.MaxPayloadMB * 1024 * 1024
		if maxBytes > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
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