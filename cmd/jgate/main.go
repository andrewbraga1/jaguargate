package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/andrewbraga1/jaguargate/internal/config"
	"github.com/andrewbraga1/jaguargate/internal/redteam"
	"github.com/andrewbraga1/jaguargate/internal/telemetry"
	"github.com/andrewbraga1/jaguargate/internal/transport"
)

const Version = "v1.0.4"

func main() {
	if len(os.Args) < 2 {
		printUsage("en")
		os.Exit(1)
	}

	subcmd := os.Args[1]
	fs := flag.NewFlagSet(subcmd, flag.ExitOnError)
	cfgPath := fs.String("c", "jaguargate.yaml", "Path to jaguargate.yaml or jaguargate.json")
	langFlag := fs.String("lang", "", "Output language override: 'en' (default) or 'pt-BR'")
	_ = fs.Parse(os.Args[2:])

	switch subcmd {
	case "version", "-v", "--version":
		fmt.Printf("JaguarGate (jgate) %s\n", Version)

	case "check":
		cfg, err := config.LoadFromFile(*cfgPath)
		activeLang := resolveLang(*langFlag, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, config.T(activeLang, config.MsgConfigInvalid, err))
			os.Exit(1)
		}
		fmt.Println(config.T(activeLang, config.MsgConfigValid, cfg.Core.Mode, cfg.Core.Preset, cfg.Network.Egress.UpstreamURL))

	case "doctor":
		runDoctor(*cfgPath, *langFlag)

	case "pounce":
		cfg, _ := config.LoadFromFile(*cfgPath)
		activeLang := resolveLang(*langFlag, cfg)
		report := redteam.RunPounceSuite(activeLang)
		fmt.Print(report.FormatReport())
		if !report.AllPassed {
			os.Exit(1)
		}

	case "serve":
		runServe(*cfgPath, *langFlag)

	default:
		printUsage(resolveLang(*langFlag, nil))
		os.Exit(1)
	}
}

func runServe(cfgPath, langOverride string) {
	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal config error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = mgr.Close() }()

	snap := mgr.Get()
	if langOverride != "" {
		snap.Core.Language = langOverride
	}

	logger := telemetry.NewZeroTrustLogger(
		os.Stdout,
		snap.Telemetry.Logging.Level,
		strings.EqualFold(snap.Telemetry.Logging.Format, "json"),
		snap.Telemetry.Logging.ZeroTrustPrompts,
		snap.Core.Language,
	)

	_ = mgr.StartHotReload(
		func(newCfg *config.Config) {
			logger.Info("JaguarGate configuration hot-reloaded atomically",
				slog.String("mode", newCfg.Core.Mode),
				slog.String("preset", newCfg.Core.Preset),
			)
		},
		func(reloadErr error) {
			logger.Error("JaguarGate rejected invalid hot-reload edit (previous config remains active)",
				slog.String("error", reloadErr.Error()),
			)
		},
	)

	srv, err := transport.NewGatewayServer(mgr, logger)
	if err != nil {
		logger.Error("failed to initialize GatewayServer", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		logger.Error("gateway server terminated with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func runDoctor(cfgPath, langOverride string) {
	cfg, err := config.LoadFromFile(cfgPath)
	activeLang := resolveLang(langOverride, cfg)
	isPT := strings.EqualFold(activeLang, "pt-BR") || strings.EqualFold(activeLang, "pt")

	if err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] %s\n", config.T(activeLang, config.MsgConfigInvalid, err))
		os.Exit(1)
	}

	// 1. Evaluate HTTP Ingress Listener status dynamically
	listenAddr := cfg.Network.Ingress.HTTP.ListenAddr
	if strings.HasPrefix(listenAddr, ":") {
		listenAddr = "127.0.0.1" + listenAddr
	}
	gatewayBaseURL := "http://" + listenAddr
	httpBadge := statusBadge(cfg.Network.Ingress.HTTP.Enabled, true)

	// 2. Evaluate Upstream AI Target reachability dynamically (TCP or Unix Socket)
	upstreamTarget := cfg.Network.Egress.UpstreamURL
	var upstreamReachable bool
	if cfg.Network.Egress.UpstreamUnixSocket != "" {
		upstreamTarget = "unix://" + cfg.Network.Egress.UpstreamUnixSocket
		upstreamReachable = checkUnixReachability(cfg.Network.Egress.UpstreamUnixSocket)
	} else {
		upstreamReachable = checkTCPReachability(cfg.Network.Egress.UpstreamURL)
	}
	upstreamBadge := statusBadge(upstreamReachable, false)

	// 3. Evaluate State Store (L1 Memory vs L2 Redis + Fail-Open) dynamically
	stateBadge, stateSummary := evaluateStateStoreStatus(cfg.Extensions.StateStore, isPT)

	// 4. Evaluate Prometheus Metrics endpoint URL dynamically
	metricsURL := gatewayBaseURL + "/metrics"
	if cfg.Telemetry.OpenTelemetry.Enabled && cfg.Telemetry.OpenTelemetry.PrometheusListen != "" {
		promAddr := cfg.Telemetry.OpenTelemetry.PrometheusListen
		if strings.HasPrefix(promAddr, ":") {
			promAddr = "127.0.0.1" + promAddr
		}
		metricsURL = "http://" + promAddr + "/metrics"
	}

	if isPT {
		fmt.Println("===============================================================================")
		fmt.Printf("  JAGUARGATE (%s) — DIAGNÓSTICO E GUIA DE CONEXÃO DEV / DEVOPS\n", Version)
		fmt.Println("===============================================================================")
		fmt.Printf("  [OK]   Arquivo de Configuração : %s (Modo: %s | Preset: %s)\n", cfgPath, cfg.Core.Mode, cfg.Core.Preset)
		fmt.Printf("  %s Escuta HTTP Local       : %s (Ativo: %v)\n", httpBadge, gatewayBaseURL, cfg.Network.Ingress.HTTP.Enabled)
		fmt.Printf("  %s Destino Upstream IA     : %s (Conectável agora: %v)\n", upstreamBadge, upstreamTarget, upstreamReachable)
		fmt.Printf("  %s Estado / Cofre L1-L2    : %s\n", stateBadge, stateSummary)
		fmt.Printf("  [OK]   Probes & Prometheus     : %s/readyz | %s\n", gatewayBaseURL, metricsURL)
		fmt.Println("-------------------------------------------------------------------------------")
		fmt.Println("  1. CONECTAR SDKs, CLINE, CURSOR OU CONTINUE (NA MESMA MÁQUINA):")
		fmt.Printf("     export OPENAI_BASE_URL=\"%s/v1\"\n", gatewayBaseURL)
		fmt.Printf("     export ANTHROPIC_BASE_URL=\"%s\"\n", gatewayBaseURL)
		fmt.Printf("     export OLLAMA_HOST=\"%s\"\n", gatewayBaseURL)
		fmt.Println("\n  2. RODAR EM DOCKER OU EM MÁQUINA / VM SEPARADA NA REDE:")
		fmt.Println("     export JAGUARGATE_LISTEN_ADDR=\"0.0.0.0:4010\"")
		fmt.Printf("     export JAGUARGATE_UPSTREAM_URL=\"%s\"\n", cfg.Network.Egress.UpstreamURL)
		fmt.Println("     ./jgate serve -c jaguargate.yaml")
		fmt.Println("\n  3. OBSERVABILIDADE (PROMETHEUS / GRAFANA / DATADOG):")
		fmt.Printf("     curl -s %s\n", metricsURL)
		fmt.Printf("     curl -s %s/readyz\n", gatewayBaseURL)
		fmt.Println("     Headers de Latência : X-JaguarGate-Latency-Us (Gateway) | X-JaguarGate-Upstream-Ms (LLM)")
		fmt.Println("===============================================================================")
		return
	}

	fmt.Println("===============================================================================")
	fmt.Printf("  JAGUARGATE (%s) — DIAGNOSTICS & DEV / DEVOPS CONNECTION GUIDE\n", Version)
	fmt.Println("===============================================================================")
	fmt.Printf("  [OK]   Configuration File      : %s (Mode: %s | Preset: %s)\n", cfgPath, cfg.Core.Mode, cfg.Core.Preset)
	fmt.Printf("  %s HTTP Ingress Listener   : %s (Enabled: %v)\n", httpBadge, gatewayBaseURL, cfg.Network.Ingress.HTTP.Enabled)
	fmt.Printf("  %s Upstream AI Target      : %s (Currently Reachable: %v)\n", upstreamBadge, upstreamTarget, upstreamReachable)
	fmt.Printf("  %s L1/L2 State Store       : %s\n", stateBadge, stateSummary)
	fmt.Printf("  [OK]   Probes & Prometheus     : %s/readyz | %s\n", gatewayBaseURL, metricsURL)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("  1. CONNECT SDKs, CLINE, CURSOR, OR CONTINUE (SAME HOST):")
	fmt.Printf("     export OPENAI_BASE_URL=\"%s/v1\"\n", gatewayBaseURL)
	fmt.Printf("     export ANTHROPIC_BASE_URL=\"%s\"\n", gatewayBaseURL)
	fmt.Printf("     export OLLAMA_HOST=\"%s\"\n", gatewayBaseURL)
	fmt.Println("\n  2. RUN IN DOCKER OR ON A DEDICATED REMOTE VM / HOST:")
	fmt.Println("     export JAGUARGATE_LISTEN_ADDR=\"0.0.0.0:4010\"")
	fmt.Printf("     export JAGUARGATE_UPSTREAM_URL=\"%s\"\n", cfg.Network.Egress.UpstreamURL)
	fmt.Println("     ./jgate serve -c jaguargate.yaml")
	fmt.Println("\n  3. OBSERVABILITY (PROMETHEUS / GRAFANA / DATADOG):")
	fmt.Printf("     curl -s %s\n", metricsURL)
	fmt.Printf("     curl -s %s/readyz\n", gatewayBaseURL)
	fmt.Println("     Latency Headers     : X-JaguarGate-Latency-Us (Gateway) | X-JaguarGate-Upstream-Ms (LLM)")
	fmt.Println("===============================================================================")
}

func statusBadge(ok bool, warnOnly bool) string {
	if ok {
		return "[OK]  "
	}
	if warnOnly {
		return "[WARN]"
	}
	return "[FAIL]"
}

func evaluateStateStoreStatus(sc config.StateStoreConfig, isPT bool) (string, string) {
	driver := strings.ToLower(strings.TrimSpace(sc.Driver))
	if driver == "" || driver == "memory" {
		if isPT {
			return "[OK]  ", "Memória Local L1 (Ultra-Baixa Latência)"
		}
		return "[OK]  ", "In-Memory L1 (Sub-Microsecond Local Store)"
	}

	// Driver is "redis": check if reachable
	redisReachable := checkTCPReachability(sc.RedisURL)
	if redisReachable {
		if isPT {
			return "[OK]  ", fmt.Sprintf("Híbrido L1 + Redis L2 AES-256-GCM (%s online)", sc.RedisURL)
		}
		return "[OK]  ", fmt.Sprintf("Hybrid L1 + Redis L2 AES-256-GCM (%s reachable)", sc.RedisURL)
	}

	if sc.FailOpenToLocalMemory {
		if isPT {
			return "[WARN]", fmt.Sprintf("Redis (%s) offline -> Fail-Open para Memória L1 ativo (JG-EXT-602)", sc.RedisURL)
		}
		return "[WARN]", fmt.Sprintf("Redis (%s) unreachable -> L1 Memory Fail-Open active (JG-EXT-602)", sc.RedisURL)
	}

	if isPT {
		return "[FAIL]", fmt.Sprintf("Redis (%s) inacessível e Fail-Open desativado", sc.RedisURL)
	}
	return "[FAIL]", fmt.Sprintf("Redis (%s) unreachable and Fail-Open disabled", sc.RedisURL)
}

func checkTCPReachability(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	if !strings.Contains(rawURL, "://") {
		conn, err := net.DialTimeout("tcp", rawURL, 300*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		switch u.Scheme {
		case "https":
			host += ":443"
		case "redis", "rediss":
			host += ":6379"
		default:
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

func checkUnixReachability(sockPath string) bool {
	if sockPath == "" {
		return false
	}
	conn, err := net.DialTimeout("unix", sockPath, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func resolveLang(flagVal string, cfg *config.Config) string {
	if strings.TrimSpace(flagVal) != "" {
		return strings.TrimSpace(flagVal)
	}
	if envLang := strings.TrimSpace(os.Getenv("JAGUARGATE_LANG")); envLang != "" {
		return envLang
	}
	if cfg != nil && strings.TrimSpace(cfg.Core.Language) != "" {
		return cfg.Core.Language
	}
	return "en"
}

func printUsage(lang string) {
	isPT := strings.EqualFold(lang, "pt-BR") || strings.EqualFold(lang, "pt")
	if isPT {
		fmt.Println("Uso: jgate <comando> [-c jaguargate.yaml] [--lang en|pt-BR]")
		fmt.Println("Comandos:")
		fmt.Println("  serve    Inicia o gateway de segurança JaguarGate (HTTP / UDS / MCP)")
		fmt.Println("  check    Valida a sintaxe e as regras do jaguargate.yaml")
		fmt.Println("  doctor   Exibe diagnóstico e guia rápido de conexão para Devs/DevOps")
		fmt.Println("  pounce   Executa a suíte integrada de Red-Teaming (8 vetores OWASP/MCP)")
		fmt.Println("  version  Exibe a versão do binário")
		return
	}
	fmt.Println("Usage: jgate <command> [-c jaguargate.yaml] [--lang en|pt-BR]")
	fmt.Println("Commands:")
	fmt.Println("  serve    Start the JaguarGate security gateway (HTTP / UDS / MCP)")
	fmt.Println("  check    Validate jaguargate.yaml syntax and security invariants")
	fmt.Println("  doctor   Run diagnostics and print Dev/DevOps quick-connection snippets")
	fmt.Println("  pounce   Execute built-in OWASP LLM & MCP Red-Teaming suite (8 vectors)")
	fmt.Println("  version  Print binary version")
}
