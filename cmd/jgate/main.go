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

	"github.com/jaguargate/jaguargate/internal/config"
	"github.com/jaguargate/jaguargate/internal/redteam"
	"github.com/jaguargate/jaguargate/internal/telemetry"
	"github.com/jaguargate/jaguargate/internal/transport"
)

const Version = "v1.0.0"

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
		fmt.Fprintln(os.Stderr, config.T(activeLang, config.MsgConfigInvalid, err))
		os.Exit(1)
	}

	upstreamReachable := checkTCPReachability(cfg.Network.Egress.UpstreamURL)

	listenAddr := cfg.Network.Ingress.HTTP.ListenAddr
	if strings.HasPrefix(listenAddr, ":") {
		listenAddr = "127.0.0.1" + listenAddr
	}
	gatewayBaseURL := "http://" + listenAddr

	if isPT {
		fmt.Println("===============================================================================")
		fmt.Printf("  JAGUARGATE (%s) — DIAGNÓSTICO E GUIA DE CONEXÃO DEV / DEVOPS\n", Version)
		fmt.Println("===============================================================================")
		fmt.Printf("  [OK] Arquivo de Configuração : %s (Modo: %s | Preset: %s)\n", cfgPath, cfg.Core.Mode, cfg.Core.Preset)
		fmt.Printf("  [OK] Escuta HTTP Local       : %s\n", gatewayBaseURL)
		fmt.Printf("  [OK] Destino Upstream IA     : %s (Conectável agora: %v)\n", cfg.Network.Egress.UpstreamURL, upstreamReachable)
		fmt.Printf("  [OK] Endpoint Prometheus     : %s/metrics\n", gatewayBaseURL)
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
		fmt.Printf("     curl -s %s/metrics\n", gatewayBaseURL)
		fmt.Println("     Header de Latência por Request: X-JaguarGate-Latency-Us")
		fmt.Println("===============================================================================")
		return
	}

	fmt.Println("===============================================================================")
	fmt.Printf("  JAGUARGATE (%s) — DIAGNOSTICS & DEV / DEVOPS CONNECTION GUIDE\n", Version)
	fmt.Println("===============================================================================")
	fmt.Printf("  [OK] Configuration File      : %s (Mode: %s | Preset: %s)\n", cfgPath, cfg.Core.Mode, cfg.Core.Preset)
	fmt.Printf("  [OK] HTTP Ingress Listener   : %s\n", gatewayBaseURL)
	fmt.Printf("  [OK] Upstream AI Target      : %s (Currently Reachable: %v)\n", cfg.Network.Egress.UpstreamURL, upstreamReachable)
	fmt.Printf("  [OK] Prometheus Endpoint     : %s/metrics\n", gatewayBaseURL)
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
	fmt.Printf("     curl -s %s/metrics\n", gatewayBaseURL)
	fmt.Println("     Per-Request Latency Header: X-JaguarGate-Latency-Us")
	fmt.Println("===============================================================================")
}

func checkTCPReachability(rawURL string) bool {
	u, err := url.Parse(rawURL)
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
