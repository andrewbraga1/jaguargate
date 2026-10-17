package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jaguargate/jaguargate/internal/config"
	"github.com/jaguargate/jaguargate/internal/telemetry"
	"github.com/jaguargate/jaguargate/internal/transport"
)

const version = "v0.2.0-core"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	cmdFlags := flag.NewFlagSet(subcmd, flag.ExitOnError)
	cfgPath := cmdFlags.String("c", "configs/jaguargate.yaml", "Path to jaguargate.yaml or jaguargate.json")
	_ = cmdFlags.Parse(os.Args[2:])

	switch subcmd {
	case "version", "-v", "--version":
		fmt.Printf("🐆 JaguarGate (jgate / onca) %s\n", version)

	case "check":
		cfg, err := config.LoadFromFile(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, config.T("pt-BR", config.MsgCheckFailed, err))
			os.Exit(1)
		}
		fmt.Println(config.T(cfg.Core.Language, config.MsgCheckSuccess, cfg.Core.Preset, cfg.Core.Mode))

	case "start":
		mgr, err := config.NewManager(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, config.T("pt-BR", config.MsgCheckFailed, err))
			os.Exit(1)
		}
		defer func() { _ = mgr.Close() }()

		snap := mgr.Get()
		logger := telemetry.NewZeroTrustLogger(
			os.Stdout,
			snap.Telemetry.Logging.Level,
			snap.Telemetry.Logging.Format == "json",
			snap.Telemetry.Logging.ZeroTrustRedaction,
			snap.Telemetry.Logging.RedactionPlaceholder,
		)

		_ = mgr.StartHotReload(
			func(newCfg *config.Config) {
				logger.Info(config.T(newCfg.Core.Language, config.MsgHotReloadSuccess),
					slog.String("preset", newCfg.Core.Preset),
					slog.String("mode", newCfg.Core.Mode),
				)
			},
			func(reloadErr error) {
				cur := mgr.Get()
				logger.Warn(config.T(cur.Core.Language, config.MsgHotReloadFailed, reloadErr))
			},
		)

		srv, err := transport.NewGatewayServer(mgr, logger)
		if err != nil {
			logger.Error("failed to initialize gateway server", slog.String("error", err.Error()))
			os.Exit(1)
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		if err := srv.Start(ctx); err != nil {
			logger.Error("gateway terminated with error", slog.String("error", err.Error()))
			os.Exit(1)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`🐆 JaguarGate (jgate / onca) — Ultra-low latency AI, Agent & MCP Security Gateway

Usage / Uso:
  jgate check [-c configs/jaguargate.yaml]   Validate configuration syntax & security presets
  jgate start [-c configs/jaguargate.yaml]   Start the multi-transport security gateway
  jgate version                              Print version information`)
}