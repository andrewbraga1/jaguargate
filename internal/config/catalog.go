package config

import (
	"fmt"
	"strings"
)

// Message catalog keys for single-language output (EN default, PT-BR optional).
const (
	MsgConfigValid    = "config_valid"
	MsgConfigInvalid  = "config_invalid"
	MsgServerStarting = "server_starting"
	MsgUDSStarting    = "uds_starting"
	MsgServerShutdown = "server_shutdown"
)

// T returns the localized string for the active language ("en" by default, "pt-BR" when configured).
func T(lang, key string, args ...any) string {
	isPT := strings.EqualFold(strings.TrimSpace(lang), "pt-BR") || strings.EqualFold(strings.TrimSpace(lang), "pt")

	var format string
	switch key {
	case MsgConfigValid:
		if isPT {
			format = "Configuração JaguarGate válida (modo=%s, preset=%s, upstream=%s)"
		} else {
			format = "JaguarGate configuration valid (mode=%s, preset=%s, upstream=%s)"
		}
	case MsgConfigInvalid:
		if isPT {
			format = "Falha na validação da configuração: %v"
		} else {
			format = "Configuration validation failed: %v"
		}
	case MsgServerStarting:
		if isPT {
			format = "JaguarGate HTTP escutando em %s -> upstream %s (modo=%s)"
		} else {
			format = "JaguarGate HTTP listening on %s -> upstream %s (mode=%s)"
		}
	case MsgUDSStarting:
		if isPT {
			format = "JaguarGate Unix Domain Socket ativo em %s (permissão=%s)"
		} else {
			format = "JaguarGate Unix Domain Socket active at %s (mode=%s)"
		}
	case MsgServerShutdown:
		if isPT {
			format = "Encerrando JaguarGate de forma graciosa..."
		} else {
			format = "Shutting down JaguarGate gracefully..."
		}
	default:
		return key
	}

	if len(args) > 0 {
		return fmt.Sprintf(format, args...)
	}
	return format
}
