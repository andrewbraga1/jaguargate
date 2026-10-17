package config

import "fmt"

// MsgKey represents a localized message identifier.
type MsgKey string

const (
	MsgCheckSuccess       MsgKey = "CHECK_SUCCESS"
	MsgCheckFailed        MsgKey = "CHECK_FAILED"
	MsgServerStarting     MsgKey = "SERVER_STARTING"
	MsgUDSStarting        MsgKey = "UDS_STARTING"
	MsgServerShutdown     MsgKey = "SERVER_SHUTDOWN"
	MsgHotReloadSuccess   MsgKey = "HOT_RELOAD_SUCCESS"
	MsgHotReloadFailed    MsgKey = "HOT_RELOAD_FAILED"
	MsgErrInvalidVersion  MsgKey = "ERR_INVALID_VERSION"
	MsgErrInvalidLang     MsgKey = "ERR_INVALID_LANG"
	MsgErrInvalidPreset   MsgKey = "ERR_INVALID_PRESET"
	MsgErrInvalidMode     MsgKey = "ERR_INVALID_MODE"
	MsgErrNoIngressActive MsgKey = "ERR_NO_INGRESS_ACTIVE"
	MsgErrInvalidUpstream MsgKey = "ERR_INVALID_UPSTREAM"
	MsgErrInvalidSocket   MsgKey = "ERR_INVALID_SOCKET"
)

var messages = map[string]map[MsgKey]string{
	"pt-BR": {
		MsgCheckSuccess:       "🐆 [JaguarGate] Configuração válida! Perfil '%s' ativo em modo '%s'. Pronto para o bote.",
		MsgCheckFailed:        "❌ [JaguarGate] Falha na validação da configuração: %v",
		MsgServerStarting:     "🐆 [JaguarGate] Escudo HTTP ativo em %s -> destino %s (modo: %s)",
		MsgUDSStarting:        "⚡ [JaguarGate] Escudo Unix Domain Socket ativo em %s (permissão: %s)",
		MsgServerShutdown:     "🛑 [JaguarGate] Encerrando conexões de forma segura (Graceful Shutdown)...",
		MsgHotReloadSuccess:   "♻️ [JaguarGate] Configuração recarregada em memória (Lock-Free Hot-Reload) sem interrupção.",
		MsgHotReloadFailed:    "⚠️ [JaguarGate] Ignorando recarregamento: o arquivo editado contém erros (%v). Mantendo configuração anterior segura.",
		MsgErrInvalidVersion:  "core.version deve ser '1.0' (recebido: '%s')",
		MsgErrInvalidLang:     "core.language deve ser 'pt-BR' ou 'en' (recebido: '%s')",
		MsgErrInvalidPreset:   "core.preset deve ser 'permissive', 'balanced' ou 'strict' (recebido: '%s')",
		MsgErrInvalidMode:     "core.mode deve ser 'shadow', 'sanitize_and_warn' ou 'hard_block' (recebido: '%s')",
		MsgErrNoIngressActive: "nenhuma porta de entrada ativa: habilite network.ingress.http, unix_socket ou grpc",
		MsgErrInvalidUpstream: "network.egress.upstream_url inválido ou vazio: '%s'",
		MsgErrInvalidSocket:   "network.ingress.unix_socket.socket_path não pode ser vazio quando unix_socket está ativo",
	},
	"en": {
		MsgCheckSuccess:       "🐆 [JaguarGate] Configuration valid! Preset '%s' active in '%s' mode. Ready to pounce.",
		MsgCheckFailed:        "❌ [JaguarGate] Configuration validation failed: %v",
		MsgServerStarting:     "🐆 [JaguarGate] HTTP shield listening on %s -> upstream %s (mode: %s)",
		MsgUDSStarting:        "⚡ [JaguarGate] Unix Domain Socket shield active at %s (mode: %s)",
		MsgServerShutdown:     "🛑 [JaguarGate] Gracefully shutting down active connections...",
		MsgHotReloadSuccess:   "♻️ [JaguarGate] Configuration hot-reloaded in memory (Lock-Free) with zero downtime.",
		MsgHotReloadFailed:    "⚠️ [JaguarGate] Skipping hot-reload: modified file has errors (%v). Keeping previous safe config.",
		MsgErrInvalidVersion:  "core.version must be '1.0' (got: '%s')",
		MsgErrInvalidLang:     "core.language must be 'en' or 'pt-BR' (got: '%s')",
		MsgErrInvalidPreset:   "core.preset must be 'permissive', 'balanced', or 'strict' (got: '%s')",
		MsgErrInvalidMode:     "core.mode must be 'shadow', 'sanitize_and_warn', or 'hard_block' (got: '%s')",
		MsgErrNoIngressActive: "no active ingress transport: enable at least one of http, unix_socket, or grpc",
		MsgErrInvalidUpstream: "invalid or empty network.egress.upstream_url: '%s'",
		MsgErrInvalidSocket:   "network.ingress.unix_socket.socket_path cannot be empty when unix_socket is enabled",
	},
}

// T translates a message key into the configured language ("en" or "pt-BR").
func T(lang string, key MsgKey, args ...any) string {
	dict, ok := messages[lang]
	if !ok {
		dict = messages["en"]
	}
	pattern, ok := dict[key]
	if !ok {
		return string(key)
	}
	if len(args) == 0 {
		return pattern
	}
	return fmt.Sprintf(pattern, args...)
}