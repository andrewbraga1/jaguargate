package config

import (
	"fmt"
	"strings"
)

// Canonical RE2 pattern expressions shared across Guards (PIIVault/Output DLP) and Zero-Trust Telemetry.
const (
	RegexExprPEMBlock         = `(?is)-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?(?:-----END(?: [A-Z0-9]+)* PRIVATE KEY-----|$)`
	RegexExprPEMBegin         = `(?i)-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----`
	RegexExprPEMEnd           = `(?i)-----END(?: [A-Z0-9]+)* PRIVATE KEY-----`
	RegexExprProviderFormat   = `\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`
	RegexExprCloudAccessID    = `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`
	RegexExprThreePartJWS     = `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`
	RegexExprAuthHeaderScheme = `(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*`
	RegexExprCNPJ             = `\b(?:[A-Za-z0-9]{2}\.[A-Za-z0-9]{3}\.[A-Za-z0-9]{3}/[A-Za-z0-9]{4}-\d{2}|[A-Za-z0-9]{8}/[A-Za-z0-9]{4}-\d{2}|\d{14})\b`
	RegexExprPaymentNumber    = `\b\d(?:[ -]?\d){12,18}\b`
	RegexExprCPFFormatted     = `\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`
	RegexExprCPFRaw           = `\b\d{11}\b`
	RegexExprPhoneBR          = `(?:\+55[\s-]?|\b55[\s-])?(?:\([1-9][1-9]\)[\s-]?|\b[1-9][1-9][\s-]?)(?:9\d{4}|[2-5]\d{3})[\s-]?\d{4}\b|(?:\+55|\b55)[1-9][1-9](?:9\d{8}|[2-5]\d{7})\b`
	RegexExprEmail            = `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`
	RegexExprVaultPlaceholder = `\x3cJG_PII_[A-Z0-9_]+_[0-9a-f]{8,32}\x3e`
)

// Message catalog keys for single-language output (EN default, PT-BR optional).
const (
	MsgConfigValid           = "config_valid"
	MsgConfigInvalid         = "config_invalid"
	MsgServerStarting        = "server_starting"
	MsgUDSStarting           = "uds_starting"
	MsgServerShutdown        = "server_shutdown"
	MsgCanaryPrevented       = "canary_prevented"
	MsgCanaryHalted          = "canary_halted"
	MsgRestrictedImage       = "restricted_image"
	MsgRestrictedScript      = "restricted_script"
	MsgRestrictedSecret      = "restricted_secret"
	MsgUnauthorizedToolOmit  = "unauthorized_tool_omitted_bracket"
	MsgUnauthorizedToolError = "unauthorized_tool_omitted_plain"
)

type localizedTemplate struct {
	EN string
	PT string
}

var messageCatalog = map[string]localizedTemplate{
	MsgConfigValid: {
		EN: "JaguarGate configuration valid (mode=%s, preset=%s, upstream=%s)",
		PT: "Configuração JaguarGate válida (modo=%s, preset=%s, upstream=%s)",
	},
	MsgConfigInvalid: {
		EN: "Configuration validation failed: %v",
		PT: "Falha na validação da configuração: %v",
	},
	MsgServerStarting: {
		EN: "JaguarGate HTTP listening on %s -> upstream %s (mode=%s)",
		PT: "JaguarGate HTTP escutando em %s -> upstream %s (modo=%s)",
	},
	MsgUDSStarting: {
		EN: "JaguarGate Unix Domain Socket active at %s (mode=%s)",
		PT: "JaguarGate Unix Domain Socket ativo em %s (permissão=%s)",
	},
	MsgServerShutdown: {
		EN: "Shutting down JaguarGate gracefully...",
		PT: "Encerrando JaguarGate de forma graciosa...",
	},
	MsgCanaryPrevented: {
		EN: "[RESTRICTED CONTENT: System Prompt Leak Prevented (JG-SEC-501)]",
		PT: "[CONTEÚDO RESTRITO: Vazamento de System Prompt Bloqueado (JG-SEC-501)]",
	},
	MsgCanaryHalted: {
		EN: "[RESTRICTED CONTENT: System Prompt Leak Halted (JG-SEC-501)]",
		PT: "[CONTEÚDO RESTRITO: Vazamento de System Prompt Interrompido (JG-SEC-501)]",
	},
	MsgRestrictedImage: {
		EN: "[RESTRICTED IMAGE (JG-SEC-502)]",
		PT: "[IMAGEM RESTRITA (JG-SEC-502)]",
	},
	MsgRestrictedScript: {
		EN: "[RESTRICTED SCRIPT (JG-SEC-502)]",
		PT: "[SCRIPT RESTRITO (JG-SEC-502)]",
	},
	MsgRestrictedSecret: {
		EN: "[RESTRICTED SECRET LEAK (JG-SEC-503)]",
		PT: "[VAZAMENTO DE SEGREDO RESTRITO (JG-SEC-503)]",
	},
	MsgUnauthorizedToolOmit: {
		EN: "[JaguarGate: Unauthorized tool call omitted by policy (JG-CFG-101)]",
		PT: "[JaguarGate: Chamada de ferramenta não autorizada omitida pela política (JG-CFG-101)]",
	},
	MsgUnauthorizedToolError: {
		EN: "JaguarGate: Unauthorized tool call omitted by policy (JG-CFG-101)",
		PT: "JaguarGate: Chamada de ferramenta não autorizada omitida pela política (JG-CFG-101)",
	},
}

// IsPortuguese returns true when the configured language selects Portuguese.
func IsPortuguese(lang string) bool {
	l := strings.TrimSpace(lang)
	return strings.EqualFold(l, "pt-BR") || strings.EqualFold(l, "pt")
}

// T returns the localized string for the active language ("en" by default, "pt-BR" when configured).
func T(lang, key string, args ...any) string {
	tmpl, ok := messageCatalog[key]
	if !ok {
		return key
	}
	format := tmpl.EN
	if IsPortuguese(lang) {
		format = tmpl.PT
	}
	if len(args) > 0 {
		return fmt.Sprintf(format, args...)
	}
	return format
}
