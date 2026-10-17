package config

import (
	"errors"
	"net/url"
	"strings"
)

// Config represents the complete declarative contract of JaguarGate.
type Config struct {
	Core       CoreConfig       `yaml:"core" json:"core"`
	Network    NetworkConfig    `yaml:"network" json:"network"`
	Guards     GuardsConfig     `yaml:"guards" json:"guards"`
	Whitelist  WhitelistConfig  `yaml:"whitelist" json:"whitelist"`
	Telemetry  TelemetryConfig  `yaml:"telemetry" json:"telemetry"`
	Extensions ExtensionsConfig `yaml:"extensions" json:"extensions"`
}

type CoreConfig struct {
	Version  string `yaml:"version" json:"version"`
	Language string `yaml:"language" json:"language"`
	Preset   string `yaml:"preset" json:"preset"`
	Mode     string `yaml:"mode" json:"mode"`
}

type NetworkConfig struct {
	Ingress IngressConfig `yaml:"ingress" json:"ingress"`
	Egress  EgressConfig  `yaml:"egress" json:"egress"`
	MCP     MCPConfig     `yaml:"mcp" json:"mcp"`
}

type IngressConfig struct {
	HTTP       HTTPIngressConfig `yaml:"http" json:"http"`
	UnixSocket UDSIngressConfig  `yaml:"unix_socket" json:"unix_socket"`
	GRPC       GRPCIngressConfig `yaml:"grpc" json:"grpc"`
}

type HTTPIngressConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	ListenAddr     string `yaml:"listen_addr" json:"listen_addr"`
	ReadTimeoutMs  int    `yaml:"read_timeout_ms" json:"read_timeout_ms"`
	WriteTimeoutMs int    `yaml:"write_timeout_ms" json:"write_timeout_ms"`
	MaxPayloadMB   int64  `yaml:"max_payload_mb" json:"max_payload_mb"`
}

type UDSIngressConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	SocketPath string `yaml:"socket_path" json:"socket_path"`
	SocketMode string `yaml:"socket_mode" json:"socket_mode"`
}

type GRPCIngressConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
}

type EgressConfig struct {
	UpstreamURL          string `yaml:"upstream_url" json:"upstream_url"`
	UpstreamUnixSocket   string `yaml:"upstream_unix_socket" json:"upstream_unix_socket"`
	KeepAlivePoolSize    int    `yaml:"keep_alive_pool_size" json:"keep_alive_pool_size"`
	IdleConnTimeoutSec   int    `yaml:"idle_conn_timeout_seconds" json:"idle_conn_timeout_seconds"`
	TLSVerify            bool   `yaml:"tls_verify" json:"tls_verify"`
}

type MCPConfig struct {
	Enabled                   bool `yaml:"enabled" json:"enabled"`
	SanitizeExternalResources bool `yaml:"sanitize_external_resources" json:"sanitize_external_resources"`
	MaxRPCBatchSize           int  `yaml:"max_rpc_batch_size" json:"max_rpc_batch_size"`
}

type GuardsConfig struct {
	Deobfuscation   DeobfuscationConfig   `yaml:"deobfuscation" json:"deobfuscation"`
	Multimodal      MultimodalConfig      `yaml:"multimodal" json:"multimodal"`
	Spotlighting    SpotlightingConfig    `yaml:"spotlighting" json:"spotlighting"`
	CanaryTokens    CanaryTokensConfig    `yaml:"canary_tokens" json:"canary_tokens"`
	PIIVault        PIIVaultConfig        `yaml:"pii_vault" json:"pii_vault"`
	OutputSanitizer OutputSanitizerConfig `yaml:"output_sanitizer" json:"output_sanitizer"`
}

type DeobfuscationConfig struct {
	Enabled               bool `yaml:"enabled" json:"enabled"`
	DecodeBase64          bool `yaml:"decode_base64" json:"decode_base64"`
	DecodeHex             bool `yaml:"decode_hex" json:"decode_hex"`
	StripInvisibleUnicode bool `yaml:"strip_invisible_unicode" json:"strip_invisible_unicode"`
	MaxDecodeDepth        int  `yaml:"max_decode_depth" json:"max_decode_depth"`
}

type MultimodalConfig struct {
	BypassRegexOnMedia   bool     `yaml:"bypass_regex_on_media" json:"bypass_regex_on_media"`
	VerifyMagicBytes     bool     `yaml:"verify_magic_bytes" json:"verify_magic_bytes"`
	StripEXIFXMPMetadata bool     `yaml:"strip_exif_xmp_metadata" json:"strip_exif_xmp_metadata"`
	AllowedMimeTypes     []string `yaml:"allowed_mime_types" json:"allowed_mime_types"`
}

type SpotlightingConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	DynamicTagPrefix string   `yaml:"dynamic_tag_prefix" json:"dynamic_tag_prefix"`
	MarkRoles        []string `yaml:"mark_roles" json:"mark_roles"`
}

type CanaryTokensConfig struct {
	Enabled                bool `yaml:"enabled" json:"enabled"`
	AutoInjectSystemPrompt bool `yaml:"auto_inject_system_prompt" json:"auto_inject_system_prompt"`
	TruncateStreamOnLeak   bool `yaml:"truncate_stream_on_leak" json:"truncate_stream_on_leak"`
}

type PIIVaultConfig struct {
	Enabled         bool            `yaml:"enabled" json:"enabled"`
	RestoreOnOutput bool            `yaml:"restore_on_output" json:"restore_on_output"`
	TTLSeconds      int             `yaml:"ttl_seconds" json:"ttl_seconds"`
	Entities        PIIEntities     `yaml:"entities" json:"entities"`
	CustomPatterns  []CustomPattern `yaml:"custom_patterns" json:"custom_patterns"`
}

type PIIEntities struct {
	CPF        bool `yaml:"cpf" json:"cpf"`
	CNPJ       bool `yaml:"cnpj" json:"cnpj"`
	CreditCard bool `yaml:"credit_card" json:"credit_card"`
	Email      bool `yaml:"email" json:"email"`
	AWSKeys    bool `yaml:"aws_keys" json:"aws_keys"`
	APISecrets bool `yaml:"api_secrets" json:"api_secrets"`
	JWTTokens  bool `yaml:"jwt_tokens" json:"jwt_tokens"`
}

type CustomPattern struct {
	Name  string `yaml:"name" json:"name"`
	Regex string `yaml:"regex" json:"regex"`
}

type OutputSanitizerConfig struct {
	BlockUntrustedMarkdownImages bool `yaml:"block_untrusted_markdown_images" json:"block_untrusted_markdown_images"`
	StripExecutableScripts       bool `yaml:"strip_executable_scripts" json:"strip_executable_scripts"`
	SlidingWindowRunes           int  `yaml:"sliding_window_runes" json:"sliding_window_runes"`
}

type WhitelistConfig struct {
	EnforceToolWhitelist bool                 `yaml:"enforce_tool_whitelist" json:"enforce_tool_whitelist"`
	AllowedTools         []string             `yaml:"allowed_tools" json:"allowed_tools"`
	AllowedMCPServers    []string             `yaml:"allowed_mcp_servers" json:"allowed_mcp_servers"`
	AllowedDomains       []string             `yaml:"allowed_domains" json:"allowed_domains"`
	CircuitBreaker       CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
}

type CircuitBreakerConfig struct {
	MaxIdenticalToolCalls int `yaml:"max_identical_tool_calls" json:"max_identical_tool_calls"`
	WindowSeconds         int `yaml:"window_seconds" json:"window_seconds"`
	MaxTokensPerSession   int `yaml:"max_tokens_per_session" json:"max_tokens_per_session"`
}

type TelemetryConfig struct {
	WarningFlags  WarningFlagsConfig `yaml:"warning_flags" json:"warning_flags"`
	Logging       LoggingConfig      `yaml:"logging" json:"logging"`
	Webhooks      WebhooksConfig     `yaml:"webhooks" json:"webhooks"`
	OpenTelemetry OTelConfig         `yaml:"opentelemetry" json:"opentelemetry"`
}

type WarningFlagsConfig struct {
	EmitHTTPHeaders          bool `yaml:"emit_http_headers" json:"emit_http_headers"`
	EmitHTTPTrailersOnStream bool `yaml:"emit_http_trailers_on_stream" json:"emit_http_trailers_on_stream"`
	EmitSSEWarningEvent      bool `yaml:"emit_sse_warning_event" json:"emit_sse_warning_event"`
	IncludeBodyTelemetry     bool `yaml:"include_body_telemetry_field" json:"include_body_telemetry_field"`
}

type LoggingConfig struct {
	Level                string `yaml:"level" json:"level"`
	Format               string `yaml:"format" json:"format"`
	ZeroTrustRedaction   bool   `yaml:"zero_trust_redaction" json:"zero_trust_redaction"`
	RedactionPlaceholder string `yaml:"redaction_placeholder" json:"redaction_placeholder"`
}

type WebhooksConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	URL                string   `yaml:"url" json:"url"`
	TriggerSeverities  []string `yaml:"trigger_severities" json:"trigger_severities"`
	RateLimitPerMinute int      `yaml:"rate_limit_per_minute" json:"rate_limit_per_minute"`
	BatchWindowSeconds int      `yaml:"batch_window_seconds" json:"batch_window_seconds"`
}

type OTelConfig struct {
	Enabled              bool   `yaml:"enabled" json:"enabled"`
	PrometheusListenAddr string `yaml:"prometheus_listen_addr" json:"prometheus_listen_addr"`
}

type ExtensionsConfig struct {
	StateStore          StateStoreConfig          `yaml:"state_store" json:"state_store"`
	WasmPlugins         WasmPluginsConfig         `yaml:"wasm_plugins" json:"wasm_plugins"`
	CommunitySignatures CommunitySignaturesConfig `yaml:"community_signatures" json:"community_signatures"`
}

type StateStoreConfig struct {
	Driver                string `yaml:"driver" json:"driver"`
	RedisURL              string `yaml:"redis_url" json:"redis_url"`
	AESGCMKeyEnv          string `yaml:"aes_gcm_key_env" json:"aes_gcm_key_env"`
	FailOpenToLocalMemory bool   `yaml:"fail_open_to_local_memory" json:"fail_open_to_local_memory"`
}

type WasmPluginsConfig struct {
	Enabled               bool   `yaml:"enabled" json:"enabled"`
	Directory             string `yaml:"directory" json:"directory"`
	MaxExecutionTimeoutMs int    `yaml:"max_execution_timeout_ms" json:"max_execution_timeout_ms"`
	MaxMemoryMegabytes    int    `yaml:"max_memory_megabytes" json:"max_memory_megabytes"`
}

type CommunitySignaturesConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Directory string `yaml:"directory" json:"directory"`
	HotReload bool   `yaml:"hot_reload" json:"hot_reload"`
}

// DefaultConfig returns a complete safe baseline configuration before applying user overrides.
func DefaultConfig() Config {
	return Config{
		Core: CoreConfig{
			Version:  "1.0",
			Language: "pt-BR",
			Preset:   "balanced",
			Mode:     "", // Resolved by ApplyPreset if left empty
		},
		Network: NetworkConfig{
			Ingress: IngressConfig{
				HTTP: HTTPIngressConfig{
					Enabled:        true,
					ListenAddr:     "127.0.0.1:4010",
					ReadTimeoutMs:  30000,
					WriteTimeoutMs: 120000,
					MaxPayloadMB:   15,
				},
				UnixSocket: UDSIngressConfig{
					Enabled:    false,
					SocketPath: "/tmp/jaguargate.sock",
					SocketMode: "0600",
				},
				GRPC: GRPCIngressConfig{
					Enabled:    false,
					ListenAddr: "127.0.0.1:4011",
				},
			},
			Egress: EgressConfig{
				UpstreamURL:        "http://127.0.0.1:11434",
				KeepAlivePoolSize:  128,
				IdleConnTimeoutSec: 90,
				TLSVerify:          true,
			},
			MCP: MCPConfig{
				Enabled:                   true,
				SanitizeExternalResources: true,
				MaxRPCBatchSize:           20,
			},
		},
		Guards: GuardsConfig{
			Deobfuscation: DeobfuscationConfig{
				Enabled:               true,
				DecodeBase64:          true,
				DecodeHex:             true,
				StripInvisibleUnicode: true,
				MaxDecodeDepth:        2,
			},
			Multimodal: MultimodalConfig{
				BypassRegexOnMedia:   true,
				VerifyMagicBytes:     true,
				StripEXIFXMPMetadata: true,
				AllowedMimeTypes:     []string{"image/jpeg", "image/png", "image/webp", "application/pdf"},
			},
			Spotlighting: SpotlightingConfig{
				Enabled:          true,
				DynamicTagPrefix: "jg_untrusted",
				MarkRoles:        []string{"tool", "function"},
			},
			CanaryTokens: CanaryTokensConfig{
				Enabled:                true,
				AutoInjectSystemPrompt: true,
				TruncateStreamOnLeak:   true,
			},
			PIIVault: PIIVaultConfig{
				Enabled:         true,
				RestoreOnOutput: true,
				TTLSeconds:      300,
				Entities: PIIEntities{
					CPF:        true,
					CNPJ:       true,
					CreditCard: true,
					Email:      false,
					AWSKeys:    true,
					APISecrets: true,
					JWTTokens:  true,
				},
			},
			OutputSanitizer: OutputSanitizerConfig{
				BlockUntrustedMarkdownImages: true,
				StripExecutableScripts:       true,
				SlidingWindowRunes:           64,
			},
		},
		Whitelist: WhitelistConfig{
			EnforceToolWhitelist: false,
			CircuitBreaker: CircuitBreakerConfig{
				MaxIdenticalToolCalls: 3,
				WindowSeconds:         120,
				MaxTokensPerSession:   32000,
			},
		},
		Telemetry: TelemetryConfig{
			WarningFlags: WarningFlagsConfig{
				EmitHTTPHeaders:          true,
				EmitHTTPTrailersOnStream: true,
				EmitSSEWarningEvent:      true,
				IncludeBodyTelemetry:     false,
			},
			Logging: LoggingConfig{
				Level:                "info",
				Format:               "json",
				ZeroTrustRedaction:   true,
				RedactionPlaceholder: "***[JG-REDACTED]***",
			},
		},
		Extensions: ExtensionsConfig{
			StateStore: StateStoreConfig{
				Driver:                "memory",
				FailOpenToLocalMemory: true,
			},
			WasmPlugins: WasmPluginsConfig{
				Enabled:               false,
				Directory:             "./plugins/wasm",
				MaxExecutionTimeoutMs: 2,
				MaxMemoryMegabytes:    16,
			},
			CommunitySignatures: CommunitySignaturesConfig{
				Enabled:   true,
				Directory: "./plugins/signatures",
				HotReload: true,
			},
		},
	}
}

// ApplyPreset adjusts default mode and strictness according to the chosen 3-line preset.
func (c *Config) ApplyPreset() {
	switch c.Core.Preset {
	case "permissive":
		if c.Core.Mode == "" {
			c.Core.Mode = "shadow"
		}
	case "balanced":
		if c.Core.Mode == "" {
			c.Core.Mode = "sanitize_and_warn"
		}
	case "strict":
		if c.Core.Mode == "" {
			c.Core.Mode = "hard_block"
		}
		c.Guards.PIIVault.Entities.Email = true
		c.Whitelist.EnforceToolWhitelist = true
	}
}

// Validate checks structural and security invariants of the configuration.
func (c *Config) Validate() error {
	lang := c.Core.Language
	if lang != "pt-BR" && lang != "en" {
		return errors.New(T("en", MsgErrInvalidLang, lang))
	}
	if c.Core.Version != "1.0" {
		return errors.New(T(lang, MsgErrInvalidVersion, c.Core.Version))
	}
	switch c.Core.Preset {
	case "permissive", "balanced", "strict":
	default:
		return errors.New(T(lang, MsgErrInvalidPreset, c.Core.Preset))
	}
	switch c.Core.Mode {
	case "shadow", "sanitize_and_warn", "hard_block":
	default:
		return errors.New(T(lang, MsgErrInvalidMode, c.Core.Mode))
	}

	if !c.Network.Ingress.HTTP.Enabled && !c.Network.Ingress.UnixSocket.Enabled && !c.Network.Ingress.GRPC.Enabled {
		return errors.New(T(lang, MsgErrNoIngressActive))
	}

	if c.Network.Ingress.UnixSocket.Enabled && strings.TrimSpace(c.Network.Ingress.UnixSocket.SocketPath) == "" {
		return errors.New(T(lang, MsgErrInvalidSocket))
	}

	u, err := url.Parse(c.Network.Egress.UpstreamURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New(T(lang, MsgErrInvalidUpstream, c.Network.Egress.UpstreamURL))
	}

	// Enforce maximum decode depth cap to prevent CPU zip-bomb style attacks
	if c.Guards.Deobfuscation.MaxDecodeDepth <= 0 || c.Guards.Deobfuscation.MaxDecodeDepth > 5 {
		c.Guards.Deobfuscation.MaxDecodeDepth = 2
	}

	// Mandatory Zero-Trust Redaction placeholder fallback
	if strings.TrimSpace(c.Telemetry.Logging.RedactionPlaceholder) == "" {
		c.Telemetry.Logging.RedactionPlaceholder = "***[JG-REDACTED]***"
	}

	return nil
}