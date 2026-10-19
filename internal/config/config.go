package config

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Config represents the complete JaguarGate v1.0 contract.
type Config struct {
	Core       CoreConfig       `yaml:"core" json:"core"`
	Network    NetworkConfig    `yaml:"network" json:"network"`
	Whitelist  WhitelistConfig  `yaml:"whitelist" json:"whitelist"`
	Guards     GuardsConfig     `yaml:"guards" json:"guards"`
	Extensions ExtensionsConfig `yaml:"extensions" json:"extensions"`
	Telemetry  TelemetryConfig  `yaml:"telemetry" json:"telemetry"`
}

type CoreConfig struct {
	Version  string `yaml:"version" json:"version"`
	Mode     string `yaml:"mode" json:"mode"`
	Preset   string `yaml:"preset" json:"preset"`
	Language string `yaml:"language" json:"language"`
}

type NetworkConfig struct {
	Ingress IngressConfig `yaml:"ingress" json:"ingress"`
	Egress  EgressConfig  `yaml:"egress" json:"egress"`
	MCP     MCPConfig     `yaml:"mcp" json:"mcp"`
}

type IngressConfig struct {
	HTTP       HTTPIngressConfig `yaml:"http" json:"http"`
	UnixSocket UnixSocketConfig  `yaml:"unix_socket" json:"unix_socket"`
	GRPC       GRPCIngressConfig `yaml:"grpc" json:"grpc"`
}

type HTTPIngressConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	ListenAddr     string `yaml:"listen_addr" json:"listen_addr"`
	ReadTimeoutMs  int    `yaml:"read_timeout_ms" json:"read_timeout_ms"`
	WriteTimeoutMs int    `yaml:"write_timeout_ms" json:"write_timeout_ms"`
	MaxPayloadMB   int64  `yaml:"max_payload_mb" json:"max_payload_mb"`
}

type UnixSocketConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	SocketPath string `yaml:"socket_path" json:"socket_path"`
	SocketMode string `yaml:"socket_mode" json:"socket_mode"`
}

type GRPCIngressConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
}

type EgressConfig struct {
	UpstreamURL        string `yaml:"upstream_url" json:"upstream_url"`
	UpstreamUnixSocket string `yaml:"upstream_unix_socket" json:"upstream_unix_socket"`
	KeepAlivePoolSize  int    `yaml:"keep_alive_pool_size" json:"keep_alive_pool_size"`
	IdleConnTimeoutSec int    `yaml:"idle_conn_timeout_sec" json:"idle_conn_timeout_sec"`
	TLSVerify          bool   `yaml:"tls_verify" json:"tls_verify"`
}

type MCPConfig struct {
	Enabled                   bool   `yaml:"enabled" json:"enabled"`
	Transport                 string `yaml:"transport" json:"transport"`
	MaxRPCBatchSize           int    `yaml:"max_rpc_batch_size" json:"max_rpc_batch_size"`
	SanitizeExternalResources bool   `yaml:"sanitize_external_resources" json:"sanitize_external_resources"`
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

type GuardsConfig struct {
	Spotlighting    SpotlightingConfig    `yaml:"spotlighting" json:"spotlighting"`
	CanaryTokens    CanaryTokensConfig    `yaml:"canary_tokens" json:"canary_tokens"`
	Deobfuscation   DeobfuscationConfig   `yaml:"deobfuscation" json:"deobfuscation"`
	Multimodal      MultimodalConfig      `yaml:"multimodal" json:"multimodal"`
	PIIVault        PIIVaultConfig        `yaml:"pii_vault" json:"pii_vault"`
	OutputSanitizer OutputSanitizerConfig `yaml:"output_sanitizer" json:"output_sanitizer"`
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

type DeobfuscationConfig struct {
	Enabled               bool `yaml:"enabled" json:"enabled"`
	MaxDecodeDepth        int  `yaml:"max_decode_depth" json:"max_decode_depth"`
	DecodeBase64          bool `yaml:"decode_base64" json:"decode_base64"`
	DecodeHex             bool `yaml:"decode_hex" json:"decode_hex"`
	StripInvisibleUnicode bool `yaml:"strip_invisible_unicode" json:"strip_invisible_unicode"`
}

type MultimodalConfig struct {
	BypassRegexOnMedia   bool     `yaml:"bypass_regex_on_media" json:"bypass_regex_on_media"`
	StripEXIFXMPMetadata bool     `yaml:"strip_exif_xmp_metadata" json:"strip_exif_xmp_metadata"`
	VerifyMagicBytes     bool     `yaml:"verify_magic_bytes" json:"verify_magic_bytes"`
	AllowedMimeTypes     []string `yaml:"allowed_mime_types" json:"allowed_mime_types"`
}

type PIIVaultConfig struct {
	Enabled         bool              `yaml:"enabled" json:"enabled"`
	RestoreOnOutput bool              `yaml:"restore_on_output" json:"restore_on_output"`
	TTLSeconds      int               `yaml:"ttl_seconds" json:"ttl_seconds"`
	Entities        PIIEntitiesConfig `yaml:"entities" json:"entities"`
}

type PIIEntitiesConfig struct {
	CPF        bool `yaml:"cpf" json:"cpf"`
	CNPJ       bool `yaml:"cnpj" json:"cnpj"`
	CreditCard bool `yaml:"credit_card" json:"credit_card"`
	Email      bool `yaml:"email" json:"email"`
	AWSKeys    bool `yaml:"aws_keys" json:"aws_keys"`
	APISecrets bool `yaml:"api_secrets" json:"api_secrets"`
	JWTTokens  bool `yaml:"jwt_tokens" json:"jwt_tokens"`
}

type OutputSanitizerConfig struct {
	SlidingWindowRunes           int  `yaml:"sliding_window_runes" json:"sliding_window_runes"`
	BlockUntrustedMarkdownImages bool `yaml:"block_untrusted_markdown_images" json:"block_untrusted_markdown_images"`
	StripExecutableScripts       bool `yaml:"strip_executable_scripts" json:"strip_executable_scripts"`
}

type ExtensionsConfig struct {
	StateStore  StateStoreConfig  `yaml:"state_store" json:"state_store"`
	WasmPlugins WasmPluginsConfig `yaml:"wasm_plugins" json:"wasm_plugins"`
}

type StateStoreConfig struct {
	Driver                string `yaml:"driver" json:"driver"`
	RedisURL              string `yaml:"redis_url" json:"redis_url"`
	AESGCMKeyEnv          string `yaml:"aes_gcm_key_env" json:"aes_gcm_key_env"`
	FailOpenToLocalMemory bool   `yaml:"fail_open_to_local_memory" json:"fail_open_to_local_memory"`
}

type WasmPluginsConfig struct {
	Enabled            bool              `yaml:"enabled" json:"enabled"`
	MaxExecutionTimeMs int               `yaml:"max_execution_time_ms" json:"max_execution_time_ms"`
	Modules            []WasmModuleEntry `yaml:"modules" json:"modules"`
}

type WasmModuleEntry struct {
	Name      string `yaml:"name" json:"name"`
	Path      string `yaml:"path" json:"path"`
	OnTimeout string `yaml:"on_timeout" json:"on_timeout"`
}

type TelemetryConfig struct {
	Logging       LoggingConfig       `yaml:"logging" json:"logging"`
	WarningFlags  WarningFlagsConfig  `yaml:"warning_flags" json:"warning_flags"`
	OpenTelemetry OpenTelemetryConfig `yaml:"opentelemetry" json:"opentelemetry"`
	Webhooks      WebhooksConfig      `yaml:"webhooks" json:"webhooks"`
}

type LoggingConfig struct {
	Format           string `yaml:"format" json:"format"`
	Level            string `yaml:"level" json:"level"`
	ZeroTrustPrompts bool   `yaml:"zero_trust_prompts" json:"zero_trust_prompts"`
}

type WarningFlagsConfig struct {
	EmitHTTPHeaders          bool `yaml:"emit_http_headers" json:"emit_http_headers"`
	EmitSSEWarningEvent      bool `yaml:"emit_sse_warning_event" json:"emit_sse_warning_event"`
	EmitHTTPTrailersOnStream bool `yaml:"emit_http_trailers_on_stream" json:"emit_http_trailers_on_stream"`
	IncludeBodyTelemetry     bool `yaml:"include_body_telemetry" json:"include_body_telemetry"`
}

type OpenTelemetryConfig struct {
	Enabled          bool   `yaml:"enabled" json:"enabled"`
	PrometheusListen string `yaml:"prometheus_listen" json:"prometheus_listen"`
	OTLPEndpoint     string `yaml:"otlp_endpoint" json:"otlp_endpoint"`
}

type WebhooksConfig struct {
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	URL        string   `yaml:"url" json:"url"`
	SecretHmac string   `yaml:"secret_hmac" json:"secret_hmac"`
	Events     []string `yaml:"events" json:"events"`
	Endpoints  []string `yaml:"endpoints" json:"endpoints"`
	TriggerOn  []string `yaml:"trigger_on" json:"trigger_on"`
}

// DefaultConfig returns the resilient Enterprise defaults with English ("en") as the default language.
func DefaultConfig() Config {
	return Config{
		Core: CoreConfig{
			Version:  "1.0",
			Mode:     "sanitize_and_warn",
			Preset:   "balanced",
			Language: "en",
		},
		Network: NetworkConfig{
			Ingress: IngressConfig{
				HTTP: HTTPIngressConfig{
					Enabled:        true,
					ListenAddr:     "127.0.0.1:4010",
					ReadTimeoutMs:  30000,
					WriteTimeoutMs: 120000,
					MaxPayloadMB:   10,
				},
				UnixSocket: UnixSocketConfig{
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
				Transport:                 "http_sse",
				MaxRPCBatchSize:           20,
				SanitizeExternalResources: true,
			},
		},
		Whitelist: WhitelistConfig{
			EnforceToolWhitelist: false,
			AllowedTools:         []string{"*"},
			AllowedMCPServers:    []string{"*"},
			AllowedDomains:       []string{"*"},
			CircuitBreaker: CircuitBreakerConfig{
				MaxIdenticalToolCalls: 3,
				WindowSeconds:         120,
				MaxTokensPerSession:   32000,
			},
		},
		Guards: GuardsConfig{
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
			Deobfuscation: DeobfuscationConfig{
				Enabled:               true,
				MaxDecodeDepth:        2,
				DecodeBase64:          true,
				DecodeHex:             true,
				StripInvisibleUnicode: true,
			},
			Multimodal: MultimodalConfig{
				BypassRegexOnMedia:   true,
				StripEXIFXMPMetadata: true,
				VerifyMagicBytes:     true,
				AllowedMimeTypes:     []string{"image/jpeg", "image/png", "image/webp", "application/pdf"},
			},
			PIIVault: PIIVaultConfig{
				Enabled:         true,
				RestoreOnOutput: true,
				TTLSeconds:      300,
				Entities: PIIEntitiesConfig{
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
				SlidingWindowRunes:           64,
				BlockUntrustedMarkdownImages: true,
				StripExecutableScripts:       true,
			},
		},
		Extensions: ExtensionsConfig{
			StateStore: StateStoreConfig{
				Driver:                "memory",
				AESGCMKeyEnv:          "JAGUARGATE_AES_KEY",
				FailOpenToLocalMemory: true,
			},
			WasmPlugins: WasmPluginsConfig{
				Enabled:            false,
				MaxExecutionTimeMs: 2,
			},
		},
		Telemetry: TelemetryConfig{
			Logging: LoggingConfig{
				Format:           "json",
				Level:            "info",
				ZeroTrustPrompts: true,
			},
			WarningFlags: WarningFlagsConfig{
				EmitHTTPHeaders:          true,
				EmitSSEWarningEvent:      true,
				EmitHTTPTrailersOnStream: true,
				IncludeBodyTelemetry:     false,
			},
			OpenTelemetry: OpenTelemetryConfig{
				Enabled:          false,
				PrometheusListen: "127.0.0.1:9091",
			},
			Webhooks: WebhooksConfig{
				Enabled:   false,
				TriggerOn: []string{"INTRUSION_ALERT"},
			},
		},
	}
}

// ApplyPreset adjusts operational mode and strictness based on core.preset.
func (c *Config) ApplyPreset() {
	switch strings.ToLower(strings.TrimSpace(c.Core.Preset)) {
	case "permissive":
		c.Core.Mode = "shadow"
	case "strict":
		c.Core.Mode = "hard_block"
		c.Whitelist.EnforceToolWhitelist = true
	case "balanced", "":
		if c.Core.Preset == "" {
			c.Core.Preset = "balanced"
		}
		if c.Core.Mode == "" {
			c.Core.Mode = "sanitize_and_warn"
		}
	}
	if strings.TrimSpace(c.Core.Language) == "" {
		c.Core.Language = "en"
	}
}

// Validate verifies structural invariants of the configuration contract.
func (c *Config) Validate() error {
	if c.Core.Version == "" {
		c.Core.Version = "1.0"
	}
	validModes := []string{"shadow", "sanitize_and_warn", "hard_block"}
	if !slices.Contains(validModes, c.Core.Mode) {
		return fmt.Errorf("invalid core.mode %q (must be shadow, sanitize_and_warn, or hard_block)", c.Core.Mode)
	}
	if c.Network.Egress.UpstreamURL == "" && c.Network.Egress.UpstreamUnixSocket == "" {
		return errors.New("network.egress.upstream_url or upstream_unix_socket is required")
	}
	if c.Network.Egress.UpstreamURL != "" {
		if _, err := url.ParseRequestURI(c.Network.Egress.UpstreamURL); err != nil {
			return fmt.Errorf("invalid network.egress.upstream_url %q: %w", c.Network.Egress.UpstreamURL, err)
		}
	}
	return nil
}
