# 🛡️ JaguarGate (`jgate`) — Relatório Técnico de Auditoria de Segurança e Hardening

> **Escopo:** Auditoria estática e dinâmica dos invariantes de segurança, isolamento multi-tenant de estado, sanitização de streaming SSE em janela deslizante, guardrails do Model Context Protocol (MCP JSON-RPC 2.0), limites de recursos e telemetria zero-trust.  
> **Status:** 12/12 Achados Totalmente Mitigados e Verificados com Testes de Regressão (`go test -race ./...`).  
> **Idioma:** [English (Oficial)](SECURITY_AUDIT_HARDENING.md) | Português (Brasil)

---

## 📋 Matriz de Remediação: Achados & Verificações

| ID | Severidade | Componente | Achado Técnico | Remediação Implementada | Teste de Regressão |
| :--- | :---: | :--- | :--- | :--- | :--- |
| **AUD-01** | **Alta** | `internal/guards/vault.go` | Cofre PII compartilhado sem isolamento por sessão/tenant; entropia degradada em 32 bits sem tratamento de colisão. | Tokens agora vinculados estritamente ao `sessionID` do chamador (`MaskTextWithSession` / `RestoreTextWithSession`), entropia ampliada para **128 bits (`[16]byte`)** com prevenção de colisão. | `TestPIIVaultCrossSessionIsolation` |
| **AUD-02** | **Alta** | `internal/guards/tools.go` `internal/guards/engine.go` `internal/stream/sse_inspector.go` | Sanitização de domínios (`JG-CFG-103`) alterava os argumentos em memória, mas não serializava o JSON final quando `pruned == 0`. | Re-serialização obrigatória aplicada sempre que `pruned > 0 \|\| len(toolCodes) > 0` na entrada, saída JSON e streaming SSE. | `TestIsolatedDomainSanitizationWithoutToolPruning` |
| **AUD-03** | **Alta** | `internal/mcp/inspector.go` `internal/guards/engine.go` | Argumentos de chamadas MCP (`params.arguments`) não eram inspecionados quando não possuíam chaves padrão de chat (`messages`/`prompt`). | Implementada varredura recursiva de JSON (`inspectArbitraryJSONMap` / `inspectArbitraryJSONSlice`, profundidade $\le 8$) inspecionando todos os campos textuais contra injeções, ofuscações, PII e domínios. | `TestMCPJSONRPCToolFirewallAndExternalResourceSanitization` |
| **AUD-04** | **Alta** | `internal/stream/sse_inspector.go` | Janela deslizante SSE exigia $\ge 3$ caracteres para reter Canary tokens, e o parser cobria apenas `choices[].delta.content` da OpenAI. | Limiar de retenção de Canary e marcadores reduzido para **1 caractere ($k \ge 1$)**; suporte nativo a formatos SSE da Anthropic (`delta.text`) e Ollama (`message.content`, `response`, `token`). | `TestSSEOneAndTwoCharPrefixSplitsAndAnthropicFormat` |
| **AUD-05** | **Alta** | `internal/transport/proxy.go` `internal/state/circuit_breaker.go` | Orçamento de tokens por sessão (`JG-CFG-202`) apenas emitia aviso sem interromper o envio ao upstream; fingerprint do circuit breaker era sensível à ordem das chaves JSON. | Excesso de quota agora rejeita imediatamente a requisição na entrada com `HTTP 429 Too Many Requests` (`res.Blocked = true`); fingerprint SHA-256 ordena chaves JSON lexicograficamente. | `TestProxyTokenBudgetEnforcementAndDeferredSSEMetrics` `TestCircuitBreakerCanonicalLoopAndTokenBudget` |
| **AUD-06** | **Média/Alta** | `internal/transport/proxy.go` | `FilterLoopingToolCalls` (`JG-CFG-201`) estava ativo apenas no tráfego MCP, deixando respostas comuns de LLMs HTTP/REST sem monitoramento. | Integrado `filterLLMResponseToolLoops` no `ModifyResponse`, podando chamadas repetidas em loop diretamente das respostas de LLMs. | `TestFilterLoopingToolCallsPruningAndShadow` |
| **AUD-07** | **Média/Alta** | `internal/extensions/sandbox.go` | Sandbox Wasm baseado em arquivo validava apenas cabeçalho de 8 bytes e retornava sucesso sem executar bytecode (falsa sensação de segurança operacional). | Retorna explicitamente `ErrWasmRuntimeNotLinked` quando nenhum runtime/hook está registrado, acionando Fail-Open transparente e flag de aviso `JG-EXT-601`. | `TestSandboxWasmMagicBytesAndTimeoutFailOpen` |
| **AUD-08** | **Alta** | `internal/state/store.go` | Erros de decifragem AES-256-GCM no Redis falhavam abertos e retornavam ciphertext bruto como texto limpo; cliente carecia de TLS (`rediss://`) e usuário ACL. | Política *fail-closed* criptográfica obrigatória (`ErrDecryptionFailed`) em caso de ciphertext corrompido ou adulterado; suporte nativo a TLS (`tls.DialWithDialer`) e `AUTH <user> <pass>`. | `TestHybridStoreAESGCMAndRedisFailOpen` |
| **AUD-09** | **Média/Alta** | `internal/transport/proxy.go` `internal/stream/sse_inspector.go` `internal/guards/vault.go` `internal/state/*` | `io.ReadAll` sem limite nas respostas upstream; ausência de teto em linhas SSE sem `\n`; mapas crescendo indefinidamente entre sessões (vulnerabilidade DoS / OOM). | Corpo de resposta envelopado com `io.LimitReader`; teto de 1MB por linha SSE sem `\n` (`maxSSELineBytes`); despejo LRU implementado ($N \le 16384$) no Vault, Store e Breaker. | Suíte de testes de estado e streaming |
| **AUD-10** | **Média** | `internal/transport/proxy.go` | Hot-reload atualizava os probes de readiness (`/readyz`), mas o proxy reverso mantinha o `targetURL` do boot; risco de desvio de política entre entrada e saída. | Snapshot de configuração fixado por requisição (`ctxConfigSnapKey`); destino upstream resolvido dinamicamente durante o `Rewrite` do proxy. | `TestHTTPAndUnixSocketProxyWithSSEStreaming` |
| **AUD-11** | **Média** | `internal/transport/proxy.go` `internal/telemetry/webhooks.go` | Métricas SSE eram gravadas antes do consumo do stream; despachante de webhooks incrementava `sentCount` em respostas HTTP 4xx/5xx. | Métricas SSE e emissão de webhooks postergadas para o término do stream via `SetOnComplete`; entregas de webhooks agora exigem estritamente HTTP 2xx para incrementar `sentCount`. | `TestPrometheusMetricsAndNonBlockingWebhook` |
| **AUD-12** | **Média** | `cmd/jgate/main.go` `README.md` | Construtor do logger zero-trust recebia código do idioma no lugar do placeholder de redação; documentação usava `start`/`bote` enquanto a CLI só aceitava `serve`/`pounce`. | Placeholder corrigido para `***[JG-REDACTED]***`; adicionados aliases na CLI para `start`/`serve` e `bote`/`pounce`; instruções de quickstart alinhadas. | `./jgate check && ./jgate pounce` |

---

## 🔬 Verificação Técnica & Resultados dos Testes

Todas as mitigações foram validadas empiricamente com detector de race conditions do Go:

```bash
$ go vet ./...
$ go test -race ./...
ok  	github.com/andrewbraga1/jaguargate/internal/config	1.036s
ok  	github.com/andrewbraga1/jaguargate/internal/extensions	1.019s
ok  	github.com/andrewbraga1/jaguargate/internal/guards	1.029s
ok  	github.com/andrewbraga1/jaguargate/internal/mcp	1.042s
ok  	github.com/andrewbraga1/jaguargate/internal/multimodal	1.033s
ok  	github.com/andrewbraga1/jaguargate/internal/redteam	1.032s
ok  	github.com/andrewbraga1/jaguargate/internal/state	1.019s
ok  	github.com/andrewbraga1/jaguargate/internal/stream	1.082s
ok  	github.com/andrewbraga1/jaguargate/internal/telemetry	1.057s
ok  	github.com/andrewbraga1/jaguargate/internal/transport	1.121s
```

