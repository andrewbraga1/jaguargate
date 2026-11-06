# 📋 JaguarGate (`jgate`) — Histórico e Registro de Achados Pré-Hardening (Baseline de Segurança)

> **Finalidade do Documento:** Registro histórico e de governança técnica documentando todas as vulnerabilidades, falhas de isolamento, lacunas de enforcement e discrepâncias arquiteturais identificadas no código original antes da implementação do hardening.  
> **Classificação:** Documento Interno de Controle e Rastreabilidade de Qualidade (AppSec).  
> **Idioma:** [English (Oficial)](AUDIT_FINDINGS_BASELINE.md) | Português (Brasil)

---

## 1. Visão Geral da Análise Pré-Hardening

O projeto apresentava uma base de engenharia bem estruturada em Go (baixo acoplamento, uso de `sync.Pool`, `atomic.Pointer`, compilação estática com Distroless). No entanto, sob uma ótica estrita de segurança e operação em ambientes corporativos ou multi-tenant, foram identificadas **12 falhas no estado original** que comprometiam os invariantes de proteção anunciados.

---

## 2. Inventário Detalhado dos Achados Originais

---

### 🔴 SEC-01: Ausência de Isolamento por Sessão no Cofre de Mascaramento PII
* **Severidade:** **Alta**
* **Componente Afetado:** `internal/guards/vault.go` (`PIIVault`, métodos `MaskText`, `RestoreText` e `storeValue`)
* **Descrição do Estado Original:**
  * O cofre `PIIVault` operava como uma estrutura global compartilhada por todo o processo.
  * O método `RestoreText(output)` recebia exclusivamente a string de saída da LLM e utilizava regex para buscar qualquer ocorrência do padrão `<JG_PII_[A-Z]+_[0-9a-f]{8}>`.
  * Se o token estivesse presente no mapa em memória (ou no Redis L2) e dentro do TTL, o valor em texto limpo era restaurado e devolvido na resposta, **sem checar a identidade da requisição, tenant ou sessionID**.
* **Impacto em Produção:**
  * Um usuário malicioso ou agente que conhecesse ou adivinhasse o identificador de um token de outro usuário (ou fizesse o modelo ecoá-lo) recebia o segredo desmascarado da outra sessão (vazamento *cross-tenant*).
* **Fator Agravante de Entropia:**
  * O token utilizava apenas 4 bytes aleatórios (`var randBytes [4]byte`, gerando 8 caracteres hexadecimais = 32 bits de entropia). Não havia checagem de colisão antes de gravar `v.entries[token]`. Em alto volume, colisões sobrescreviam dados de terceiros.

---

### 🔴 SEC-02: Falha Silenciosa na Sanitização de Domínios em Tool Calls
* **Severidade:** **Alta**
* **Componente Afetado:** `internal/guards/tools.go` (`SanitizeToolCallsSlice` e `SanitizeOutputJSON`)
* **Descrição do Estado Original:**
  * A função `SanitizeToolCallsSlice` identificava URLs fora da whitelist (`AllowedDomains`) dentro dos argumentos da ferramenta e substituía a string por `https://blocked.jaguargate.local/restricted`.
  * Porém, a função retornava apenas `(kept, codes, prunedCount)`.
  * Nas funções chamadoras (`InspectJSONPayload`, `SanitizeOutputJSON` e `handleSSELine`), a variável `modified` só era marcada como `true` se `pruned > 0` (quando a ferramenta inteira era excluída).
* **Impacto em Produção:**
  * Em uma requisição com uma ferramenta autorizada que recebesse uma URL proibida (ex: `https://evil-exfil.com`), o gateway gerava a flag `JG-CFG-103` nos cabeçalhos, mas **não serializava a alteração**. O corpo original contendo a URL maliciosa era entregue intacto ao consumidor.
* **Lacuna do Teste Original:**
  * O teste unitário original combinava uma ferramenta proibida (`drop_production_db`) com uma URL proibida. A remoção da primeira forçava `pruned = 1`, mascarando o bug no caso isolado.

---

### 🔴 SEC-03: Falta de Inspeção nos Argumentos de Chamadas MCP (`tools/call`)
* **Severidade:** **Alta**
* **Componente Afetado:** `internal/mcp/inspector.go` (`inspectSingleRPCObject`) e `internal/guards/engine.go`
* **Descrição do Estado Original:**
  * Ao receber um JSON-RPC de MCP com método `tools/call`, o inspetor serializava `params.arguments` em bytes e chamava `ins.engine.InspectJSONPayload(argsBytes, cfg)`.
  * O método `InspectJSONPayload` fazia `json.Unmarshal` e procurava exclusivamente pelas chaves `"tools"`, `"messages"` e `"prompt"`.
  * Objetos com esquemas arbitrários de ferramentas (ex: `{"cmd": "...", "query": "..."}`) não batiam em nenhuma dessas chaves.
* **Impacto em Produção:**
  * Argumentos de ferramentas MCP passavam completamente imunes à detecção de Prompt Injection (`JG-SEC-401`), desofuscação (`JG-SEC-402`) e mascaramento de PII (`JG-PII-301`/`302`).

---

### 🔴 SEC-04: Janela Deslizante SSE Permitia Evasão em Prefixos Curtos e Ignorava Outros Formatos
* **Severidade:** **Alta**
* **Componente Afetado:** `internal/stream/sse_inspector.go` (`splitHoldbackSuffix` e `handleSSELine`)
* **Descrição do Estado Original:**
  * A retenção do Canary Token na cauda do chunk SSE usava `for k := maxK; k >= 3; k--`. Se o Canary fosse fragmentado na transmissão TCP deixando apenas 1 ou 2 caracteres no final do chunk (ex: `"j"` ou `"jg"`), esses caracteres eram descarregados imediatamente ao cliente. O chunk seguinte não conseguia mais reconstruir o padrão completo.
  * O mesmo ocorria com imagens Markdown: a retenção exigia pelo menos `![`, deixando passar divisões entre `!` e `[`.
  * O parser SSE só inspecionava payloads JSON com a chave `choices[].delta.content` (OpenAI).
* **Impacto em Produção:**
  * Vazamento de System Prompt não era interrompido quando fragmentado em chunks pequenos;
  * Payloads de outros provedores (como Anthropic `delta.text` ou Ollama `message.content`/`response`) passavam pelo SSE sem qualquer filtro.

---

### 🔴 SEC-05: Orçamento de Tokens (`JG-CFG-202`) Não Bloqueava Requisições
* **Severidade:** **Alta**
* **Componente Afetado:** `internal/transport/proxy.go` (`GatewayServer.Handler`)
* **Descrição do Estado Original:**
  * Quando `CheckAndTrackTokens` detectava que a sessão ultrapassou o teto configurado de tokens, o handler registrava a flag `JG-CFG-202` e marcava `res.Severity = "CONFIG_WARNING"`.
  * No entanto, o código **não definia `res.Blocked = true`**.
* **Impacto em Produção:**
  * Mesmo no modo `hard_block`, a requisição continuava fluindo diretamente para a LLM upstream, falhando no objetivo central de limitar custos ou conter agentes em loop.

---

### 🟠 SEC-06: Disjuntor de Loop em LLMs Inativo e Fingerprint com Ordem de Chaves Frágil
* **Severidade:** **Média/Alta**
* **Componente Afetado:** `internal/state/circuit_breaker.go` e `internal/transport/proxy.go`
* **Descrição do Estado Original:**
  * O cálculo de fingerprint usava `json.Compact`, que remove espaços em branco, mas preserva a ordem das chaves do objeto JSON. Assim, `{"a":1,"b":2}` e `{"b":2,"a":1}` geravam hashes SHA-256 distintos, permitindo evasão do disjuntor.
  * A função `FilterLoopingToolCalls` só era chamada no protocolo MCP, não estando conectada ao fluxo de resposta de LLMs HTTP (`choices[].message.tool_calls`).

---

### 🟠 SEC-07: Sandbox Wasm Inoperante com Retorno Silencioso de Sucesso
* **Severidade:** **Média/Alta**
* **Componente Afetado:** `internal/extensions/sandbox.go` (`runSingleModule`)
* **Descrição do Estado Original:**
  * Caso o usuário configurasse um módulo Wasm via arquivo (`mod.Path`), o código validava apenas os 8 bytes de cabeçalho (`\x00asm\x01\x00\x00\x00`) e devolvia o payload intacto com erro `nil`.
* **Impacto em Produção:**
  * O administrador acreditava que uma regra ou política em WebAssembly estava em execução e protegendo o tráfego, quando na realidade nenhuma instrução Wasm era executada.

---

### 🔴 SEC-08: Criptografia AES-256-GCM Fail-Open em Erros de Decifragem no Redis
* **Severidade:** **Alta**
* **Componente Afetado:** `internal/state/store.go` (`HybridStore.Get`)
* **Descrição do Estado Original:**
  * Se a função `s.Decrypt(raw)` falhasse (devido a chave divergente, payload corrompido ou adulteração de tag GCM), o bloco `if decErr == nil` era ignorado e a função executava `return raw, "", nil`.
* **Impacto em Produção:**
  * O sistema devolvia o ciphertext bruto em base64 como se fosse o dado decifrado com sucesso.
  * O cliente Redis utilizava apenas conexões TCP em texto puro (`net.DialTimeout`), ignorando esquemas `rediss://` e autenticação ACL com usuário.

---

### 🟠 SEC-09: Ausência de Limites de Leitura e Crescimento Indefinido de Memória (DoS)
* **Severidade:** **Média/Alta**
* **Componente Afetado:** `internal/transport/proxy.go`, `internal/stream/sse_inspector.go` e mapas de estado
* **Descrição do Estado Original:**
  * Respostas HTTP upstream não-SSE eram lidas com `io.ReadAll(resp.Body)` sem limite de tamanho. Um upstream comprometido ou descontrolado podia enviar respostas de múltiplos gigabytes, esgotando a RAM do proxy.
  * No SSE, se o upstream enviasse um fluxo contínuo sem quebras de linha (`\n`), o buffer `rawBuf` crescia indefinidamente.
  * Os mapas `toolHistory` e `tokenUsage` do `CircuitBreaker` não possuíam rotina de descarte de sessões expiradas.

---

### 🟡 SEC-10: Hot Reload Inconsistente no Proxy Reverso
* **Severidade:** **Média**
* **Componente Afetado:** `internal/transport/proxy.go` (`NewGatewayServer`)
* **Descrição do Estado Original:**
  * A URL do provedor upstream (`targetURL`) era resolvida uma única vez na inicialização do servidor.
  * Caso o arquivo de configuração fosse alterado para apontar para outro upstream, os endpoints de healthcheck (`/readyz`) passavam a testar o novo host, enquanto o proxy reverso continuava encaminhando o tráfego para o host antigo.

---

### 🟡 SEC-11: Telemetria Prematura no Streaming e Contabilização Irreal de Webhooks
* **Severidade:** **Média**
* **Componente Afetado:** `internal/transport/proxy.go` e `internal/telemetry/webhooks.go`
* **Descrição do Estado Original:**
  * As métricas de requisição no Prometheus eram registradas no início do stream SSE (`metrics.RecordRequest`), antes que os tokens fossem processados. Se um vazamento de Canary ocorresse segundos depois, o contador já havia registrado a requisição como `CLEAN`.
  * O despachante de webhooks incrementava o contador de sucessos (`sentCount`) para qualquer requisição que recebesse resposta HTTP, inclusive com códigos `4xx` ou `5xx`.

---

### 🟡 SEC-12: Falha no Placeholder do Logger Zero-Trust e Discrepância de CLI
* **Severidade:** **Média**
* **Componente Afetado:** `cmd/jgate/main.go`
* **Descrição do Estado Original:**
  * A chamada de inicialização do logger passava o idioma (`snap.Core.Language`, ex: `"en"` ou `"pt-BR"`) na posição do argumento `placeholder`. Como resultado, qualquer dado sensível mascarado nos logs era substituído pela palavra `"en"` ou `"pt-BR"`, em vez de `***[JG-REDACTED]***`.
  * A documentação instruía o comando `jgate start`, enquanto a CLI só reconhecia `jgate serve`.

---

## 3. Matriz de Rastreabilidade Pré-Hardening

| ID Original | Categoria OWASP / CWE | Status Anterior | Condição Pós-Hardening |
| :--- | :--- | :---: | :--- |
| **SEC-01** | CWE-284 / OWASP LLM02 (Sensitive Information Disclosure) | **Vulnerável** | Mitigado com tokens 128-bit e vínculo estrito ao `sessionID`. |
| **SEC-02** | CWE-863 / OWASP LLM06 (Excessive Agency / SSRF) | **Vulnerável** | Mitigado com re-serialização obrigatória na presença de códigos de aviso. |
| **SEC-03** | CWE-20 / OWASP LLM01 (Prompt Injection via MCP) | **Vulnerável** | Mitigado com inspeção recursiva de todos os campos de argumentos. |
| **SEC-04** | CWE-200 / OWASP LLM07 (System Prompt Leakage) | **Vulnerável** | Mitigado com retenção $k \ge 1$ e suporte a múltiplos provedores. |
| **SEC-05** | CWE-400 / OWASP LLM10 (Unbounded Consumption) | **Vulnerável** | Mitigado com bloqueio HTTP 429 prévio à chamada upstream. |
| **SEC-06** | CWE-834 / OWASP LLM10 (Excessive Iteration / Loops) | **Vulnerável** | Mitigado com normalização canônica e filtro em respostas de LLMs. |
| **SEC-07** | CWE-390 / Falha de Integridade de Política | **Vulnerável** | Mitigado com fail-open transparente e aviso explícito `JG-EXT-601`. |
| **SEC-08** | CWE-311 / CWE-327 (Cryptographic Issues) | **Vulnerável** | Mitigado com fail-closed em erros GCM e suporte a TLS/ACL. |
| **SEC-09** | CWE-770 (Allocation of Resources Without Limits) | **Vulnerável** | Mitigado com tetos de buffer, limites de leitura e eviction de memória. |
| **SEC-10** | CWE-440 (Configuration Inconsistency) | **Vulnerável** | Mitigado com snapshot por requisição e re-roteamento dinâmico. |
| **SEC-11** | CWE-778 (Insufficient Logging & Telemetry) | **Vulnerável** | Mitigado com métricas pós-stream e validação de status 2xx em webhooks. |
| **SEC-12** | CWE-532 (Insertion of Sensitive Information into Log File) | **Vulnerável** | Mitigado com correção do placeholder e paridade de comandos CLI. |

---
*Documento arquivado para fins de auditoria interna, controle de versões e validação de conformidade.*

