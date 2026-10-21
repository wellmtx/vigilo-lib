# Contrato de eventos — schema v1

Formato que a lib envia para a API de ingestão. Está **congelado** na versão 1: a ingestão e o worker (no repositório da plataforma) e a camada RASP são construídos em cima dele.

Fonte da verdade no código: [`packages/core/src/contract.ts`](../packages/core/src/contract.ts) (constantes, limites e JSON Schema) e [`packages/core/src/types.ts`](../packages/core/src/types.ts) (tipos). O teste [`contract.test.ts`](../packages/core/test/contract.test.ts) valida eventos reais do client contra o schema.

## Artefatos para o backend

A plataforma é escrita em Go e não importa código da lib. A ponte entre os dois são arquivos gerados pelo `pnpm build` e versionados no repositório (também vão no pacote npm do `@vigilo/core`):

| Arquivo | Conteúdo |
| --- | --- |
| [`packages/core/schemas/event-batch.v1.json`](../packages/core/schemas/event-batch.v1.json) | JSON Schema (draft 2020-12) do corpo de `POST /v1/events` |
| [`packages/core/schemas/examples/batch-v1.json`](../packages/core/schemas/examples/batch-v1.json) | Lote real produzido pela lib (evento limpo, SQLi com scanner, NoSQLi com IPv6 e campos `null`, rate limit), com ids e horários fixos |

O backend copia esses arquivos e, no teste de contrato dele, decodifica o exemplo nas structs da ingestão e confere os limites. Se a lib mudar o formato, o teste do backend quebra antes do deploy. Um teste da lib falha quando os arquivos ficam desatualizados em relação ao código.

## Requisição

```
POST /v1/events
Authorization: Bearer <api key do projeto>
Content-Type: application/json
Content-Encoding: gzip
```

Resposta esperada: `202 Accepted`. A lib trata qualquer outra resposta como falha e tenta de novo com backoff (3 tentativas); depois disso o lote é descartado e contado em `dropped`.

## Envelope do lote

| Campo | Tipo | Regra |
| --- | --- | --- |
| `schemaVersion` | `1` | Constante. A ingestão escolhe o validador por este campo |
| `sdk.name` | string | `@vigilo/core` (até 64) |
| `sdk.version` | string | Versão da lib (até 32). Ajuda a rastrear falso positivo por versão |
| `sentAt` | ISO 8601 UTC | Horário do envio. Comparado com o horário de chegada, estima o desvio de relógio da instância |
| `events` | array | De 1 a 500 eventos |

## Evento

Todos os campos estão sempre presentes; os opcionais vêm como `null`.

| Campo | Tipo | Regra |
| --- | --- | --- |
| `eventId` | UUID v7 | Gerado na lib. Chave de idempotência: reenvio não duplica |
| `ts` | ISO 8601 UTC | Fim da requisição, no relógio do servidor do cliente |
| `method` | string | Até 16 caracteres |
| `route` | string | Padrão da rota (`/users/:id`) quando o framework informa. Até 512 |
| `status` | inteiro | 100 a 999 |
| `durationMs` | número | ≥ 0, 3 casas decimais |
| `ip` | IPv4 ou IPv6 | IP real do cliente (ver `trustProxy`). Sem zona IPv6 e sem prefixo `::ffff:` |
| `srcPort` | inteiro ou `null` | 0 a 65535. Essencial por causa do CGNAT |
| `userAgent` | string ou `null` | Até 512 |
| `threatType` | enum ou `null` | Tipo da ameaça mais grave do evento |
| `severity` | 1 a 5 ou `null` | Severidade da ameaça mais grave |
| `threats` | array | Até 32, mais graves primeiro quando corta. Vazio em evento limpo |
| `blocked` | boolean | A lib respondeu 403 (modo `block`) |
| `payload` | string ou `null` | Só em evento suspeito: JSON `{query, body}` mascarado, até 2 KB e sufixo `…[truncated]` |

### Ameaça (`threats[]`)

| Campo | Tipo | Regra |
| --- | --- | --- |
| `type` | enum | `sqli`, `nosqli`, `traversal`, `xss`, `scanner`, `scan`, `bruteforce`, `ratelimit`, `cmdi` |
| `severity` | 1 a 5 | 1 informativo, 5 crítico |
| `location` | string | Onde o sinal apareceu: `query.id`, `body.user.name`, `path`, `header.user-agent`, `ip`. Até 256 |
| `rule` | string | Regra que disparou, ex.: `sqli.union-select`. Até 64 |
| `layer` | enum | `signature` (camada 1), `rasp` (camada 1b, nos drivers), `ip` (camada 2) |

Uma ameaça `rasp` confirma que a entrada alterou a estrutura da query ou do comando, então a plataforma pode tratá-la com mais confiança do que uma assinatura. Hoje a RASP emite `sqli` com severidade 5 e regra `rasp.sqli.pg`, com `location` apontando a entrada que causou a injeção (ex.: `params.id`, `body.name`). Novos drivers seguem o padrão `rasp.<tipo>.<driver>`. `cmdi` já faz parte do contrato e será emitido quando o `child_process` for instrumentado. Quando a RASP bloqueia, `blocked` fica `true` e `status` é o que a aplicação respondeu depois do erro (em geral 500).

### Exemplo

```json
{
  "schemaVersion": 1,
  "sdk": { "name": "@vigilo/core", "version": "0.0.1" },
  "sentAt": "2026-10-21T16:40:05.120Z",
  "events": [
    {
      "eventId": "019a07c1-3b2e-7c4d-9a1f-5e6b7c8d9e0f",
      "ts": "2026-10-21T16:40:01.874Z",
      "method": "GET",
      "route": "/users/:id",
      "status": 200,
      "durationMs": 3.412,
      "ip": "203.0.113.10",
      "srcPort": 51234,
      "userAgent": "sqlmap/1.7",
      "threatType": "sqli",
      "severity": 4,
      "threats": [
        { "type": "sqli", "severity": 4, "location": "query.id", "rule": "sqli.union-select", "layer": "signature" },
        { "type": "scanner", "severity": 2, "location": "header.user-agent", "rule": "scanner.user-agent", "layer": "signature" }
      ],
      "blocked": false,
      "payload": "{\"query\":{\"id\":\"1 UNION SELECT 1\"}}"
    }
  ]
}
```

## Regras de evolução

- **Dentro da v1, só mudanças aditivas:** campo novo opcional (pode vir `null` ou ausente) ou valor novo de enum. A lib nunca remove nem muda o tipo de um campo.
- **A ingestão é tolerante:** decodifica o JSON em structs com `encoding/json`, que ignora campos desconhecidos (não use `DisallowUnknownFields`), e valida tipos, enums e limites no código. Assim, uma versão nova da lib não quebra numa plataforma antiga. O JSON Schema tem `additionalProperties: false` porque descreve o que a lib emite; ele serve para testar a lib e os exemplos, não para rejeitar lotes na ingestão.
- **Valor novo de enum é exceção:** a ingestão rejeita `type` desconhecido. Ela precisa ser atualizada antes de publicar uma lib que emita o tipo novo.
- **Mudança incompatível** (remover campo, mudar tipo, campo novo obrigatório) exige `schemaVersion: 2`, e a ingestão aceita as duas versões até as libs antigas saírem de uso.
- A lib corta os valores nos limites antes de enviar. A ingestão rejeita o que passar deles.

## Mapeamento para o banco

O worker grava cada evento numa linha da tabela `events` da plataforma: os campos em camelCase viram snake_case, `threats` vai inteiro para a coluna `jsonb`, `project_id` vem da API key (nunca do corpo) e `asn`, `country` e `ip_flags` são preenchidos no enriquecimento.
