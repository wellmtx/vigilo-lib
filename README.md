# Vigilo

Segurança de APIs para Node.js: uma lib que roda dentro da sua aplicação, detecta ataques em tempo real e envia eventos mascarados para um painel com alertas e relatórios.

> Status: em desenvolvimento, ainda não publicado no npm.

## Pacotes

| Pacote | Para |
| --- | --- |
| [`@vigilo/core`](packages/core) | Detecção, estado por IP, mascaramento e envio de eventos |
| [`@vigilo/express`](packages/express) | Express 4 e 5 |
| [`@vigilo/fastify`](packages/fastify) | Fastify 5 |
| [`@vigilo/http`](packages/http) | `node:http` puro |

## Uso

**Express**

```js
import express from 'express';
import { shield } from '@vigilo/express';

const app = express();
app.use(express.json());                                       // antes do shield, para inspecionar o corpo
app.use(shield({ apiKey: process.env.VIGILO_KEY, mode: 'monitor' }));
```

**Fastify**

```js
import Fastify from 'fastify';
import { vigilo } from '@vigilo/fastify';

const app = Fastify();
await app.register(vigilo, { apiKey: process.env.VIGILO_KEY });
```

**node:http**

```js
import http from 'node:http';
import { withVigilo } from '@vigilo/http';

http.createServer(withVigilo(handler, { apiKey: process.env.VIGILO_KEY })).listen(3000);
```

### Opções principais

| Opção | Padrão | Descrição |
| --- | --- | --- |
| `apiKey` | — | Chave do projeto. Sem ela, nada é enviado |
| `mode` | `'monitor'` | `monitor` só registra; `block` responde 403 |
| `blockSeverity` | `4` | Severidade mínima (1 a 5) para bloquear |
| `trustProxy` | `false` | `true` confia em proxies em rede privada; ou uma lista de IPs |
| `ignoreRoutes` | `[]` | Rotas ignoradas (ex.: `'/health'`) |
| `sampleRate` | `1` | Fração das requisições limpas que gera evento; suspeitas sempre geram |
| `masking.extraKeys` | `[]` | Chaves extras a mascarar além das padrão |

### Garantias

- **Fail-open:** qualquer erro interno da lib deixa a requisição seguir.
- **Assíncrono:** eventos vão em lotes (5 s ou 500 eventos), com gzip, retry e buffer limitado.
- **LGPD:** `Authorization`, cookies, senhas, tokens, CPF, CNPJ, e-mail e cartão são mascarados antes de sair do processo; o payload só é enviado em eventos suspeitos e limitado a 2 KB.

## O que detecta hoje

- SQL injection (união, tautologias, comentários, queries empilhadas, time-based)
- NoSQL injection (operadores `$ne`, `$gt`, `$where`… como chaves vindas do usuário)
- Path traversal, inclusive com encoding duplo
- XSS refletido
- User agents de scanners e paths típicos de varredura (`/.env`, `/wp-login.php`)
- Varredura por excesso de 404, força bruta em rotas de login e excesso de volume (padrão: 600 requisições por minuto), por IP

O formato dos eventos enviados está em [docs/event-contract.md](docs/event-contract.md) (schema v1, congelado).

Próximo passo: camada RASP, que envolve os drivers (`pg`, `mysql2`, `mongodb`, `fs`, `child_process`) para confirmar quando a entrada do usuário altera a estrutura da query.

## Desenvolvimento

Requer Node.js 20+ e pnpm (`corepack enable`).

```bash
pnpm install
pnpm test          # vitest
pnpm build         # compila os pacotes e gera packages/core/schemas/
pnpm typecheck
```

Estrutura:

```
packages/                 lib open source (core + adapters)
packages/core/schemas/    JSON Schema e exemplo do contrato de eventos (gerados no build)
docs/event-contract.md    formato dos eventos enviados para a plataforma
```

## Licença

Apache 2.0.
