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

### Camada RASP (PostgreSQL)

Com o driver `pg` instrumentado, a lib confere cada query antes de ela ir para o banco. Se uma entrada da requisição (params, query string, corpo, chaves do corpo ou cabeçalhos como `user-agent`) mudou a estrutura do SQL, por exemplo fechando aspas ou acrescentando `OR`, `UNION`, `;` ou um comentário, o evento registra uma ameaça `sqli` de severidade 5 com `layer: 'rasp'`. Isso confirma que a rota é vulnerável. Queries parametrizadas (`$1`) nunca disparam.

```js
import pg from 'pg';
import { instrumentPg, shield } from '@vigilo/express';   // também em @vigilo/fastify e @vigilo/http

instrumentPg(pg);   // uma vez, na inicialização; vale para Client e Pool
```

No modo `block`, a query não é executada e a chamada falha com `VigiloBlockedError` (`code: 'VIGILO_BLOCKED'`), pelo mesmo canal que o `pg` usaria (promise ou callback). O tratamento de erro da sua aplicação decide a resposta. Cursores e streams (objetos com `submit`) só são registrados, nunca bloqueados. Queries fora de uma requisição (jobs, migrations) não são verificadas.

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
- SQL injection confirmada no driver `pg` (camada RASP)

O formato dos eventos enviados está em [docs/event-contract.md](docs/event-contract.md) (schema v1, congelado).

Próximos passos da RASP: `mysql2`, `mongodb`, `fs` e `child_process`.

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
