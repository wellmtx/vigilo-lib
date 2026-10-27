# Vigilo

Segurança de APIs para Node.js: uma lib que roda dentro da sua aplicação, detecta ataques em tempo real e envia eventos mascarados para um painel com alertas e relatórios.

> Status: beta. Os pacotes estão no npm; a API pode mudar até a versão 1.0.

```bash
npm install @vigilo/express   # ou @vigilo/fastify, @vigilo/http
```

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

### Camada RASP (drivers e APIs do Node)

Com os drivers instrumentados, a lib confere cada chamada **antes** de ela chegar ao banco, ao disco ou ao shell. Se uma entrada da requisição (params, query string, corpo, chaves do corpo ou cabeçalhos como `user-agent`) mudou a estrutura do que vai ser executado, o evento registra uma ameaça de severidade 5 com `layer: 'rasp'`. Isso confirma que a rota é vulnerável, com poucos falsos positivos.

| Função | Alvo | Detecta | Regra |
| --- | --- | --- | --- |
| `instrumentPg(pg)` | `pg` (`Client`, `Pool`) | SQL injection | `rasp.sqli.pg` |
| `instrumentMysql2(mysql)` | `mysql2` e `mysql2/promise` (`query`, `execute`, pool) | SQL injection | `rasp.sqli.mysql2` |
| `instrumentMongodb(mongodb)` | `mongodb` (`Collection`); com Mongoose, `mongoose.mongo` | operador `$` vindo do usuário e código em `$where` | `rasp.nosqli.mongodb` |
| `instrumentFs()` | `node:fs` (callback, sync, `fs/promises`, streams) | path traversal (`../` que sobe de diretório, caminho absoluto do usuário) | `rasp.traversal.fs` |
| `instrumentChildProcess()` | `node:child_process` com shell | command injection (`;`, `\|`, `&&`, `$(...)`, crase, saída de aspas) | `rasp.cmdi.child_process` |

```js
import pg from 'pg';
import { instrumentFs, instrumentPg, shield } from '@vigilo/express';   // também em @vigilo/fastify e @vigilo/http

instrumentPg(pg);   // uma vez, na inicialização
instrumentFs();
```

Queries parametrizadas (`$1`, `?`), filtros com operadores escritos pelo desenvolvedor e `spawn`/`execFile` sem shell nunca disparam. Chamadas fora de uma requisição (jobs, migrations) não são verificadas.

No modo `block`, a chamada não é executada e falha com `VigiloBlockedError` (`code: 'VIGILO_BLOCKED'`) pelo canal de erro normal dela: callback, promise rejeitada ou exceção (funções síncronas, `find`/`aggregate` do MongoDB, streams do `fs` e `child_process`). O tratamento de erro da sua aplicação decide a resposta; veja o [exemplo](examples/express-pg). Cursores do `pg` e a API de eventos do `mysql2` (sem callback) só são registrados, nunca bloqueados.

### Opções principais

| Opção | Padrão | Descrição |
| --- | --- | --- |
| `apiKey` | — | Chave do projeto. Sem ela, nada é enviado |
| `mode` | do painel | `monitor` só registra; `block` responde 403. Sem este campo, vale o modo do projeto no painel (consultado ao iniciar e a cada minuto, começando em `monitor`); definido no código, ele prevalece |
| `remoteConfig` | `true` | `false` desliga a consulta do modo ao painel |
| `blockSeverity` | `4` | Severidade mínima (1 a 5) para bloquear |
| `trustProxy` | `false` | `true` confia em proxies em rede privada; ou uma lista de IPs |
| `ignoreRoutes` | `[]` | Rotas ignoradas (ex.: `'/health'`) |
| `sampleRate` | `1` | Fração das requisições limpas que gera evento; suspeitas sempre geram |
| `masking.extraKeys` | `[]` | Chaves extras a mascarar além das padrão |

### Garantias

- **Fail-open:** qualquer erro interno da lib deixa a requisição seguir.
- **Assíncrono:** eventos vão em lotes (5 s ou 500 eventos), com gzip e buffer limitado. Falhas temporárias têm nova tentativa; `Retry-After` da plataforma pausa os envios sem perder eventos; lote recusado (ex.: API key inválida) não é reenviado. `client.stats()` mostra `sent`, `dropped`, `failedBatches` e `rejectedBatches`.
- **LGPD:** `Authorization`, cookies, senhas, tokens, CPF, CNPJ, e-mail e cartão são mascarados antes de sair do processo; o payload só é enviado em eventos suspeitos e limitado a 2 KB. O path concreto nunca é enviado: o evento leva o padrão da rota (`/users/:id`), e quando o framework não o informa, segmentos com dados ou símbolos viram `:id`.

## O que detecta hoje

- SQL injection (união, tautologias, comentários, queries empilhadas, time-based)
- NoSQL injection (operadores `$ne`, `$gt`, `$where`… como chaves vindas do usuário)
- Path traversal, inclusive com encoding duplo
- XSS refletido
- User agents de scanners e paths típicos de varredura (`/.env`, `/wp-login.php`)
- Varredura por excesso de 404, força bruta em rotas de login e excesso de volume (padrão: 600 requisições por minuto), por IP
- Confirmação na execução (camada RASP): SQL injection no `pg` e no `mysql2`, NoSQL injection no `mongodb`, path traversal no `fs` e command injection no `child_process`

O formato dos eventos enviados está em [docs/event-contract.md](docs/event-contract.md) (schema v1, congelado).

## Qualidade e desempenho

Medidos em 21/10/2026 com Node 24, sobre um corpus próprio de payloads de ataque e entradas legítimas típicas de APIs brasileiras ([corpus](packages/core/test/corpus)). Como o corpus foi escrito por nós, os números servem para evitar regressões, não como garantia contra qualquer ataque.

| Camada | Detecção | Falso positivo |
| --- | --- | --- |
| Assinaturas (na requisição) | SQLi 90,9%, NoSQLi 100%, traversal 100%, XSS 93,8%, scanners 100% | 0% em 66 entradas legítimas |
| RASP (na execução) | 100% em SQLi, NoSQLi, traversal e command injection | 0% em 66 entradas legítimas |

| Overhead (p99) | Tempo |
| --- | --- |
| Por requisição no Express (middleware + registro do evento) | 14 µs |
| `inspect` + `record` com corpo JSON de ~1 KB | 34 µs |
| Checagem da RASP por query | 8 µs |

Reproduza com `pnpm eval:detection` e `pnpm bench`.

## Desenvolvimento

Requer Node.js 20+ e pnpm (`corepack enable`).

```bash
pnpm install
pnpm test          # vitest
pnpm build         # compila os pacotes e gera packages/core/schemas/
pnpm typecheck
pnpm eval:detection   # tabela de detecção e falsos positivos sobre o corpus
pnpm bench            # overhead por requisição e por query
```

Estrutura:

```
packages/                 lib open source (core + adapters)
packages/core/schemas/    JSON Schema e exemplo do contrato de eventos (gerados no build)
docs/event-contract.md    formato dos eventos enviados para a plataforma
examples/express-pg/      app vulnerável de exemplo (roda sem banco, com pg-mem)
```

## Publicação

Os quatro pacotes têm sempre a mesma versão, igual ao `SDK_VERSION` enviado nos eventos. Para publicar:

```bash
node scripts/set-version.mjs 0.1.0   # muda a versão dos pacotes e do SDK_VERSION
pnpm build                           # regenera packages/core/schemas/ com a versão nova
git commit -am "chore: release 0.1.0"
git tag v0.1.0
git push origin main v0.1.0
```

A tag dispara o workflow [`release.yml`](.github/workflows/release.yml), que roda os testes e publica no npm por trusted publishing, com provenance. Não há token do npm no repositório.

> **Hoje a publicação pelo workflow falha** com `403 OIDC permission denied`: o npm ainda não aceita o formato de identidade que o GitHub usa para repositórios criados depois de 15/07/2026 ([npm/cli#9969](https://github.com/npm/cli/issues/9969), aberto). Até a correção, publique à mão a partir da tag, com o 2FA da conta:
>
> ```bash
> git checkout v0.1.0 && pnpm install --frozen-lockfile && pnpm build && pnpm test
> mkdir -p release && for p in core express fastify http; do (cd packages/$p && pnpm pack --pack-destination ../../release); done
> for p in core express fastify http; do npm publish ./release/vigilo-$p-0.1.0.tgz --access public; done
> ```
>
> Sem o workflow, a versão sai sem provenance. Quando o npm corrigir o bug, o workflow volta a funcionar sem mudança.

## Licença

Apache 2.0.
