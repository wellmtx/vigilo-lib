# @vigilo/core

Núcleo da [Vigilo](https://github.com/wellmtx/vigilo-lib): detecção de ataques, estado por IP, camada RASP, mascaramento e envio dos eventos para a plataforma.

**Para usar na sua API, instale o adapter do seu framework**, que já traz o core:

| Framework | Pacote |
| --- | --- |
| Express 4 e 5 | [`@vigilo/express`](https://www.npmjs.com/package/@vigilo/express) |
| Fastify 5 | [`@vigilo/fastify`](https://www.npmjs.com/package/@vigilo/fastify) |
| `node:http` | [`@vigilo/http`](https://www.npmjs.com/package/@vigilo/http) |

## Uso direto

Para outro framework, use o cliente do core. Ele nunca lança exceção (fail-open):

```js
import { createVigilo } from '@vigilo/core';

const vigilo = createVigilo({ apiKey: process.env.VIGILO_KEY, mode: 'monitor' });

// a cada requisição, antes do handler
const request = { method, route: '/users/:id', path, query, headers, body, ip };
const decision = vigilo.inspect(request);
if (decision.block) { /* responda 403 */ }

// depois da resposta
vigilo.record(request, { status, durationMs, decision });
```

`route` deve ser o padrão da rota, nunca o path concreto: ele vai para a plataforma sem mascaramento. Se o framework não informar o padrão, use `normalizeRoutePath(path)`.

O formato dos eventos está no [contrato de eventos](https://github.com/wellmtx/vigilo-lib/blob/main/docs/event-contract.md), e o JSON Schema vai junto no pacote, em `schemas/`. As opções e garantias estão no [README principal](https://github.com/wellmtx/vigilo-lib#readme).

## Licença

Apache 2.0.
