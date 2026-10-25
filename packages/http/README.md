# @vigilo/http

Adapter [Vigilo](https://github.com/wellmtx/vigilo-lib) para `node:http` puro: detecta ataques em tempo real dentro da sua API (SQL e NoSQL injection, path traversal, XSS, scanners, força bruta) e envia eventos mascarados para o painel da Vigilo.

## Instalação

```bash
npm install @vigilo/http
```

Requer Node.js 20 ou mais recente.

## Uso

```js
import http from 'node:http';
import { withVigilo } from '@vigilo/http';

const handler = (req, res) => { /* sua aplicação */ };
http.createServer(withVigilo(handler, { apiKey: process.env.VIGILO_KEY, mode: 'monitor' })).listen(3000);
```

`mode: 'monitor'` (padrão) só registra; `mode: 'block'` responde 403 às ameaças a partir de `blockSeverity` (padrão 4). Sem um framework, a lib não conhece o padrão da rota: o evento leva o path com ids e dados trocados por `:id` (`/users/42` vira `/users/:id`).

### Camada RASP

Confirma o ataque no ponto de execução, antes de a query, o acesso a arquivo ou o comando rodar:

```js
import pg from 'pg';
import { instrumentFs, instrumentPg } from '@vigilo/http';

instrumentPg(pg);   // uma vez, na inicialização
instrumentFs();
```

Também estão disponíveis `instrumentMysql2`, `instrumentMongodb` e `instrumentChildProcess`.

Todas as opções, garantias (fail-open, envio assíncrono, mascaramento para a LGPD) e o que a lib detecta estão no [README principal](https://github.com/wellmtx/vigilo-lib#readme).

## Licença

Apache 2.0.
