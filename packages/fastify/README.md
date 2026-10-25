# @vigilo/fastify

Plugin [Vigilo](https://github.com/wellmtx/vigilo-lib) para Fastify 5: detecta ataques em tempo real dentro da sua API (SQL e NoSQL injection, path traversal, XSS, scanners, força bruta) e envia eventos mascarados para o painel da Vigilo.

## Instalação

```bash
npm install @vigilo/fastify
```

Requer Node.js 20 ou mais recente.

## Uso

```js
import Fastify from 'fastify';
import { vigilo } from '@vigilo/fastify';

const app = Fastify();
await app.register(vigilo, { apiKey: process.env.VIGILO_KEY, mode: 'monitor' });
```

`mode: 'monitor'` (padrão) só registra; `mode: 'block'` responde 403 às ameaças a partir de `blockSeverity` (padrão 4). Para trocar a resposta de bloqueio, passe `onBlock(request, reply, decision)`. O cliente fica disponível em `app.vigilo`.

### Camada RASP

Confirma o ataque no ponto de execução, antes de a query, o acesso a arquivo ou o comando rodar:

```js
import pg from 'pg';
import { instrumentFs, instrumentPg } from '@vigilo/fastify';

instrumentPg(pg);   // uma vez, na inicialização
instrumentFs();
```

Também estão disponíveis `instrumentMysql2`, `instrumentMongodb` e `instrumentChildProcess`. No modo `block`, a chamada falha com `VigiloBlockedError` (`code: 'VIGILO_BLOCKED'`) e o tratamento de erro da sua aplicação decide a resposta.

Todas as opções, garantias (fail-open, envio assíncrono, mascaramento para a LGPD) e o que a lib detecta estão no [README principal](https://github.com/wellmtx/vigilo-lib#readme).

## Licença

Apache 2.0.
