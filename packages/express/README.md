# @vigilo/express

Middleware [Vigilo](https://github.com/wellmtx/vigilo-lib) para Express 4 e 5: detecta ataques em tempo real dentro da sua API (SQL e NoSQL injection, path traversal, XSS, scanners, força bruta) e envia eventos mascarados para o painel da Vigilo.

## Instalação

```bash
npm install @vigilo/express
```

Requer Node.js 20 ou mais recente.

## Uso

```js
import express from 'express';
import { shield } from '@vigilo/express';

const app = express();
app.use(express.json());   // antes do shield, para inspecionar o corpo
app.use(shield({ apiKey: process.env.VIGILO_KEY, mode: 'monitor' }));
```

`mode: 'monitor'` (padrão) só registra; `mode: 'block'` responde 403 às ameaças a partir de `blockSeverity` (padrão 4). Para trocar a resposta de bloqueio, passe `onBlock(req, res, decision)`.

### Camada RASP

Confirma o ataque no ponto de execução, antes de a query, o acesso a arquivo ou o comando rodar:

```js
import pg from 'pg';
import { instrumentFs, instrumentPg } from '@vigilo/express';

instrumentPg(pg);   // uma vez, na inicialização
instrumentFs();
```

Também estão disponíveis `instrumentMysql2`, `instrumentMongodb` e `instrumentChildProcess`. No modo `block`, a chamada falha com `VigiloBlockedError` (`code: 'VIGILO_BLOCKED'`) e o tratamento de erro da sua aplicação decide a resposta.

Todas as opções, garantias (fail-open, envio assíncrono, mascaramento para a LGPD) e o que a lib detecta estão no [README principal](https://github.com/wellmtx/vigilo-lib#readme).

## Licença

Apache 2.0.
