# Exemplo: Express + PostgreSQL

App **propositalmente vulnerável** para ver a Vigilo detectar e bloquear ataques. Ele só escuta em `127.0.0.1`; não publique.

Sem configuração nenhuma, usa um PostgreSQL em memória ([pg-mem](https://github.com/oguimbal/pg-mem)) e imprime os eventos no terminal.

## Rodar

Na raiz do repositório:

```bash
pnpm install
pnpm build
pnpm --filter @vigilo/example-express-pg start
```

| Variável | Padrão | Efeito |
| --- | --- | --- |
| `VIGILO_MODE` | `block` | `monitor` deixa tudo seguir e só registra |
| `DATABASE_URL` | — | Usa um PostgreSQL real (ex.: `postgres://vigilo:vigilo@localhost:5432/vigilo`) |
| `VIGILO_KEY` | — | Envia os eventos para a plataforma em vez de imprimir |
| `PORT` | `3000` | Porta do servidor |

## Ataques de teste

Em outro terminal:

```bash
# SQLi em parâmetro de rota. Passa pelas assinaturas; a RASP do pg confirma e bloqueia.
curl "http://127.0.0.1:3000/users/1%20%7C%7C%201%3D1"

# SQLi dentro de literal, também só a RASP pega.
curl "http://127.0.0.1:3000/search?name=x'%20OR%20name%20OR%20'"

# A mesma entrada numa rota parametrizada: nenhum alerta da RASP.
curl "http://127.0.0.1:3000/safe/users/1%20%7C%7C%201%3D1"

# Path traversal: a assinatura bloqueia na entrada; em monitor, a RASP do fs confirma a leitura.
curl "http://127.0.0.1:3000/files?name=../server.js"
```

Saída esperada no terminal do servidor (modo `block`):

```
[vigilo] GET /users/:id → 403 | sqli sev 5 BLOQUEADO | rasp:rasp.sqli.pg@params.id
[vigilo] GET /search → 403 | sqli sev 5 BLOQUEADO | rasp:rasp.sqli.pg@query.name
[vigilo] GET /files → 403 | traversal sev 4 BLOQUEADO | signature:traversal.dot-dot@query.name
```

Com `VIGILO_MODE=monitor` as requisições seguem (o pg-mem pode responder 500 porque não executa o SQL injetado) e o evento mostra as duas camadas, por exemplo `signature:traversal.dot-dot` e `rasp:rasp.traversal.fs` no `/files`.

## O que olhar no código

- [`server.js`](server.js): `instrumentPg`/`instrumentFs` antes de criar o pool, `shield` depois do `express.json()` e um handler de erro que transforma `VIGILO_BLOCKED` em 403.
