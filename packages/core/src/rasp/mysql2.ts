import { collectRaspInputs } from './inputs.js';
import { findSqlInjection } from './sql.js';
import { trailingCallback, wrapMethod, type Delivery, type WrapSpec } from './wrap.js';

/** Formato mínimo do módulo `mysql2` (`import mysql from 'mysql2'`, `require('mysql2')` ou `mysql2/promise`). */
export interface Mysql2Module {
  Connection?: unknown;
  Pool?: unknown;
  /** Só em `mysql2/promise`. */
  PromisePool?: unknown;
}

const spec: WrapSpec = {
  driver: 'mysql2',
  detect(args, context) {
    const text = queryText(args[0]);
    if (!text) return undefined;
    const input = findSqlInjection(text, collectRaspInputs(context.sources()), 'mysql');
    return input && { type: 'sqli', severity: 5, location: input.location, rule: 'rasp.sqli.mysql2', layer: 'rasp' };
  },
  delivery(args): Delivery | undefined {
    const callback = trailingCallback(args);
    if (callback) return { via: 'callback', callback };
    // Comando `Query` já montado, com callback guardado em `onResult`.
    const command = args[0] as { onResult?: unknown } | undefined;
    if (command && typeof command === 'object' && typeof command.onResult === 'function') {
      return { via: 'callback', callback: command.onResult as (error: Error) => void };
    }
    // Sem callback a API é de eventos (`.on('error')`/stream): só registra.
    return undefined;
  },
};

/** `PromisePool` (de `mysql2/promise`) sempre devolve promise. */
const promiseSpec: WrapSpec = { ...spec, delivery: () => ({ via: 'promise' }) };

/**
 * Camada RASP para o driver `mysql2`: envolve `query` e `execute` das conexões e do pool.
 * A API de promise (`mysql2/promise`) delega para essas funções; passe qualquer um dos dois módulos
 * (ou os dois).
 * Queries com placeholders (`?`, `:nome`) são conferidas antes da formatação, então os valores
 * passados à parte nunca disparam.
 *
 * ```js
 * import mysql from 'mysql2';
 * import { instrumentMysql2 } from '@vigilo/express';
 * instrumentMysql2(mysql);
 * ```
 */
export function instrumentMysql2(mysql: Mysql2Module): boolean {
  let patched = false;
  for (const target of [mysql?.Connection, mysql?.Pool]) {
    const proto = baseProto(target);
    if (!proto) continue;
    for (const method of ['query', 'execute']) patched = wrapMethod(proto, method, spec) || patched;
  }
  // A fila do pool pode rodar a query no contexto de outra requisição: confere também na chamada ao pool.
  const promisePool = baseProto(mysql?.PromisePool);
  if (promisePool) {
    for (const method of ['query', 'execute']) patched = wrapMethod(promisePool, method, promiseSpec) || patched;
  }
  return patched;
}

/** O `query` mora na classe base (`BaseConnection`, `BasePool`); envolver nela cobre as subclasses. */
function baseProto(target: unknown): object | undefined {
  if (typeof target !== 'function') return undefined;
  let proto = (target as { prototype?: object }).prototype;
  while (proto && !Object.prototype.hasOwnProperty.call(proto, 'query')) {
    proto = Object.getPrototypeOf(proto) ?? undefined;
    if (proto === Object.prototype) return undefined;
  }
  return proto;
}

function queryText(arg: unknown): string | undefined {
  if (typeof arg === 'string') return arg;
  if (arg && typeof arg === 'object') {
    const sql = (arg as { sql?: unknown }).sql;
    if (typeof sql === 'string') return sql;
  }
  return undefined;
}
