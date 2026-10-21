import { collectRaspInputs } from './inputs.js';
import { findSqlInjection } from './sql.js';
import { trailingCallback, wrapMethod, type Delivery, type WrapSpec } from './wrap.js';

/** Formato mínimo do módulo `pg` (`import pg from 'pg'` ou `require('pg')`). */
export interface PgModule {
  Client?: unknown;
  Pool?: unknown;
}

const spec: WrapSpec = {
  driver: 'pg',
  detect(args, context) {
    const text = queryText(args[0]);
    if (!text) return undefined;
    const input = findSqlInjection(text, collectRaspInputs(context.sources()), 'postgres');
    return input && { type: 'sqli', severity: 5, location: input.location, rule: 'rasp.sqli.pg', layer: 'rasp' };
  },
  delivery(args): Delivery | undefined {
    const config = args[0] as { submit?: unknown; callback?: unknown } | undefined;
    // Objetos "submittable" (cursores, streams) não têm um canal de erro que possamos usar com segurança.
    if (config && typeof config === 'object' && typeof config.submit === 'function') return undefined;
    const callback =
      trailingCallback(args) ??
      (config && typeof config === 'object' && typeof config.callback === 'function'
        ? (config.callback as (error: Error) => void)
        : undefined);
    return callback ? { via: 'callback', callback } : { via: 'promise' };
  },
};

/**
 * Camada RASP para o driver `pg`: envolve `Client.prototype.query` e `Pool.prototype.query`
 * e confere, antes de cada query, se alguma entrada da requisição atual mudou a estrutura
 * do SQL. Fora de uma requisição (jobs, migrations) nada é verificado.
 *
 * ```js
 * import pg from 'pg';
 * import { instrumentPg } from '@vigilo/express';
 * instrumentPg(pg);
 * ```
 *
 * O `Pool` também é envolvido porque a fila interna dele pode executar a query no contexto
 * assíncrono de outra requisição; verificar na chamada garante a requisição certa.
 * Devolve `true` se algum protótipo foi instrumentado. Chamar de novo não envolve duas vezes.
 */
export function instrumentPg(pg: PgModule): boolean {
  let patched = false;
  for (const target of [pg?.Client, pg?.Pool]) {
    const proto = typeof target === 'function' ? (target as { prototype?: object }).prototype : undefined;
    if (proto) patched = wrapMethod(proto, 'query', spec) || patched;
  }
  return patched;
}

function queryText(config: unknown): string | undefined {
  if (typeof config === 'string') return config;
  if (config && typeof config === 'object') {
    const text = (config as { text?: unknown }).text;
    if (typeof text === 'string') return text;
  }
  return undefined;
}
