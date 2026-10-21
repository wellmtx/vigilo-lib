import type { Threat } from '../types.js';
import { currentContext, reportThreat } from './context.js';
import { collectRaspInputs } from './inputs.js';
import { findSqlInjection } from './sql.js';

/** Erro devolvido ao código da aplicação quando a RASP bloqueia uma query no modo `block`. */
export class VigiloBlockedError extends Error {
  readonly code = 'VIGILO_BLOCKED';

  constructor(readonly threat: Threat) {
    super(`vigilo: blocked ${threat.type} at ${threat.location}`);
    this.name = 'VigiloBlockedError';
  }
}

type QueryFn = (this: unknown, ...args: unknown[]) => unknown;

interface Patchable {
  prototype: { query?: QueryFn };
}

/** Formato mínimo do módulo `pg` (`import pg from 'pg'` ou `require('pg')`). */
export interface PgModule {
  Client?: unknown;
  Pool?: unknown;
}

const PATCHED = Symbol.for('vigilo.rasp.pg');
const RULE = 'rasp.sqli.pg';

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
    if (isPatchable(target)) patched = patch(target.prototype) || patched;
  }
  return patched;
}

function isPatchable(target: unknown): target is Patchable {
  return (
    typeof target === 'function' &&
    typeof (target as Patchable).prototype?.query === 'function'
  );
}

function patch(proto: Patchable['prototype']): boolean {
  if (Object.prototype.hasOwnProperty.call(proto, PATCHED)) return true;
  const original = proto.query!;
  const wrapped: QueryFn = function vigiloQuery(this: unknown, ...args: unknown[]) {
    const blocked = inspectQuery(args[0]);
    if (blocked) return reject(args, blocked);
    return original.apply(this, args);
  };
  Object.defineProperty(proto, 'query', { value: wrapped, writable: true, configurable: true });
  Object.defineProperty(proto, PATCHED, { value: original });
  return true;
}

/** Devolve o erro de bloqueio quando a query deve ser barrada. Nunca lança (fail-open). */
function inspectQuery(config: unknown): VigiloBlockedError | undefined {
  const context = currentContext();
  if (!context) return undefined;
  try {
    const text = queryText(config);
    if (!text) return undefined;
    const input = findSqlInjection(text, collectRaspInputs(context.sources()), 'postgres');
    if (!input) return undefined;

    const threat: Threat = { type: 'sqli', severity: 5, location: input.location, rule: RULE, layer: 'rasp' };
    reportThreat(context, threat);
    // Objetos "submittable" (cursores, streams) não têm um canal de erro que possamos usar com segurança.
    if (context.mode !== 'block' || threat.severity < context.blockSeverity || isSubmittable(config)) return undefined;
    context.blocked = true;
    return new VigiloBlockedError(threat);
  } catch (error) {
    context.logger?.warn('vigilo: erro interno na RASP do pg (fail-open)', String(error));
    return undefined;
  }
}

function queryText(config: unknown): string | undefined {
  if (typeof config === 'string') return config;
  if (config && typeof config === 'object') {
    const text = (config as { text?: unknown }).text;
    if (typeof text === 'string') return text;
  }
  return undefined;
}

function isSubmittable(config: unknown): boolean {
  return !!config && typeof config === 'object' && typeof (config as { submit?: unknown }).submit === 'function';
}

/** Entrega o erro pelo mesmo canal que o `pg` usaria: callback ou promise. */
function reject(args: unknown[], error: VigiloBlockedError): unknown {
  const config = args[0] as { callback?: unknown } | undefined;
  const callback =
    args.slice(1).find((arg) => typeof arg === 'function') ??
    (config && typeof config === 'object' && typeof config.callback === 'function' ? config.callback : undefined);
  if (typeof callback === 'function') {
    process.nextTick(callback as (err: Error) => void, error);
    return undefined;
  }
  return Promise.reject(error);
}
