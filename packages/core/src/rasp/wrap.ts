import { promisify } from 'node:util';
import type { Threat } from '../types.js';
import { currentContext, reportThreat, type RequestContext } from './context.js';

/** Erro devolvido ao código da aplicação quando a RASP bloqueia uma chamada no modo `block`. */
export class VigiloBlockedError extends Error {
  readonly code = 'VIGILO_BLOCKED';

  constructor(readonly threat: Threat) {
    super(`vigilo: blocked ${threat.type} at ${threat.location}`);
    this.name = 'VigiloBlockedError';
  }
}

/** Como o erro de bloqueio chega à aplicação, imitando o canal de erro normal da função. */
export type Delivery =
  | { via: 'callback'; callback: (error: Error) => void }
  | { via: 'promise' }
  | { via: 'throw' };

export interface WrapSpec {
  /** Nome usado nos logs (ex.: `pg`, `fs`). */
  driver: string;
  /** Analisa os argumentos da chamada. Pode lançar: o wrapper trata como fail-open. */
  detect(args: unknown[], context: RequestContext): Threat | undefined;
  /** Canal para entregar o bloqueio. `undefined` quando a chamada não pode ser bloqueada com segurança (só registra). */
  delivery(args: unknown[]): Delivery | undefined;
}

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;

const ORIGINALS = Symbol.for('vigilo.rasp.originals');

/**
 * Envolve `target[name]`. Idempotente: chamar de novo no mesmo alvo não envolve duas vezes.
 * Devolve `true` se o método existe e está (ou já estava) instrumentado.
 */
export function wrapMethod(target: object, name: string, spec: WrapSpec): boolean {
  const holder = target as Record<string | symbol, unknown>;
  const original = holder[name];
  if (typeof original !== 'function') return false;

  let originals = Object.prototype.hasOwnProperty.call(holder, ORIGINALS)
    ? (holder[ORIGINALS] as Record<string, AnyFn>)
    : undefined;
  if (originals?.[name]) return true;
  if (!originals) {
    originals = {};
    Object.defineProperty(holder, ORIGINALS, { value: originals });
  }
  originals[name] = original as AnyFn;

  const wrapped = wrapFunction(original as AnyFn, spec);

  const descriptor = Object.getOwnPropertyDescriptor(holder, name);
  Object.defineProperty(holder, name, {
    value: wrapped,
    writable: true,
    configurable: true,
    enumerable: descriptor?.enumerable ?? false,
  });
  return true;
}

function wrapFunction(original: AnyFn, spec: WrapSpec): AnyFn {
  const wrapped: AnyFn = function vigiloWrapped(this: unknown, ...args: unknown[]) {
    const blocked = check(spec, args);
    if (blocked) {
      const { error, delivery } = blocked;
      if (delivery.via === 'callback') {
        process.nextTick(delivery.callback, error);
        return undefined;
      }
      if (delivery.via === 'promise') return Promise.reject(error);
      throw error;
    }
    return original.apply(this, args);
  };
  Object.defineProperty(wrapped, 'name', { value: original.name });

  // Preserva propriedades próprias do original. A versão de `util.promisify` (ex.: `exec`, que
  // resolve `{ stdout, stderr }`) chama o original por dentro, então também é envolvida.
  for (const key of Reflect.ownKeys(original)) {
    if (key === 'length' || key === 'name' || key === 'prototype') continue;
    const descriptor = Object.getOwnPropertyDescriptor(original, key)!;
    if (key === promisify.custom && typeof descriptor.value === 'function') {
      descriptor.value = wrapFunction(descriptor.value as AnyFn, { ...spec, delivery: () => ({ via: 'promise' }) });
    }
    Object.defineProperty(wrapped, key, descriptor);
  }
  return wrapped;
}

/** Devolve o erro e o canal quando a chamada deve ser bloqueada. Nunca lança (fail-open). */
function check(spec: WrapSpec, args: unknown[]): { error: VigiloBlockedError; delivery: Delivery } | undefined {
  const context = currentContext();
  if (!context) return undefined;
  try {
    const threat = spec.detect(args, context);
    if (!threat) return undefined;
    reportThreat(context, threat);
    if (context.mode !== 'block' || threat.severity < context.blockSeverity) return undefined;
    const delivery = spec.delivery(args);
    if (!delivery) return undefined;
    context.blocked = true;
    return { error: new VigiloBlockedError(threat), delivery };
  } catch (error) {
    context.logger?.warn(`vigilo: erro interno na RASP do ${spec.driver} (fail-open)`, String(error));
    return undefined;
  }
}

/** Último argumento a partir de `from` que é uma função (callbacks do estilo Node). */
export function trailingCallback(args: unknown[], from = 1): ((error: Error) => void) | undefined {
  for (let i = args.length - 1; i >= from; i--) {
    if (typeof args[i] === 'function') return args[i] as (error: Error) => void;
  }
  return undefined;
}
