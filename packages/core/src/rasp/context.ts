import { AsyncLocalStorage } from 'node:async_hooks';
import type { HeaderValue, Logger, Mode, Severity, Threat } from '../types.js';

/** Fontes de entrada do usuário como o framework as entrega ao handler (já parseadas, sem normalizar). */
export interface InputSources {
  query?: unknown;
  body?: unknown;
  params?: unknown;
  path?: string;
  headers?: Record<string, HeaderValue>;
}

/**
 * Estado da requisição visto pela camada RASP. É criado pelo adapter e propagado com
 * `AsyncLocalStorage` até as chamadas dos drivers (`pg`, ...).
 */
export interface RequestContext {
  readonly mode: Mode;
  readonly blockSeverity: Severity;
  readonly logger?: Logger | undefined;
  /**
   * Lê as fontes no momento da chamada ao driver: o corpo e os params de rota costumam
   * ser preenchidos depois que o middleware do Vigilo roda.
   */
  sources(): InputSources;
  /** Ameaças confirmadas pela RASP durante a requisição. */
  readonly threats: Threat[];
  /** true quando alguma chamada ao driver foi bloqueada. */
  blocked: boolean;
}

const storage = new AsyncLocalStorage<RequestContext>();

export function currentContext(): RequestContext | undefined {
  return storage.getStore();
}

/** Executa `fn` (e tudo o que ela agendar) dentro do contexto da requisição. */
export function runWithContext<T>(context: RequestContext, fn: () => T): T {
  return storage.run(context, fn);
}

/** Registra uma ameaça no contexto, sem duplicar a mesma regra no mesmo local. */
export function reportThreat(context: RequestContext, threat: Threat): void {
  const duplicate = context.threats.some((t) => t.rule === threat.rule && t.location === threat.location);
  if (!duplicate) context.threats.push(threat);
}
