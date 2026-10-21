import { clip, clipThreats, LIMITS } from './contract.js';
import { detect, highestSeverity } from './detectors/index.js';
import type { InputSources, RequestContext } from './rasp/context.js';
import { buildPayload, type MaskingOptions } from './masking.js';
import { IpTracker, type TrackerOptions } from './tracker.js';
import { EventTransport, type SendFn, type TransportStats } from './transport.js';
import type { TrustProxy } from './ip.js';
import type { Decision, Logger, Mode, NormalizedRequest, ResponseOutcome, Severity, VigiloEvent } from './types.js';
import { uuidv7 } from './uuid.js';

export const DEFAULT_ENDPOINT = 'https://ingest.vigilosec.com';

export interface VigiloOptions {
  /** Chave do projeto, criada no painel. Sem ela, nada é enviado (útil em desenvolvimento). */
  apiKey?: string | undefined;
  /** `monitor` (padrão) só registra; `block` responde 403 às requisições suspeitas. */
  mode?: Mode;
  /** Severidade mínima para bloquear no modo `block`. Padrão: 4. */
  blockSeverity?: Severity;
  /** URL da API de ingestão. Padrão: `VIGILO_ENDPOINT` ou o endpoint da plataforma. */
  endpoint?: string;
  /** Quando confiar em `X-Forwarded-For`. Padrão: `false`. */
  trustProxy?: TrustProxy;
  /** Fração das requisições limpas que gera evento (0 a 1). Suspeitas são sempre enviadas. Padrão: 1. */
  sampleRate?: number;
  /** Rotas ignoradas por completo (ex.: health check). */
  ignoreRoutes?: Array<string | RegExp>;
  masking?: MaskingOptions;
  tracker?: TrackerOptions;
  /** Ajustes do envio em lote. */
  batchSize?: number;
  flushIntervalMs?: number;
  maxBufferSize?: number;
  /** Substitui o envio HTTP (testes ou transportes alternativos). */
  send?: SendFn;
  logger?: Logger;
}

export interface VigiloClient {
  readonly mode: Mode;
  readonly trustProxy: TrustProxy;
  /** Camada 1 e flags da camada 2. Nunca lança exceção (fail-open). */
  inspect(req: NormalizedRequest): Decision;
  /**
   * Cria o contexto da camada RASP para uma requisição. O adapter executa o handler dentro
   * dele (`runWithContext`) e o devolve em `record`, no campo `outcome.context`.
   */
  createContext(sources: () => InputSources): RequestContext;
  /** Registra o resultado da requisição e enfileira o evento. Nunca lança exceção. */
  record(req: NormalizedRequest, outcome: ResponseOutcome): void;
  isIgnored(route: string): boolean;
  flush(): Promise<void>;
  close(): Promise<void>;
  stats(): TransportStats;
}

const NO_THREATS: Decision = Object.freeze({ threats: [], block: false }) as Decision;

export function createVigilo(options: VigiloOptions = {}): VigiloClient {
  const mode: Mode = options.mode ?? 'monitor';
  const blockSeverity = options.blockSeverity ?? 4;
  const sampleRate = clamp(options.sampleRate ?? 1);
  const logger = options.logger;
  const tracker = new IpTracker(options.tracker);
  const transport = new EventTransport({
    apiKey: options.apiKey,
    endpoint: options.endpoint ?? process.env.VIGILO_ENDPOINT ?? DEFAULT_ENDPOINT,
    batchSize: options.batchSize,
    flushIntervalMs: options.flushIntervalMs,
    maxBufferSize: options.maxBufferSize,
    send: options.send,
    logger,
  });

  if (!options.apiKey && !options.send) {
    logger?.warn('vigilo: apiKey ausente; eventos não serão enviados');
  }

  const ignore = options.ignoreRoutes ?? [];
  const isIgnored = (route: string) =>
    ignore.some((rule) => (typeof rule === 'string' ? rule === route : rule.test(route)));

  return {
    mode,
    trustProxy: options.trustProxy ?? false,
    isIgnored,

    inspect(req) {
      try {
        if (isIgnored(req.route)) return NO_THREATS;
        const threats = detect(req);
        threats.push(...tracker.flagsFor(req.ip));
        const block = mode === 'block' && threats.some((t) => t.severity >= blockSeverity);
        return { threats, block };
      } catch (error) {
        logger?.warn('vigilo: erro interno em inspect (fail-open)', String(error));
        return NO_THREATS;
      }
    },

    createContext(sources) {
      return { mode, blockSeverity, logger, sources, threats: [], blocked: false };
    },

    record(req, outcome) {
      try {
        if (isIgnored(req.route)) return;
        const all = [...outcome.decision.threats, ...(outcome.context?.threats ?? [])];
        const observed = tracker.observe(req.ip, req.route, outcome.status);
        if (observed) all.push(observed);
        const threats = clipThreats(all);

        const suspicious = threats.length > 0;
        if (!suspicious && sampleRate < 1 && Math.random() >= sampleRate) return;

        const top = highestSeverity(threats);
        const event: VigiloEvent = {
          eventId: uuidv7(),
          ts: new Date().toISOString(),
          method: clip(req.method, LIMITS.method),
          route: clip(req.route, LIMITS.route),
          status: outcome.status,
          durationMs: Math.round(outcome.durationMs * 1000) / 1000,
          ip: req.ip,
          srcPort: req.srcPort ?? null,
          userAgent: req.userAgent ? clip(req.userAgent, LIMITS.userAgent) : null,
          threatType: top?.type ?? null,
          severity: top?.severity ?? null,
          threats,
          blocked: outcome.decision.block || outcome.context?.blocked === true,
          payload: suspicious ? buildPayload({ query: req.query, body: req.body }, options.masking) : null,
        };
        transport.push(event);
      } catch (error) {
        logger?.warn('vigilo: erro interno em record (fail-open)', String(error));
      }
    },

    flush: () => transport.flush(),
    close: () => transport.close(),
    stats: () => transport.getStats(),
  };
}

function clamp(value: number): number {
  if (Number.isNaN(value)) return 1;
  return Math.min(1, Math.max(0, value));
}
