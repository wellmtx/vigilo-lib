import { clip, clipThreats, LIMITS } from './contract.js';
import { detect, highestSeverity } from './detectors/index.js';
import type { InputSources, RequestContext } from './rasp/context.js';
import { buildPayload, type MaskingOptions } from './masking.js';
import { IpTracker, type TrackerOptions } from './tracker.js';
import { RemoteConfig } from './remote-config.js';
import { EventTransport, type SendFn, type TransportStats } from './transport.js';
import type { TrustProxy } from './ip.js';
import type { Decision, Logger, Mode, NormalizedRequest, ResponseOutcome, Severity, VigiloEvent } from './types.js';
import { uuidv7 } from './uuid.js';

export const DEFAULT_ENDPOINT = 'https://ingest.vigilosec.com';

export interface VigiloOptions {
  /** Chave do projeto, criada no painel. Sem ela, nada é enviado (útil em desenvolvimento). */
  apiKey?: string | undefined;
  /**
   * `monitor` só registra; `block` responde 403 às requisições suspeitas. Sem este
   * campo, o modo vem do painel (consultado ao iniciar e a cada minuto), começando
   * em `monitor`. Definido aqui, ele prevalece e o painel não é consultado.
   */
  mode?: Mode;
  /** Consultar o modo no painel quando `mode` não é definido. Padrão: `true`. */
  remoteConfig?: boolean;
  /** Intervalo entre consultas ao painel. Padrão: 60 s. */
  configIntervalMs?: number;
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
  /** Modo atual (pode mudar quando vem do painel). */
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
  let mode: Mode = options.mode ?? 'monitor';
  const blockSeverity = options.blockSeverity ?? 4;
  const sampleRate = clamp(options.sampleRate ?? 1);
  const logger = options.logger;
  const tracker = new IpTracker(options.tracker);
  const endpoint = options.endpoint ?? process.env.VIGILO_ENDPOINT ?? DEFAULT_ENDPOINT;
  const transport = new EventTransport({
    apiKey: options.apiKey,
    endpoint,
    batchSize: options.batchSize,
    flushIntervalMs: options.flushIntervalMs,
    maxBufferSize: options.maxBufferSize,
    send: options.send,
    logger,
  });

  if (!options.apiKey && !options.send) {
    logger?.warn('vigilo: apiKey ausente; eventos não serão enviados');
  }

  // O modo vem do painel, salvo quando o código o define.
  const remote =
    options.mode === undefined && options.apiKey && !options.send && options.remoteConfig !== false
      ? new RemoteConfig({
          endpoint,
          apiKey: options.apiKey,
          intervalMs: options.configIntervalMs,
          logger,
          onMode: (next) => {
            if (next !== mode) logger?.warn('vigilo: modo alterado pelo painel', { from: mode, to: next });
            mode = next;
          },
        })
      : undefined;
  remote?.start();

  const ignore = options.ignoreRoutes ?? [];
  const isIgnored = (route: string) =>
    ignore.some((rule) => (typeof rule === 'string' ? rule === route : rule.test(route)));

  return {
    get mode() {
      return mode;
    },
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
          payload: suspicious
            ? buildPayload({ path: req.path, query: req.query, params: routeParams(outcome), body: req.body }, options.masking)
            : null,
        };
        transport.push(event);
      } catch (error) {
        logger?.warn('vigilo: erro interno em record (fail-open)', String(error));
      }
    },

    flush: () => transport.flush(),
    close: () => {
      remote?.stop();
      return transport.close();
    },
    stats: () => transport.getStats(),
  };
}

/** Parâmetros de rota (`/users/:id`), lidos pelo contexto da requisição depois do roteamento. */
function routeParams(outcome: ResponseOutcome): unknown {
  try {
    return outcome.context?.sources().params;
  } catch {
    return undefined;
  }
}

function clamp(value: number): number {
  if (Number.isNaN(value)) return 1;
  return Math.min(1, Math.max(0, value));
}
