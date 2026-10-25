import { gzipSync } from 'node:zlib';
import { buildBatch, LIMITS } from './contract.js';
import type { Logger, VigiloEvent } from './types.js';

export type SendFn = (events: VigiloEvent[]) => Promise<void>;

export interface TransportOptions {
  apiKey?: string | undefined;
  /** URL base da API de ingestão. */
  endpoint: string;
  /** Envia quando o lote atinge este tamanho. Padrão e máximo: 500. */
  batchSize?: number;
  /** Envia a cada intervalo, mesmo com lote incompleto. Padrão: 5 s. */
  flushIntervalMs?: number;
  /** Tamanho máximo do buffer; acima disso os eventos mais antigos são descartados. Padrão: 10.000. */
  maxBufferSize?: number;
  /** Tentativas por lote antes de desistir. Padrão: 3. */
  maxRetries?: number;
  /** Timeout de cada envio. Padrão: 3 s. */
  timeoutMs?: number;
  /** Substitui o envio HTTP (testes ou transportes alternativos). */
  send?: SendFn;
  logger?: Logger | undefined;
}

export interface TransportStats {
  queued: number;
  sent: number;
  dropped: number;
  /** Lotes descartados depois de esgotar as tentativas (rede, timeout, 5xx). */
  failedBatches: number;
  /** Lotes recusados pela ingestão sem chance de dar certo (4xx como 400, 401, 413); não há nova tentativa. */
  rejectedBatches: number;
}

/**
 * Resposta de erro da ingestão. Um `send` próprio pode lançar este erro para
 * ter o mesmo tratamento do envio HTTP padrão.
 */
export class IngestionError extends Error {
  constructor(
    readonly status: number,
    /** Prazo pedido pelo header `Retry-After`, em milissegundos. */
    readonly retryAfterMs?: number,
  ) {
    super(`ingestion responded ${status}`);
    this.name = 'IngestionError';
  }
}

/** Pausa máxima pedida por `Retry-After` que a lib respeita. */
const MAX_PAUSE_MS = 5 * 60_000;

type SendOutcome = { kind: 'sent' } | { kind: 'failed' } | { kind: 'rejected'; status: number } | { kind: 'paused'; ms: number };

/**
 * Buffer em memória com envio assíncrono em lote. Nada aqui pode lançar exceção
 * para o código do cliente: falhas viram contadores e logs.
 */
export class EventTransport {
  private buffer: VigiloEvent[] = [];
  private timer: NodeJS.Timeout | undefined;
  private inFlight: Promise<void> | undefined;
  private readonly stats: TransportStats = { queued: 0, sent: 0, dropped: 0, failedBatches: 0, rejectedBatches: 0 };
  private pausedUntil = 0;
  private lastRejectedStatus: number | undefined;
  private readonly send: SendFn;
  private readonly batchSize: number;
  private readonly maxBufferSize: number;
  private readonly maxRetries: number;

  constructor(private readonly options: TransportOptions) {
    this.batchSize = Math.min(Math.max(1, options.batchSize ?? LIMITS.batchSize), LIMITS.batchSize);
    this.maxBufferSize = options.maxBufferSize ?? 10_000;
    this.maxRetries = options.maxRetries ?? 3;
    this.send = options.send ?? ((events) => this.httpSend(events));

    const interval = options.flushIntervalMs ?? 5_000;
    if (interval > 0) {
      this.timer = setInterval(() => void this.flush(), interval);
      // Não impede o processo do cliente de encerrar.
      this.timer.unref();
    }
  }

  push(event: VigiloEvent): void {
    this.buffer.push(event);
    this.stats.queued++;
    if (this.buffer.length > this.maxBufferSize) {
      const overflow = this.buffer.length - this.maxBufferSize;
      this.buffer.splice(0, overflow);
      this.stats.dropped += overflow;
    }
    if (this.buffer.length >= this.batchSize) void this.flush();
  }

  /**
   * Envia tudo o que está no buffer. Nunca rejeita. Enquanto a ingestão pede
   * para esperar (`Retry-After`), não envia, salvo com `force` (no `close`).
   */
  async flush(force = false): Promise<void> {
    if (this.inFlight) return this.inFlight;
    if (this.buffer.length === 0) return;
    if (!force && Date.now() < this.pausedUntil) return;
    this.inFlight = this.drain().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush(true);
  }

  getStats(): TransportStats {
    return { ...this.stats, queued: this.buffer.length };
  }

  private async drain(): Promise<void> {
    while (this.buffer.length > 0) {
      const batch = this.buffer.splice(0, this.batchSize);
      const outcome = await this.sendWithRetry(batch);
      switch (outcome.kind) {
        case 'sent':
          this.stats.sent += batch.length;
          this.lastRejectedStatus = undefined;
          continue;
        case 'paused':
          // A ingestão pediu para esperar: o lote volta para o início do buffer.
          this.buffer.unshift(...batch);
          this.pausedUntil = Date.now() + outcome.ms;
          this.options.logger?.warn('vigilo: ingestão pediu para esperar; envio pausado', { ms: outcome.ms });
          return;
        case 'rejected':
          this.stats.rejectedBatches++;
          this.stats.dropped += batch.length;
          // Um aviso por status, não a cada lote (ex.: API key inválida dá 401 em todos).
          if (this.lastRejectedStatus !== outcome.status) {
            this.lastRejectedStatus = outcome.status;
            this.options.logger?.warn('vigilo: ingestão recusou o lote; eventos descartados', {
              status: outcome.status,
              hint: rejectionHint(outcome.status),
            });
          }
          // Provavelmente vale para os próximos lotes também; o próximo ciclo tenta de novo.
          return;
        case 'failed':
          this.stats.failedBatches++;
          this.stats.dropped += batch.length;
          // Para de tentar nesta rodada; o próximo ciclo tenta os eventos restantes.
          return;
      }
    }
  }

  private async sendWithRetry(batch: VigiloEvent[]): Promise<SendOutcome> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        await this.send(batch);
        return { kind: 'sent' };
      } catch (error) {
        if (error instanceof IngestionError) {
          if (error.retryAfterMs !== undefined && (error.status === 429 || error.status === 503)) {
            return { kind: 'paused', ms: Math.min(Math.max(error.retryAfterMs, 1_000), MAX_PAUSE_MS) };
          }
          if (!isRetryable(error.status)) return { kind: 'rejected', status: error.status };
        }
        this.options.logger?.warn('vigilo: falha ao enviar eventos', { attempt: attempt + 1, error: String(error) });
        if (attempt < this.maxRetries - 1) await sleep(200 * 2 ** attempt);
      }
    }
    return { kind: 'failed' };
  }

  private async httpSend(events: VigiloEvent[]): Promise<void> {
    if (!this.options.apiKey) return;
    const body = gzipSync(Buffer.from(JSON.stringify(buildBatch(events)), 'utf8'));
    const response = await fetch(new URL('/v1/events', this.options.endpoint), {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.options.apiKey}`,
        'content-type': 'application/json',
        'content-encoding': 'gzip',
      },
      body,
      signal: AbortSignal.timeout(this.options.timeoutMs ?? 3_000),
    });
    if (!response.ok) {
      throw new IngestionError(response.status, parseRetryAfter(response.headers.get('retry-after')));
    }
  }
}

/** 408 (timeout), 429 (limite) e 5xx podem dar certo numa nova tentativa; os demais 4xx, não. */
function isRetryable(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

function rejectionHint(status: number): string {
  if (status === 401 || status === 403) return 'confira a apiKey';
  if (status === 404) return 'confira o endpoint';
  if (status === 413) return 'lote grande demais';
  return 'lote fora do contrato; atualize a lib';
}

/** `Retry-After` em segundos ou como data HTTP. */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1_000;
  // Data HTTP sempre tem o nome do dia e do mês; sem letras, Date.parse aceitaria "-5".
  if (!/[a-z]/i.test(trimmed)) return undefined;
  const date = Date.parse(trimmed);
  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
  });
}
