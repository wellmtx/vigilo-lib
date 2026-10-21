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
  failedBatches: number;
}

/**
 * Buffer em memória com envio assíncrono em lote. Nada aqui pode lançar exceção
 * para o código do cliente: falhas viram contadores e logs.
 */
export class EventTransport {
  private buffer: VigiloEvent[] = [];
  private timer: NodeJS.Timeout | undefined;
  private inFlight: Promise<void> | undefined;
  private readonly stats: TransportStats = { queued: 0, sent: 0, dropped: 0, failedBatches: 0 };
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

  /** Envia tudo o que está no buffer. Nunca rejeita. */
  async flush(): Promise<void> {
    if (this.inFlight) return this.inFlight;
    if (this.buffer.length === 0) return;
    this.inFlight = this.drain().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush();
  }

  getStats(): TransportStats {
    return { ...this.stats, queued: this.buffer.length };
  }

  private async drain(): Promise<void> {
    while (this.buffer.length > 0) {
      const batch = this.buffer.splice(0, this.batchSize);
      const ok = await this.sendWithRetry(batch);
      if (ok) {
        this.stats.sent += batch.length;
      } else {
        this.stats.failedBatches++;
        this.stats.dropped += batch.length;
        // Para de tentar nesta rodada; o próximo ciclo tenta os eventos restantes.
        return;
      }
    }
  }

  private async sendWithRetry(batch: VigiloEvent[]): Promise<boolean> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        await this.send(batch);
        return true;
      } catch (error) {
        this.options.logger?.warn('vigilo: falha ao enviar eventos', { attempt: attempt + 1, error: String(error) });
        if (attempt < this.maxRetries - 1) await sleep(200 * 2 ** attempt);
      }
    }
    return false;
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
    if (!response.ok && response.status !== 202) {
      throw new Error(`ingestion responded ${response.status}`);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
  });
}
