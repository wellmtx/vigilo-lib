import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EventTransport, IngestionError, parseRetryAfter } from '../src/transport.js';
import type { VigiloEvent } from '../src/types.js';

function event(id = 1): VigiloEvent {
  return {
    eventId: `019a07c1-3b2e-7c4d-9a1f-5e6b7c8d9e${String(id).padStart(2, '0')}`,
    ts: '2026-10-25T12:00:00.000Z',
    method: 'GET',
    route: '/users/:id',
    status: 200,
    durationMs: 1,
    ip: '203.0.113.1',
    srcPort: 1234,
    userAgent: null,
    threatType: null,
    severity: null,
    threats: [],
    blocked: false,
    payload: null,
  };
}

function logger() {
  return { warn: vi.fn(), debug: vi.fn(), info: vi.fn(), error: vi.fn() };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('EventTransport: respostas da ingestão', () => {
  it('não tenta de novo em 4xx definitivo e conta o lote recusado', async () => {
    for (const status of [400, 401, 403, 404, 413, 422]) {
      const send = vi.fn().mockRejectedValue(new IngestionError(status));
      const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, maxRetries: 3, send });
      transport.push(event());
      await transport.flush();
      expect(send, `status ${status}`).toHaveBeenCalledTimes(1);
      expect(transport.getStats()).toMatchObject({ rejectedBatches: 1, failedBatches: 0, dropped: 1, queued: 0 });
    }
  });

  it('avisa uma vez por status recusado, não a cada lote', async () => {
    const log = logger();
    const send = vi.fn().mockRejectedValue(new IngestionError(401));
    const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, send, logger: log });
    for (let i = 0; i < 3; i++) {
      transport.push(event(i));
      await transport.flush();
    }
    expect(send).toHaveBeenCalledTimes(3);
    expect(log.warn).toHaveBeenCalledTimes(1);
    expect(log.warn.mock.calls[0]?.[1]).toMatchObject({ status: 401, hint: 'confira a apiKey' });
  });

  it('para a rodada no 4xx em vez de queimar os outros lotes', async () => {
    const send = vi.fn().mockRejectedValue(new IngestionError(401));
    const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, batchSize: 1, send });
    transport.push(event(1));
    transport.push(event(2));
    await transport.flush();
    expect(send).toHaveBeenCalledTimes(1);
    expect(transport.getStats()).toMatchObject({ rejectedBatches: 1, queued: 1 });
  });

  it('tenta de novo em 5xx, 408, 429 sem Retry-After e erro de rede', async () => {
    vi.useFakeTimers();
    for (const error of [new IngestionError(500), new IngestionError(408), new IngestionError(429), new Error('ECONNRESET')]) {
      const send = vi.fn().mockRejectedValue(error);
      const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, maxRetries: 3, send });
      transport.push(event());
      const done = transport.flush();
      await vi.runAllTimersAsync();
      await done;
      expect(send, String(error)).toHaveBeenCalledTimes(3);
      expect(transport.getStats()).toMatchObject({ failedBatches: 1, rejectedBatches: 0, dropped: 1 });
    }
  });

  it('com Retry-After em 503 ou 429, guarda o lote e pausa os envios', async () => {
    vi.useFakeTimers({ now: new Date('2026-10-25T12:00:00Z') });
    for (const status of [503, 429]) {
      const send = vi.fn().mockRejectedValueOnce(new IngestionError(status, 30_000)).mockResolvedValue(undefined);
      const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, send });
      transport.push(event(1));
      await transport.flush();
      expect(send).toHaveBeenCalledTimes(1);
      expect(transport.getStats()).toMatchObject({ queued: 1, dropped: 0, sent: 0 });

      transport.push(event(2));
      vi.advanceTimersByTime(29_000);
      await transport.flush();
      expect(send, 'paused: no send').toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(1_000);
      await transport.flush();
      expect(send).toHaveBeenCalledTimes(2);
      expect(send.mock.calls[1]?.[0]).toHaveLength(2); // o lote devolvido vai junto, na ordem
      expect(send.mock.calls[1]?.[0][0].eventId).toBe(event(1).eventId);
      expect(transport.getStats()).toMatchObject({ queued: 0, sent: 2, dropped: 0 });
    }
  });

  it('limita a pausa a 5 minutos', async () => {
    vi.useFakeTimers({ now: new Date('2026-10-25T12:00:00Z') });
    const send = vi.fn().mockRejectedValueOnce(new IngestionError(503, 3_600_000)).mockResolvedValue(undefined);
    const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, send });
    transport.push(event());
    await transport.flush();
    vi.advanceTimersByTime(5 * 60_000);
    await transport.flush();
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('close envia mesmo durante a pausa', async () => {
    vi.useFakeTimers({ now: new Date('2026-10-25T12:00:00Z') });
    const send = vi.fn().mockRejectedValueOnce(new IngestionError(503, 30_000)).mockResolvedValue(undefined);
    const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, send });
    transport.push(event());
    await transport.flush();
    await transport.close();
    expect(send).toHaveBeenCalledTimes(2);
    expect(transport.getStats()).toMatchObject({ sent: 1, queued: 0 });
  });
});

describe('EventTransport: envio HTTP', () => {
  let server: Server | undefined;
  afterEach(() => server?.close());

  async function ingestion(respond: (attempt: number) => { status: number; headers?: Record<string, string> }) {
    let attempts = 0;
    server = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        const { status, headers } = respond(++attempts);
        res.writeHead(status, { 'content-type': 'application/json', ...headers });
        res.end('{}');
      });
    });
    server.listen(0);
    await new Promise((resolve) => server!.once('listening', resolve));
    return { endpoint: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, attempts: () => attempts };
  }

  it('lê o status e o Retry-After da resposta', async () => {
    const ing = await ingestion((n) => (n === 1 ? { status: 503, headers: { 'retry-after': '30' } } : { status: 202 }));
    const transport = new EventTransport({ endpoint: ing.endpoint, apiKey: 'vk_test', flushIntervalMs: 0 });
    transport.push(event());
    await transport.flush();
    expect(ing.attempts()).toBe(1);
    expect(transport.getStats()).toMatchObject({ queued: 1, dropped: 0 });
    await transport.close(); // força o envio
    expect(ing.attempts()).toBe(2);
    expect(transport.getStats()).toMatchObject({ sent: 1, queued: 0 });
  });

  it('não repete 401', async () => {
    const ing = await ingestion(() => ({ status: 401 }));
    const transport = new EventTransport({ endpoint: ing.endpoint, apiKey: 'vk_wrong', flushIntervalMs: 0, maxRetries: 3 });
    transport.push(event());
    await transport.flush();
    expect(ing.attempts()).toBe(1);
    expect(transport.getStats()).toMatchObject({ rejectedBatches: 1, dropped: 1 });
  });
});

describe('parseRetryAfter', () => {
  it('aceita segundos e data HTTP', () => {
    const now = Date.parse('2026-10-25T12:00:00Z');
    expect(parseRetryAfter('30', now)).toBe(30_000);
    expect(parseRetryAfter(' 0 ', now)).toBe(0);
    expect(parseRetryAfter('Sun, 25 Oct 2026 12:01:00 GMT', now)).toBe(60_000);
    expect(parseRetryAfter('Sun, 25 Oct 2026 11:00:00 GMT', now)).toBe(0);
  });

  it('ignora valor ausente ou inválido', () => {
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter('')).toBeUndefined();
    expect(parseRetryAfter('soon')).toBeUndefined();
    expect(parseRetryAfter('-5')).toBeUndefined();
  });
});
