import { afterEach, describe, expect, it, vi } from 'vitest';
import { createVigilo } from '../src/client.js';
import { request } from './fixtures.js';

type Reply = { status: number; body?: unknown } | Error;

/** fetch falso: responde à rota de configuração conforme `replies` (a última se repete). */
function stubFetch(replies: Reply[]) {
  const calls: { url: string; auth: string | null }[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, auth: new Headers(init?.headers).get('authorization') });
    const reply = replies[Math.min(calls.length - 1, replies.length - 1)]!;
    if (reply instanceof Error) throw reply;
    return new Response(reply.body === undefined ? null : JSON.stringify(reply.body), { status: reply.status });
  });
  vi.stubGlobal('fetch', fetchMock);
  return calls;
}

const logger = () => ({ debug: vi.fn(), warn: vi.fn() });
// Requisição que dispara uma assinatura de severidade 4 (SQLi).
const attack = () => request({ query: { q: "1' UNION SELECT password FROM users--" } });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('modo vindo do painel', () => {
  it('começa em monitor e passa a bloquear quando o painel manda', async () => {
    const calls = stubFetch([{ status: 200, body: { mode: 'block' } }]);
    const client = createVigilo({ apiKey: 'vk_test', endpoint: 'https://ingest.test', flushIntervalMs: 0, logger: logger() });
    await vi.waitFor(() => expect(client.mode).toBe('block'));
    expect(calls[0]).toEqual({ url: 'https://ingest.test/v1/config', auth: 'Bearer vk_test' });
    expect(client.inspect(attack()).block).toBe(true);
    expect(client.createContext(() => ({})).mode).toBe('block');
    await client.close();
  });

  it('não consulta o painel quando o código define o modo', async () => {
    const calls = stubFetch([{ status: 200, body: { mode: 'block' } }]);
    const client = createVigilo({ apiKey: 'vk_test', endpoint: 'https://ingest.test', mode: 'monitor', flushIntervalMs: 0 });
    await new Promise((r) => setTimeout(r, 20));
    expect(calls.filter((c) => c.url.endsWith('/v1/config'))).toHaveLength(0);
    expect(client.mode).toBe('monitor');
    expect(client.inspect(attack()).block).toBe(false);
    await client.close();
  });

  it('não consulta sem apiKey nem com remoteConfig: false', async () => {
    const calls = stubFetch([{ status: 200, body: { mode: 'block' } }]);
    const a = createVigilo({ endpoint: 'https://ingest.test', flushIntervalMs: 0 });
    const b = createVigilo({ apiKey: 'vk_test', endpoint: 'https://ingest.test', remoteConfig: false, flushIntervalMs: 0 });
    await new Promise((r) => setTimeout(r, 20));
    expect(calls).toHaveLength(0);
    expect([a.mode, b.mode]).toEqual(['monitor', 'monitor']);
  });

  it('mantém o último modo quando o painel falha e avisa uma vez por problema', async () => {
    vi.useFakeTimers();
    const log = logger();
    const calls = stubFetch([
      { status: 200, body: { mode: 'block' } },
      new TypeError('fetch failed'),
      new TypeError('fetch failed'),
      { status: 401, body: { error: 'invalid api key' } },
      { status: 401, body: { error: 'invalid api key' } },
      { status: 200, body: { mode: 'nonsense' } },
    ]);
    const client = createVigilo({ apiKey: 'vk_test', endpoint: 'https://ingest.test', configIntervalMs: 1000, flushIntervalMs: 0, logger: log });
    await vi.advanceTimersByTimeAsync(0);
    expect(client.mode).toBe('block');
    await vi.advanceTimersByTimeAsync(5000);
    expect(calls).toHaveLength(6);
    expect(client.mode).toBe('block');
    const warnings = log.warn.mock.calls.filter(([msg]) => String(msg).includes('modo do painel')).map(([, meta]) => meta);
    expect(warnings).toEqual([
      { problem: 'TypeError', hint: undefined },
      { problem: 'http 401', hint: 'confira a apiKey' },
      { problem: 'resposta inválida', hint: undefined },
    ]);
    await client.close();
  });

  it('volta para monitor quando o painel muda, e para de consultar no close', async () => {
    vi.useFakeTimers();
    const calls = stubFetch([
      { status: 200, body: { mode: 'block' } },
      { status: 200, body: { mode: 'monitor' } },
    ]);
    const client = createVigilo({ apiKey: 'vk_test', endpoint: 'https://ingest.test', configIntervalMs: 1000, flushIntervalMs: 0 });
    await vi.advanceTimersByTimeAsync(0);
    expect(client.mode).toBe('block');
    await vi.advanceTimersByTimeAsync(1000);
    expect(client.mode).toBe('monitor');
    expect(client.inspect(attack()).block).toBe(false);
    await client.close();
    const before = calls.length;
    await vi.advanceTimersByTimeAsync(5000);
    expect(calls.length).toBe(before);
  });
});
