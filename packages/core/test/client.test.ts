import { describe, expect, it, vi } from 'vitest';
import { createVigilo } from '../src/client.js';
import { EventTransport } from '../src/transport.js';
import type { VigiloEvent } from '../src/types.js';
import { request } from './fixtures.js';

function setup(options: Parameters<typeof createVigilo>[0] = {}) {
  const sent: VigiloEvent[] = [];
  const client = createVigilo({
    flushIntervalMs: 0,
    send: async (events) => {
      sent.push(...events);
    },
    ...options,
  });
  return { client, sent };
}

describe('createVigilo', () => {
  it('em monitor, detecta mas não bloqueia', () => {
    const { client } = setup();
    const decision = client.inspect(request({ query: { id: "1' OR '1'='1" } }));
    expect(decision.threats.length).toBeGreaterThan(0);
    expect(decision.block).toBe(false);
  });

  it('em block, bloqueia ameaças acima da severidade mínima', () => {
    const { client } = setup({ mode: 'block' });
    expect(client.inspect(request({ query: { id: '1 UNION SELECT 1' } })).block).toBe(true);
    expect(client.inspect(request({ userAgent: 'nikto' })).block).toBe(false);
  });

  it('envia evento mascarado só quando há ameaça', async () => {
    const { client, sent } = setup();
    const suspicious = request({ query: { q: '<script>x</script>', email: 'ana@x.com' } });
    client.record(suspicious, { status: 200, durationMs: 1.23456, decision: client.inspect(suspicious) });
    const clean = request();
    client.record(clean, { status: 200, durationMs: 1, decision: client.inspect(clean) });
    await client.flush();

    expect(sent).toHaveLength(2);
    const [first, second] = sent;
    expect(first?.threatType).toBe('xss');
    expect(first?.payload).toContain('[EMAIL]');
    expect(first?.payload).not.toContain('ana@x.com');
    expect(first?.eventId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7/);
    expect(second?.payload).toBeNull();
  });

  it('ignora rotas configuradas', async () => {
    const { client, sent } = setup({ ignoreRoutes: ['/health'] });
    const req = request({ route: '/health', path: '/health', query: { q: '<script>' } });
    expect(client.inspect(req).threats).toEqual([]);
    client.record(req, { status: 200, durationMs: 1, decision: client.inspect(req) });
    await client.flush();
    expect(sent).toHaveLength(0);
  });

  it('é fail-open: erro interno não lança', () => {
    const { client } = setup();
    const broken = { ...request(), get query(): Record<string, unknown> { throw new Error('boom'); } };
    expect(() => client.inspect(broken)).not.toThrow();
    expect(client.inspect(broken)).toEqual({ threats: [], block: false });
  });
});

describe('EventTransport', () => {
  it('descarta os eventos mais antigos quando o buffer enche', () => {
    const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, maxBufferSize: 2, batchSize: 100, send: async () => {} });
    for (let i = 0; i < 5; i++) transport.push({ eventId: String(i) } as VigiloEvent);
    expect(transport.getStats()).toMatchObject({ queued: 2, dropped: 3 });
  });

  it('faz retry e conta lotes que falharam', async () => {
    vi.useFakeTimers();
    const send = vi.fn().mockRejectedValue(new Error('offline'));
    const transport = new EventTransport({ endpoint: 'http://x', flushIntervalMs: 0, maxRetries: 2, send });
    transport.push({ eventId: '1' } as VigiloEvent);
    const done = transport.flush();
    await vi.runAllTimersAsync();
    await done;
    vi.useRealTimers();
    expect(send).toHaveBeenCalledTimes(2);
    expect(transport.getStats()).toMatchObject({ failedBatches: 1, dropped: 1 });
  });
});
