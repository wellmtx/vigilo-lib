import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createVigilo } from '../src/client.js';
import { buildBatch, EVENT_BATCH_SCHEMA, LIMITS, SDK_VERSION, THREAT_TYPES } from '../src/contract.js';
import { EventTransport } from '../src/transport.js';
import type { Threat, VigiloEvent } from '../src/types.js';
import { request } from './fixtures.js';
import pkg from '../package.json' with { type: 'json' };

const ajv = new Ajv2020({ allErrors: true });
addFormats.default(ajv);
const validateBatch = ajv.compile(EVENT_BATCH_SCHEMA);

function expectValid(batch: unknown) {
  const ok = validateBatch(batch);
  expect(validateBatch.errors ?? []).toEqual([]);
  expect(ok).toBe(true);
}

async function produce(build: (client: ReturnType<typeof createVigilo>) => void): Promise<VigiloEvent[]> {
  const sent: VigiloEvent[] = [];
  const client = createVigilo({ flushIntervalMs: 0, send: async (events) => void sent.push(...events) });
  build(client);
  await client.flush();
  return sent;
}

describe('contrato do evento (schema v1)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('eventos limpos e suspeitos produzidos pelo client respeitam o schema', async () => {
    const events = await produce((client) => {
      const reqs = [
        request(),
        request({ query: { id: "1' OR '1'='1" }, body: { password: 'x', email: 'ana@x.com' } }),
        request({ userAgent: undefined, srcPort: undefined, ip: '2001:db8::1' }),
        request({ path: '/.env', userAgent: 'sqlmap/1.7' }),
      ];
      for (const req of reqs) client.record(req, { status: 200, durationMs: 0.5, decision: client.inspect(req) });
    });
    expect(events).toHaveLength(4);
    expectValid(buildBatch(events));
    for (const event of events) for (const threat of event.threats) expect(threat.layer).toBeDefined();
  });

  it('corta campos longos e excesso de ameaças antes de enviar', async () => {
    const threats: Threat[] = Array.from({ length: 50 }, (_, i) => ({
      type: 'xss',
      severity: i === 49 ? 5 : 2,
      location: `body.${'k'.repeat(400)}.${i}`,
      rule: 'xss.script-tag',
      layer: 'signature',
    }));
    const [event] = await produce((client) => {
      const req = request({ route: `/${'a'.repeat(2_000)}`, userAgent: 'U'.repeat(5_000), method: 'X'.repeat(40) });
      client.record(req, { status: 200, durationMs: 1, decision: { threats, block: false } });
    });
    expect(event!.route).toHaveLength(LIMITS.route);
    expect(event!.userAgent).toHaveLength(LIMITS.userAgent);
    expect(event!.threats).toHaveLength(LIMITS.threats);
    expect(event!.severity).toBe(5);
    expectValid(buildBatch([event!]));
  });

  it('payload truncado cabe no limite do schema', async () => {
    const [event] = await produce((client) => {
      const req = request({ query: { q: '<script>' }, body: { text: 'é'.repeat(10_000) } });
      client.record(req, { status: 200, durationMs: 1, decision: client.inspect(req) });
    });
    expect(event!.payload).toContain('[truncated]');
    expectValid(buildBatch([event!]));
  });

  it('rejeita lote vazio, acima do limite ou com tipo de ameaça desconhecido', async () => {
    const [event] = await produce((client) => client.record(request(), { status: 200, durationMs: 1, decision: { threats: [], block: false } }));
    expect(validateBatch(buildBatch([]))).toBe(false);
    expect(validateBatch(buildBatch(Array.from({ length: LIMITS.batchSize + 1 }, () => event!)))).toBe(false);
    const bad = { ...event!, threatType: 'ddos', severity: 3 };
    expect(validateBatch(buildBatch([bad as unknown as VigiloEvent]))).toBe(false);
  });

  it('os arquivos em schemas/ estão em dia com o código (rode `pnpm build` se falhar)', () => {
    const schemas = new URL('../schemas/', import.meta.url);
    const { $schema, ...exported } = JSON.parse(readFileSync(new URL('event-batch.v1.json', schemas), 'utf8'));
    expect($schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(exported).toEqual(JSON.parse(JSON.stringify(EVENT_BATCH_SCHEMA)));
    expectValid(JSON.parse(readFileSync(new URL('examples/batch-v1.json', schemas), 'utf8')));
  });

  it('o envio HTTP manda o envelope versionado, em gzip', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 202 }));
    vi.stubGlobal('fetch', fetchMock);
    const transport = new EventTransport({ apiKey: 'k', endpoint: 'https://ingest.test', flushIntervalMs: 0 });
    const [event] = await produce((client) => client.record(request(), { status: 200, durationMs: 1, decision: { threats: [], block: false } }));
    transport.push(event!);
    await transport.flush();

    const [url, init] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(String(url)).toBe('https://ingest.test/v1/events');
    const body = JSON.parse(gunzipSync(init.body as Buffer).toString('utf8'));
    expect(body).toMatchObject({ schemaVersion: 1, sdk: { name: '@vigilo/core', version: SDK_VERSION } });
    expectValid(body);
  });

  it('nunca monta lotes acima do limite do schema', async () => {
    const batches: number[] = [];
    const transport = new EventTransport({
      endpoint: 'https://ingest.test',
      flushIntervalMs: 0,
      batchSize: 5_000,
      send: async (events) => void batches.push(events.length),
    });
    const [event] = await produce((client) => client.record(request(), { status: 200, durationMs: 1, decision: { threats: [], block: false } }));
    for (let i = 0; i < 1_200; i++) transport.push(event!);
    await transport.flush();
    expect(Math.max(...batches)).toBeLessThanOrEqual(LIMITS.batchSize);
  });

  it('SDK_VERSION acompanha o package.json e a lista de tipos cobre o union', () => {
    expect(SDK_VERSION).toBe(pkg.version);
    expect(THREAT_TYPES).toContain('ratelimit');
    expect(THREAT_TYPES).toContain('cmdi');
  });
});
