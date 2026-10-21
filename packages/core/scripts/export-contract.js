// Gera os artefatos do contrato a partir do código compilado (rode depois do `tsc`):
// - schemas/event-batch.v1.json: JSON Schema do corpo de `POST /v1/events`
// - schemas/examples/batch-v1.json: lote real produzido pela lib, com ids e horários fixos
// O backend (Go) copia esses arquivos e roda o próprio teste de contrato contra eles.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildBatch, createVigilo, EVENT_BATCH_SCHEMA } from '../dist/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'schemas');

const base = {
  method: 'GET',
  route: '/users/:id',
  path: '/users/42',
  query: {},
  headers: {},
  ip: '203.0.113.10',
  srcPort: 51234,
  userAgent: 'Mozilla/5.0',
};

const requests = [
  { req: base, status: 200 },
  {
    req: { ...base, ip: '192.0.2.44', query: { id: '1 UNION SELECT password FROM users' }, userAgent: 'sqlmap/1.7' },
    status: 200,
  },
  {
    req: {
      ...base,
      method: 'POST',
      route: '/login',
      path: '/login',
      body: { email: 'ana@example.com', password: { $ne: null } },
      ip: '2001:db8::1',
      srcPort: undefined,
      userAgent: undefined,
    },
    status: 401,
  },
  // Segunda requisição do mesmo IP passa do limite de volume do exemplo.
  { req: { ...base, ip: '198.51.100.7', route: '/products', path: '/products' }, status: 200 },
  { req: { ...base, ip: '198.51.100.7', route: '/products', path: '/products' }, status: 200 },
];

const events = [];
const client = createVigilo({
  flushIntervalMs: 0,
  // Volume baixo só para o exemplo incluir uma ameaça da camada `ip`.
  tracker: { rateLimitThreshold: 2 },
  send: async (batch) => void events.push(...batch),
});
for (const { req, status } of requests) {
  client.record(req, { status, durationMs: 3.4125, decision: client.inspect(req) });
}
await client.flush();

const fixed = events.map((event, i) => ({
  ...event,
  eventId: `019a07c1-3b2e-7c4d-9a1f-5e6b7c8d9e0${i}`,
  ts: `2026-10-21T16:40:0${i}.000Z`,
}));
const batch = buildBatch(fixed, new Date('2026-10-21T16:40:05.000Z'));

const write = (file, data) => {
  mkdirSync(dirname(join(root, file)), { recursive: true });
  writeFileSync(join(root, file), `${JSON.stringify(data, null, 2)}\n`);
};
write('event-batch.v1.json', { $schema: 'https://json-schema.org/draft/2020-12/schema', ...EVENT_BATCH_SCHEMA });
write('examples/batch-v1.json', batch);
