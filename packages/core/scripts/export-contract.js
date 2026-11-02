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
// Injeção confirmada pela RASP no driver, com o ponto do código que montou a query.
const rasp = { ...base, ip: '203.0.113.99', path: '/users/1 OR 1=1' };
client.record(rasp, {
  status: 500,
  durationMs: 3.4125,
  decision: client.inspect(rasp),
  context: {
    mode: 'monitor',
    blockSeverity: 4,
    sources: () => ({ params: { id: '1 OR 1=1' } }),
    blocked: false,
    threats: [
      {
        type: 'sqli',
        severity: 5,
        location: 'params.id',
        rule: 'rasp.sqli.pg',
        layer: 'rasp',
        callsite: {
          file: 'src/repositories/users.ts',
          line: 18,
          column: 27,
          function: 'findUserById',
          callers: [
            { file: 'src/usecases/get-user.ts', line: 9, column: 10, function: 'getUser' },
            { file: 'src/routes/users.ts', line: 12, column: 3, function: null },
          ],
        },
      },
    ],
  },
});
await client.flush();

const fixed = events.map((event, i) => ({
  ...event,
  eventId: `019a07c1-3b2e-7c4d-9a1f-5e6b7c8d9e0${i}`,
  ts: `2026-10-21T16:40:0${i}.000Z`,
}));
const batch = buildBatch(fixed, new Date('2026-10-21T16:40:05.000Z'), '3f2c9a1e8b7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f');

const write = (file, data) => {
  mkdirSync(dirname(join(root, file)), { recursive: true });
  writeFileSync(join(root, file), `${JSON.stringify(data, null, 2)}\n`);
};
write('event-batch.v1.json', { $schema: 'https://json-schema.org/draft/2020-12/schema', ...EVENT_BATCH_SCHEMA });
write('examples/batch-v1.json', batch);
