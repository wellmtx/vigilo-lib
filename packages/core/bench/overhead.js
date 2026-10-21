// Mede o custo da lib por requisição e por query, sobre o código compilado (rode `pnpm build` antes).
// Uso: node packages/core/bench/overhead.js
import { createVigilo, instrumentPg, runWithContext } from '../dist/index.js';

const N = Number(process.env.BENCH_N ?? 100_000);
const WARMUP = 10_000;

function percentiles(samples) {
  samples.sort((a, b) => a - b);
  const at = (p) => samples[Math.min(samples.length - 1, Math.floor(samples.length * p))] / 1000;
  return { p50: at(0.5), p99: at(0.99), 'p99.9': at(0.999) };
}

function bench(name, fn) {
  for (let i = 0; i < WARMUP; i++) fn(i);
  const samples = new Array(N);
  for (let i = 0; i < N; i++) {
    const start = process.hrtime.bigint();
    fn(i);
    samples[i] = Number(process.hrtime.bigint() - start);
  }
  const p = percentiles(samples);
  return { cenário: name, 'p50 (µs)': p.p50.toFixed(1), 'p99 (µs)': p.p99.toFixed(1), 'p99.9 (µs)': p['p99.9'].toFixed(1) };
}

const client = createVigilo({ flushIntervalMs: 0, maxBufferSize: 1_000, send: async () => {} });
const ip = (i) => `203.0.${(i >> 8) & 255}.${i & 255}`;
const base = (i) => ({
  method: 'GET',
  route: '/products/:id',
  path: `/products/${i % 1000}`,
  query: { page: '2', sort: 'created_at', q: 'notebook gamer' },
  headers: { 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', accept: 'application/json' },
  ip: ip(i),
  srcPort: 50_000 + (i % 1000),
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
});
const body = {
  name: 'Ana Souza',
  email: 'ana@example.com',
  address: { street: 'Rua das Flores', number: '120', city: 'São Paulo', zip: '01310-200' },
  items: Array.from({ length: 10 }, (_, k) => ({ sku: `SKU-${k}`, qty: k + 1, note: 'sem cebola, por favor' })),
};

const request = (req) => {
  const decision = client.inspect(req);
  client.record(req, { status: 200, durationMs: 3, decision });
};

const rows = [
  bench('GET limpo (inspect + record)', (i) => request(base(i))),
  bench('POST com JSON de ~1 KB', (i) => request({ ...base(i), method: 'POST', route: '/orders', body })),
  bench('GET com SQLi (gera evento mascarado)', (i) =>
    request({ ...base(i), query: { id: "1' UNION SELECT password FROM users--" } }),
  ),
];

// RASP: custo da checagem por query, com o driver substituído por uma função vazia.
class FakeClient {
  query() {}
}
instrumentPg({ Client: FakeClient });
const db = new FakeClient();
const context = client.createContext(() => ({
  params: { id: '42' },
  query: { page: '2', sort: 'created_at', q: 'notebook gamer' },
  body,
  headers: base(0).headers,
  path: '/products/42',
}));
const sql = 'SELECT o.id, o.total FROM orders o JOIN users u ON u.id = o.user_id WHERE u.id = $1 ORDER BY o.created_at DESC';
const concatenated = `SELECT * FROM products WHERE name ILIKE '%notebook gamer%' ORDER BY created_at LIMIT 20`;
rows.push(
  bench('RASP pg: query parametrizada', () => runWithContext(context, () => db.query(sql, [42]))),
  bench('RASP pg: query com entrada concatenada', () => runWithContext(context, () => db.query(concatenated))),
);

console.log(`\nOverhead da lib (${N.toLocaleString('pt-BR')} amostras por cenário, Node ${process.version})\n`);
console.table(rows);
