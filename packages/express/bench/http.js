// Mede o overhead do middleware Express num servidor HTTP real (rode `pnpm build` antes).
// Uso: node packages/express/bench/http.js
import http from 'node:http';
import express from 'express';
import { shield } from '../dist/index.js';

const N = Number(process.env.BENCH_N ?? 20_000);
const WARMUP = 2_000;

function percentiles(samples) {
  samples.sort((a, b) => a - b);
  const at = (p) => samples[Math.min(samples.length - 1, Math.floor(samples.length * p))];
  return { p50: at(0.5), p99: at(0.99) };
}

async function run(withShield) {
  const app = express();
  app.use(express.json());
  const middlewareTimes = [];
  if (withShield) {
    const mw = shield({ flushIntervalMs: 0, maxBufferSize: 1_000, send: async () => {} });
    // Mede o tempo gasto dentro do middleware (até chamar `next`) e no registro do evento.
    const record = mw.client.record;
    let recordTime = 0;
    mw.client.record = (...args) => {
      const start = process.hrtime.bigint();
      record(...args);
      recordTime = Number(process.hrtime.bigint() - start);
      middlewareTimes[middlewareTimes.length - 1] += recordTime;
    };
    app.use((req, res, next) => {
      const start = process.hrtime.bigint();
      mw(req, res, () => {
        middlewareTimes.push(Number(process.hrtime.bigint() - start));
        next();
      });
    });
  }
  app.get('/products/:id', (req, res) => res.json({ id: req.params.id, name: 'Notebook', price: 4999.9 }));

  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const { port } = server.address();
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  const get = (i) =>
    new Promise((resolve, reject) => {
      const start = process.hrtime.bigint();
      http
        .get({ host: '127.0.0.1', port, path: `/products/${i % 1000}?page=2&sort=created_at`, agent }, (res) => {
          res.resume();
          res.on('end', () => resolve(Number(process.hrtime.bigint() - start)));
        })
        .on('error', reject);
    });

  for (let i = 0; i < WARMUP; i++) await get(i);
  middlewareTimes.length = 0;
  const latencies = [];
  for (let i = 0; i < N; i++) latencies.push(await get(i));
  agent.destroy();
  server.close();
  return { latencies: percentiles(latencies), middleware: middlewareTimes.length ? percentiles(middlewareTimes) : undefined };
}

const baseline = await run(false);
const shielded = await run(true);
const ms = (ns) => (ns / 1e6).toFixed(3);
const us = (ns) => (ns / 1e3).toFixed(1);

console.log(`\nExpress + shield (${N.toLocaleString('pt-BR')} requisições sequenciais, keep-alive, Node ${process.version})\n`);
console.table([
  { medida: 'tempo dentro da lib (middleware + record)', p50: `${us(shielded.middleware.p50)} µs`, p99: `${us(shielded.middleware.p99)} µs` },
  { medida: 'latência ponta a ponta sem shield', p50: `${ms(baseline.latencies.p50)} ms`, p99: `${ms(baseline.latencies.p99)} ms` },
  { medida: 'latência ponta a ponta com shield', p50: `${ms(shielded.latencies.p50)} ms`, p99: `${ms(shielded.latencies.p99)} ms` },
]);
console.log('A diferença de latência ponta a ponta inclui ruído do sistema; a linha "tempo dentro da lib" é a medida direta.');
