// App de exemplo PROPOSITALMENTE VULNERÁVEL, para ver a Vigilo detectar ataques.
// Não publique este servidor: ele só escuta em 127.0.0.1.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import pg from 'pg';
import { instrumentFs, instrumentPg, shield } from '@vigilo/express';

const mode = process.env.VIGILO_MODE === 'monitor' ? 'monitor' : 'block';
const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');

// Sem VIGILO_KEY, os eventos aparecem no terminal em vez de irem para a plataforma.
const printEvents = async (events) => {
  for (const e of events) {
    if (!e.threatType) continue;
    const where = e.threats.map((t) => `${t.layer}:${t.rule}@${t.location}`).join(', ');
    console.log(`[vigilo] ${e.method} ${e.route} → ${e.status} | ${e.threatType} sev ${e.severity}${e.blocked ? ' BLOQUEADO' : ''} | ${where}`);
  }
};

// Banco: PostgreSQL real com DATABASE_URL; senão, um PostgreSQL em memória (pg-mem).
let Pool = pg.Pool;
if (!process.env.DATABASE_URL) {
  const { newDb } = await import('pg-mem');
  const memoryPg = newDb().adapters.createPg();
  Pool = memoryPg.Pool;
  instrumentPg(memoryPg);
  console.log('Usando PostgreSQL em memória (defina DATABASE_URL para um banco real).');
}
instrumentPg(pg);
instrumentFs();

const db = new Pool({ connectionString: process.env.DATABASE_URL });
await db.query(`
  CREATE TABLE IF NOT EXISTS users (id int PRIMARY KEY, name text, email text, password_hash text);
  DELETE FROM users;
  INSERT INTO users VALUES (1, 'Ana', 'ana@example.com', 'x1'), (2, 'Bruno', 'bruno@example.com', 'x2');
`);

const app = express();
app.use(express.json());
const vigilo = shield({
  apiKey: process.env.VIGILO_KEY,
  mode,
  flushIntervalMs: 1_000,
  ...(process.env.VIGILO_KEY ? {} : { send: printEvents }),
});
app.use(vigilo);

// VULNERÁVEL: concatena o parâmetro de rota no SQL.
app.get('/users/:id', async (req, res) => {
  const { rows } = await db.query(`SELECT id, name, email FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

// VULNERÁVEL: concatena a query string dentro de um literal.
app.get('/search', async (req, res) => {
  const { rows } = await db.query(`SELECT id, name FROM users WHERE name = '${req.query.name ?? ''}'`);
  res.json(rows);
});

// Seguro: query parametrizada. Nunca dispara, mesmo com payload malicioso.
app.get('/safe/users/:id', async (req, res) => {
  const { rows } = await db.query('SELECT id, name, email FROM users WHERE id = $1', [Number(req.params.id) || 0]);
  res.json(rows);
});

// VULNERÁVEL: monta o caminho do arquivo com a entrada do usuário.
app.get('/files', async (req, res) => {
  const content = await readFile(path.join(publicDir, String(req.query.name ?? '')), 'utf8');
  res.type('text/plain').send(content);
});

// No modo `block`, a RASP faz a chamada ao banco/arquivo falhar com VigiloBlockedError.
app.use((error, _req, res, _next) => {
  if (error?.code === 'VIGILO_BLOCKED') return res.status(403).json({ error: 'Bloqueado pela Vigilo' });
  res.status(500).json({ error: 'Erro interno' });
});

const port = Number(process.env.PORT ?? 3000);
const server = app.listen(port, '127.0.0.1', () => {
  console.log(`Exemplo em http://127.0.0.1:${port} (modo ${mode}). Veja o README para os ataques de teste.`);
});

process.on('SIGINT', async () => {
  server.close();
  await vigilo.client.close();
  await db.end();
  process.exit(0);
});
