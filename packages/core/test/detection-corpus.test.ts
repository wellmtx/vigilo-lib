import { posix, win32 } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { detect } from '../src/detectors/index.js';
import { findNoSqlInjection } from '../src/rasp/nosql.js';
import { findPathTraversal } from '../src/rasp/path.js';
import { findCommandInjection } from '../src/rasp/shell.js';
import { findSqlInjection } from '../src/rasp/sql.js';
import type { ThreatType } from '../src/types.js';
import { CMDI, NOSQLI_OPERATORS, NOSQLI_WHERE, SCANNER_AGENTS, SQLI, TRAVERSAL, XSS } from './corpus/attacks.js';
import { BENIGN } from './corpus/benign.js';
import { request } from './fixtures.js';

/**
 * Mede detecção e falsos positivos das camadas 1 (assinaturas) e 1b (RASP) sobre o corpus.
 * Rode `pnpm eval:detection` para ver a tabela. Os limites abaixo protegem contra regressão.
 */

interface Row {
  camada: string;
  conjunto: string;
  total: number;
  disparos: number;
  taxa: string;
  misses: string[];
}
const rows: Row[] = [];

function measure<T>(camada: string, conjunto: string, items: T[], fires: (item: T) => boolean, label: (item: T) => string): Row {
  const misses: string[] = [];
  let hits = 0;
  for (const item of items) {
    if (fires(item)) hits++;
    else misses.push(label(item));
  }
  const row = { camada, conjunto, total: items.length, disparos: hits, taxa: `${((hits / items.length) * 100).toFixed(1)}%`, misses };
  rows.push(row);
  return row;
}

const at = (value: string) => [{ location: 'query.q', value }];
const signatureTypes = (req: Parameters<typeof detect>[0]) => new Set(detect(req).map((t) => t.type));
const signatureFires = (type: ThreatType) => (value: string) => signatureTypes(request({ query: { q: value } })).has(type);

// Queries que um backend real escreve, todas parametrizadas: a RASP não pode disparar em nenhuma.
const APP_QUERIES = [
  'SELECT id, name, email FROM users WHERE id = $1',
  'SELECT * FROM products WHERE name ILIKE $1 ORDER BY created_at DESC LIMIT 20 OFFSET $2',
  "SELECT * FROM orders WHERE status = 'paid' AND user_id = $1 ORDER BY price,asc",
  'INSERT INTO reviews (product_id, text, rating) VALUES ($1, $2, $3) RETURNING id',
  'UPDATE users SET name = $1, updated_at = now() WHERE id = $2',
  'SELECT u.id, u.name FROM users u JOIN memberships m ON m.user_id = u.id WHERE m.tenant_id = $1',
  'DELETE FROM sessions WHERE expires_at < now()',
  'SELECT count(*) FROM events WHERE ts > now() - interval \'1 day\'',
];

describe('corpus: camada 1 (assinaturas)', () => {
  it('detecção por categoria', () => {
    const sqli = measure('assinaturas', 'SQLi', SQLI, (p) => signatureFires('sqli')(p.value), (p) => p.value);
    measure('assinaturas', 'NoSQLi (operador no corpo)', NOSQLI_OPERATORS, (op) =>
      signatureTypes(request({ body: { password: op } })).has('nosqli'), (op) => JSON.stringify(op));
    measure('assinaturas', 'Path traversal', TRAVERSAL, (p) => signatureFires('traversal')(p.value), (p) => p.value);
    const xss = measure('assinaturas', 'XSS', XSS, signatureFires('xss'), (v) => v);
    measure('assinaturas', 'Scanners (user agent)', SCANNER_AGENTS, (ua) =>
      signatureTypes(request({ userAgent: ua })).has('scanner'), (v) => v);
    // A camada 1 é conservadora de propósito (a RASP confirma); estes pisos só evitam regressão.
    expect(sqli.disparos / sqli.total).toBeGreaterThanOrEqual(0.85);
    expect(xss.disparos / xss.total).toBeGreaterThanOrEqual(0.9);
  });

  it('falsos positivos em entradas legítimas (query e corpo) ficam abaixo de 5%', () => {
    const row = measure('assinaturas', 'Legítimas (falso positivo)', BENIGN, (v) =>
      detect(request({ query: { q: v }, body: { text: v } })).length > 0, (v) => v);
    expect(row.disparos / row.total).toBeLessThan(0.05);
  });
});

describe('corpus: camada 1b (RASP)', () => {
  it('SQLi no contexto vulnerável correspondente: 100%', () => {
    const row = measure('rasp', 'SQLi (pg/mysql2)', SQLI, (p) => {
      const sql = p.context === 'string' ? `SELECT * FROM users WHERE name = '${p.value}'` : `SELECT * FROM users WHERE id = ${p.value}`;
      return findSqlInjection(sql, at(p.value), p.dialect ?? 'postgres') !== undefined;
    }, (p) => p.value);
    expect(row.misses).toEqual([]);
  });

  it('NoSQLi (operador do usuário no filtro e código em $where): 100%', () => {
    const ops = measure('rasp', 'NoSQLi operadores (mongodb)', NOSQLI_OPERATORS, (op) => {
      const body = { password: structuredClone(op) };
      return findNoSqlInjection([{ email: 'a@b.c', password: body.password }], { body }) !== undefined;
    }, (op) => JSON.stringify(op));
    const where = measure('rasp', 'NoSQLi $where (mongodb)', NOSQLI_WHERE, (v) =>
      findNoSqlInjection([{ $where: `this.name == '${v}'` }], { query: { name: v } }) !== undefined, (v) => v);
    expect([...ops.misses, ...where.misses]).toEqual([]);
  });

  it('path traversal (path.join e caminho direto): 100%', () => {
    const row = measure('rasp', 'Path traversal (fs)', TRAVERSAL, (p) => {
      const windows = p.value.includes('\\');
      const path =
        p.context === 'direct' ? p.value : windows ? win32.join('C:\\app\\public', p.value) : posix.join('/srv/app/public', p.value);
      return findPathTraversal([path], at(p.value)) !== undefined;
    }, (p) => p.value);
    expect(row.misses).toEqual([]);
  });

  it('injeção de comando no contexto vulnerável correspondente: 100%', () => {
    const row = measure('rasp', 'Command injection (child_process)', CMDI, (p) => {
      const cmd =
        p.context === 'bare' ? `ping -c 1 ${p.value}` : p.context === 'squote' ? `convert '${p.value}' out.png` : `grep "${p.value}" app.log`;
      return findCommandInjection(cmd, at(p.value)) !== undefined;
    }, (p) => JSON.stringify(p.value));
    expect(row.misses).toEqual([]);
  });

  it('nenhum falso positivo em entradas legítimas com código seguro', () => {
    const fp = measure('rasp', 'Legítimas (falso positivo)', BENIGN, (v) => {
      const inputs = at(v);
      const escaped = `SELECT * FROM users WHERE name = '${v.replace(/'/g, "''")}'`;
      const numeric = /^-?\d+(\.\d+)?$/.test(v) ? [`SELECT * FROM products WHERE id = ${v}`] : [];
      const sql = [...APP_QUERIES, escaped, ...numeric].some((q) => findSqlInjection(q, inputs) !== undefined);
      const nosql = findNoSqlInjection([{ name: v, deleted: { $ne: true }, price: { $gte: 10 } }], { query: { q: v } }) !== undefined;
      const fs = findPathTraversal([posix.join('/srv/app/public', v)], inputs) !== undefined;
      const shell = findCommandInjection(`convert '${v.replace(/'/g, "'\\''")}' out.png`, inputs) !== undefined;
      return sql || nosql || fs || shell;
    }, (v) => v);
    expect(fp.misses.length).toBe(BENIGN.length);
  });
});

afterAll(() => {
  const table = rows.map(({ misses, ...row }) => ({ ...row, 'não detectados / disparos': row.conjunto.startsWith('Legítimas') ? '' : misses.length }));
  console.log('\nCorpus de detecção\n');
  console.table(table);
  for (const row of rows) {
    const list = row.conjunto.startsWith('Legítimas')
      ? BENIGN.filter((v) => !row.misses.includes(v))
      : row.misses;
    if (list.length > 0) console.log(`${row.camada} · ${row.conjunto} · ${row.conjunto.startsWith('Legítimas') ? 'disparou em' : 'não detectou'}:\n  ${list.join('\n  ')}`);
  }
});
