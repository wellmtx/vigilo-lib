import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import express from 'express';
import { afterEach, describe, expect, it } from 'vitest';
import type { VigiloEvent } from '@vigilo/core';
import { instrumentPg, shield } from '../src/index.js';

/** Driver falso com o formato do `pg`: registra o SQL em vez de ir ao banco. */
const executed: string[] = [];
class FakeClient {
  async query(text: string) {
    executed.push(text);
    return { rows: [] };
  }
}
instrumentPg({ Client: FakeClient });
const db = new FakeClient();


let server: Server | undefined;
afterEach(() => server?.close());

async function start(mode: 'monitor' | 'block') {
  const sent: VigiloEvent[] = [];
  const app = express();
  app.use(express.json());
  const mw = shield({ mode, flushIntervalMs: 0, send: async (events) => void sent.push(...events) });
  app.use(mw);
  app.get('/users/:id', (_req, res) => void res.json({ ok: true }));
  app.post('/login', (_req, res) => void res.status(401).json({ ok: false }));
  server = app.listen(0);
  await new Promise((resolve) => server!.once('listening', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { base, sent, client: mw.client };
}

describe('@vigilo/express', () => {
  it('em monitor deixa passar e registra o padrão da rota', async () => {
    const { base, sent, client } = await start('monitor');
    const res = await fetch(`${base}/users/1?id=${encodeURIComponent("1' OR '1'='1")}`);
    expect(res.status).toBe(200);
    await client.flush();
    expect(sent[0]).toMatchObject({ route: '/users/:id', threatType: 'sqli', blocked: false, status: 200 });
  });

  it('em block responde 403', async () => {
    const { base, sent, client } = await start('block');
    const res = await fetch(`${base}/users/1?q=${encodeURIComponent('1 UNION SELECT password FROM users')}`);
    expect(res.status).toBe(403);
    await client.flush();
    expect(sent[0]).toMatchObject({ blocked: true, status: 403 });
  });

  it('bloqueado antes do roteamento, não envia o payload do path no route', async () => {
    const { base, sent, client } = await start('block');
    const res = await fetch(`${base}/users/${encodeURIComponent('1 UNION SELECT password FROM users')}`, {
      headers: { 'user-agent': 'sqlmap/1.7' },
    });
    expect(res.status).toBe(403);
    await client.flush();
    expect(sent[0]).toMatchObject({ route: '/users/:id', blocked: true, threatType: 'sqli' });
  });

  it('inspeciona o corpo JSON', async () => {
    const { base, sent, client } = await start('monitor');
    await fetch(`${base}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user: 'admin', password: { $ne: null } }),
    });
    await client.flush();
    expect(sent[0]).toMatchObject({ threatType: 'nosqli', status: 401 });
    expect(sent[0]?.payload).not.toContain('$ne');
  });

  it('requisição limpa gera evento sem payload', async () => {
    const { base, sent, client } = await start('monitor');
    await fetch(`${base}/users/7`);
    await client.flush();
    expect(sent[0]).toMatchObject({ threatType: null, payload: null, route: '/users/:id' });
  });
});

// `1 || 1=1` passa pelas assinaturas (ver o corpus de detecção): só a RASP pega.
describe('@vigilo/express + RASP (pg)', () => {
  async function startDb(mode: 'monitor' | 'block') {
    const sent: VigiloEvent[] = [];
    const app = express();
    const mw = shield({ mode, flushIntervalMs: 0, send: async (events) => void sent.push(...events) });
    app.use(mw);
    // Rota vulnerável de propósito: concatena o parâmetro no SQL.
    app.get('/users/:id', async (req, res) => {
      await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
      res.json({ ok: true });
    });
    // Como no exemplo: o bloqueio da RASP vira 403 num tratador de erro, fora da rota.
    app.use((err: { code?: string }, _req: express.Request, res: express.Response, next: express.NextFunction) => {
      if (err.code === 'VIGILO_BLOCKED') return void res.status(403).json({ error: 'Forbidden' });
      next(err);
    });
    server = app.listen(0);
    await new Promise((resolve) => server!.once('listening', resolve));
    return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, sent, client: mw.client };
  }

  it('em monitor registra a injeção confirmada no driver, com o local do parâmetro', async () => {
    const { base, sent, client } = await startDb('monitor');
    executed.length = 0;
    expect((await fetch(`${base}/users/${encodeURIComponent('1 || 1=1')}`)).status).toBe(200);
    await client.flush();
    expect(executed).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      threatType: 'sqli',
      severity: 5,
      blocked: false,
      threats: [{ layer: 'rasp', location: 'params.id', rule: 'rasp.sqli.pg' }],
    });
    // A evidência do ataque pela rota fica no payload: o path e o parâmetro.
    const payload = JSON.parse(sent[0]!.payload!);
    expect(payload).toMatchObject({ path: '/users/1 || 1=1', params: { id: '1 || 1=1' } });
    expect(sent[0]!.route).toBe('/users/:id');
  });

  it('em block impede a query, que falha no handler', async () => {
    const { base, sent, client } = await startDb('block');
    executed.length = 0;
    expect((await fetch(`${base}/users/${encodeURIComponent('1 || 1=1')}`)).status).toBe(403);
    await client.flush();
    expect(executed).toHaveLength(0);
    expect(sent[0]).toMatchObject({ blocked: true, threats: [{ layer: 'rasp' }] });
    // Mesmo respondido fora da rota (no tratador de erro), o payload guarda o parâmetro.
    expect(JSON.parse(sent[0]!.payload!)).toMatchObject({ path: '/users/1 || 1=1', params: { id: '1 || 1=1' } });
  });

  it('requisição legítima chega ao banco sem ameaça', async () => {
    const { base, sent, client } = await startDb('block');
    executed.length = 0;
    expect((await fetch(`${base}/users/42`)).status).toBe(200);
    await client.flush();
    expect(executed).toEqual(['SELECT * FROM users WHERE id = 42']);
    expect(sent[0]).toMatchObject({ threatType: null, blocked: false });
  });
});
