import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import express from 'express';
import { afterEach, describe, expect, it } from 'vitest';
import type { VigiloEvent } from '@vigilo/core';
import { shield } from '../src/index.js';

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
