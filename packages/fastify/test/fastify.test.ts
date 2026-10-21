import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import type { VigiloEvent } from '@vigilo/core';
import { vigilo } from '../src/index.js';

async function build(mode: 'monitor' | 'block') {
  const sent: VigiloEvent[] = [];
  const app = Fastify();
  await app.register(vigilo, { mode, flushIntervalMs: 0, send: async (events) => void sent.push(...events) });
  app.get('/users/:id', async () => ({ ok: true }));
  app.post('/search', async () => ({ ok: true }));
  await app.ready();
  return { app, sent };
}

describe('@vigilo/fastify', () => {
  it('em monitor deixa passar e registra o padrão da rota', async () => {
    const { app, sent } = await build('monitor');
    const res = await app.inject({ url: '/users/1', query: { q: '<script>alert(1)</script>' } });
    expect(res.statusCode).toBe(200);
    await app.vigilo.flush();
    expect(sent[0]).toMatchObject({ route: '/users/:id', threatType: 'xss', blocked: false });
    await app.close();
  });

  it('em block responde 403', async () => {
    const { app, sent } = await build('block');
    const res = await app.inject({ method: 'POST', url: '/search', payload: { q: "x'; DROP TABLE users" } });
    expect(res.statusCode).toBe(403);
    await app.vigilo.flush();
    expect(sent[0]).toMatchObject({ blocked: true, threatType: 'sqli', status: 403 });
    await app.close();
  });

  it('registra rotas inexistentes (404) com sinais de varredura', async () => {
    const { app, sent } = await build('monitor');
    const res = await app.inject({ url: '/.env' });
    expect(res.statusCode).toBe(404);
    await app.vigilo.flush();
    expect(sent[0]).toMatchObject({ status: 404, threatType: 'scan' });
    await app.close();
  });
});
