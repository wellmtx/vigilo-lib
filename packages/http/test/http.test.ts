import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { request as rawRequest } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import type { VigiloEvent } from '@vigilo/core';
import { instrumentPg, withVigilo } from '../src/index.js';

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
  const listener = withVigilo(
    (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    },
    { mode, flushIntervalMs: 0, send: async (events) => void sent.push(...events) },
  );
  server = createServer(listener).listen(0);
  await new Promise((resolve) => server!.once('listening', resolve));
  return { port: (server.address() as AddressInfo).port, sent, client: listener.client };
}

/** fetch normaliza `../`; aqui o path precisa chegar cru ao servidor. */
function get(port: number, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    rawRequest({ host: '127.0.0.1', port, path }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    })
      .on('error', reject)
      .end();
  });
}

describe('@vigilo/http', () => {
  it('detecta traversal no path cru e normaliza a rota', async () => {
    const { port, sent, client } = await start('monitor');
    expect(await get(port, '/files/42/../../etc/passwd')).toBe(200);
    await client.flush();
    expect(sent[0]).toMatchObject({ threatType: 'traversal' });
  });

  it('em block responde 403', async () => {
    const { port, client, sent } = await start('block');
    expect(await get(port, `/users/9?id=${encodeURIComponent('1 UNION SELECT 1')}`)).toBe(403);
    await client.flush();
    expect(sent[0]).toMatchObject({ route: '/users/:id', blocked: true });
  });
});

// `1 || 1=1` passa pelas assinaturas (ver o corpus de detecção): só a RASP pega.
describe('@vigilo/http + RASP (pg)', () => {
  async function startDb(mode: 'monitor' | 'block') {
    const sent: VigiloEvent[] = [];
    const listener = withVigilo(
      async (req, res) => {
        const id = new URL(req.url ?? '/', 'http://localhost').searchParams.get('id');
        try {
          await db.query(`SELECT * FROM users WHERE id = ${id}`);
          res.writeHead(200).end('ok');
        } catch {
          res.writeHead(500).end('error');
        }
      },
      { mode, flushIntervalMs: 0, send: async (events) => void sent.push(...events) },
    );
    server = createServer(listener).listen(0);
    await new Promise((resolve) => server!.once('listening', resolve));
    return { port: (server.address() as AddressInfo).port, sent, client: listener.client };
  }

  it('em block impede a injeção vinda da query string', async () => {
    const { port, sent, client } = await startDb('block');
    executed.length = 0;
    expect(await get(port, `/users?id=${encodeURIComponent('1 || 1=1')}`)).toBe(500);
    await client.flush();
    expect(executed).toHaveLength(0);
    expect(sent[0]).toMatchObject({ blocked: true, threats: [{ layer: 'rasp', location: 'query.id' }] });
  });

  it('em monitor deixa seguir e registra', async () => {
    const { port, sent, client } = await startDb('monitor');
    executed.length = 0;
    expect(await get(port, `/users?id=${encodeURIComponent('1 || 1=1')}`)).toBe(200);
    await client.flush();
    expect(executed).toHaveLength(1);
    expect(sent[0]).toMatchObject({ blocked: false, threats: [{ layer: 'rasp' }] });
  });
});
