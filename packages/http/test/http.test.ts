import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { request as rawRequest } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import type { VigiloEvent } from '@vigilo/core';
import { withVigilo } from '../src/index.js';

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
