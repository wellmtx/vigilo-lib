import { describe, expect, it } from 'vitest';
import { createVigilo } from '../src/client.js';
import { LIMITS } from '../src/contract.js';
import { captureCallsite, pickCallsite } from '../src/rasp/callsite.js';
import { runWithContext } from '../src/rasp/context.js';
import { wrapMethod } from '../src/rasp/wrap.js';
import type { Threat } from '../src/types.js';

const cwd = '/srv/app';
const stack = (...frames: string[]) => ['Error', ...frames.map((f) => `    at ${f}`)].join('\n');

describe('pickCallsite', () => {
  it('escolhe o primeiro frame da aplicação, com caminho relativo', () => {
    const picked = pickCallsite(
      stack(
        'Client.query (/srv/app/node_modules/knex/lib/client.js:10:5)',
        'processTicksAndRejections (node:internal/process/task_queues:95:5)',
        'async UserRepo.find (/srv/app/src/repos/users.ts:42:18)',
        'handler (/srv/app/src/routes/users.ts:7:3)',
      ),
      cwd,
    );
    expect(picked).toEqual({
      file: 'src/repos/users.ts',
      line: 42,
      column: 18,
      function: 'UserRepo.find',
      callers: [{ file: 'src/routes/users.ts', line: 7, column: 3, function: 'handler' }],
    });
  });

  it('leva o caminho da requisição em callers, sem dependências nem frames repetidos', () => {
    const picked = pickCallsite(
      stack(
        'async findProductById (/srv/app/src/repositories/products.ts:11:20)',
        'async getProduct (/srv/app/src/usecases/get-product.ts:8:10)',
        'Layer.handle (/srv/app/node_modules/express/lib/router/layer.js:95:5)',
        'async /srv/app/src/routes/products.ts:14:3',
        'async /srv/app/src/routes/products.ts:14:3',
      ),
      cwd,
    );
    expect(picked?.callers).toEqual([
      { file: 'src/usecases/get-product.ts', line: 8, column: 10, function: 'getProduct' },
      { file: 'src/routes/products.ts', line: 14, column: 3, function: null },
    ]);
  });

  it('limita os chamadores e omite o campo sem nenhum', () => {
    const frames = Array.from({ length: 20 }, (_, i) => `f${i} (/srv/app/src/f${i}.ts:1:1)`);
    expect(pickCallsite(stack(...frames), cwd)?.callers).toHaveLength(LIMITS.callers);
    expect(pickCallsite(stack('f (/srv/app/a.js:1:1)'), cwd)).not.toHaveProperty('callers');
  });

  it('aceita URL file:// (ESM) e frame sem nome de função', () => {
    expect(pickCallsite(stack('file:///srv/app/dist/server.mjs:3:9'), cwd)).toEqual({
      file: 'dist/server.mjs',
      line: 3,
      column: 9,
      function: null,
    });
    expect(pickCallsite(stack('Object.<anonymous> (/srv/app/index.js:1:1)'), cwd)?.function).toBeNull();
  });

  it('nunca devolve caminho fora do diretório da aplicação', () => {
    expect(pickCallsite(stack('run (/home/ana/scripts/job.js:1:1)'), cwd)).toBeUndefined();
    expect(pickCallsite(stack('run (/srv/application/x.js:1:1)'), cwd)).toBeUndefined();
    expect(pickCallsite(stack('eval (eval at load (/srv/app/a.js:1:1), <anonymous>:1:1)'), cwd)).toBeUndefined();
    expect(pickCallsite(stack('new Promise (<anonymous>)'), cwd)).toBeUndefined();
  });

  it('ignora dependências em qualquer nível de node_modules', () => {
    const picked = pickCallsite(
      stack('q (/srv/app/packages/api/node_modules/pg/lib/client.js:1:1)', 'h (/srv/app/packages/api/src/h.ts:9:2)'),
      cwd,
    );
    expect(picked?.file).toBe('packages/api/src/h.ts');
  });

  it('corta nome de função longo e descarta arquivo acima do limite', () => {
    const longName = 'f'.repeat(500);
    expect(pickCallsite(stack(`${longName} (/srv/app/a.js:1:1)`), cwd)?.function).toHaveLength(LIMITS.callsiteFunction);
    expect(pickCallsite(stack(`g (/srv/app/${'d/'.repeat(200)}a.js:1:1)`), cwd)).toBeUndefined();
  });
});

describe('callsite na RASP', () => {
  const detectAlways = {
    driver: 'fake',
    detect: (): Threat => ({ type: 'sqli', severity: 5, location: 'query.id', rule: 'rasp.sqli.fake', layer: 'rasp' }),
    delivery: () => undefined,
  };

  it('aponta quem chamou o driver, não o wrapper da Vigilo', () => {
    const driver = { query: (_sql: string) => 'ok' };
    wrapMethod(driver, 'query', detectAlways);
    const ctx = createVigilo({ mode: 'monitor', send: async () => {} }).createContext(() => ({}));
    function getUser() {
      return driver.query('SELECT 1');
    }
    runWithContext(ctx, getUser);
    expect(ctx.threats[0]?.callsite).toMatchObject({ line: expect.any(Number), function: 'getUser' });
    expect(ctx.threats[0]?.callsite?.file).toMatch(/(^|\/)test\/rasp-callsite\.test\.ts$/);
  });

  it('restaura Error.stackTraceLimit', () => {
    const before = Error.stackTraceLimit;
    captureCallsite(captureCallsite);
    expect(Error.stackTraceLimit).toBe(before);
  });
});

describe('release', () => {
  async function batchRelease(options: { release?: string; env?: string }) {
    const previous = process.env.VIGILO_RELEASE;
    if (options.env === undefined) delete process.env.VIGILO_RELEASE;
    else process.env.VIGILO_RELEASE = options.env;
    const bodies: unknown[] = [];
    const fetchMock = async (_url: URL, init: RequestInit) => {
      const { gunzipSync } = await import('node:zlib');
      bodies.push(JSON.parse(gunzipSync(init.body as Buffer).toString('utf8')));
      return new Response(null, { status: 202 });
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const client = createVigilo({
        apiKey: 'k',
        endpoint: 'https://ingest.test',
        remoteConfig: false,
        flushIntervalMs: 0,
        ...(options.release === undefined ? {} : { release: options.release }),
      });
      client.record(
        { method: 'GET', route: '/', path: '/', query: {}, headers: {}, ip: '203.0.113.1' },
        { status: 200, durationMs: 1, decision: { threats: [], block: false } },
      );
      await client.close();
    } finally {
      globalThis.fetch = originalFetch;
      if (previous === undefined) delete process.env.VIGILO_RELEASE;
      else process.env.VIGILO_RELEASE = previous;
    }
    return (bodies[0] as { release: unknown }).release;
  }

  it('vem da opção, depois de VIGILO_RELEASE, e é null sem nenhum', async () => {
    expect(await batchRelease({ release: '3f2c9a1', env: 'v9' })).toBe('3f2c9a1');
    expect(await batchRelease({ env: 'v1.2.3+build.7' })).toBe('v1.2.3+build.7');
    expect(await batchRelease({})).toBeNull();
  });

  it('descarta valor fora do formato em vez de perder o lote', async () => {
    expect(await batchRelease({ release: 'main; rm -rf /' })).toBeNull();
    expect(await batchRelease({ release: 'a'.repeat(LIMITS.release + 1) })).toBeNull();
  });
});
