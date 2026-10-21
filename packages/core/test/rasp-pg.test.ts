import pg from 'pg';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createVigilo } from '../src/client.js';
import { runWithContext, type InputSources, type RequestContext } from '../src/rasp/context.js';
import { instrumentPg } from '../src/rasp/pg.js';
import { VigiloBlockedError } from '../src/rasp/wrap.js';

// Substitui a ida ao banco antes de instrumentar: o wrapper envolve o stub, nos protótipos reais do pg.
const clientQuery = vi.fn(async () => ({ rows: [] }));
const poolQuery = vi.fn(async () => ({ rows: [] }));

beforeAll(() => {
  pg.Client.prototype.query = clientQuery as unknown as typeof pg.Client.prototype.query;
  pg.Pool.prototype.query = poolQuery as unknown as typeof pg.Pool.prototype.query;
  expect(instrumentPg(pg)).toBe(true);
});

function context(mode: 'monitor' | 'block', sources: InputSources): RequestContext {
  return createVigilo({ mode, flushIntervalMs: 0, send: async () => {} }).createContext(() => sources);
}

const attack = { params: { id: '1 OR 1=1' } };
const sqlFor = (id: string) => `SELECT * FROM users WHERE id = ${id}`;

describe('instrumentPg', () => {
  it('em monitor registra a ameaça da camada rasp e deixa a query seguir', async () => {
    const ctx = context('monitor', attack);
    const client = new pg.Client();
    clientQuery.mockClear();
    await runWithContext(ctx, () => client.query(sqlFor('1 OR 1=1')));
    expect(clientQuery).toHaveBeenCalledOnce();
    expect(ctx.threats).toEqual([
      { type: 'sqli', severity: 5, location: 'params.id', rule: 'rasp.sqli.pg', layer: 'rasp' },
    ]);
    expect(ctx.blocked).toBe(false);
  });

  it('em block rejeita a promise sem executar a query', async () => {
    const ctx = context('block', attack);
    const client = new pg.Client();
    clientQuery.mockClear();
    const result = runWithContext(ctx, () => client.query(sqlFor('1 OR 1=1')));
    await expect(result).rejects.toBeInstanceOf(VigiloBlockedError);
    await expect(result).rejects.toMatchObject({ code: 'VIGILO_BLOCKED' });
    expect(clientQuery).not.toHaveBeenCalled();
    expect(ctx.blocked).toBe(true);
  });

  it('em block entrega o erro pelo callback quando há um', async () => {
    const ctx = context('block', attack);
    const client = new pg.Client();
    const error = await new Promise<Error>((resolve) => {
      runWithContext(ctx, () => client.query(sqlFor('1 OR 1=1'), [], (err: Error) => resolve(err)));
    });
    expect(error).toBeInstanceOf(VigiloBlockedError);
  });

  it('verifica Pool.query e objetos de configuração ({ text })', async () => {
    const ctx = context('block', attack);
    const pool = new pg.Pool();
    poolQuery.mockClear();
    await expect(runWithContext(ctx, () => pool.query({ text: sqlFor('1 OR 1=1') }))).rejects.toBeInstanceOf(
      VigiloBlockedError,
    );
    expect(poolQuery).not.toHaveBeenCalled();
    await pool.end();
  });

  it('não bloqueia objetos submittable (cursores), só registra', async () => {
    const ctx = context('block', attack);
    const client = new pg.Client();
    clientQuery.mockClear();
    const cursor = { text: sqlFor('1 OR 1=1'), submit: () => {} };
    await runWithContext(ctx, () => client.query(cursor as unknown as string));
    expect(clientQuery).toHaveBeenCalledOnce();
    expect(ctx.threats).toHaveLength(1);
    expect(ctx.blocked).toBe(false);
  });

  it('não interfere em query parametrizada nem fora de uma requisição', async () => {
    const ctx = context('block', attack);
    const client = new pg.Client();
    clientQuery.mockClear();
    await runWithContext(ctx, () => client.query('SELECT * FROM users WHERE id = $1', ['1 OR 1=1']));
    await client.query(sqlFor('1 OR 1=1'));
    expect(clientQuery).toHaveBeenCalledTimes(2);
    expect(ctx.threats).toEqual([]);
  });

  it('lê as fontes no momento da query (params preenchidos depois do middleware)', async () => {
    const sources: InputSources = {};
    const ctx = context('monitor', sources);
    const client = new pg.Client();
    await runWithContext(ctx, async () => {
      sources.params = { id: '1 OR 1=1' };
      await client.query(sqlFor('1 OR 1=1'));
    });
    expect(ctx.threats[0]?.location).toBe('params.id');
  });

  it('é fail-open: erro ao ler as entradas não impede a query', async () => {
    const ctx = createVigilo({ mode: 'block', flushIntervalMs: 0, send: async () => {} }).createContext(() => {
      throw new Error('boom');
    });
    clientQuery.mockClear();
    await runWithContext(ctx, () => new pg.Client().query(sqlFor('1 OR 1=1')));
    expect(clientQuery).toHaveBeenCalledOnce();
  });

  it('é idempotente e ignora módulos sem Client/Pool', () => {
    const before = pg.Client.prototype.query;
    instrumentPg(pg);
    expect(pg.Client.prototype.query).toBe(before);
    expect(instrumentPg({} as never)).toBe(false);
  });

  it('o evento enviado inclui a ameaça rasp e marca blocked', async () => {
    const sent: unknown[] = [];
    const vigilo = createVigilo({ mode: 'block', flushIntervalMs: 0, send: async (events) => void sent.push(...events) });
    const ctx = vigilo.createContext(() => attack);
    await runWithContext(ctx, () => new pg.Client().query(sqlFor('1 OR 1=1'))).catch(() => {});
    const req = { method: 'GET', route: '/users/:id', path: '/users/1', query: {}, headers: {}, ip: '203.0.113.1' };
    vigilo.record(req, { status: 500, durationMs: 1, decision: vigilo.inspect(req), context: ctx });
    await vigilo.flush();
    expect(sent[0]).toMatchObject({ threatType: 'sqli', severity: 5, blocked: true, threats: [{ layer: 'rasp' }] });
  });
});
