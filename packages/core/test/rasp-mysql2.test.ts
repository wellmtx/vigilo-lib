import mysql from 'mysql2';
import mysqlPromise from 'mysql2/promise';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createVigilo } from '../src/client.js';
import { runWithContext, type InputSources, type RequestContext } from '../src/rasp/context.js';
import { instrumentMysql2 } from '../src/rasp/mysql2.js';
import { VigiloBlockedError } from '../src/rasp/wrap.js';

// As funções originais ficam na classe base; o stub entra lá antes de instrumentar.
const baseConnection = Object.getPrototypeOf(mysql.Connection.prototype) as Record<string, unknown>;
const basePool = Object.getPrototypeOf(mysql.Pool.prototype) as Record<string, unknown>;
const calls: string[] = [];
const fakeQuery = vi.fn(function (this: unknown, sql: unknown, values?: unknown, cb?: unknown) {
  const callback = typeof values === 'function' ? values : cb;
  calls.push(typeof sql === 'string' ? sql : String((sql as { sql: string }).sql));
  if (typeof callback === 'function') process.nextTick(() => callback(null, [], []));
  return {};
});

beforeAll(() => {
  for (const proto of [baseConnection, basePool]) {
    proto.query = fakeQuery;
    proto.execute = fakeQuery;
  }
  expect(instrumentMysql2(mysql)).toBe(true);
  expect(instrumentMysql2(mysqlPromise)).toBe(true);
});

function context(mode: 'monitor' | 'block', sources: InputSources): RequestContext {
  return createVigilo({ mode, flushIntervalMs: 0, send: async () => {} }).createContext(() => sources);
}

const attack = { query: { name: "x' OR 1=1 #" } };
const sqlFor = (name: string) => `SELECT * FROM users WHERE name = '${name}'`;
const connection = () => Object.create(mysql.Connection.prototype) as mysql.Connection;

describe('instrumentMysql2', () => {
  it('em monitor registra a injeção (dialeto MySQL) e deixa a query seguir', async () => {
    const ctx = context('monitor', attack);
    calls.length = 0;
    await new Promise((resolve) => runWithContext(ctx, () => connection().query(sqlFor(attack.query.name), resolve)));
    expect(calls).toHaveLength(1);
    expect(ctx.threats).toEqual([
      { type: 'sqli', severity: 5, location: 'query.name', rule: 'rasp.sqli.mysql2', layer: 'rasp' },
    ]);
  });

  it('em block entrega o erro pelo callback sem executar', async () => {
    const ctx = context('block', attack);
    calls.length = 0;
    const error = await new Promise((resolve) =>
      runWithContext(ctx, () => connection().query({ sql: sqlFor(attack.query.name) }, resolve)),
    );
    expect(error).toBeInstanceOf(VigiloBlockedError);
    expect(calls).toHaveLength(0);
    expect(ctx.blocked).toBe(true);
  });

  it('cobre execute e o pool', async () => {
    const ctx = context('block', attack);
    const pool = Object.create(mysql.Pool.prototype) as mysql.Pool;
    const errors = await Promise.all([
      new Promise((resolve) => runWithContext(ctx, () => connection().execute(sqlFor(attack.query.name), [], resolve))),
      new Promise((resolve) => runWithContext(ctx, () => pool.query(sqlFor(attack.query.name), resolve))),
    ]);
    expect(errors.every((e) => e instanceof VigiloBlockedError)).toBe(true);
  });

  it('PromisePool rejeita a promise em block', async () => {
    const ctx = context('block', attack);
    const pool = Object.create(mysqlPromise.PromisePool.prototype) as mysqlPromise.Pool;
    await expect(runWithContext(ctx, () => pool.query(sqlFor(attack.query.name)))).rejects.toBeInstanceOf(
      VigiloBlockedError,
    );
  });

  it('sem callback (API de eventos) só registra', () => {
    const ctx = context('block', attack);
    calls.length = 0;
    runWithContext(ctx, () => connection().query(sqlFor(attack.query.name)));
    expect(calls).toHaveLength(1);
    expect(ctx.threats).toHaveLength(1);
    expect(ctx.blocked).toBe(false);
  });

  it('placeholders nunca disparam, mesmo com valor malicioso', async () => {
    const ctx = context('block', attack);
    calls.length = 0;
    await new Promise((resolve) =>
      runWithContext(ctx, () => connection().query('SELECT * FROM users WHERE name = ?', [attack.query.name], resolve)),
    );
    expect(calls).toHaveLength(1);
    expect(ctx.threats).toEqual([]);
  });

  it('é idempotente', () => {
    const before = baseConnection.query;
    instrumentMysql2(mysql);
    expect(baseConnection.query).toBe(before);
  });
});
