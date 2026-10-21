import * as mongodb from 'mongodb';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createVigilo } from '../src/client.js';
import { runWithContext, type InputSources, type RequestContext } from '../src/rasp/context.js';
import { instrumentMongodb } from '../src/rasp/mongodb.js';
import { findNoSqlInjection } from '../src/rasp/nosql.js';
import { VigiloBlockedError } from '../src/rasp/wrap.js';

const proto = mongodb.Collection.prototype as unknown as Record<string, unknown>;
const executed: string[] = [];

beforeAll(() => {
  // Troca a ida ao banco por stubs antes de instrumentar.
  for (const method of ['findOne', 'updateOne', 'deleteMany', 'countDocuments']) {
    proto[method] = vi.fn(async () => void executed.push(method));
  }
  proto.find = vi.fn(() => {
    executed.push('find');
    return { toArray: async () => [] };
  });
  expect(instrumentMongodb(mongodb)).toBe(true);
});

function context(mode: 'monitor' | 'block', sources: InputSources): RequestContext {
  return createVigilo({ mode, flushIntervalMs: 0, send: async () => {} }).createContext(() => sources);
}

const users = () => Object.create(mongodb.Collection.prototype) as mongodb.Collection;

describe('findNoSqlInjection', () => {
  it('detecta operador escolhido pelo usuário dentro do filtro (mesmo objeto ou cópia)', () => {
    const body = { email: 'a@b.c', password: { $ne: null } };
    expect(findNoSqlInjection([{ email: body.email, password: body.password }], { body })).toBe('body.password');
    expect(findNoSqlInjection([{ ...body, password: { ...body.password } }], { body })).toBe('body.password');
  });

  it('detecta operador vindo da query string (qs: user[$gt]=)', () => {
    const query = { user: { $gt: '' } };
    expect(findNoSqlInjection([{ user: query.user }], { query })).toBe('query.user');
  });

  it('detecta update inteiro controlado pelo usuário', () => {
    const body = { $set: { role: 'admin' } };
    expect(findNoSqlInjection([{ _id: 1 }, body], { body })).toBe('body');
  });

  it('detecta operador dentro de pipeline de aggregate', () => {
    const body = { status: { $regex: '.*' } };
    expect(findNoSqlInjection([[{ $match: { status: body.status } }, { $limit: 10 }]], { body })).toBe('body.status');
  });

  it('detecta entrada com código dentro de $where', () => {
    const query = { name: "x' || '1'=='1" };
    const filter = { $where: `this.name == '${query.name}'` };
    expect(findNoSqlInjection([filter], { query })).toBe('query.name');
  });

  it('não dispara em operadores escritos pelo desenvolvedor com valores do usuário', () => {
    const query = { min: '10', q: 'notebook' };
    const filter = { price: { $gte: Number(query.min) }, name: { $regex: query.q, $options: 'i' }, deleted: { $ne: true } };
    expect(findNoSqlInjection([filter], { query })).toBeUndefined();
  });

  it('não dispara com corpo comum, sem operadores', () => {
    const body = { name: 'Ana', tags: ['a', 'b'], address: { city: 'Recife' } };
    expect(findNoSqlInjection([{ name: body.name }, { $set: body }], { body })).toBeUndefined();
  });

  it('não dispara quando o operador do usuário não chega ao banco (sanitizado)', () => {
    const body = { password: { $ne: null } };
    expect(findNoSqlInjection([{ password: String(body.password) }], { body })).toBeUndefined();
  });
});

describe('instrumentMongodb', () => {
  const attack = { body: { email: 'admin@x.com', password: { $ne: null } } };

  it('em monitor registra e deixa a operação seguir', async () => {
    const ctx = context('monitor', attack);
    executed.length = 0;
    await runWithContext(ctx, () => users().findOne({ email: attack.body.email, password: attack.body.password }));
    expect(executed).toEqual(['findOne']);
    expect(ctx.threats).toEqual([
      { type: 'nosqli', severity: 5, location: 'body.password', rule: 'rasp.nosqli.mongodb', layer: 'rasp' },
    ]);
  });

  it('em block rejeita métodos de promise sem executar', async () => {
    const ctx = context('block', attack);
    executed.length = 0;
    await expect(
      runWithContext(ctx, () => users().updateOne({ password: attack.body.password }, { $set: { role: 'x' } })),
    ).rejects.toBeInstanceOf(VigiloBlockedError);
    expect(executed).toEqual([]);
    expect(ctx.blocked).toBe(true);
  });

  it('em block lança na chamada de find (cursor síncrono)', () => {
    const ctx = context('block', attack);
    expect(() => runWithContext(ctx, () => users().find({ password: attack.body.password }))).toThrow(VigiloBlockedError);
  });

  it('filtro legítimo passa', async () => {
    const ctx = context('block', attack);
    executed.length = 0;
    await runWithContext(ctx, () => users().countDocuments({ email: attack.body.email, active: { $eq: true } }));
    expect(executed).toEqual(['countDocuments']);
    expect(ctx.threats).toEqual([]);
  });
});
