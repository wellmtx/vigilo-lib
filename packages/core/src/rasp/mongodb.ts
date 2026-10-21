import { findNoSqlInjection } from './nosql.js';
import { trailingCallback, wrapMethod, type Delivery, type WrapSpec } from './wrap.js';

/** Formato mínimo do módulo `mongodb` (ou `mongoose.mongo`). */
export interface MongodbModule {
  Collection?: unknown;
}

/** Métodos de `Collection` e os índices dos argumentos que levam filtro, update ou pipeline. */
const METHODS: Record<string, number[]> = {
  find: [0],
  findOne: [0],
  countDocuments: [0],
  count: [0],
  distinct: [1],
  deleteOne: [0],
  deleteMany: [0],
  findOneAndDelete: [0],
  updateOne: [0, 1],
  updateMany: [0, 1],
  replaceOne: [0, 1],
  findOneAndUpdate: [0, 1],
  findOneAndReplace: [0, 1],
  aggregate: [0],
};

/** Devolvem cursor de forma síncrona: o bloqueio só pode ser uma exceção na chamada. */
const CURSOR_METHODS = new Set(['find', 'aggregate']);

function specFor(method: string, indexes: number[]): WrapSpec {
  return {
    driver: 'mongodb',
    detect(args, context) {
      const location = findNoSqlInjection(
        indexes.map((i) => args[i]),
        context.sources(),
      );
      if (!location) return undefined;
      return { type: 'nosqli', severity: 5, location, rule: 'rasp.nosqli.mongodb', layer: 'rasp' };
    },
    delivery(args): Delivery {
      // Drivers antigos (até a v5) ainda aceitavam callback.
      const callback = trailingCallback(args);
      if (callback) return { via: 'callback', callback };
      return CURSOR_METHODS.has(method) ? { via: 'throw' } : { via: 'promise' };
    },
  };
}

/**
 * Camada RASP para o driver `mongodb`: confere filtros, updates e pipelines de `Collection`
 * antes de irem ao banco. Com Mongoose, passe o driver que ele usa: `instrumentMongodb(mongoose.mongo)`.
 *
 * No modo `block`, os métodos que devolvem promise rejeitam com `VigiloBlockedError`;
 * `find` e `aggregate`, que devolvem cursor, lançam o erro na chamada.
 *
 * ```js
 * import * as mongodb from 'mongodb';
 * import { instrumentMongodb } from '@vigilo/express';
 * instrumentMongodb(mongodb);
 * ```
 */
export function instrumentMongodb(mongodb: MongodbModule): boolean {
  const Collection = mongodb?.Collection;
  const proto = typeof Collection === 'function' ? (Collection as { prototype?: object }).prototype : undefined;
  if (!proto) return false;
  let patched = false;
  for (const [method, indexes] of Object.entries(METHODS)) {
    patched = wrapMethod(proto, method, specFor(method, indexes)) || patched;
  }
  return patched;
}
