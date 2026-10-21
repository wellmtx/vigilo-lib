import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { fileURLToPath } from 'node:url';
import { collectRaspInputs } from './inputs.js';
import { findPathTraversal } from './path.js';
import { trailingCallback, wrapMethod, type Delivery, type WrapSpec } from './wrap.js';

/** Funções que leem, escrevem, listam ou apagam, e os índices dos argumentos que são caminhos. */
const CALLBACK_API: Record<string, number[]> = {
  readFile: [0],
  writeFile: [0],
  appendFile: [0],
  open: [0],
  readdir: [0],
  unlink: [0],
  rm: [0],
  copyFile: [0, 1],
  rename: [0, 1],
};
const SYNC_API: Record<string, number[]> = {
  readFileSync: [0],
  writeFileSync: [0],
  appendFileSync: [0],
  openSync: [0],
  readdirSync: [0],
  unlinkSync: [0],
  rmSync: [0],
  copyFileSync: [0, 1],
  renameSync: [0, 1],
  createReadStream: [0],
  createWriteStream: [0],
};

function specFor(indexes: number[], delivery: (args: unknown[]) => Delivery): WrapSpec {
  return {
    driver: 'fs',
    detect(args, context) {
      const paths = indexes.map((i) => pathString(args[i])).filter((p): p is string => p !== undefined);
      if (paths.length === 0) return undefined;
      const input = findPathTraversal(paths, collectRaspInputs(context.sources()));
      return input && { type: 'traversal', severity: 5, location: input.location, rule: 'rasp.traversal.fs', layer: 'rasp' };
    },
    delivery,
  };
}

const viaCallback = (args: unknown[]): Delivery => {
  const callback = trailingCallback(args);
  return callback ? { via: 'callback', callback } : { via: 'throw' };
};
const viaThrow = (): Delivery => ({ via: 'throw' });
const viaPromise = (): Delivery => ({ via: 'promise' });

/**
 * Camada RASP para `node:fs`: confere os caminhos passados às funções que leem, escrevem,
 * listam ou apagam arquivos (API de callback, síncrona, `fs.promises` e streams).
 * Vale também para `import { readFile } from 'node:fs'` e `node:fs/promises`.
 *
 * No modo `block`, o erro chega pelo callback, pela promise rejeitada ou como exceção
 * (funções síncronas e streams).
 *
 * ```js
 * import { instrumentFs } from '@vigilo/express';
 * instrumentFs();
 * ```
 */
export function instrumentFs(): boolean {
  let patched = false;
  for (const [name, indexes] of Object.entries(CALLBACK_API)) {
    patched = wrapMethod(fs, name, specFor(indexes, viaCallback)) || patched;
    patched = wrapMethod(fs.promises, name, specFor(indexes, viaPromise)) || patched;
  }
  for (const [name, indexes] of Object.entries(SYNC_API)) {
    patched = wrapMethod(fs, name, specFor(indexes, viaThrow)) || patched;
  }
  // Atualiza os exports nomeados ESM (`import { readFile } from 'node:fs'`).
  syncBuiltinESMExports();
  return patched;
}

function pathString(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (value instanceof URL && value.protocol === 'file:') {
    try {
      return fileURLToPath(value);
    } catch {
      return undefined;
    }
  }
  return undefined;
}
