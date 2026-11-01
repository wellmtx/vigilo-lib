import { isAbsolute, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LIMITS } from '../contract.js';
import type { Callsite } from '../types.js';

/** Frames lidos da pilha: ORMs e query builders costumam empilhar vários antes do driver. */
const MAX_FRAMES = 50;

const FRAME = /^\s*at (?:(.+?) \()?(.+?):(\d+):(\d+)\)?$/;

/**
 * Ponto do código da aplicação que chamou o driver: o primeiro frame abaixo de `below`
 * (o wrapper da RASP) que não está em `node_modules` nem nos módulos internos do Node.
 * O arquivo sai relativo a `cwd`; fora dele (ou sem caminho), não há callsite, para que
 * caminhos absolutos da máquina (com nome de usuário, por exemplo) nunca saiam do processo.
 * Com `--enable-source-maps`, a pilha já aponta o arquivo original (`.ts`).
 */
export function captureCallsite(below: Function, cwd: string = process.cwd()): Callsite | undefined {
  const holder: { stack?: string } = {};
  const limit = Error.stackTraceLimit;
  try {
    Error.stackTraceLimit = MAX_FRAMES;
    Error.captureStackTrace(holder, below);
  } finally {
    Error.stackTraceLimit = limit;
  }
  return pickCallsite(holder.stack ?? '', cwd);
}

/** Escolhe o primeiro frame da aplicação numa pilha do V8. */
export function pickCallsite(stack: string, cwd: string): Callsite | undefined {
  for (const line of stack.split('\n')) {
    const match = FRAME.exec(line);
    if (!match) continue;
    const [, name, location, row, col] = match;
    const file = appFile(location!, cwd);
    if (!file) continue;
    return { file, line: Number(row), column: Number(col) || null, function: functionName(name) };
  }
  return undefined;
}

function appFile(location: string, cwd: string): string | undefined {
  if (location.startsWith('node:') || location.includes('eval at ')) return undefined;
  let path = location;
  if (path.startsWith('file://')) {
    try {
      path = fileURLToPath(path);
    } catch {
      return undefined;
    }
  }
  if (!isAbsolute(path)) return undefined;
  const rel = relative(cwd, path);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return undefined;
  const file = rel.split(sep).join('/');
  if (file.split('/').includes('node_modules')) return undefined;
  return file.length <= LIMITS.callsiteFile ? file : undefined;
}

function functionName(name: string | undefined): string | null {
  if (!name) return null;
  const clean = name.replace(/^(async|new) /, '');
  if (clean === '' || clean.includes('<anonymous>')) return null;
  return clean.length > LIMITS.callsiteFunction ? clean.slice(0, LIMITS.callsiteFunction) : clean;
}
