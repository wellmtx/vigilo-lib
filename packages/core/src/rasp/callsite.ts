import { isAbsolute, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LIMITS } from '../contract.js';
import type { Callsite, CallsiteFrame } from '../types.js';

/** Frames lidos da pilha: ORMs e query builders costumam empilhar vários antes do driver. */
const MAX_FRAMES = 50;

// `at nome (arquivo:linha:coluna)` ou, sem nome, `at [async ]arquivo:linha:coluna`.
const FRAME = /^\s*at (?:(.+?) \(|(?:async )?)(.+?):(\d+):(\d+)\)?$/;

/**
 * Ponto do código da aplicação que chamou o driver: o primeiro frame abaixo de `below`
 * (o wrapper da RASP) que não está em `node_modules` nem nos módulos internos do Node.
 * Os frames seguintes da aplicação vão em `callers`: o caminho da requisição até a falha
 * (com `await`, o V8 inclui os frames assíncronos). O arquivo sai relativo a `cwd`; fora
 * dele (ou sem caminho), o frame é ignorado, para que caminhos absolutos da máquina (com
 * nome de usuário, por exemplo) nunca saiam do processo. Com `--enable-source-maps`, a
 * pilha já aponta o arquivo original (`.ts`).
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

/** Escolhe os frames da aplicação numa pilha do V8: o primeiro é o callsite, os outros, quem chamou. */
export function pickCallsite(stack: string, cwd: string): Callsite | undefined {
  const frames: CallsiteFrame[] = [];
  for (const line of stack.split('\n')) {
    const match = FRAME.exec(line);
    if (!match) continue;
    const [, name, location, row, col] = match;
    const file = appFile(location!, cwd);
    if (!file) continue;
    const frame = { file, line: Number(row), column: Number(col) || null, function: functionName(name) };
    // Recursão ou o mesmo ponto em sequência: um frame só.
    const previous = frames.at(-1);
    if (previous && previous.file === frame.file && previous.line === frame.line) continue;
    frames.push(frame);
    if (frames.length > LIMITS.callers) break;
  }
  const [callsite, ...callers] = frames;
  if (!callsite) return undefined;
  return callers.length > 0 ? { ...callsite, callers } : callsite;
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
