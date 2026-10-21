import type { InputValue } from '../normalize.js';
import type { InputSources } from './context.js';

const MAX_DEPTH = 10;
const MAX_NODES = 2_000;
/** Operadores que executam JavaScript no servidor do banco. */
const JS_OPERATORS = new Set(['$where', '$function', '$accumulator']);
/** Caracteres que, dentro de código JavaScript, indicam que a entrada saiu de um literal. */
const CODE_CHARS = /['"`;(){}|&=]/;

interface OperatorInput {
  location: string;
  value: Record<string, unknown>;
}

/**
 * Procura NoSQL injection num filtro, update ou pipeline do MongoDB:
 * 1. um objeto com operadores (`{ $ne: null }`, `{ $gt: '' }`, `{ $regex: '.*' }`) vindo da
 *    requisição aparece dentro da query, ou seja, o usuário escolheu o operador;
 * 2. código de `$where`/`$function`/`$accumulator` contém uma entrada com caracteres de código.
 * Devolve o local da entrada responsável.
 */
export function findNoSqlInjection(queries: unknown[], sources: InputSources): string | undefined {
  const operators: OperatorInput[] = [];
  const strings: InputValue[] = [];
  for (const [prefix, value] of [['params', sources.params], ['query', sources.query], ['body', sources.body]] as const) {
    collect(value, prefix, 0, operators, strings);
  }
  if (operators.length === 0 && strings.length === 0) return undefined;

  let nodes = 0;
  const visit = (node: unknown, depth: number): string | undefined => {
    if (node === null || typeof node !== 'object' || depth > MAX_DEPTH || ++nodes > MAX_NODES) return undefined;
    if (Array.isArray(node)) {
      for (const item of node) {
        const found = visit(item, depth + 1);
        if (found) return found;
      }
      return undefined;
    }
    const record = node as Record<string, unknown>;
    if (hasOperatorKey(record)) {
      const match = operators.find((op) => op.value === record || deepEqual(op.value, record, 0));
      if (match) return match.location;
    }
    for (const [key, value] of Object.entries(record)) {
      if (JS_OPERATORS.has(key)) {
        const found = injectedCode(value, strings);
        if (found) return found;
      }
      const found = visit(value, depth + 1);
      if (found) return found;
    }
    return undefined;
  };

  for (const query of queries) {
    const found = visit(query, 0);
    if (found) return found;
  }
  return undefined;
}

function collect(value: unknown, location: string, depth: number, operators: OperatorInput[], strings: InputValue[]): void {
  if (depth > MAX_DEPTH || value == null) return;
  if (typeof value === 'string') {
    if (value.length >= 2 && CODE_CHARS.test(value)) strings.push({ location, value });
    return;
  }
  if (typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((item, i) => collect(item, `${location}[${i}]`, depth + 1, operators, strings));
    return;
  }
  const record = value as Record<string, unknown>;
  if (hasOperatorKey(record)) operators.push({ location, value: record });
  for (const [key, child] of Object.entries(record)) collect(child, `${location}.${key}`, depth + 1, operators, strings);
}

/** Código JS montado com entrada do usuário (string única ou `{ body: '...' }` do `$function`). */
function injectedCode(value: unknown, strings: InputValue[]): string | undefined {
  const code =
    typeof value === 'string'
      ? value
      : value && typeof value === 'object' && typeof (value as { body?: unknown }).body === 'string'
        ? ((value as { body: string }).body)
        : undefined;
  if (!code) return undefined;
  return strings.find((input) => code.includes(input.value))?.location;
}

function hasOperatorKey(record: Record<string, unknown>): boolean {
  for (const key in record) if (key.startsWith('$')) return true;
  return false;
}

function deepEqual(a: unknown, b: unknown, depth: number): boolean {
  if (a === b) return true;
  if (depth > MAX_DEPTH || a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  return aKeys.every((key) =>
    deepEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key], depth + 1),
  );
}
