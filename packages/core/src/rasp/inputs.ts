import { headerValue, type InputValue } from '../normalize.js';
import type { InputSources } from './context.js';

const MAX_DEPTH = 8;
const MAX_VALUES = 500;
/** Cabeçalhos que aplicações costumam gravar no banco (logs de acesso, auditoria). */
const HEADERS = ['user-agent', 'referer', 'x-forwarded-for'];

/**
 * Coleta as entradas do usuário exatamente como o código da aplicação as recebe.
 * Diferente da camada de assinaturas, não decodifica nem normaliza espaços: a RASP
 * procura o valor literal dentro da query que vai para o banco.
 * Chaves de objetos entram também (ex.: coluna dinâmica em `UPDATE ... SET ${key}`).
 */
export function collectRaspInputs(sources: InputSources): InputValue[] {
  const out: InputValue[] = [];
  walk(sources.params, 'params', 0, out);
  walk(sources.query, 'query', 0, out);
  walk(sources.body, 'body', 0, out);
  if (sources.path) {
    for (const segment of sources.path.split('/')) {
      if (segment) out.push({ location: 'path', value: safeDecode(segment) });
    }
  }
  for (const name of HEADERS) {
    const value = headerValue(sources.headers?.[name]);
    if (value) out.push({ location: `header.${name}`, value });
  }
  return out;
}

function walk(input: unknown, location: string, depth: number, out: InputValue[]): void {
  if (out.length >= MAX_VALUES || depth > MAX_DEPTH || input == null) return;
  if (typeof input === 'string') {
    out.push({ location, value: input });
    return;
  }
  if (typeof input !== 'object') return;
  if (Array.isArray(input)) {
    input.forEach((item, i) => walk(item, `${location}[${i}]`, depth + 1, out));
    return;
  }
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    const child = `${location}.${key}`;
    out.push({ location: child, value: key });
    walk(value, child, depth + 1, out);
  }
}

function safeDecode(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}
