const MAX_DEPTH = 8;
const MAX_VALUES = 500;
const MAX_VALUE_LENGTH = 8_192;

export interface InputValue {
  location: string;
  value: string;
}

/**
 * Decodifica URL encoding repetidamente (até 3 vezes) para desfazer tentativas de
 * disfarce como `%252e%252e%252f`, remove bytes nulos e espaços em excesso.
 */
export function decodeValue(raw: string): string {
  let value = raw.length > MAX_VALUE_LENGTH ? raw.slice(0, MAX_VALUE_LENGTH) : raw;
  for (let i = 0; i < 3; i++) {
    if (!/%[0-9a-f]{2}/i.test(value) && !value.includes('+')) break;
    try {
      const next = decodeURIComponent(value.replace(/\+/g, ' '));
      if (next === value) break;
      value = next;
    } catch {
      break;
    }
  }
  return value.replace(/\0/g, '').replace(/\s+/g, ' ');
}

/** Percorre query/body e devolve cada valor textual com sua localização. */
export function collectValues(input: unknown, prefix: string): InputValue[] {
  const out: InputValue[] = [];
  walk(input, prefix, 0, out);
  return out;
}

/** Devolve as chaves de objetos (ex.: `$ne`), usadas na detecção de NoSQL injection. */
export function collectKeys(input: unknown, prefix: string): InputValue[] {
  const out: InputValue[] = [];
  walkKeys(input, prefix, 0, out);
  return out;
}

function walk(input: unknown, location: string, depth: number, out: InputValue[]): void {
  if (out.length >= MAX_VALUES || depth > MAX_DEPTH || input == null) return;
  if (typeof input === 'string') {
    out.push({ location, value: decodeValue(input) });
    return;
  }
  if (typeof input === 'number' || typeof input === 'boolean') return;
  if (Array.isArray(input)) {
    input.forEach((item, i) => walk(item, `${location}[${i}]`, depth + 1, out));
    return;
  }
  if (typeof input === 'object') {
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      walk(value, `${location}.${key}`, depth + 1, out);
    }
  }
}

function walkKeys(input: unknown, location: string, depth: number, out: InputValue[]): void {
  if (out.length >= MAX_VALUES || depth > MAX_DEPTH || input == null || typeof input !== 'object') return;
  if (Array.isArray(input)) {
    input.forEach((item, i) => walkKeys(item, `${location}[${i}]`, depth + 1, out));
    return;
  }
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    out.push({ location: `${location}.${key}`, value: key });
    walkKeys(value, `${location}.${key}`, depth + 1, out);
  }
}

const ID_SEGMENT =
  /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24,}|[A-Za-z0-9_-]{32,})$/i;

/**
 * Converte um path concreto num padrão aproximado (`/users/42` → `/users/:id`).
 * Usado quando o framework não informa o padrão da rota (ex.: `node:http`).
 */
export function normalizeRoutePath(path: string): string {
  const clean = path.split('?')[0] ?? '/';
  const segments = clean.split('/').map((segment) => (ID_SEGMENT.test(segment) ? ':id' : segment));
  const joined = segments.join('/');
  return joined === '' ? '/' : joined;
}

export function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}
