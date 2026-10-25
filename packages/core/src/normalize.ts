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

/** Segmento com cara de nome de recurso, versão ou arquivo (`users`, `v1`, `wp-login.php`). */
const NAME_SEGMENT = /^[A-Za-z0-9._~-]{1,64}$/;

/** Dígitos num segmento longo indicam dado (CPF, telefone, data, token), não nome. */
const DATA_SEGMENT = /^(?=.*\d).{8,}$/;

/**
 * Converte um path concreto num padrão aproximado (`/users/42` → `/users/:id`).
 * Usado quando o framework não informa o padrão da rota: sempre no `node:http`
 * e, no Express e no Fastify, em 404 e em requisições bloqueadas antes do
 * roteamento.
 *
 * O `route` vai para a plataforma sem mascaramento, então só ficam segmentos
 * com cara de nome. Ids, dados e qualquer coisa com encoding, espaço ou
 * símbolo (payload de ataque, e-mail, CPF, `..`) viram `:id`: o path de
 * `/users/1%20UNION%20SELECT...` vira `/users/:id`, como o framework diria.
 */
export function normalizeRoutePath(path: string): string {
  const clean = path.split('?')[0] ?? '/';
  const joined = clean.split('/').map(routeSegment).join('/');
  return joined === '' ? '/' : joined;
}

function routeSegment(segment: string): string {
  if (segment === '') return segment;
  const isName =
    NAME_SEGMENT.test(segment) && !ID_SEGMENT.test(segment) && !DATA_SEGMENT.test(segment) && !/^\.\.?$/.test(segment);
  return isName ? segment : ':id';
}

export function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}
