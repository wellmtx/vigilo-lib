import type { HeaderValue } from './types.js';

export const REDACTED = '[REDACTED]';
export const DEFAULT_PAYLOAD_LIMIT = 2_048;

const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
]);

const SENSITIVE_KEY = /pass(?:word|wd)?|senha|secret|token|authorization|api[_-]?key|cpf|cnpj|card|cartao|cvv|ssn/i;

const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const CPF = /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g;
const CNPJ = /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g;
const CARD_CANDIDATE = /\b(?:\d[ -]?){13,19}\b/g;

export interface MaskingOptions {
  /** Chaves extras (além das padrão) cujo valor deve ser removido. */
  extraKeys?: Array<string | RegExp>;
}

export function maskHeaders(headers: Record<string, HeaderValue>): Record<string, HeaderValue> {
  const out: Record<string, HeaderValue> = {};
  for (const [name, value] of Object.entries(headers)) {
    out[name] = SENSITIVE_HEADERS.has(name.toLowerCase()) ? REDACTED : value;
  }
  return out;
}

/** Substitui dados pessoais dentro de um texto livre. */
export function maskString(value: string): string {
  return value
    .replace(EMAIL, '[EMAIL]')
    .replace(CNPJ, '[CNPJ]')
    .replace(CPF, '[CPF]')
    .replace(CARD_CANDIDATE, (match) => (luhn(match) ? '[CARD]' : match));
}

/** Copia o objeto mascarando chaves sensíveis e dados pessoais em strings. */
export function maskObject(input: unknown, options: MaskingOptions = {}, depth = 0): unknown {
  if (depth > 8) return '[DEPTH]';
  if (typeof input === 'string') return maskString(input);
  if (Array.isArray(input)) return input.map((item) => maskObject(item, options, depth + 1));
  if (input && typeof input === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      out[key] = isSensitiveKey(key, options) ? REDACTED : maskObject(value, options, depth + 1);
    }
    return out;
  }
  return input;
}

/** Serializa o payload mascarado e corta no limite de bytes (2 KB por padrão). */
export function buildPayload(
  parts: { query?: unknown; body?: unknown },
  options: MaskingOptions = {},
  limit: number = DEFAULT_PAYLOAD_LIMIT,
): string {
  const json = JSON.stringify({
    query: maskObject(parts.query ?? {}, options),
    body: parts.body === undefined ? undefined : maskObject(parts.body, options),
  });
  const buffer = Buffer.from(json, 'utf8');
  if (buffer.byteLength <= limit) return json;
  return `${buffer.subarray(0, limit).toString('utf8')}…[truncated]`;
}

function isSensitiveKey(key: string, options: MaskingOptions): boolean {
  if (SENSITIVE_KEY.test(key)) return true;
  return (options.extraKeys ?? []).some((rule) =>
    typeof rule === 'string' ? rule.toLowerCase() === key.toLowerCase() : rule.test(key),
  );
}

function luhn(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}
