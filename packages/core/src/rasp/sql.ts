import type { InputValue } from '../normalize.js';

export type SqlDialect = 'postgres' | 'mysql';

export type SqlTokenKind =
  | 'string'
  | 'identifier'
  | 'keyword'
  | 'number'
  | 'parameter'
  | 'operator'
  | 'punctuation'
  | 'comment';

export interface SqlToken {
  kind: SqlTokenKind;
  start: number;
  end: number;
}

/** Palavras reservadas que mudam a estrutura de uma query quando vêm da entrada do usuário. */
const KEYWORDS = new Set([
  'ALL', 'ALTER', 'AND', 'ANY', 'AS', 'ASC', 'BETWEEN', 'BY', 'CASE', 'CAST', 'COPY', 'CREATE',
  'CROSS', 'DELETE', 'DESC', 'DISTINCT', 'DO', 'DROP', 'ELSE', 'END', 'EXCEPT', 'EXEC', 'EXECUTE',
  'EXISTS', 'FALSE', 'FETCH', 'FIRST', 'FROM', 'FULL', 'GRANT', 'GROUP', 'HAVING', 'ILIKE', 'IN',
  'INNER', 'INSERT', 'INTERSECT', 'INTO', 'IS', 'JOIN', 'LAST', 'LEFT', 'LIKE', 'LIMIT', 'LOAD',
  'NOT', 'NULL', 'NULLS', 'OFFSET', 'ON', 'OR', 'ORDER', 'OUTER', 'PREPARE', 'REGEXP', 'RETURNING',
  'REVOKE', 'RIGHT', 'RLIKE', 'SELECT', 'SET', 'SIMILAR', 'SOME', 'TABLE', 'THEN', 'TRUE',
  'TRUNCATE', 'UNION', 'UPDATE', 'USING', 'VALUES', 'WHEN', 'WHERE', 'WITH', 'XOR',
]);

/**
 * Palavras-chave que, ao lado de identificadores, ainda não mudam a estrutura da query
 * (ex.: `ORDER BY ${coluna} ${direção}` com `name desc`).
 */
const ORDERING_KEYWORDS = new Set(['ASC', 'DESC', 'NULLS', 'FIRST', 'LAST']);

const WORD_START = /[A-Za-z_\u0080-￿]/;
const WORD_PART = /[A-Za-z0-9_$\u0080-￿]/;
const DIGIT = /[0-9]/;
const OPERATOR_CHAR = /[+\-*/<>=~!@#%^&|:?]/;
const PUNCTUATION = new Set(['(', ')', ',', ';', '.', '[', ']', '{', '}']);

/**
 * Tokenizador léxico tolerante: nunca lança exceção e trata literais ou comentários
 * não terminados como indo até o fim do texto (é assim que uma injeção quebrada aparece).
 */
export function tokenizeSql(sql: string, dialect: SqlDialect = 'postgres'): SqlToken[] {
  const tokens: SqlToken[] = [];
  const n = sql.length;
  let i = 0;

  while (i < n) {
    const ch = sql[i]!;
    const next = sql[i + 1];
    const start = i;

    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f') {
      i++;
      continue;
    }

    if ((ch === '-' && next === '-') || (dialect === 'mysql' && ch === '#')) {
      const eol = sql.indexOf('\n', i);
      i = eol === -1 ? n : eol;
      tokens.push({ kind: 'comment', start, end: i });
      continue;
    }

    if (ch === '/' && next === '*') {
      i = skipBlockComment(sql, i, dialect === 'postgres');
      tokens.push({ kind: 'comment', start, end: i });
      continue;
    }

    if (ch === "'") {
      i = skipQuoted(sql, i, "'", dialect === 'mysql');
      tokens.push({ kind: 'string', start, end: i });
      continue;
    }

    if (ch === '"') {
      // No MySQL (sem ANSI_QUOTES), aspas duplas delimitam strings.
      i = skipQuoted(sql, i, '"', dialect === 'mysql');
      tokens.push({ kind: dialect === 'mysql' ? 'string' : 'identifier', start, end: i });
      continue;
    }

    if (ch === '`' && dialect === 'mysql') {
      i = skipQuoted(sql, i, '`', false);
      tokens.push({ kind: 'identifier', start, end: i });
      continue;
    }

    if (ch === '$' && dialect === 'postgres') {
      if (next !== undefined && DIGIT.test(next)) {
        i++;
        while (i < n && DIGIT.test(sql[i]!)) i++;
        tokens.push({ kind: 'parameter', start, end: i });
        continue;
      }
      const tag = dollarTag(sql, i);
      if (tag) {
        const close = sql.indexOf(tag, i + tag.length);
        i = close === -1 ? n : close + tag.length;
        tokens.push({ kind: 'string', start, end: i });
        continue;
      }
    }

    if (ch === '?' && dialect === 'mysql') {
      i++;
      tokens.push({ kind: 'parameter', start, end: i });
      continue;
    }

    if (DIGIT.test(ch) || (ch === '.' && next !== undefined && DIGIT.test(next))) {
      i = skipNumber(sql, i);
      tokens.push({ kind: 'number', start, end: i });
      continue;
    }

    if (WORD_START.test(ch)) {
      // Prefixos de string: E'...' (escape com barra no PostgreSQL), N'', B'', X''.
      if (next === "'" && /[EeNnBbXx]/.test(ch)) {
        i = skipQuoted(sql, i + 1, "'", dialect === 'mysql' || ch === 'E' || ch === 'e');
        tokens.push({ kind: 'string', start, end: i });
        continue;
      }
      while (i < n && WORD_PART.test(sql[i]!)) i++;
      const word = sql.slice(start, i).toUpperCase();
      tokens.push({ kind: KEYWORDS.has(word) ? 'keyword' : 'identifier', start, end: i });
      continue;
    }

    if (PUNCTUATION.has(ch)) {
      i++;
      tokens.push({ kind: 'punctuation', start, end: i });
      continue;
    }

    if (OPERATOR_CHAR.test(ch)) {
      i++;
      // Um operador termina antes de um início de comentário (`=--`, `+/*`).
      while (i < n && OPERATOR_CHAR.test(sql[i]!) && !startsComment(sql, i, dialect)) i++;
      tokens.push({ kind: 'operator', start, end: i });
      continue;
    }

    // Qualquer outro caractere vira um operador de um caractere: muda a estrutura se vier do usuário.
    i++;
    tokens.push({ kind: 'operator', start, end: i });
  }

  return tokens;
}

/**
 * Procura uma entrada do usuário que, onde aparece no texto da query, atravessa mais de
 * um token de forma que muda a estrutura (fecha aspas, adiciona operador, palavra-chave,
 * comentário, parênteses ou `;`). Entradas contidas num único token (dentro de um literal,
 * um número, um identificador) são seguras, mesmo que pareçam SQL.
 */
export function findSqlInjection(
  sql: string,
  inputs: InputValue[],
  dialect: SqlDialect = 'postgres',
): InputValue | undefined {
  let tokens: SqlToken[] | undefined;
  for (const input of inputs) {
    const value = input.value;
    if (value.length < 2 || value.length > sql.length) continue;
    let at = sql.indexOf(value);
    while (at !== -1) {
      tokens ??= tokenizeSql(sql, dialect);
      if (changesStructure(sql, tokens, at, at + value.length)) return input;
      at = sql.indexOf(value, at + 1);
    }
  }
  return undefined;
}

function changesStructure(sql: string, tokens: SqlToken[], start: number, end: number): boolean {
  let covered = 0;
  let onlyHarmless = true;
  for (const token of tokens) {
    if (token.end <= start) continue;
    if (token.start >= end) break;
    covered++;
    if (!isHarmless(sql, token)) onlyHarmless = false;
  }
  return covered > 1 && !onlyHarmless;
}

/** Tokens que podem vir em sequência do usuário sem mudar a forma da query: listas de colunas e ordenação. */
function isHarmless(sql: string, token: SqlToken): boolean {
  switch (token.kind) {
    case 'identifier':
    case 'number':
      return true;
    case 'punctuation': {
      const ch = sql[token.start];
      return ch === ',' || ch === '.';
    }
    case 'keyword':
      return ORDERING_KEYWORDS.has(sql.slice(token.start, token.end).toUpperCase());
    default:
      return false;
  }
}

function startsComment(sql: string, i: number, dialect: SqlDialect): boolean {
  const pair = sql.slice(i, i + 2);
  return pair === '--' || pair === '/*' || (dialect === 'mysql' && sql[i] === '#');
}

function skipBlockComment(sql: string, i: number, nested: boolean): number {
  let depth = 0;
  while (i < sql.length) {
    if (sql[i] === '/' && sql[i + 1] === '*') {
      depth = nested ? depth + 1 : 1;
      i += 2;
    } else if (sql[i] === '*' && sql[i + 1] === '/') {
      depth--;
      i += 2;
      if (depth === 0) return i;
    } else {
      i++;
    }
  }
  return sql.length;
}

/** Avança sobre um literal entre `quote`, aceitando a aspa dobrada e, se `backslash`, `\` como escape. */
function skipQuoted(sql: string, i: number, quote: string, backslash: boolean): number {
  i++;
  while (i < sql.length) {
    const ch = sql[i];
    if (backslash && ch === '\\') {
      i += 2;
    } else if (ch === quote) {
      if (sql[i + 1] === quote) {
        i += 2;
      } else {
        return i + 1;
      }
    } else {
      i++;
    }
  }
  return sql.length;
}

/** `$$` ou `$tag$` no início de uma string com dollar quoting do PostgreSQL. */
function dollarTag(sql: string, i: number): string | undefined {
  const match = /^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
  return match?.[0];
}

function skipNumber(sql: string, i: number): number {
  if (sql[i] === '0' && (sql[i + 1] === 'x' || sql[i + 1] === 'X')) {
    i += 2;
    while (i < sql.length && /[0-9a-fA-F]/.test(sql[i]!)) i++;
    return i;
  }
  while (i < sql.length && /[0-9.]/.test(sql[i]!)) i++;
  if ((sql[i] === 'e' || sql[i] === 'E') && /[0-9+-]/.test(sql[i + 1] ?? '')) {
    i += 2;
    while (i < sql.length && DIGIT.test(sql[i]!)) i++;
  }
  return i;
}
