import type { InputValue } from '../normalize.js';

export type ShellTokenKind = 'word' | 'squote' | 'dquote' | 'operator' | 'substitution' | 'comment';

export interface ShellToken {
  kind: ShellTokenKind;
  start: number;
  end: number;
}

const OPERATORS = ['&&', '||', '>>', '<<', ';', '&', '|', '>', '<', '(', ')', '\n'];
const WORD_BREAK = /[\s;&|<>()'"`]/;
/** Dentro de aspas duplas o shell ainda expande `$(...)`, `${...}` e crases. */
const DQUOTE_EXPANSION = /\$\(|\$\{|`/;

/** Tokenizador léxico de comandos `sh`/`bash`, tolerante a aspas e substituições não terminadas. */
export function tokenizeShell(command: string): ShellToken[] {
  const tokens: ShellToken[] = [];
  const n = command.length;
  let i = 0;

  while (i < n) {
    const ch = command[i]!;
    const start = i;

    if (ch === ' ' || ch === '\t' || ch === '\r') {
      i++;
      continue;
    }
    if (ch === '#' && (i === 0 || /[\s;&|()]/.test(command[i - 1]!))) {
      const eol = command.indexOf('\n', i);
      i = eol === -1 ? n : eol;
      tokens.push({ kind: 'comment', start, end: i });
      continue;
    }
    if (ch === "'") {
      const close = command.indexOf("'", i + 1);
      i = close === -1 ? n : close + 1;
      tokens.push({ kind: 'squote', start, end: i });
      continue;
    }
    if (ch === '"') {
      i = skipDoubleQuoted(command, i);
      tokens.push({ kind: 'dquote', start, end: i });
      continue;
    }
    if (ch === '`') {
      const close = command.indexOf('`', i + 1);
      i = close === -1 ? n : close + 1;
      tokens.push({ kind: 'substitution', start, end: i });
      continue;
    }
    if (ch === '$' && (command[i + 1] === '(' || command[i + 1] === '{')) {
      i = skipBalanced(command, i + 1, command[i + 1] === '(' ? '(' : '{', command[i + 1] === '(' ? ')' : '}');
      tokens.push({ kind: 'substitution', start, end: i });
      continue;
    }
    const operator = OPERATORS.find((op) => command.startsWith(op, i));
    if (operator) {
      i += operator.length;
      tokens.push({ kind: 'operator', start, end: i });
      continue;
    }
    // Palavra: vai até um separador; `\` escapa o próximo caractere.
    while (i < n && !WORD_BREAK.test(command[i]!) && !(command[i] === '$' && /[({]/.test(command[i + 1] ?? ''))) {
      i += command[i] === '\\' ? 2 : 1;
    }
    if (i === start) i++;
    tokens.push({ kind: 'word', start, end: Math.min(i, n) });
  }
  return tokens;
}

/**
 * Procura uma entrada que, onde aparece no comando, cobre um operador, uma substituição ou
 * um comentário, sai de dentro de aspas, ou leva uma expansão para dentro de aspas duplas.
 * Várias palavras simples (`arquivo com espaço.txt`) e texto dentro de aspas simples são seguros.
 */
export function findCommandInjection(command: string, inputs: InputValue[]): InputValue | undefined {
  let tokens: ShellToken[] | undefined;
  for (const input of inputs) {
    const value = input.value;
    if (value.length < 2 || value.length > command.length) continue;
    let at = command.indexOf(value);
    while (at !== -1) {
      tokens ??= tokenizeShell(command);
      if (changesCommand(tokens, at, at + value.length, value)) return input;
      at = command.indexOf(value, at + 1);
    }
  }
  return undefined;
}

function changesCommand(tokens: ShellToken[], start: number, end: number, value: string): boolean {
  const covered = tokens.filter((t) => t.end > start && t.start < end);
  for (const token of covered) {
    if (token.kind === 'operator' || token.kind === 'substitution' || token.kind === 'comment') return true;
    if (token.kind === 'dquote' && DQUOTE_EXPANSION.test(value)) return true;
  }
  if (covered.length <= 1) return false;
  // Mais de um token: perigoso se a entrada começa ou termina no meio de um trecho entre aspas.
  return covered.some(
    (t) => (t.kind === 'squote' || t.kind === 'dquote') && (t.start < start || t.end > end),
  );
}

function skipDoubleQuoted(command: string, i: number): number {
  i++;
  while (i < command.length) {
    if (command[i] === '\\') i += 2;
    else if (command[i] === '"') return i + 1;
    else i++;
  }
  return command.length;
}

function skipBalanced(command: string, i: number, open: string, close: string): number {
  let depth = 0;
  while (i < command.length) {
    if (command[i] === open) depth++;
    else if (command[i] === close && --depth === 0) return i + 1;
    i++;
  }
  return command.length;
}
