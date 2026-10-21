import { posix } from 'node:path';
import type { InputValue } from '../normalize.js';

const ABSOLUTE = /^(?:\/|[A-Za-z]:[\\/]|\\\\)/;

/**
 * Procura path traversal num caminho que vai para o sistema de arquivos. A entrada dispara quando:
 * - usa `..` para subir acima do ponto onde foi inserida (`../../etc/passwd` dispara;
 *   `fotos/../capa.png` não) e aparece no caminho, literal ou já resolvida por `path.join`
 *   (o caminho termina com o que sobra depois dos `..`, como `/etc/passwd`);
 * - é um caminho absoluto e o caminho final começa com ela (o usuário escolheu a raiz).
 */
export function findPathTraversal(paths: string[], inputs: InputValue[]): InputValue | undefined {
  for (const input of inputs) {
    const value = input.value;
    if (value.length < 2) continue;
    const escapes = climbsAbove(value);
    const absolute = ABSOLUTE.test(value);
    if (!escapes && !absolute) continue;
    const target = escapes ? afterClimb(value) : undefined;
    for (const path of paths) {
      if (absolute && path.startsWith(value)) return input;
      if (!escapes) continue;
      if (path.includes(value)) return input;
      const unixPath = path.replace(/\\/g, '/');
      if (target && (unixPath === target || unixPath.endsWith(`/${target}`))) return input;
    }
  }
  return undefined;
}

/** true se, percorrendo os segmentos, `..` sobe acima do diretório de partida. */
function climbsAbove(value: string): boolean {
  if (!value.includes('..')) return false;
  let depth = 0;
  for (const segment of value.split(/[\\/]+/)) {
    if (segment === '..') {
      if (--depth < 0) return true;
    } else if (segment !== '' && segment !== '.') {
      depth++;
    }
  }
  return false;
}

/** O destino depois dos `..` iniciais: `../../etc/passwd` → `etc/passwd`. */
function afterClimb(value: string): string | undefined {
  const normalized = posix.normalize(value.replace(/\\/g, '/'));
  const rest = normalized.replace(/^(?:\.\.\/)+/, '');
  return rest && rest !== '..' && rest !== '.' ? rest : undefined;
}
