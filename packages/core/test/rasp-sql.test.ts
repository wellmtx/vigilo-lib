import { describe, expect, it } from 'vitest';
import type { InputValue } from '../src/normalize.js';
import { findSqlInjection, tokenizeSql, type SqlDialect } from '../src/rasp/sql.js';

const input = (value: string, location = 'query.q'): InputValue => ({ location, value });
const kinds = (sql: string, dialect?: SqlDialect) =>
  tokenizeSql(sql, dialect).map((t) => [t.kind, sql.slice(t.start, t.end)]);

/** Simula a aplicação vulnerável: concatena a entrada no SQL e pergunta se a RASP detecta. */
const detects = (template: (v: string) => string, value: string, dialect?: SqlDialect) =>
  findSqlInjection(template(value), [input(value)], dialect) !== undefined;

describe('tokenizeSql', () => {
  it('separa literais, identificadores, palavras-chave, parâmetros e operadores', () => {
    expect(kinds("SELECT \"user\".name FROM users WHERE id = $1 AND note <> 'it''s'")).toEqual([
      ['keyword', 'SELECT'],
      ['identifier', '"user"'],
      ['punctuation', '.'],
      ['identifier', 'name'],
      ['keyword', 'FROM'],
      ['identifier', 'users'],
      ['keyword', 'WHERE'],
      ['identifier', 'id'],
      ['operator', '='],
      ['parameter', '$1'],
      ['keyword', 'AND'],
      ['identifier', 'note'],
      ['operator', '<>'],
      ['string', "'it''s'"],
    ]);
  });

  it('reconhece comentários, inclusive aninhados e colados em operadores', () => {
    expect(kinds("a =-- fim\n/* x /* y */ z */ b")).toEqual([
      ['identifier', 'a'],
      ['operator', '='],
      ['comment', '-- fim'],
      ['comment', '/* x /* y */ z */'],
      ['identifier', 'b'],
    ]);
  });

  it('reconhece dollar quoting e strings com escape (E-strings)', () => {
    expect(kinds("SELECT $tag$ it's $$ ok $tag$, E'a\\'b', 1.5e3")).toEqual([
      ['keyword', 'SELECT'],
      ['string', "$tag$ it's $$ ok $tag$"],
      ['punctuation', ','],
      ['string', "E'a\\'b'"],
      ['punctuation', ','],
      ['number', '1.5e3'],
    ]);
  });

  it('trata literal não terminado como indo até o fim', () => {
    expect(kinds("WHERE a = 'x")).toEqual([
      ['keyword', 'WHERE'],
      ['identifier', 'a'],
      ['operator', '='],
      ['string', "'x"],
    ]);
  });

  it('no MySQL, # é comentário, crase é identificador e \\ escapa aspas', () => {
    expect(kinds("SELECT `a` FROM t WHERE b = 'x\\'y' # fim", 'mysql')).toEqual([
      ['keyword', 'SELECT'],
      ['identifier', '`a`'],
      ['keyword', 'FROM'],
      ['identifier', 't'],
      ['keyword', 'WHERE'],
      ['identifier', 'b'],
      ['operator', '='],
      ['string', "'x\\'y'"],
      ['comment', '# fim'],
    ]);
  });
});

describe('findSqlInjection: detecção', () => {
  const quoted = (v: string) => `SELECT * FROM users WHERE name = '${v}'`;
  const numeric = (v: string) => `SELECT * FROM users WHERE id = ${v}`;

  it('tautologia que fecha a aspa', () => {
    expect(detects(quoted, "x' OR '1'='1")).toBe(true);
  });

  it('comentário que descarta o resto da query', () => {
    expect(detects((v) => `SELECT * FROM users WHERE name = '${v}' AND active`, "admin'--")).toBe(true);
  });

  it('UNION em campo numérico', () => {
    expect(detects(numeric, '1 UNION SELECT password FROM users')).toBe(true);
  });

  it('query empilhada', () => {
    expect(detects(numeric, '1; DROP TABLE users')).toBe(true);
  });

  it('tautologia só com palavras-chave (sem operador)', () => {
    expect(detects(numeric, '1 OR true')).toBe(true);
  });

  it('time-based com função', () => {
    expect(detects(numeric, '1 AND pg_sleep(5) IS NULL')).toBe(true);
  });

  it('nome de coluna dinâmico vindo de chave de objeto', () => {
    const key = "name = 'x', role = 'admin' --";
    const sql = `UPDATE users SET ${key} = $1 WHERE id = $2`;
    expect(findSqlInjection(sql, [input(key, 'body.' + key)])?.location).toBe(`body.${key}`);
  });

  it('acha a ocorrência perigosa mesmo depois de uma segura', () => {
    const sql = "SELECT * FROM t WHERE a = '1 OR 1=1' OR b = 1 OR 1=1";
    expect(findSqlInjection(sql, [input('1 OR 1=1')])).toBeDefined();
  });

  it('em MySQL, barra invertida não escapa a quebra da aspa', () => {
    expect(detects((v) => `SELECT * FROM t WHERE a = '${v}'`, "x' OR 1=1 #", 'mysql')).toBe(true);
  });

  it('devolve o local da entrada que causou a injeção', () => {
    const sql = numeric('1 OR 1=1');
    const found = findSqlInjection(sql, [input('users', 'query.table'), input('1 OR 1=1', 'params.id')]);
    expect(found?.location).toBe('params.id');
  });
});

describe('findSqlInjection: falsos positivos', () => {
  it('query parametrizada não contém a entrada, por mais maliciosa que seja', () => {
    expect(findSqlInjection('SELECT * FROM users WHERE name = $1', [input("x' OR '1'='1")])).toBeUndefined();
  });

  it('número concatenado é um único token', () => {
    expect(detects((v) => `SELECT * FROM users WHERE id = ${v}`, '42')).toBe(false);
  });

  it('texto com palavras SQL dentro de um literal', () => {
    expect(detects((v) => `INSERT INTO posts (title) VALUES ('${v}')`, 'how to select from a union or drop table')).toBe(false);
  });

  it('aspa escapada corretamente pela aplicação', () => {
    const v = "O'Brien";
    const sql = `SELECT * FROM users WHERE name = '${v.replace(/'/g, "''")}'`;
    expect(findSqlInjection(sql, [input(v)])).toBeUndefined();
  });

  it('ordenação e lista de colunas escolhidas pelo usuário', () => {
    expect(detects((v) => `SELECT * FROM users ORDER BY ${v}`, 'created_at desc')).toBe(false);
    expect(detects((v) => `SELECT ${v} FROM users`, 'id, name, users.email')).toBe(false);
    expect(detects((v) => `SELECT * FROM users ORDER BY ${v}`, 'name ASC NULLS LAST')).toBe(false);
  });

  it('palavra comum que também aparece no SQL do desenvolvedor', () => {
    const sql = 'SELECT * FROM users WHERE status = $1';
    expect(findSqlInjection(sql, [input('users'), input('select'), input('status')])).toBeUndefined();
  });

  it('padrão de LIKE e texto dentro de comentário do desenvolvedor', () => {
    expect(detects((v) => `SELECT * FROM p WHERE name LIKE '%${v}%'`, 'café com leite')).toBe(false);
    const sql = '/* list active users */ SELECT * FROM users';
    expect(findSqlInjection(sql, [input('list active users')])).toBeUndefined();
  });

  it('aspas dentro de dollar quoting', () => {
    expect(detects((v) => `SELECT $q$${v}$q$`, "it's a 'quote'")).toBe(false);
  });

  it('ignora entradas de um caractere', () => {
    expect(findSqlInjection('SELECT * FROM t WHERE a = 1', [input('='), input('1')])).toBeUndefined();
  });
});
