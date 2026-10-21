import fs from 'node:fs';
import { readFile as namedReadFile } from 'node:fs/promises';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { createVigilo } from '../src/client.js';
import { runWithContext, type InputSources, type RequestContext } from '../src/rasp/context.js';
import { instrumentFs } from '../src/rasp/fs.js';
import { findPathTraversal } from '../src/rasp/path.js';
import { VigiloBlockedError } from '../src/rasp/wrap.js';

// Estrutura: <tmp>/public/doc.txt (permitido) e <tmp>/secret.txt (fora da pasta pública).
const root = mkdtempSync(join(tmpdir(), 'vigilo-fs-'));
const publicDir = join(root, 'public');
mkdirSync(join(publicDir, 'fotos'), { recursive: true });
writeFileSync(join(publicDir, 'doc.txt'), 'ok');
writeFileSync(join(publicDir, 'capa.png'), 'png');
writeFileSync(join(root, 'secret.txt'), 'segredo');

beforeAll(() => {
  expect(instrumentFs()).toBe(true);
});

function context(mode: 'monitor' | 'block', sources: InputSources): RequestContext {
  return createVigilo({ mode, flushIntervalMs: 0, send: async () => {} }).createContext(() => sources);
}

const input = (value: string, location = 'query.file') => ({ location, value });

describe('findPathTraversal', () => {
  it('detecta ../ literal e já resolvido por path.join', () => {
    expect(findPathTraversal(['/srv/public/../../etc/passwd'], [input('../../etc/passwd')])).toBeDefined();
    expect(findPathTraversal([join('/srv/public', '../../etc/passwd')], [input('../../etc/passwd')])).toBeDefined();
    expect(findPathTraversal(['C:\\app\\public\\..\\..\\win.ini'], [input('..\\..\\win.ini')])).toBeDefined();
  });

  it('detecta caminho absoluto escolhido pelo usuário', () => {
    expect(findPathTraversal(['/etc/passwd'], [input('/etc/passwd')])).toBeDefined();
  });

  it('não dispara com nomes de arquivo comuns nem com .. que não sobe', () => {
    expect(findPathTraversal(['/srv/public/relatorio..final.pdf'], [input('relatorio..final.pdf')])).toBeUndefined();
    expect(findPathTraversal(['/srv/public/capa.png'], [input('fotos/../capa.png')])).toBeUndefined();
    expect(findPathTraversal(['/srv/public/doc.txt'], [input('doc.txt')])).toBeUndefined();
  });

  it('não dispara quando um caminho absoluto do usuário só aparece no meio', () => {
    expect(findPathTraversal(['/app/views/dashboard.html'], [input('/dashboard', 'query.next')])).toBeUndefined();
  });
});

describe('instrumentFs', () => {
  const attack = { query: { file: '../secret.txt' } };
  const target = () => join(publicDir, attack.query.file);

  it('em monitor registra e deixa ler', async () => {
    const ctx = context('monitor', attack);
    const data = await runWithContext(ctx, () => fs.promises.readFile(target(), 'utf8'));
    expect(data).toBe('segredo');
    expect(ctx.threats).toEqual([
      { type: 'traversal', severity: 5, location: 'query.file', rule: 'rasp.traversal.fs', layer: 'rasp' },
    ]);
  });

  it('em block: promise rejeita, callback recebe erro, sync e stream lançam', async () => {
    const ctx = context('block', attack);
    await expect(runWithContext(ctx, () => fs.promises.readFile(target()))).rejects.toBeInstanceOf(VigiloBlockedError);
    await expect(runWithContext(ctx, () => namedReadFile(target()))).rejects.toBeInstanceOf(VigiloBlockedError);
    const error = await new Promise((resolve) => runWithContext(ctx, () => fs.readFile(target(), (err) => resolve(err))));
    expect(error).toBeInstanceOf(VigiloBlockedError);
    expect(() => runWithContext(ctx, () => fs.readFileSync(target()))).toThrow(VigiloBlockedError);
    expect(() => runWithContext(ctx, () => fs.createReadStream(target()))).toThrow(VigiloBlockedError);
    expect(ctx.blocked).toBe(true);
  });

  it('confere os dois caminhos de copyFile', () => {
    const ctx = context('block', { body: { dest: '../../tmp/x' } });
    expect(() =>
      runWithContext(ctx, () => fs.copyFileSync(join(publicDir, 'doc.txt'), join(publicDir, '../../tmp/x'))),
    ).toThrow(VigiloBlockedError);
  });

  it('leitura legítima passa em block', async () => {
    const ctx = context('block', { query: { file: 'doc.txt' }, path: '/files/doc.txt' });
    const data = await runWithContext(ctx, () => fs.promises.readFile(join(publicDir, 'doc.txt'), 'utf8'));
    expect(data).toBe('ok');
    expect(ctx.threats).toEqual([]);
  });

  it('fora de uma requisição nada é verificado', () => {
    expect(fs.readFileSync(join(publicDir, '../secret.txt'), 'utf8')).toBe('segredo');
  });

  it('é idempotente', () => {
    const before = fs.readFile;
    instrumentFs();
    expect(fs.readFile).toBe(before);
  });
});
