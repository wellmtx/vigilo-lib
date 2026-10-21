import { describe, expect, it } from 'vitest';
import { buildPayload, maskHeaders, maskObject, maskString, REDACTED } from '../src/masking.js';

describe('masking', () => {
  it('remove cabeçalhos sensíveis', () => {
    expect(maskHeaders({ authorization: 'Bearer abc', cookie: 'sid=1', accept: '*/*' })).toEqual({
      authorization: REDACTED,
      cookie: REDACTED,
      accept: '*/*',
    });
  });

  it('mascara e-mail, CPF, CNPJ e cartão válido em texto livre', () => {
    const out = maskString('joao@empresa.com.br 123.456.789-09 12.345.678/0001-95 4111 1111 1111 1111');
    expect(out).toBe('[EMAIL] [CPF] [CNPJ] [CARD]');
  });

  it('não mascara números que não passam no Luhn', () => {
    expect(maskString('pedido 1234567890123')).toBe('pedido 1234567890123');
  });

  it('remove valores de chaves sensíveis em objetos aninhados', () => {
    expect(maskObject({ user: { password: 'x', name: 'Ana' }, apiKey: 'k', tags: ['ok'] })).toEqual({
      user: { password: REDACTED, name: 'Ana' },
      apiKey: REDACTED,
      tags: ['ok'],
    });
  });

  it('aceita chaves extras configuradas', () => {
    expect(maskObject({ matricula: '123' }, { extraKeys: ['matricula'] })).toEqual({ matricula: REDACTED });
  });

  it('trunca o payload no limite de bytes', () => {
    const payload = buildPayload({ body: { text: 'a'.repeat(5_000) } });
    expect(Buffer.byteLength(payload)).toBeLessThan(2_100);
    expect(payload.endsWith('[truncated]')).toBe(true);
  });
});
