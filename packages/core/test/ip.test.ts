import { describe, expect, it } from 'vitest';
import { normalizeRoutePath } from '../src/normalize.js';
import { resolveClientIp } from '../src/ip.js';

describe('resolveClientIp', () => {
  it('ignora X-Forwarded-For quando não há proxy confiável', () => {
    expect(resolveClientIp('203.0.113.9', '1.2.3.4', false)).toBe('203.0.113.9');
  });

  it('usa o primeiro IP não confiável da direita para a esquerda', () => {
    expect(resolveClientIp('10.0.0.2', '198.51.100.7, 10.0.0.5', true)).toBe('198.51.100.7');
  });

  it('não confia no header se o socket não é um proxy confiável', () => {
    expect(resolveClientIp('198.51.100.7', '1.2.3.4', true)).toBe('198.51.100.7');
  });

  it('aceita lista explícita de proxies', () => {
    expect(resolveClientIp('192.0.2.1', '198.51.100.7', ['192.0.2.1'])).toBe('198.51.100.7');
  });

  it('remove o prefixo IPv4-mapeado', () => {
    expect(resolveClientIp('::ffff:203.0.113.9', undefined, false)).toBe('203.0.113.9');
  });
});

describe('normalizeRoutePath', () => {
  it('troca ids por :id', () => {
    expect(normalizeRoutePath('/users/42/orders/3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90')).toBe('/users/:id/orders/:id');
  });

  it('mantém segmentos textuais', () => {
    expect(normalizeRoutePath('/api/v1/health')).toBe('/api/v1/health');
  });
});
