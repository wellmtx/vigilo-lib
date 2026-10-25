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
    expect(normalizeRoutePath('/api/oauth2/token')).toBe('/api/oauth2/token');
    expect(normalizeRoutePath('/produtos/camiseta-azul')).toBe('/produtos/camiseta-azul');
  });

  it('mantém alvos de scanners', () => {
    expect(normalizeRoutePath('/.env')).toBe('/.env');
    expect(normalizeRoutePath('/.git/config')).toBe('/.git/config');
    expect(normalizeRoutePath('/wp-login.php')).toBe('/wp-login.php');
  });

  it('não deixa payload de ataque no route', () => {
    expect(normalizeRoutePath('/users/1%20UNION%20SELECT%20password%20FROM%20users')).toBe('/users/:id');
    expect(normalizeRoutePath("/users/1' OR '1'='1")).toBe('/users/:id');
    expect(normalizeRoutePath('/search/<script>alert(1)</script>')).toBe('/search/:id/:id');
    expect(normalizeRoutePath('/files/../../etc/passwd')).toBe('/files/:id/:id/etc/passwd');
    expect(normalizeRoutePath('/files/..%2f..%2fetc%2fpasswd')).toBe('/files/:id');
    expect(normalizeRoutePath('/run/$(id)')).toBe('/run/:id');
  });

  it('não deixa dados pessoais no route', () => {
    expect(normalizeRoutePath('/clientes/123.456.789-00')).toBe('/clientes/:id');
    expect(normalizeRoutePath('/contatos/joao@exemplo.com.br')).toBe('/contatos/:id');
    expect(normalizeRoutePath('/telefones/+5511987654321')).toBe('/telefones/:id');
    expect(normalizeRoutePath('/reset/eyJhbGciOiJIUzI1NiJ9')).toBe('/reset/:id');
    expect(normalizeRoutePath('/relatorios/2026-10-25')).toBe('/relatorios/:id');
  });

  it('troca segmentos longos demais', () => {
    expect(normalizeRoutePath(`/a/${'x'.repeat(65)}`)).toBe('/a/:id');
  });

  it('ignora a query string e mantém a raiz', () => {
    expect(normalizeRoutePath('/users/42?email=a@b.com')).toBe('/users/:id');
    expect(normalizeRoutePath('/')).toBe('/');
    expect(normalizeRoutePath('')).toBe('/');
  });
});
